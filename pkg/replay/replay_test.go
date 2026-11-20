package replay

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func writeScenario(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "http-404.yaml")
	content := `type: leaky
name: test/http-404
description: repeated 404
filter: evt.Meta.log_type == "http" && evt.Parsed.status == "404"
groupby: evt.Meta.source_ip
capacity: 2
leakspeed: 10s
labels:
  remediation: true
version: ` + version + `
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func testHTTPEvent(ip, status string, ts time.Time) pipeline.Event {
	return pipeline.Event{
		Type:          pipeline.LOG,
		ExpectMode:    pipeline.TIMEMACHINE,
		Parsed:        map[string]string{"status": status},
		Meta:          map[string]string{"source_ip": ip, "log_type": "http"},
		Unmarshaled:   map[string]any{},
		MarshaledTime: ts.UTC().Format(time.RFC3339Nano),
	}
}

func TestReplayThree404TriggersBan(t *testing.T) {
	rules, err := LoadRuleSet([]string{writeScenario(t, "0.3")}, t.TempDir())
	require.NoError(t, err)
	require.Len(t, rules.Rules, 1)
	require.Equal(t, "0.3", rules.Rules[0].Version)

	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	source := SourceFromEvents([]pipeline.Event{
		testHTTPEvent("192.0.2.10", "404", start),
		testHTTPEvent("192.0.2.10", "404", start.Add(time.Second)),
		testHTTPEvent("192.0.2.10", "404", start.Add(2*time.Second)),
	}, SourceLocalLogs, "fixture", Coverage{Complete: true})

	result, err := Replay(t.Context(), rules, source, Options{Settle: 200 * time.Millisecond})
	require.NoError(t, err)
	require.Equal(t, 1, result.Overflows)
	require.Len(t, result.Bans, 1)
	require.Equal(t, "192.0.2.10", result.Bans[0].Value)
	require.Equal(t, "test/http-404", result.Bans[0].Scenario)
	require.Equal(t, "0.3", result.Bans[0].ScenarioVersion)
	require.NotEmpty(t, result.Bans[0].ScenarioHash)
	require.Equal(t, 4*time.Hour, result.Bans[0].Duration)
	require.Equal(t, "medium", result.Confidence.Level)
}

func TestReplayPreservesThreshold(t *testing.T) {
	rules, err := LoadRuleSet([]string{writeScenario(t, "0.3")}, t.TempDir())
	require.NoError(t, err)

	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	source := SourceFromEvents([]pipeline.Event{
		testHTTPEvent("192.0.2.11", "404", start),
		testHTTPEvent("192.0.2.11", "200", start.Add(time.Second)),
	}, SourceLocalLogs, "fixture", Coverage{Complete: true})

	result, err := Replay(t.Context(), rules, source, Options{Settle: 100 * time.Millisecond})
	require.NoError(t, err)
	require.Zero(t, result.Overflows)
	require.Empty(t, result.Bans)
}

func TestReplayShardedIsDeterministic(t *testing.T) {
	rules, err := LoadRuleSet([]string{writeScenario(t, "0.3")}, t.TempDir())
	require.NoError(t, err)

	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	events := []pipeline.Event{
		testHTTPEvent("192.0.2.30", "404", start),
		testHTTPEvent("192.0.2.31", "404", start),
		testHTTPEvent("192.0.2.30", "404", start.Add(time.Second)),
		testHTTPEvent("192.0.2.31", "404", start.Add(time.Second)),
		testHTTPEvent("192.0.2.30", "404", start.Add(2*time.Second)),
		testHTTPEvent("192.0.2.31", "404", start.Add(2*time.Second)),
	}
	source := SourceFromEvents(events, SourceLocalLogs, "fixture", Coverage{Complete: true})

	serial, err := Replay(t.Context(), rules, source, Options{Settle: 200 * time.Millisecond})
	require.NoError(t, err)

	sharded, err := Replay(t.Context(), rules, source, Options{
		Workers: 2,
		Settle:  200 * time.Millisecond,
		ShardKey: func(event pipeline.Event) string {
			return event.Meta["source_ip"]
		},
	})
	require.NoError(t, err)
	require.Equal(t, serial.Bans, sharded.Bans)
	require.Len(t, sharded.Bans, 2)
}

func TestMergeBans(t *testing.T) {
	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	bans := []Ban{
		{Scope: "Ip", Type: "ban", Value: "192.0.2.1", Scenario: "rule/a", Duration: time.Hour, StartedAt: start, Until: start.Add(time.Hour), Severity: 1},
		{Scope: "Ip", Type: "ban", Value: "192.0.2.1", Scenario: "rule/b", Duration: 4 * time.Hour, StartedAt: start, Until: start.Add(4 * time.Hour), Severity: 5},
	}

	longest := mergeBans(bans, MergeLongest)
	require.Len(t, longest, 1)
	require.Equal(t, 4*time.Hour, longest[0].Duration)
	require.Equal(t, []string{"rule/a", "rule/b"}, longest[0].Rules)

	sum := mergeBans(bans, MergeSum)
	require.Len(t, sum, 1)
	require.Equal(t, 5*time.Hour, sum[0].Duration)

	severity := mergeBans(bans, MergeSeverity)
	require.Len(t, severity, 1)
	require.Equal(t, "rule/b", severity[0].Scenario)
	require.Equal(t, 4*time.Hour, severity[0].Duration)
}

func TestCompareAndFeedback(t *testing.T) {
	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	predicted := []Ban{
		{Scope: "Ip", Type: "ban", Value: "192.0.2.1", Scenario: "rule/a", ScenarioVersion: "1", ScenarioHash: "abc", Duration: 4 * time.Hour, StartedAt: start, Until: start.Add(4 * time.Hour)},
		{Scope: "Ip", Type: "ban", Value: "192.0.2.2", Scenario: "rule/a", ScenarioVersion: "1", ScenarioHash: "abc", Duration: 4 * time.Hour, StartedAt: start, Until: start.Add(4 * time.Hour)},
	}
	actual := []Ban{
		{Scope: "Ip", Type: "ban", Value: "192.0.2.1", Scenario: "rule/a", Duration: 4 * time.Hour, StartedAt: start, Until: start.Add(4 * time.Hour)},
		{Scope: "Ip", Type: "ban", Value: "192.0.2.3", Scenario: "rule/a", Duration: 4 * time.Hour, StartedAt: start, Until: start.Add(4 * time.Hour)},
	}

	result := &Result{Bans: predicted}
	store, err := OpenFeedbackStore("")
	require.NoError(t, err)
	require.NoError(t, store.Add(Feedback{
		Rule:       "rule/a",
		Version:    "1",
		Hash:       "abc",
		Scope:      "Ip",
		Type:       "ban",
		Value:      "192.0.2.2",
		DetectedAt: start,
		RevokedAt:  start.Add(90 * time.Second),
	}))
	store.Apply(result)
	require.Len(t, result.Feedback, 1)
	require.Equal(t, 2, result.Feedback[0].Hits)
	require.Equal(t, 1, result.Feedback[0].FalsePositives)
	require.InDelta(t, 0.5, result.Feedback[0].Score, 0.001)

	comparison := result.Compare(actual, store.List())
	require.Equal(t, 2, comparison.Summary.PredictedBans)
	require.Equal(t, 2, comparison.Summary.ActualBans)
	require.Equal(t, 1, comparison.Summary.FalsePositiveBans)
	require.Equal(t, 90*time.Second, comparison.Summary.RevocationLatency)
	require.Len(t, comparison.Diff.OnlyPredicted, 1)
	require.Equal(t, "192.0.2.2", comparison.Diff.OnlyPredicted[0].Value)
	require.Len(t, comparison.Diff.OnlyActual, 1)
	require.Equal(t, "192.0.2.3", comparison.Diff.OnlyActual[0].Value)
}

func TestSourceFromAlertsAndBans(t *testing.T) {
	scope := "Ip"
	value := "192.0.2.44"
	scenario := "test/http-404"
	version := "0.3"
	hash := "deadbeef"
	duration := "4h"
	ts := "2026-11-20T10:00:00Z"
	alerts := []*models.Alert{{
		Scenario:        &scenario,
		ScenarioVersion: &version,
		ScenarioHash:    &hash,
		StopAt:          &ts,
		Source:          &models.Source{Scope: &scope, Value: &value, IP: value},
		Events: []*models.Event{{
			Timestamp: &ts,
			Meta:      models.Meta{{Key: "source_ip", Value: value}},
		}},
		Decisions: []*models.Decision{{
			Scope:    &scope,
			Type:     new("ban"),
			Value:    &value,
			Duration: &duration,
			Scenario: &scenario,
		}},
	}}

	source := SourceFromAlerts(alerts, SourceAlertDB, "alerts")
	require.False(t, source.Coverage.Complete)
	require.Len(t, source.Events, 1)
	require.Equal(t, value, source.Events[0].Meta["source_ip"])

	bans := BansFromAlerts(alerts)
	require.Len(t, bans, 1)
	require.Equal(t, 4*time.Hour, bans[0].Duration)
	require.Equal(t, version, bans[0].ScenarioVersion)
	require.Equal(t, hash, bans[0].ScenarioHash)
}

func TestDiffRuleSets(t *testing.T) {
	previous := &RuleSet{Rules: []RuleRef{
		{Name: "rule/removed", Version: "1", Hash: "a"},
		{Name: "rule/changed", Version: "1", Hash: "b"},
		{Name: "rule/same", Version: "1", Hash: "c"},
	}}
	current := &RuleSet{Rules: []RuleRef{
		{Name: "rule/added", Version: "1", Hash: "d"},
		{Name: "rule/changed", Version: "2", Hash: "e"},
		{Name: "rule/same", Version: "1", Hash: "c"},
	}}

	diff := DiffRuleSets(previous, current)
	require.Equal(t, []RuleRef{{Name: "rule/added", Version: "1", Hash: "d"}}, diff.Added)
	require.Equal(t, []RuleRef{{Name: "rule/removed", Version: "1", Hash: "a"}}, diff.Removed)
	require.Equal(t, []RuleRef{{Name: "rule/changed", Version: "2", Hash: "e"}}, diff.Changed)
}

func TestEmptyReplayHasLowConfidence(t *testing.T) {
	rules, err := LoadRuleSet([]string{writeScenario(t, "0.3")}, t.TempDir())
	require.NoError(t, err)

	result, err := Replay(t.Context(), rules, SourceFromEvents(nil, SourceAlertDB, "empty", Coverage{}), Options{})
	require.NoError(t, err)
	require.Zero(t, result.Events)
	require.Zero(t, result.Overflows)
	require.Equal(t, "low", result.Confidence.Level)
	require.Zero(t, result.Confidence.Score)
}

func TestFeedbackStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feedback.json")
	store, err := OpenFeedbackStore(path)
	require.NoError(t, err)

	detected := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	require.NoError(t, store.Add(Feedback{
		Rule:       "rule/a",
		Version:    "1",
		Hash:       "abc",
		Scope:      "Ip",
		Type:       "ban",
		Value:      "192.0.2.1",
		Reason:     "legacy browser",
		DetectedAt: detected,
		RevokedAt:  detected.Add(30 * time.Second),
	}))

	reloaded, err := OpenFeedbackStore(path)
	require.NoError(t, err)
	require.Equal(t, store.List(), reloaded.List())
	require.Equal(t, 30*time.Second, reloaded.List()[0].latency())
}

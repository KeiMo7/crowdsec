package replay

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type SourceKind string

const (
	SourceLocalLogs  SourceKind = "local_logs"
	SourceAlertDB    SourceKind = "alert_db"
	SourceNodeExport SourceKind = "node_export"
)

type Coverage struct {
	Complete   bool      `json:"complete" yaml:"complete"`
	EventCount int       `json:"event_count" yaml:"event_count"`
	From       time.Time `json:"from,omitempty" yaml:"from,omitempty"`
	To         time.Time `json:"to,omitempty" yaml:"to,omitempty"`
	Notes      []string  `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type Source struct {
	Kind     SourceKind       `json:"kind" yaml:"kind"`
	Name     string           `json:"name" yaml:"name"`
	Events   []pipeline.Event `json:"events" yaml:"events"`
	Coverage Coverage         `json:"coverage" yaml:"coverage"`
}

func (s Source) validate() error {
	switch s.Kind {
	case SourceLocalLogs, SourceAlertDB, SourceNodeExport:
	default:
		return fmt.Errorf("unknown replay source kind %q", s.Kind)
	}
	if s.Name == "" {
		return fmt.Errorf("replay source name is required")
	}
	return nil
}

func (s Source) summary() SourceSummary {
	coverage := s.Coverage
	if coverage.EventCount == 0 {
		coverage.EventCount = len(s.Events)
	}
	if coverage.From.IsZero() || coverage.To.IsZero() {
		for _, event := range s.Events {
			ts := eventTime(event)
			if ts.IsZero() {
				continue
			}
			if coverage.From.IsZero() || ts.Before(coverage.From) {
				coverage.From = ts
			}
			if coverage.To.IsZero() || ts.After(coverage.To) {
				coverage.To = ts
			}
		}
	}
	return SourceSummary{
		Kind:     s.Kind,
		Name:     s.Name,
		Coverage: coverage,
	}
}

type SourceSummary struct {
	Kind     SourceKind `json:"kind" yaml:"kind"`
	Name     string     `json:"name" yaml:"name"`
	Coverage Coverage   `json:"coverage" yaml:"coverage"`
}

type Ban struct {
	Scope           string        `json:"scope" yaml:"scope"`
	Type            string        `json:"type" yaml:"type"`
	Value           string        `json:"value" yaml:"value"`
	Scenario        string        `json:"scenario" yaml:"scenario"`
	ScenarioVersion string        `json:"scenario_version,omitempty" yaml:"scenario_version,omitempty"`
	ScenarioHash    string        `json:"scenario_hash,omitempty" yaml:"scenario_hash,omitempty"`
	Rules           []string      `json:"rules,omitempty" yaml:"rules,omitempty"`
	Duration        time.Duration `json:"duration" yaml:"duration"`
	StartedAt       time.Time     `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	Until           time.Time     `json:"until,omitempty" yaml:"until,omitempty"`
	Simulated       bool          `json:"simulated,omitempty" yaml:"simulated,omitempty"`
	Severity        int           `json:"severity,omitempty" yaml:"severity,omitempty"`
}

func (b Ban) Key() string {
	return strings.ToLower(b.Scope) + "\x00" + strings.ToLower(b.Type) + "\x00" + b.Value
}

func (b Ban) ruleIdentity() string {
	return b.Scenario + "\x00" + b.ScenarioVersion + "\x00" + b.ScenarioHash
}

func sortBans(bans []Ban) {
	sort.SliceStable(bans, func(i, j int) bool {
		if bans[i].StartedAt.Equal(bans[j].StartedAt) {
			return bans[i].Key() < bans[j].Key()
		}
		if bans[i].StartedAt.IsZero() {
			return false
		}
		if bans[j].StartedAt.IsZero() {
			return true
		}
		return bans[i].StartedAt.Before(bans[j].StartedAt)
	})
}

func eventTime(event pipeline.Event) time.Time {
	if event.MarshaledTime != "" {
		if ts, err := time.Parse(time.RFC3339Nano, event.MarshaledTime); err == nil {
			return ts
		}
	}
	return event.Time
}

type Options struct {
	Profiles           []*Profile
	Merge              MergeStrategy
	Workers            int
	BatchSize          int
	Settle             time.Duration
	PreserveInputOrder bool
	SeverityByScenario map[string]int
	// ShardKey is optional. When set with Workers > 1, events with the same
	// key are replayed in their own bucket store. The key must be at least as
	// fine-grained as every scenario's groupby expression.
	ShardKey func(pipeline.Event) string
}

func (o Options) withDefaults() Options {
	if o.Merge == "" {
		o.Merge = MergeLongest
	}
	if o.Workers < 1 {
		o.Workers = 1
	}
	if o.BatchSize < 1 {
		o.BatchSize = 1000
	}
	if o.Settle <= 0 {
		o.Settle = 100 * time.Millisecond
	}
	return o
}

type Result struct {
	RulesetID  string        `json:"ruleset_id" yaml:"ruleset_id"`
	Rules      []RuleRef     `json:"rules" yaml:"rules"`
	Source     SourceSummary `json:"source" yaml:"source"`
	StartedAt  time.Time     `json:"started_at" yaml:"started_at"`
	FinishedAt time.Time     `json:"finished_at" yaml:"finished_at"`
	Events     int           `json:"events" yaml:"events"`
	Overflows  int           `json:"overflows" yaml:"overflows"`
	Skipped    int           `json:"skipped" yaml:"skipped"`
	Bans       []Ban         `json:"bans" yaml:"bans"`
	Confidence Confidence    `json:"confidence" yaml:"confidence"`
	Feedback   []RuleScore   `json:"feedback,omitempty" yaml:"feedback,omitempty"`
	Errors     []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type RuleRef struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Hash    string `json:"hash" yaml:"hash"`
}

type Confidence struct {
	Level   string   `json:"level" yaml:"level"`
	Score   float64  `json:"score" yaml:"score"`
	Reasons []string `json:"reasons" yaml:"reasons"`
}

type Diff struct {
	OnlyPredicted []Ban `json:"only_predicted,omitempty" yaml:"only_predicted,omitempty"`
	OnlyActual    []Ban `json:"only_actual,omitempty" yaml:"only_actual,omitempty"`
	Changed       []Ban `json:"changed,omitempty" yaml:"changed,omitempty"`
}

type Summary struct {
	PredictedBans     int           `json:"predicted_bans" yaml:"predicted_bans"`
	ActualBans        int           `json:"actual_bans" yaml:"actual_bans"`
	FalsePositiveBans int           `json:"false_positive_bans" yaml:"false_positive_bans"`
	RevocationLatency time.Duration `json:"revocation_latency" yaml:"revocation_latency"`
}

type Comparison struct {
	Summary Summary `json:"summary" yaml:"summary"`
	Diff    Diff    `json:"diff" yaml:"diff"`
}

package replay

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type indexedEvent struct {
	event pipeline.Event
	index int
	time  time.Time
}

type shardResult struct {
	overflows int
	events    int
	skipped   int
	bans      []Ban
	errors    []string
}

func Replay(ctx context.Context, rules *RuleSet, source Source, opts Options) (*Result, error) {
	if rules == nil {
		return nil, fmt.Errorf("replay rules are required")
	}
	if err := source.validate(); err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	if err := opts.Merge.Validate(); err != nil {
		return nil, err
	}

	decisionEngine, err := newDecisionEngine(opts)
	if err != nil {
		return nil, err
	}

	started := time.Now().UTC()
	events := prepareEvents(source.Events, opts.PreserveInputOrder)
	shards := shardEvents(events, opts)

	results := make([]shardResult, len(shards))
	if opts.Workers <= 1 || len(shards) <= 1 {
		for idx := range shards {
			results[idx] = replayShard(ctx, rules, shards[idx], decisionEngine, opts)
		}
	} else {
		var wg sync.WaitGroup
		sem := make(chan struct{}, opts.Workers)
		for idx := range shards {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[idx] = replayShard(ctx, rules, shards[idx], decisionEngine, opts)
			}(idx)
		}
		wg.Wait()
	}

	result := &Result{
		RulesetID:  rules.ID,
		Rules:      append([]RuleRef(nil), rules.Rules...),
		Source:     source.summary(),
		StartedAt:  started,
		FinishedAt: time.Now().UTC(),
	}
	allBans := make([]Ban, 0)
	for _, shard := range results {
		result.Events += shard.events
		result.Overflows += shard.overflows
		result.Skipped += shard.skipped
		result.Errors = append(result.Errors, shard.errors...)
		allBans = append(allBans, shard.bans...)
	}

	result.Bans = mergeBans(allBans, opts.Merge)
	sort.Strings(result.Errors)
	result.Confidence = confidenceFor(result, source)
	return result, nil
}

func prepareEvents(events []pipeline.Event, preserveOrder bool) []indexedEvent {
	prepared := make([]indexedEvent, 0, len(events))
	for idx, event := range events {
		event = event.CopyForBucket()
		event.ExpectMode = pipeline.TIMEMACHINE
		if event.MarshaledTime == "" && !event.Time.IsZero() {
			event.MarshaledTime = event.Time.UTC().Format(time.RFC3339Nano)
		}
		prepared = append(prepared, indexedEvent{
			event: event,
			index: idx,
			time:  eventTime(event),
		})
	}

	if !preserveOrder {
		sort.SliceStable(prepared, func(i, j int) bool {
			if prepared[i].time.Equal(prepared[j].time) {
				return prepared[i].index < prepared[j].index
			}
			if prepared[i].time.IsZero() {
				return false
			}
			if prepared[j].time.IsZero() {
				return true
			}
			return prepared[i].time.Before(prepared[j].time)
		})
	}

	return prepared
}

func shardEvents(events []indexedEvent, opts Options) [][]indexedEvent {
	if opts.Workers <= 1 || opts.ShardKey == nil {
		return [][]indexedEvent{events}
	}

	shards := make(map[string][]indexedEvent)
	for _, event := range events {
		key := opts.ShardKey(event.event)
		shards[key] = append(shards[key], event)
	}

	keys := make([]string, 0, len(shards))
	for key := range shards {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([][]indexedEvent, 0, len(keys))
	for _, key := range keys {
		out = append(out, shards[key])
	}
	return out
}

func replayShard(
	parent context.Context,
	rules *RuleSet,
	events []indexedEvent,
	engine *decisionEngine,
	opts Options,
) shardResult {
	result := shardResult{}
	if len(events) == 0 {
		return result
	}

	response := make(chan pipeline.Event, 4096)
	factories, err := rules.factories(response)
	if err != nil {
		result.errors = append(result.errors, fmt.Sprintf("loading rules: %s", err))
		return result
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	collected := make(chan []pipeline.Event, 1)
	stopCollect := make(chan struct{})
	go func() {
		var overflows []pipeline.Event
		for {
			select {
			case event := <-response:
				overflows = append(overflows, event)
			case <-stopCollect:
				collected <- overflows
				return
			}
		}
	}()

	buckets := leakybucket.NewBucketStore()
	for idx, item := range events {
		if item.time.IsZero() {
			result.skipped++
			continue
		}

		if idx > 0 && idx%opts.BatchSize == 0 {
			leakybucket.GarbageCollectBuckets(item.time, buckets)
		}

		if _, err := leakybucket.PourItemToHolders(ctx, item.event, factories, buckets, nil); err != nil {
			result.errors = append(result.errors, fmt.Sprintf("event %d: %s", item.index, err))
			continue
		}
		result.events++
	}

	time.Sleep(opts.Settle)
	cancel()
	time.Sleep(opts.Settle)
	close(stopCollect)
	overflows := <-collected

	for _, event := range overflows {
		if event.Overflow.Alert == nil {
			continue
		}
		result.overflows++
		bans, errs := engine.decisionsFromOverflow(event)
		result.bans = append(result.bans, bans...)
		result.errors = append(result.errors, errs...)
	}

	return result
}

type decisionEngine struct {
	profiles []*csprofiles.Runtime
	opts     Options
}

func newDecisionEngine(opts Options) (*decisionEngine, error) {
	profiles := opts.Profiles
	if profiles == nil {
		profiles = defaultReplayProfiles()
	}

	runtimeProfiles, err := csprofiles.NewProfile(profiles)
	if err != nil {
		return nil, fmt.Errorf("compiling replay profiles: %w", err)
	}

	return &decisionEngine{
		profiles: runtimeProfiles,
		opts:     opts,
	}, nil
}

func defaultReplayProfiles() []*Profile {
	duration := "4h"
	decisionType := "ban"
	return []*Profile{
		{
			Name:    "replay_default_ip",
			Filters: []string{`Alert.Remediation == true && Alert.GetScope() == "Ip"`},
			Decisions: []models.Decision{
				{Type: &decisionType, Duration: &duration},
			},
			OnSuccess: "break",
		},
		{
			Name:    "replay_default_range",
			Filters: []string{`Alert.Remediation == true && Alert.GetScope() == "Range"`},
			Decisions: []models.Decision{
				{Type: &decisionType, Duration: &duration},
			},
			OnSuccess: "break",
		},
	}
}

func (e *decisionEngine) decisionsFromOverflow(event pipeline.Event) ([]Ban, []string) {
	alerts := event.Overflow.APIAlerts
	if len(alerts) == 0 && event.Overflow.Alert != nil {
		alerts = []models.Alert{*event.Overflow.Alert}
	}

	bans := make([]Ban, 0)
	errs := make([]string, 0)
	for _, alert := range alerts {
		alert := alert
		for idx, profile := range e.profiles {
			decisions, matched, err := profile.EvaluateProfile(&alert)
			if err != nil {
				errs = append(errs, fmt.Sprintf("profile %s: %s", profile.Cfg.Name, err))
				switch profile.Cfg.OnError {
				case "continue", "ignore":
					continue
				case "apply":
					matched = true
				case "break":
					break
				default:
					continue
				}
			}
			if !matched {
				continue
			}

			for _, decision := range decisions {
				ban, err := banFromDecision(&alert, decision, e.opts)
				if err != nil {
					errs = append(errs, fmt.Sprintf("profile %s: %s", profile.Cfg.Name, err))
					continue
				}
				bans = append(bans, ban)
			}

			if profile.Cfg.OnSuccess == "break" {
				break
			}
			if idx == len(e.profiles)-1 {
				break
			}
		}
	}

	return bans, errs
}

func banFromDecision(alert *models.Alert, decision *models.Decision, opts Options) (Ban, error) {
	if decision == nil || decision.Scope == nil || decision.Type == nil || decision.Value == nil {
		return Ban{}, fmt.Errorf("profile generated an incomplete decision")
	}

	duration := 4 * time.Hour
	if decision.Duration != nil && *decision.Duration != "" {
		parsed, err := cstime.ParseDurationWithDays(*decision.Duration)
		if err != nil {
			return Ban{}, fmt.Errorf("invalid decision duration %q: %w", *decision.Duration, err)
		}
		duration = parsed
	}

	startedAt := time.Time{}
	if alert.StopAt != nil {
		startedAt, _ = time.Parse(time.RFC3339, *alert.StopAt)
	}
	if startedAt.IsZero() && alert.StartAt != nil {
		startedAt, _ = time.Parse(time.RFC3339, *alert.StartAt)
	}

	scenario := ""
	if alert.Scenario != nil {
		scenario = *alert.Scenario
	}
	version := ""
	if alert.ScenarioVersion != nil {
		version = *alert.ScenarioVersion
	}
	hash := ""
	if alert.ScenarioHash != nil {
		hash = *alert.ScenarioHash
	}

	ban := Ban{
		Scope:           *decision.Scope,
		Type:            *decision.Type,
		Value:           *decision.Value,
		Scenario:        scenario,
		ScenarioVersion: version,
		ScenarioHash:    hash,
		Duration:        duration,
		StartedAt:       startedAt,
		Simulated:       decision.Simulated != nil && *decision.Simulated,
		Severity:        opts.SeverityByScenario[scenario],
		Rules:           []string{scenario},
	}
	if !startedAt.IsZero() {
		ban.Until = startedAt.Add(duration)
	}
	return ban, nil
}

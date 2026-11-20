package replay

import (
	"sort"
	"time"
)

type MergeStrategy string

const (
	// MergeLongest preserves the historical LAPI/bouncer behavior: for the
	// same scope/type/value, the decision with the latest expiry wins.
	MergeLongest MergeStrategy = "longest"
	// MergeSum adds the duration contributed by every matching rule.
	MergeSum MergeStrategy = "sum"
	// MergeSeverity keeps the rule with the highest Severity, then falls back
	// to the longest duration when severities are equal.
	MergeSeverity MergeStrategy = "severity"
)

func (s MergeStrategy) Validate() error {
	switch s {
	case "", MergeLongest, MergeSum, MergeSeverity:
		return nil
	default:
		return &invalidMergeStrategy{strategy: s}
	}
}

type invalidMergeStrategy struct {
	strategy MergeStrategy
}

func (e *invalidMergeStrategy) Error() string {
	return "unknown decision duration merge strategy: " + string(e.strategy)
}

func mergeBans(bans []Ban, strategy MergeStrategy) []Ban {
	if strategy == "" {
		strategy = MergeLongest
	}

	groups := make(map[string][]Ban)
	for _, ban := range bans {
		groups[ban.Key()] = append(groups[ban.Key()], ban)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	merged := make([]Ban, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].Until.Equal(group[j].Until) {
				if group[i].Severity == group[j].Severity {
					return group[i].ruleIdentity() < group[j].ruleIdentity()
				}
				return group[i].Severity > group[j].Severity
			}
			return group[i].Until.After(group[j].Until)
		})

		ban := group[0]
		ban.Rules = mergeRuleNames(group)
		switch strategy {
		case MergeSum:
			ban = mergeSum(group)
		case MergeSeverity:
			ban = mergeSeverity(group)
		case MergeLongest:
			ban.Duration = positiveDuration(ban.Until.Sub(ban.StartedAt), ban.Duration)
		}
		merged = append(merged, ban)
	}

	sortBans(merged)
	return merged
}

func mergeRuleNames(group []Ban) []string {
	seen := make(map[string]struct{})
	for _, ban := range group {
		name := ban.Scenario
		if name == "" {
			name = ban.ScenarioHash
		}
		if name != "" {
			seen[name] = struct{}{}
		}
		for _, rule := range ban.Rules {
			seen[rule] = struct{}{}
		}
	}

	rules := make([]string, 0, len(seen))
	for rule := range seen {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	return rules
}

func mergeSum(group []Ban) Ban {
	ban := group[0]
	ban.Duration = 0
	start := ban.StartedAt

	for _, item := range group {
		ban.Duration += positiveDuration(item.Duration, item.Until.Sub(item.StartedAt))
		if !item.StartedAt.IsZero() && (start.IsZero() || item.StartedAt.Before(start)) {
			start = item.StartedAt
		}
	}

	ban.StartedAt = start
	if !start.IsZero() {
		ban.Until = start.Add(ban.Duration)
	}
	return ban
}

func mergeSeverity(group []Ban) Ban {
	sort.SliceStable(group, func(i, j int) bool {
		if group[i].Severity == group[j].Severity {
			return group[i].Until.After(group[j].Until)
		}
		return group[i].Severity > group[j].Severity
	})

	return group[0]
}

func positiveDuration(preferred, fallback time.Duration) time.Duration {
	if preferred > 0 {
		return preferred
	}
	if fallback > 0 {
		return fallback
	}
	return 0
}

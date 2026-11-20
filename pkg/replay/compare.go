package replay

import (
	"sort"
	"time"
)

func Compare(predicted, actual []Ban) Comparison {
	predicted = mergeBans(predicted, MergeLongest)
	actual = mergeBans(actual, MergeLongest)

	predictedByKey := make(map[string]Ban, len(predicted))
	for _, ban := range predicted {
		predictedByKey[ban.Key()] = ban
	}
	actualByKey := make(map[string]Ban, len(actual))
	for _, ban := range actual {
		actualByKey[ban.Key()] = ban
	}

	diff := Diff{}
	for key, predictedBan := range predictedByKey {
		actualBan, ok := actualByKey[key]
		if !ok {
			diff.OnlyPredicted = append(diff.OnlyPredicted, predictedBan)
			continue
		}
		if decisionDurationChanged(predictedBan, actualBan) {
			changed := predictedBan
			changed.Duration = actualBan.Duration
			changed.Until = actualBan.Until
			changed.Rules = mergeRuleNames([]Ban{predictedBan, actualBan})
			diff.Changed = append(diff.Changed, changed)
		}
	}
	for key, actualBan := range actualByKey {
		if _, ok := predictedByKey[key]; !ok {
			diff.OnlyActual = append(diff.OnlyActual, actualBan)
		}
	}

	sortBans(diff.OnlyPredicted)
	sortBans(diff.OnlyActual)
	sortBans(diff.Changed)

	return Comparison{
		Summary: Summary{
			PredictedBans: uniqueBanCount(predicted),
			ActualBans:    uniqueBanCount(actual),
		},
		Diff: diff,
	}
}

func (r *Result) Compare(actual []Ban, feedback []Feedback) Comparison {
	comparison := Compare(r.Bans, actual)

	falsePositiveKeys := make(map[string]struct{})
	var totalLatency time.Duration
	var latencyCount int
	for _, item := range feedback {
		falsePositiveKeys[item.key()] = struct{}{}
		if latency := item.latency(); latency > 0 {
			totalLatency += latency
			latencyCount++
		}
	}
	comparison.Summary.FalsePositiveBans = len(falsePositiveKeys)
	if latencyCount > 0 {
		comparison.Summary.RevocationLatency = totalLatency / time.Duration(latencyCount)
	}

	return comparison
}

func uniqueBanCount(bans []Ban) int {
	keys := make(map[string]struct{}, len(bans))
	for _, ban := range bans {
		if ban.Simulated {
			continue
		}
		keys[ban.Key()] = struct{}{}
	}
	return len(keys)
}

func decisionDurationChanged(predicted, actual Ban) bool {
	if predicted.Duration != actual.Duration {
		return true
	}
	if predicted.Until.IsZero() || actual.Until.IsZero() {
		return predicted.Until.IsZero() != actual.Until.IsZero()
	}
	return !predicted.Until.Equal(actual.Until)
}

func sortBansByKey(bans []Ban) {
	sort.SliceStable(bans, func(i, j int) bool {
		return bans[i].Key() < bans[j].Key()
	})
}

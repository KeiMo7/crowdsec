package replay

import "fmt"

func confidenceFor(result *Result, source Source) Confidence {
	score := 0.5
	reasons := make([]string, 0, 4)

	if result.Events == 0 {
		return Confidence{
			Level: "low",
			Score: 0,
			Reasons: append(reasons,
				"source produced no replayable events",
				"no ban estimate can be trusted from this sample",
			),
		}
	}

	switch source.Kind {
	case SourceLocalLogs:
		score += 0.25
		reasons = append(reasons, "replayed from locally collected parsed events")
	case SourceNodeExport:
		score += 0.1
		reasons = append(reasons, "replayed from a sample exported by another node; coverage may be partial")
	case SourceAlertDB:
		score -= 0.2
		reasons = append(reasons, "replayed from historical alerts; only event windows that overflowed are present")
	}

	if source.Coverage.Complete {
		score += 0.2
		reasons = append(reasons, "source declares complete coverage")
	} else {
		score -= 0.15
		reasons = append(reasons, "source coverage is not declared complete")
	}

	switch {
	case result.Events >= 10000:
		score += 0.1
	case result.Events < 100:
		score -= 0.3
		reasons = append(reasons, fmt.Sprintf("small replay sample (%d events)", result.Events))
	}

	if result.Skipped > 0 {
		ratio := float64(result.Skipped) / float64(max(result.Events+result.Skipped, 1))
		score -= min(ratio, 0.25)
		reasons = append(reasons, fmt.Sprintf("%d events were skipped", result.Skipped))
	}
	if len(result.Errors) > 0 {
		score -= min(float64(len(result.Errors))/100, 0.2)
		reasons = append(reasons, fmt.Sprintf("%d replay errors were recorded", len(result.Errors)))
	}

	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}

	level := "low"
	switch {
	case score >= 0.8:
		level = "high"
	case score >= 0.45:
		level = "medium"
	}

	return Confidence{Level: level, Score: score, Reasons: reasons}
}

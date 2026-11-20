package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type AlertQuerier interface {
	QueryAlertWithFilter(ctx context.Context, filter map[string][]string) ([]*ent.Alert, error)
}

// LoadSourceFromDB reads historical alerts directly from the LAPI database.
// Alert events are retained overflow windows, so the resulting confidence is
// intentionally lower than a complete local event replay.
func LoadSourceFromDB(ctx context.Context, db AlertQuerier, filter map[string][]string, name string) (Source, []Ban, error) {
	alerts, err := db.QueryAlertWithFilter(ctx, filter)
	if err != nil {
		return Source{}, nil, fmt.Errorf("querying historical alerts: %w", err)
	}
	if name == "" {
		name = "alert_db"
	}

	events := make([]pipeline.Event, 0)
	bans := make([]Ban, 0)
	for _, alert := range alerts {
		events = append(events, eventsFromEntAlert(alert)...)
		bans = append(bans, bansFromEntAlert(alert)...)
	}

	source := SourceFromEvents(events, SourceAlertDB, name, Coverage{
		Complete: false,
		Notes: []string{
			"historical alerts contain only the events retained in each overflow window",
		},
	})
	sortBans(bans)
	return source, bans, nil
}

func eventsFromEntAlert(alert *ent.Alert) []pipeline.Event {
	if alert == nil {
		return nil
	}

	sourceIP := ""
	if alert.SourceScope == "Ip" {
		sourceIP = alert.SourceIp
		if sourceIP == "" {
			sourceIP = alert.SourceValue
		}
	}

	if len(alert.Edges.Events) == 0 {
		event := pipeline.Event{
			Type:          pipeline.LOG,
			ExpectMode:    pipeline.TIMEMACHINE,
			Parsed:        make(map[string]string),
			Meta:          make(map[string]string),
			Unmarshaled:   make(map[string]any),
			MarshaledTime: alert.StoppedAt.UTC().Format(time.RFC3339Nano),
		}
		if sourceIP != "" {
			event.Meta["source_ip"] = sourceIP
		}
		return []pipeline.Event{event}
	}

	events := make([]pipeline.Event, 0, len(alert.Edges.Events))
	for _, stored := range alert.Edges.Events {
		event := pipeline.Event{
			Type:          pipeline.LOG,
			ExpectMode:    pipeline.TIMEMACHINE,
			Parsed:        make(map[string]string),
			Meta:          make(map[string]string),
			Unmarshaled:   make(map[string]any),
			MarshaledTime: stored.Time.UTC().Format(time.RFC3339Nano),
		}

		var meta models.Meta
		if err := json.Unmarshal([]byte(stored.Serialized), &meta); err == nil {
			for _, item := range meta {
				if item != nil {
					event.Meta[item.Key] = item.Value
				}
			}
		}
		if sourceIP != "" {
			event.Meta["source_ip"] = sourceIP
		}
		events = append(events, event)
	}
	return events
}

func bansFromEntAlert(alert *ent.Alert) []Ban {
	if alert == nil {
		return nil
	}

	startedAt := alert.StoppedAt
	bans := make([]Ban, 0, len(alert.Edges.Decisions))
	for _, decision := range alert.Edges.Decisions {
		if decision == nil {
			continue
		}
		duration := time.Duration(0)
		until := time.Time{}
		if decision.Until != nil {
			until = *decision.Until
			duration = until.Sub(startedAt)
		}

		bans = append(bans, Ban{
			Scope:           decision.Scope,
			Type:            decision.Type,
			Value:           decision.Value,
			Scenario:        alert.Scenario,
			ScenarioVersion: alert.ScenarioVersion,
			ScenarioHash:    alert.ScenarioHash,
			Rules:           []string{alert.Scenario},
			Duration:        duration,
			StartedAt:       startedAt,
			Until:           until,
			Simulated:       decision.Simulated,
		})
	}
	return bans
}

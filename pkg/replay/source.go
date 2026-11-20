package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type eventFile struct {
	Events []pipeline.Event `json:"events" yaml:"events"`
	Lines  []pipeline.Event `json:"lines" yaml:"lines"`
}

func LoadSourceFile(path string, kind SourceKind, name string) (Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Source{}, fmt.Errorf("reading replay source %q: %w", path, err)
	}
	if name == "" {
		name = path
	}

	if source, ok, err := sourceFromJSON(data, kind, name); ok {
		return source, err
	}
	if source, ok, err := sourceFromJSONLines(data, kind, name); ok {
		return source, err
	}

	var file eventFile
	if err := yaml.Unmarshal(data, &file); err == nil {
		events := file.Events
		if len(events) == 0 {
			events = file.Lines
		}
		if len(events) > 0 {
			return SourceFromEvents(events, kind, name, Coverage{
				Complete: kind == SourceLocalLogs || kind == SourceNodeExport,
			}), nil
		}
	}

	return Source{}, fmt.Errorf("replay source %q is not a supported event or alert export", path)
}

func sourceFromJSON(data []byte, kind SourceKind, name string) (Source, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Source{}, false, nil
	}

	if trimmed[0] == '[' {
		var events []pipeline.Event
		if err := json.Unmarshal(trimmed, &events); err == nil && len(events) > 0 && looksLikeEvent(events[0]) {
			return SourceFromEvents(events, kind, name, Coverage{
				Complete: kind == SourceLocalLogs || kind == SourceNodeExport,
			}), true, nil
		}

		var alerts []*models.Alert
		if err := json.Unmarshal(trimmed, &alerts); err == nil && len(alerts) > 0 {
			return SourceFromAlerts(alerts, kind, name), true, nil
		}
	}

	var file eventFile
	if err := json.Unmarshal(trimmed, &file); err == nil {
		events := file.Events
		if len(events) == 0 {
			events = file.Lines
		}
		if len(events) > 0 {
			return SourceFromEvents(events, kind, name, Coverage{
				Complete: kind == SourceLocalLogs || kind == SourceNodeExport,
			}), true, nil
		}
	}

	var alerts []*models.Alert
	if err := json.Unmarshal(trimmed, &alerts); err == nil && len(alerts) > 0 {
		return SourceFromAlerts(alerts, kind, name), true, nil
	}

	return Source{}, false, nil
}

func sourceFromJSONLines(data []byte, kind SourceKind, name string) (Source, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

	events := make([]pipeline.Event, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event pipeline.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			if lineNumber == 1 {
				return Source{}, false, nil
			}
			return Source{}, true, fmt.Errorf("parsing replay source line %d: %w", lineNumber, err)
		}
		if !looksLikeEvent(event) {
			return Source{}, false, nil
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return Source{}, true, fmt.Errorf("reading replay source: %w", err)
	}
	if len(events) == 0 {
		return Source{}, false, nil
	}

	return SourceFromEvents(events, kind, name, Coverage{
		Complete: kind == SourceLocalLogs || kind == SourceNodeExport,
	}), true, nil
}

func looksLikeEvent(event pipeline.Event) bool {
	return event.MarshaledTime != "" ||
		!event.Time.IsZero() ||
		len(event.Parsed) > 0 ||
		len(event.Meta) > 0 ||
		len(event.Unmarshaled) > 0 ||
		event.Type == pipeline.OVFLW
}

func SourceFromEvents(events []pipeline.Event, kind SourceKind, name string, coverage Coverage) Source {
	coverage.EventCount = len(events)
	return Source{
		Kind:     kind,
		Name:     name,
		Events:   events,
		Coverage: coverage,
	}
}

func SourceFromAlerts(alerts []*models.Alert, kind SourceKind, name string) Source {
	events := make([]pipeline.Event, 0)
	for _, alert := range alerts {
		if alert == nil {
			continue
		}
		sourceIP := ""
		if alert.Source != nil && alert.Source.Scope != nil && strings.EqualFold(*alert.Source.Scope, "ip") {
			sourceIP = alert.Source.IP
			if sourceIP == "" && alert.Source.Value != nil {
				sourceIP = *alert.Source.Value
			}
		}

		if len(alert.Events) == 0 {
			event := pipeline.Event{
				Type:        pipeline.LOG,
				ExpectMode:  pipeline.TIMEMACHINE,
				Parsed:      make(map[string]string),
				Meta:        make(map[string]string),
				Unmarshaled: make(map[string]any),
			}
			if alert.StopAt != nil {
				event.MarshaledTime = *alert.StopAt
			}
			if sourceIP != "" {
				event.Meta["source_ip"] = sourceIP
			}
			events = append(events, event)
			continue
		}

		for _, exported := range alert.Events {
			event := pipeline.Event{
				Type:        pipeline.LOG,
				ExpectMode:  pipeline.TIMEMACHINE,
				Parsed:      make(map[string]string),
				Meta:        make(map[string]string),
				Unmarshaled: make(map[string]any),
			}
			if exported.Timestamp != nil {
				event.MarshaledTime = *exported.Timestamp
			}
			for _, meta := range exported.Meta {
				if meta == nil {
					continue
				}
				event.Meta[meta.Key] = meta.Value
			}
			if sourceIP != "" {
				event.Meta["source_ip"] = sourceIP
			}
			events = append(events, event)
		}
	}

	coverage := Coverage{
		Complete: false,
		Notes: []string{
			"historical alerts contain only the events retained in each overflow window",
		},
	}
	return SourceFromEvents(events, kind, name, coverage)
}

func BansFromAlerts(alerts []*models.Alert) []Ban {
	bans := make([]Ban, 0)
	for _, alert := range alerts {
		if alert == nil {
			continue
		}

		scenario, version, hash := "", "", ""
		if alert.Scenario != nil {
			scenario = *alert.Scenario
		}
		if alert.ScenarioVersion != nil {
			version = *alert.ScenarioVersion
		}
		if alert.ScenarioHash != nil {
			hash = *alert.ScenarioHash
		}

		startedAt := time.Time{}
		if alert.StopAt != nil {
			startedAt, _ = time.Parse(time.RFC3339, *alert.StopAt)
		}
		if startedAt.IsZero() && alert.StartAt != nil {
			startedAt, _ = time.Parse(time.RFC3339, *alert.StartAt)
		}

		for _, decision := range alert.Decisions {
			if decision == nil || decision.Scope == nil || decision.Type == nil || decision.Value == nil {
				continue
			}
			duration := time.Duration(0)
			if decision.Duration != nil {
				duration, _ = cstime.ParseDurationWithDays(*decision.Duration)
			}
			simulated := alert.Simulated != nil && *alert.Simulated
			if decision.Simulated != nil {
				simulated = *decision.Simulated
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
				Simulated:       simulated,
				Rules:           []string{scenario},
			}
			if !startedAt.IsZero() && duration > 0 {
				ban.Until = startedAt.Add(duration)
			}
			bans = append(bans, ban)
		}
	}

	sortBans(bans)
	return bans
}

func LoadAlertExport(path string, kind SourceKind, name string) (Source, []Ban, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Source{}, nil, fmt.Errorf("reading alert export %q: %w", path, err)
	}
	if name == "" {
		name = path
	}

	var alerts []*models.Alert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return Source{}, nil, fmt.Errorf("parsing alert export %q: %w", path, err)
	}
	if len(alerts) == 0 {
		return Source{}, nil, errors.New("no alerts in export")
	}
	return SourceFromAlerts(alerts, kind, name), BansFromAlerts(alerts), nil
}

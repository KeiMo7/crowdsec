package replay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Feedback struct {
	Rule       string    `json:"rule" yaml:"rule"`
	Version    string    `json:"version,omitempty" yaml:"version,omitempty"`
	Hash       string    `json:"hash,omitempty" yaml:"hash,omitempty"`
	Scope      string    `json:"scope" yaml:"scope"`
	Type       string    `json:"type" yaml:"type"`
	Value      string    `json:"value" yaml:"value"`
	Reason     string    `json:"reason,omitempty" yaml:"reason,omitempty"`
	DetectedAt time.Time `json:"detected_at" yaml:"detected_at"`
	RevokedAt  time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
}

func (f Feedback) key() string {
	return Ban{Scope: f.Scope, Type: f.Type, Value: f.Value}.Key()
}

func (f Feedback) latency() time.Duration {
	if f.RevokedAt.IsZero() || f.DetectedAt.IsZero() || f.RevokedAt.Before(f.DetectedAt) {
		return 0
	}
	return f.RevokedAt.Sub(f.DetectedAt)
}

type RuleScore struct {
	Rule           string  `json:"rule" yaml:"rule"`
	Version        string  `json:"version,omitempty" yaml:"version,omitempty"`
	Hash           string  `json:"hash,omitempty" yaml:"hash,omitempty"`
	Hits           int     `json:"hits" yaml:"hits"`
	FalsePositives int     `json:"false_positives" yaml:"false_positives"`
	Score          float64 `json:"score" yaml:"score"`
}

type FeedbackStore struct {
	mu    sync.RWMutex
	path  string
	items []Feedback
}

func OpenFeedbackStore(path string) (*FeedbackStore, error) {
	store := &FeedbackStore{path: path}
	if path == "" {
		return store, nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading replay feedback: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.items); err != nil {
		return nil, fmt.Errorf("parsing replay feedback: %w", err)
	}
	return store, nil
}

func (s *FeedbackStore) Add(feedback Feedback) error {
	if feedback.Rule == "" {
		return errors.New("feedback rule is required")
	}
	if feedback.Scope == "" || feedback.Type == "" || feedback.Value == "" {
		return errors.New("feedback scope, type and value are required")
	}
	if feedback.DetectedAt.IsZero() {
		feedback.DetectedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, feedback)
	return s.persistLocked()
}

func (s *FeedbackStore) List() []Feedback {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Feedback(nil), s.items...)
}

func (s *FeedbackStore) Persist() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistLocked()
}

func (s *FeedbackStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("creating replay feedback directory: %w", err)
	}

	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling replay feedback: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".replay-feedback-*")
	if err != nil {
		return fmt.Errorf("creating replay feedback temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing replay feedback: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing replay feedback: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing replay feedback: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replacing replay feedback: %w", err)
	}
	return nil
}

func (s *FeedbackStore) Apply(result *Result) {
	if result == nil {
		return
	}

	hits := make(map[string]int)
	hitKeysByRule := make(map[string]map[string]struct{})
	for _, ban := range result.Bans {
		key := feedbackRuleKey(ban.Scenario, ban.ScenarioVersion, ban.ScenarioHash)
		hits[key]++
		if hitKeysByRule[ban.Scenario] == nil {
			hitKeysByRule[ban.Scenario] = make(map[string]struct{})
		}
		hitKeysByRule[ban.Scenario][key] = struct{}{}
	}

	falsePositives := make(map[string]int)
	for _, item := range s.List() {
		key := feedbackRuleKey(item.Rule, item.Version, item.Hash)
		if item.Version == "" && item.Hash == "" {
			if keys := hitKeysByRule[item.Rule]; len(keys) > 0 {
				for hitKey := range keys {
					falsePositives[hitKey]++
				}
				continue
			}
		}
		falsePositives[key]++
	}

	keys := make(map[string]struct{})
	for key := range hits {
		keys[key] = struct{}{}
	}
	for key := range falsePositives {
		keys[key] = struct{}{}
	}

	scores := make([]RuleScore, 0, len(keys))
	for key := range keys {
		rule, version, hash := splitFeedbackRuleKey(key)
		hitCount := hits[key]
		fpCount := falsePositives[key]
		denominator := hitCount
		if fpCount > denominator {
			denominator = fpCount
		}

		score := 1.0
		if denominator > 0 {
			score = float64(max(denominator-fpCount, 0)) / float64(denominator)
		}
		scores = append(scores, RuleScore{
			Rule:           rule,
			Version:        version,
			Hash:           hash,
			Hits:           hitCount,
			FalsePositives: fpCount,
			Score:          score,
		})
	}

	sortScores(scores)
	result.Feedback = scores
}

func feedbackRuleKey(rule, version, hash string) string {
	return rule + "\x00" + version + "\x00" + hash
}

func splitFeedbackRuleKey(key string) (string, string, string) {
	var rule, version, hash string
	parts := []string{"", "", ""}
	start := 0
	idx := 0
	for i := 0; i < len(key); i++ {
		if key[i] == 0 && idx < 2 {
			parts[idx] = key[start:i]
			idx++
			start = i + 1
		}
	}
	parts[idx] = key[start:]
	rule, version, hash = parts[0], parts[1], parts[2]
	return rule, version, hash
}

func sortScores(scores []RuleScore) {
	for i := 1; i < len(scores); i++ {
		for j := i; j > 0; j-- {
			if scores[j-1].Rule < scores[j].Rule ||
				(scores[j-1].Rule == scores[j].Rule && scores[j-1].Hash <= scores[j].Hash) {
				break
			}
			scores[j-1], scores[j] = scores[j], scores[j-1]
		}
	}
}

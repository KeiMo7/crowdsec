package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Profile = csconfig.ProfileCfg

type RuleSet struct {
	ID      string
	Rules   []RuleRef
	DataDir string

	sources []leaky.ScenarioSource
	loadMu  sync.Mutex
}

func LoadRuleSet(paths []string, dataDir string) (*RuleSet, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one scenario file is required")
	}

	expanded, err := expandScenarioPaths(paths)
	if err != nil {
		return nil, err
	}

	sources := make([]leaky.ScenarioSource, 0, len(expanded))
	for _, path := range expanded {
		hash, version, err := scenarioFileMetadata(path)
		if err != nil {
			return nil, err
		}
		sources = append(sources, leaky.ScenarioSource{
			Name:    strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Path:    path,
			Version: version,
			Hash:    hash,
		})
	}

	return NewRuleSet(sources, dataDir)
}

func expandScenarioPaths(paths []string) ([]string, error) {
	expanded := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("reading scenario path %q: %w", path, err)
		}
		if !info.IsDir() {
			expanded = append(expanded, path)
			continue
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("reading scenario directory %q: %w", path, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".yaml" || ext == ".yml" {
				expanded = append(expanded, filepath.Join(path, entry.Name()))
			}
		}
	}
	sort.Strings(expanded)
	if len(expanded) == 0 {
		return nil, errors.New("no scenario files found")
	}
	return expanded, nil
}

func NewRuleSet(sources []leaky.ScenarioSource, dataDir string) (*RuleSet, error) {
	if len(sources) == 0 {
		return nil, errors.New("at least one scenario is required")
	}

	unique := make(map[string]leaky.ScenarioSource, len(sources))
	for _, source := range sources {
		if source.Path == "" {
			return nil, errors.New("scenario path is required")
		}
		if source.Hash == "" {
			hash, version, err := scenarioFileMetadata(source.Path)
			if err != nil {
				return nil, err
			}
			source.Hash = hash
			if source.Version == "" {
				source.Version = version
			}
		}
		if source.Version == "" {
			source.Version = "local"
		}
		if source.Name == "" {
			source.Name = strings.TrimSuffix(filepath.Base(source.Path), filepath.Ext(source.Path))
		}
		key := source.Path + "\x00" + source.Version + "\x00" + source.Hash
		unique[key] = source
	}

	ordered := make([]leaky.ScenarioSource, 0, len(unique))
	for _, source := range unique {
		ordered = append(ordered, source)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path == ordered[j].Path {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].Path < ordered[j].Path
	})

	response := make(chan pipeline.Event, 1024)
	factories, err := leaky.LoadBucketFactoriesFromScenarios(
		ordered, dataDir, response, false, leaky.NoSimulation,
	)
	if err != nil {
		return nil, fmt.Errorf("loading replay rules: %w", err)
	}
	close(response)

	rules := make([]RuleRef, 0, len(factories))
	seenRules := make(map[string]struct{})
	for _, factory := range factories {
		ref := RuleRef{
			Name:    factory.Spec.Name,
			Version: factory.Spec.ScenarioVersion,
			Hash:    factoryHash(factory, ordered),
		}
		key := ref.Name + "\x00" + ref.Version + "\x00" + ref.Hash
		if _, ok := seenRules[key]; ok {
			continue
		}
		seenRules[key] = struct{}{}
		rules = append(rules, ref)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Name == rules[j].Name {
			return rules[i].Hash < rules[j].Hash
		}
		return rules[i].Name < rules[j].Name
	})

	rulesetID := ruleSetID(rules)
	return &RuleSet{
		ID:      rulesetID,
		Rules:   rules,
		DataDir: dataDir,
		sources: ordered,
	}, nil
}

func (r *RuleSet) factories(response chan pipeline.Event) ([]leaky.BucketFactory, error) {
	r.loadMu.Lock()
	defer r.loadMu.Unlock()
	return leaky.LoadBucketFactoriesFromScenarios(
		r.sources, r.DataDir, response, false, leaky.NoSimulation,
	)
}

func factoryHash(factory leaky.BucketFactory, sources []leaky.ScenarioSource) string {
	path := filepath.Clean(factory.Filename)
	for _, source := range sources {
		if filepath.Clean(source.Path) == path {
			return source.Hash
		}
	}
	return ""
}

func scenarioFileMetadata(path string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("opening scenario %q: %w", path, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", "", fmt.Errorf("hashing scenario %q: %w", path, err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("rewinding scenario %q: %w", path, err)
	}

	decoder := yaml.NewDecoder(file)
	versions := make(map[string]struct{})
	for {
		var spec leaky.BucketSpec
		if err := decoder.Decode(&spec); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", "", fmt.Errorf("reading scenario %q: %w", path, err)
		}
		if spec.ScenarioVersion != "" {
			versions[spec.ScenarioVersion] = struct{}{}
		}
	}

	version := "local"
	if len(versions) == 1 {
		for item := range versions {
			version = item
		}
	}

	return hex.EncodeToString(hash.Sum(nil)), version, nil
}

func ruleSetID(rules []RuleRef) string {
	hash := sha256.New()
	for _, rule := range rules {
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00", rule.Name, rule.Version, rule.Hash)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type RuleSetDiff struct {
	Added   []RuleRef `json:"added,omitempty" yaml:"added,omitempty"`
	Removed []RuleRef `json:"removed,omitempty" yaml:"removed,omitempty"`
	Changed []RuleRef `json:"changed,omitempty" yaml:"changed,omitempty"`
}

// DiffRuleSets identifies which scenario files changed between two replay
// rule sets. It is intentionally name/version/hash based so a replay result
// can be tied back to the exact rule that produced a different ban.
func DiffRuleSets(previous, current *RuleSet) RuleSetDiff {
	if previous == nil || current == nil {
		return RuleSetDiff{}
	}

	previousRules := make(map[string]RuleRef, len(previous.Rules))
	for _, rule := range previous.Rules {
		previousRules[rule.Name] = rule
	}
	currentRules := make(map[string]RuleRef, len(current.Rules))
	for _, rule := range current.Rules {
		currentRules[rule.Name] = rule
	}

	diff := RuleSetDiff{}
	for name, currentRule := range currentRules {
		previousRule, ok := previousRules[name]
		if !ok {
			diff.Added = append(diff.Added, currentRule)
			continue
		}
		if previousRule.Version != currentRule.Version || previousRule.Hash != currentRule.Hash {
			diff.Changed = append(diff.Changed, currentRule)
		}
	}
	for name, previousRule := range previousRules {
		if _, ok := currentRules[name]; !ok {
			diff.Removed = append(diff.Removed, previousRule)
		}
	}

	sortRuleRefs(diff.Added)
	sortRuleRefs(diff.Removed)
	sortRuleRefs(diff.Changed)
	return diff
}

func sortRuleRefs(rules []RuleRef) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Name == rules[j].Name {
			return rules[i].Hash < rules[j].Hash
		}
		return rules[i].Name < rules[j].Name
	})
}

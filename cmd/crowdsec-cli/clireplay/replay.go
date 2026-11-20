package clireplay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/replay"
)

type cliReplay struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliReplay {
	return &cliReplay{cfg: cfg}
}

type runOptions struct {
	sourcePath    string
	sourceKind    string
	actualPath    string
	profilesPath  string
	feedbackPath  string
	merge         string
	workers       int
	batchSize     int
	preserveOrder bool
	shardBy       string
}

func (c *cliReplay) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay [scenario files or directories...]",
		Short: "Replay scenario rules on historical events",
		Long: "Replay scenario rules on parsed event exports or historical alerts. " +
			"The replay uses the same bucket and profile decision code as the live pipeline, " +
			"but never writes alerts or decisions.",
		Example: `cscli replay ./scenarios --source events.json --source-kind local_logs
cscli replay new-rule.yaml --source alerts.json --source-kind alert_db --actual alerts.json`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.run(cmd, args, runOptions{
				sourcePath:    cmd.Flags().Lookup("source").Value.String(),
				sourceKind:    cmd.Flags().Lookup("source-kind").Value.String(),
				actualPath:    cmd.Flags().Lookup("actual").Value.String(),
				profilesPath:  cmd.Flags().Lookup("profiles").Value.String(),
				feedbackPath:  cmd.Flags().Lookup("feedback").Value.String(),
				merge:         cmd.Flags().Lookup("merge-durations").Value.String(),
				workers:       mustInt(cmd.Flags().Lookup("workers").Value.String()),
				batchSize:     mustInt(cmd.Flags().Lookup("batch-size").Value.String()),
				preserveOrder: cmd.Flags().Lookup("preserve-order").Value.String() == "true",
				shardBy:       cmd.Flags().Lookup("shard-by").Value.String(),
			})
		},
	}

	flags := cmd.Flags()
	flags.String("source", "", "event/alert export to replay, or 'db' for the local alert database")
	flags.String("source-kind", string(replay.SourceLocalLogs), "source kind: local_logs, alert_db or node_export")
	flags.String("actual", "", "historical alerts export used as the actual online bans")
	flags.String("profiles", "", "profiles YAML (defaults to api.server.profiles_path)")
	flags.String("feedback", "", "false-positive feedback JSON file")
	flags.String("merge-durations", string(replay.MergeLongest), "duration merge: longest, sum or severity")
	flags.Int("workers", 1, "parallel shards (requires groupby-compatible source sharding)")
	flags.Int("batch-size", 1000, "events to process per batch")
	flags.Bool("preserve-order", false, "do not sort events by their parsed timestamp")
	flags.String("shard-by", "", "parallel shard key: source_ip (must match every scenario groupby)")
	_ = cmd.MarkFlagRequired("source")

	cmd.AddCommand(c.newFeedbackCommand())
	return cmd
}

func (c *cliReplay) run(cmd *cobra.Command, args []string, opts runOptions) error {
	scenarios, err := resolveScenarios(args, c.cfg())
	if err != nil {
		return err
	}

	rules, err := replay.LoadRuleSet(scenarios, c.cfg().ConfigPaths.DataDir)
	if err != nil {
		return err
	}

	var (
		source       replay.Source
		actualFromDB []replay.Ban
	)
	if replay.SourceKind(opts.sourceKind) == replay.SourceAlertDB && opts.sourcePath == "db" {
		db, err := database.NewClient(cmd.Context(), c.cfg().DbConfig, nil)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		source, actualFromDB, err = replay.LoadSourceFromDB(cmd.Context(), db, map[string][]string{
			"limit": {"0"},
			"sort":  {"ASC"},
		}, "lapi_db")
		if err != nil {
			return err
		}
	} else {
		source, err = replay.LoadSourceFile(opts.sourcePath, replay.SourceKind(opts.sourceKind), opts.sourcePath)
		if err != nil {
			return err
		}
	}

	profiles, err := c.loadProfiles(opts.profilesPath)
	if err != nil {
		return err
	}

	feedbackPath := opts.feedbackPath
	if feedbackPath == "" {
		feedbackPath = filepath.Join(c.cfg().ConfigPaths.DataDir, "replay-feedback.json")
	}
	feedback, err := replay.OpenFeedbackStore(feedbackPath)
	if err != nil {
		return err
	}

	options := replay.Options{
		Profiles:           profiles,
		Merge:              replay.MergeStrategy(opts.merge),
		Workers:            opts.workers,
		BatchSize:          opts.batchSize,
		PreserveInputOrder: opts.preserveOrder,
	}
	switch opts.shardBy {
	case "":
	case "source_ip":
		options.ShardKey = func(event pipeline.Event) string {
			return event.Meta["source_ip"]
		}
	default:
		return fmt.Errorf("unsupported --shard-by value %q", opts.shardBy)
	}

	result, err := replay.Replay(cmd.Context(), rules, source, options)
	if err != nil {
		return err
	}
	feedback.Apply(result)

	actual := actualFromDB
	if opts.actualPath != "" {
		_, actual, err = replay.LoadAlertExport(opts.actualPath, replay.SourceAlertDB, opts.actualPath)
		if err != nil {
			return err
		}
	}
	comparison := result.Compare(actual, feedback.List())

	switch c.cfg().Cscli.Output {
	case "json":
		data, err := json.MarshalIndent(struct {
			Result     *replay.Result    `json:"replay"`
			Comparison replay.Comparison `json:"comparison"`
		}{Result: result, Comparison: comparison}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	case "raw":
		for _, ban := range result.Bans {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\t%s\n",
				ban.Scope, ban.Type, ban.Value, ban.Scenario, ban.Duration, ban.Until.Format(time.RFC3339))
		}
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "Ruleset: %s\n", result.RulesetID)
		fmt.Fprintf(cmd.OutOrStdout(), "Source: %s (%s, %d events)\n", result.Source.Name, result.Source.Kind, result.Events)
		fmt.Fprintf(cmd.OutOrStdout(), "Confidence: %s (%.2f)\n", result.Confidence.Level, result.Confidence.Score)
		for _, reason := range result.Confidence.Reasons {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", reason)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Overflows: %d, predicted bans: %d, actual bans: %d\n",
			result.Overflows, comparison.Summary.PredictedBans, comparison.Summary.ActualBans)
		fmt.Fprintf(cmd.OutOrStdout(), "Only predicted: %d, only actual: %d, duration changed: %d\n",
			len(comparison.Diff.OnlyPredicted), len(comparison.Diff.OnlyActual), len(comparison.Diff.Changed))
		if comparison.Summary.FalsePositiveBans > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "False positives: %d, mean revocation latency: %s\n",
				comparison.Summary.FalsePositiveBans, comparison.Summary.RevocationLatency)
		}
	}

	return nil
}

func (c *cliReplay) loadProfiles(path string) ([]*replay.Profile, error) {
	if path == "" {
		server := c.cfg().API.Server
		if server == nil {
			return nil, nil
		}
		path = server.ProfilesPath
		if len(server.Profiles) > 0 {
			return server.Profiles, nil
		}
	}
	if path == "" {
		return nil, nil
	}

	server := &csconfig.LocalApiServerCfg{ProfilesPath: path}
	if err := server.LoadProfiles(); err != nil {
		return nil, err
	}
	return server.Profiles, nil
}

func resolveScenarios(args []string, cfg *csconfig.Config) ([]string, error) {
	if len(args) == 0 {
		args = []string{filepath.Join(cfg.ConfigPaths.ConfigDir, "scenarios")}
	}

	paths := make([]string, 0)
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("reading scenario path %q: %w", arg, err)
		}
		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}
		entries, err := os.ReadDir(arg)
		if err != nil {
			return nil, fmt.Errorf("reading scenario directory %q: %w", arg, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".yaml" || ext == ".yml" {
				paths = append(paths, filepath.Join(arg, entry.Name()))
			}
		}
	}

	slices.Sort(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no scenario files found")
	}
	return paths, nil
}

func mustInt(value string) int {
	var result int
	_, _ = fmt.Sscanf(value, "%d", &result)
	return result
}

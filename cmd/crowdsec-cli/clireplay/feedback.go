package clireplay

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/replay"
)

type feedbackOptions struct {
	scenario   string
	version    string
	hash       string
	scope      string
	decision   string
	value      string
	reason     string
	detectedAt time.Time
	revokedAt  time.Time
	path       string
}

func (c *cliReplay) newFeedbackCommand() *cobra.Command {
	opts := feedbackOptions{}
	cmd := &cobra.Command{
		Use:   "feedback",
		Short: "Record a false-positive ban for rule scoring",
		Example: `cscli replay feedback --scenario crowdsecurity/http-bad-user-agent \
  --scenario-version 0.3 --scenario-hash <hash> --ip 203.0.113.10 --reason "legacy browser"`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.path == "" {
				opts.path = filepath.Join(c.cfg().ConfigPaths.DataDir, "replay-feedback.json")
			}
			store, err := replay.OpenFeedbackStore(opts.path)
			if err != nil {
				return err
			}
			if opts.detectedAt.IsZero() {
				opts.detectedAt = time.Now().UTC()
			}
			if err := store.Add(replay.Feedback{
				Rule:       opts.scenario,
				Version:    opts.version,
				Hash:       opts.hash,
				Scope:      opts.scope,
				Type:       opts.decision,
				Value:      opts.value,
				Reason:     opts.reason,
				DetectedAt: opts.detectedAt,
				RevokedAt:  opts.revokedAt,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "feedback recorded for %s (%s)\n", opts.scenario, opts.value)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.scenario, "scenario", "", "scenario that produced the false positive")
	flags.StringVar(&opts.version, "scenario-version", "", "scenario version")
	flags.StringVar(&opts.hash, "scenario-hash", "", "scenario hash")
	flags.StringVar(&opts.scope, "scope", "ip", "decision scope")
	flags.StringVar(&opts.decision, "type", "ban", "decision type")
	flags.StringVar(&opts.value, "value", "", "blocked value")
	flags.StringVar(&opts.value, "ip", "", "shorthand for --scope ip --value")
	flags.StringVar(&opts.reason, "reason", "", "why the ban was a false positive")
	timeFormats := []string{time.RFC3339, time.RFC3339Nano}
	flags.TimeVar(&opts.detectedAt, "detected-at", time.Time{}, timeFormats, "when the false positive was detected (defaults to now)")
	flags.TimeVar(&opts.revokedAt, "revoked-at", time.Time{}, timeFormats, "when the ban was revoked (defaults to unset)")
	flags.StringVar(&opts.path, "feedback-file", "", "feedback JSON file")
	_ = cmd.MarkFlagRequired("scenario")

	return cmd
}

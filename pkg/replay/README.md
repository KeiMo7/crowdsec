# Scenario replay

`pkg/replay` runs scenario files against parsed event samples without writing
alerts or decisions. It reuses the live `leakybucket` scenario parser and
`csprofiles` decision generation.

## Sources

- `local_logs`: parsed event export (JSON array, `{"events": [...]}`, YAML, or JSONL).
- `alert_db`: local LAPI alert database (`LoadSourceFromDB`) or an alert export.
- `node_export`: an event sample produced by another node.

Every result records the source kind/name and coverage. Alert-based replays are
marked partial because alerts only retain the overflow event window.

## Duration merge

The default is `longest`, which matches the existing LAPI deduplication rule
for the same scope/type/value. `sum` and `severity` are available for replay
what-if analysis.

## Revocation

Use `cscli decisions delete --scenario <name> --scenario-version <version>
--scenario-hash <hash>` to expire only the bans created by that exact rule
version. Expired decisions flow through the existing decision stream, with
natural expiry as the fallback when a node misses the update.

## Feedback

Record false positives with `cscli replay feedback ...`. Replays reload the
feedback file and include a per-rule score based on hits and confirmed false
positives.

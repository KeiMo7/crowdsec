package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
)

const expiryMaxBatchSize = 20000

var (
	ErrExpiryBatchSize   = errors.New("invalid decision expiry batch size")
	ErrExpiryPolicy      = errors.New("invalid decision expiry policy")
	ErrExpiryRowMismatch = errors.New("decision expiry affected an unexpected number of rows")
)

// DecisionExpiryPolicy bounds decision lifetimes and drops simulated ones that
// have been over for too long.
type DecisionExpiryPolicy struct {
	Now            time.Time
	BatchSize      int
	SimulatedGrace time.Duration
	MaxLifetime    time.Duration
	DryRun         bool
}

// DecisionExpiryReport is the result of an ApplyDecisionExpiry pass.
type DecisionExpiryReport struct {
	Examined int
	Clamped  int
	Purged   int
	Skipped  int
	Batches  int
	Errors   []error
}

func NormalizeDecisionExpiryPolicy(policy DecisionExpiryPolicy) (DecisionExpiryPolicy, error) {
	if policy.Now.IsZero() {
		policy.Now = time.Now().UTC()
	}

	switch {
	case policy.BatchSize <= 0:
		policy.BatchSize = decisionDeleteBulkSize
	case policy.BatchSize > expiryMaxBatchSize:
		return policy, fmt.Errorf("%w: %d > %d", ErrExpiryBatchSize, policy.BatchSize, expiryMaxBatchSize)
	}

	if policy.SimulatedGrace < 0 || policy.MaxLifetime < 0 {
		return policy, fmt.Errorf("%w: negative grace (%s) or max lifetime (%s)",
			ErrExpiryPolicy, policy.SimulatedGrace, policy.MaxLifetime)
	}

	return policy, nil
}

// ApplyDecisionExpiry clamps the "until" of decisions ending after
// Now+MaxLifetime and hard-deletes simulated decisions that ended more than
// SimulatedGrace ago. Real decisions are never deleted, only shortened.
//
// The two stages are disjoint: clamping pushes "until" into the future, past
// anything the purge stage looks at, so no row is examined twice.
func (c *Client) ApplyDecisionExpiry(ctx context.Context, policy DecisionExpiryPolicy) (DecisionExpiryReport, error) {
	policy, err := NormalizeDecisionExpiryPolicy(policy)
	if err != nil {
		return DecisionExpiryReport{}, err
	}

	resume := c.PauseFlush()
	defer resume()

	var report DecisionExpiryReport

	c.countUndatedDecisions(ctx, policy, &report)
	c.clampDecisionLifetimes(ctx, policy, &report)
	c.purgeExpiredSimulatedDecisions(ctx, policy, &report)

	return report, errors.Join(report.Errors...)
}

// countUndatedDecisions records the decisions without an "until": neither stage
// can act on them, so they are only reported as skipped.
func (c *Client) countUndatedDecisions(ctx context.Context, policy DecisionExpiryPolicy, report *DecisionExpiryReport) {
	if policy.MaxLifetime <= 0 && policy.SimulatedGrace <= 0 {
		return
	}

	count, err := c.Ent.Decision.Query().Where(decision.UntilIsNil()).Count(ctx)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Errorf("count decisions without until: %w", err))
		return
	}

	report.Skipped += count
}

// clampDecisionLifetimes shortens the decisions ending after Now+MaxLifetime.
func (c *Client) clampDecisionLifetimes(ctx context.Context, policy DecisionExpiryPolicy, report *DecisionExpiryReport) {
	if policy.MaxLifetime <= 0 {
		return
	}

	limit := policy.Now.Add(policy.MaxLifetime)
	cursor := 0

	for {
		if err := ctx.Err(); err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("decision expiry interrupted: %w", err))
			return
		}

		batch, err := c.Ent.Decision.Query().
			Where(
				decision.IDGT(cursor),
				decision.UntilGT(limit),
			).
			Order(ent.Asc(decision.FieldID)).
			Limit(policy.BatchSize).
			All(ctx)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("query decisions to clamp: %w", err))
			return
		}

		if len(batch) == 0 {
			return
		}

		report.Batches++
		report.Examined += len(batch)

		ids := decisionIDs(batch)
		cursor = ids[len(ids)-1]

		if policy.DryRun {
			report.Clamped += len(batch)
		} else {
			rows, err := c.Ent.Decision.
				Update().
				Where(decision.IDIn(ids...)).
				SetUntil(limit).
				Save(ctx)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Errorf("clamp decisions: %w", err))
			} else {
				report.Clamped += rows

				if rows != len(batch) {
					report.Errors = append(report.Errors, fmt.Errorf("%w: clamped %d of %d rows", ErrExpiryRowMismatch, rows, len(batch)))
				}
			}
		}

		if len(batch) < policy.BatchSize {
			return
		}
	}
}

// purgeExpiredSimulatedDecisions deletes the simulated decisions that ended
// more than SimulatedGrace ago.
func (c *Client) purgeExpiredSimulatedDecisions(ctx context.Context, policy DecisionExpiryPolicy, report *DecisionExpiryReport) {
	if policy.SimulatedGrace <= 0 {
		return
	}

	limit := policy.Now.Add(-policy.SimulatedGrace)
	cursor := 0

	for {
		if err := ctx.Err(); err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("decision expiry interrupted: %w", err))
			return
		}

		batch, err := c.Ent.Decision.Query().
			Where(
				decision.IDGT(cursor),
				decision.UntilLT(limit),
				decision.SimulatedEQ(true),
			).
			Order(ent.Asc(decision.FieldID)).
			Limit(policy.BatchSize).
			All(ctx)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("query decisions to purge: %w", err))
			return
		}

		if len(batch) == 0 {
			return
		}

		report.Batches++
		report.Examined += len(batch)

		ids := decisionIDs(batch)
		cursor = ids[len(ids)-1]

		if policy.DryRun {
			report.Purged += len(batch)
		} else {
			rows, err := c.deleteDecisionBatch(ctx, batch)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Errorf("purge decisions: %w", err))
			} else {
				report.Purged += rows

				if rows != len(batch) {
					report.Errors = append(report.Errors, fmt.Errorf("%w: purged %d of %d rows", ErrExpiryRowMismatch, rows, len(batch)))
				}
			}
		}

		if len(batch) < policy.BatchSize {
			return
		}
	}
}

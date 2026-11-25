package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func seedExpiryDecision(t *testing.T, ctx context.Context, c *Client, until *time.Time, simulated bool, value string) *ent.Decision {
	t.Helper()

	q := c.Ent.Decision.Create().
		SetScenario("expiry-test").
		SetType("ban").
		SetScope("Ip").
		SetValue(value).
		SetOrigin("test").
		SetSimulated(simulated)

	if until != nil {
		q = q.SetUntil(*until)
	}

	d, err := q.Save(ctx)
	require.NoError(t, err)

	return d
}

func decisionUntil(t *testing.T, ctx context.Context, c *Client, id int) *time.Time {
	t.Helper()

	d, err := c.Ent.Decision.Get(ctx, id)
	if err != nil {
		return nil
	}

	return d.Until
}

func TestNormalizeDecisionExpiryPolicy(t *testing.T) {
	tests := []struct {
		name       string
		in         DecisionExpiryPolicy
		wantBatch  int
		wantErrIs  error
		wantNowSet bool
	}{
		{"defaults", DecisionExpiryPolicy{}, decisionDeleteBulkSize, nil, true},
		{"keeps explicit batch size", DecisionExpiryPolicy{BatchSize: 5}, 5, nil, true},
		{"batch size too large", DecisionExpiryPolicy{BatchSize: 20001}, 0, ErrExpiryBatchSize, true},
		{"negative grace", DecisionExpiryPolicy{SimulatedGrace: -time.Second}, 0, ErrExpiryPolicy, true},
		{"negative max lifetime", DecisionExpiryPolicy{MaxLifetime: -time.Second}, 0, ErrExpiryPolicy, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDecisionExpiryPolicy(tc.in)
			if tc.wantErrIs != nil {
				require.ErrorIs(t, err, tc.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantBatch, got.BatchSize)
			require.False(t, got.Now.IsZero())
		})
	}

	// the injected clock is kept as is
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := NormalizeDecisionExpiryPolicy(DecisionExpiryPolicy{Now: fixed})
	require.NoError(t, err)
	require.Equal(t, fixed, got.Now)
}

func TestApplyDecisionExpiryClampsLongLived(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	maxLifetime := time.Hour

	tooLong := seedExpiryDecision(t, ctx, c, new(now.Add(10*time.Hour)), false, "1.2.3.1")
	inRange := seedExpiryDecision(t, ctx, c, new(now.Add(30*time.Minute)), false, "1.2.3.2")
	undated := seedExpiryDecision(t, ctx, c, nil, false, "1.2.3.3")

	report, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{
		Now:            now,
		MaxLifetime:    maxLifetime,
		SimulatedGrace: time.Hour,
	})
	require.NoError(t, err)

	require.Equal(t, 1, report.Clamped)
	require.Equal(t, 0, report.Purged)
	require.Equal(t, 1, report.Skipped, "until NULL is only counted as skipped")
	require.Equal(t, 1, report.Examined, "only the row that matched a stage was examined")
	require.Empty(t, report.Errors)

	require.Equal(t, now.Add(maxLifetime), *decisionUntil(t, ctx, c, tooLong.ID))
	require.Equal(t, now.Add(30*time.Minute), *decisionUntil(t, ctx, c, inRange.ID))
	require.Nil(t, decisionUntil(t, ctx, c, undated.ID))
}

func TestApplyDecisionExpiryNeverPurgesRealDecisions(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	expired := seedExpiryDecision(t, ctx, c, new(now.Add(-48*time.Hour)), false, "1.2.3.4")

	report, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{
		Now:            now,
		SimulatedGrace: time.Hour,
	})
	require.NoError(t, err)
	require.Zero(t, report.Purged)
	require.Zero(t, report.Clamped)

	until := decisionUntil(t, ctx, c, expired.ID)
	require.NotNil(t, until, "a real decision must survive its expiry")
	require.Equal(t, now.Add(-48*time.Hour), *until)
}

func TestApplyDecisionExpiryPurgesExpiredSimulated(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	old := seedExpiryDecision(t, ctx, c, new(now.Add(-2*time.Hour)), true, "1.2.3.5")
	recent := seedExpiryDecision(t, ctx, c, new(now.Add(-1*time.Minute)), true, "1.2.3.6")

	report, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{
		Now:            now,
		SimulatedGrace: time.Hour,
	})
	require.NoError(t, err)
	require.Equal(t, 1, report.Purged)
	require.Empty(t, report.Errors)

	require.Nil(t, decisionUntil(t, ctx, c, old.ID))

	until := decisionUntil(t, ctx, c, recent.ID)
	require.NotNil(t, until)
}

func TestApplyDecisionExpiryBatches(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)

	for i := range 5 {
		seedExpiryDecision(t, ctx, c, new(now.Add(10*time.Hour+time.Duration(i)*time.Second)), false, "2.2.3."+string(rune('0'+i)))
	}

	report, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{
		Now:         now,
		BatchSize:   2,
		MaxLifetime: time.Hour,
	})
	require.NoError(t, err)
	require.Equal(t, 5, report.Clamped)
	require.Equal(t, 3, report.Batches, "5 rows in batches of 2 need three batches")
	require.Empty(t, report.Errors)
}

func TestApplyDecisionExpiryDryRun(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	longLived := seedExpiryDecision(t, ctx, c, new(now.Add(10*time.Hour)), false, "3.2.3.1")
	stale := seedExpiryDecision(t, ctx, c, new(now.Add(-2*time.Hour)), true, "3.2.3.2")

	report, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{
		Now:            now,
		MaxLifetime:    time.Hour,
		SimulatedGrace: time.Hour,
		DryRun:         true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, report.Clamped)
	require.Equal(t, 1, report.Purged)

	// nothing was written
	require.Equal(t, now.Add(10*time.Hour), *decisionUntil(t, ctx, c, longLived.ID))

	stillThere := decisionUntil(t, ctx, c, stale.ID)
	require.NotNil(t, stillThere, "dry run must not delete")
}

func TestApplyDecisionExpiryContextCancelled(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)

	for i := range 5 {
		seedExpiryDecision(t, ctx, c, new(now.Add(10*time.Hour+time.Duration(i)*time.Second)), false, "4.2.3."+string(rune('0'+i)))
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	_, err := c.ApplyDecisionExpiry(cancelCtx, DecisionExpiryPolicy{
		Now:         now,
		BatchSize:   1,
		MaxLifetime: time.Hour,
	})
	require.ErrorIs(t, err, context.Canceled)
}

func TestApplyDecisionExpiryIsIdempotent(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	seedExpiryDecision(t, ctx, c, new(now.Add(10*time.Hour)), false, "5.2.3.1")
	seedExpiryDecision(t, ctx, c, new(now.Add(-2*time.Hour)), true, "5.2.3.2")

	policy := DecisionExpiryPolicy{
		Now:            now,
		MaxLifetime:    time.Hour,
		SimulatedGrace: time.Hour,
	}

	first, err := c.ApplyDecisionExpiry(ctx, policy)
	require.NoError(t, err)
	require.Equal(t, 1, first.Clamped)
	require.Equal(t, 1, first.Purged)

	second, err := c.ApplyDecisionExpiry(ctx, policy)
	require.NoError(t, err)
	require.Zero(t, second.Clamped)
	require.Zero(t, second.Purged)
	require.Empty(t, second.Errors)
}

func TestApplyDecisionExpiryInvalidPolicy(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	_, err := c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{BatchSize: 20001})
	require.ErrorIs(t, err, ErrExpiryBatchSize)

	_, err = c.ApplyDecisionExpiry(ctx, DecisionExpiryPolicy{MaxLifetime: -time.Hour})
	require.ErrorIs(t, err, ErrExpiryPolicy)
}

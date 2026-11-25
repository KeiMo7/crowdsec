package leakybucket

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func testLogger() *log.Entry {
	return log.WithField("test", "leakguard")
}

// newTestBucket builds a Leaky the way LoadOrStoreBucketFromHolder would, minus
// the goroutine, so tests control exactly when it is alive or finished.
var testBucketSeq atomic.Int64

func newTestBucket(mapkey string, scenario string, duration time.Duration) *Leaky {
	return &Leaky{
		Mapkey:   mapkey,
		Uuid:     fmt.Sprintf("uuid-%s-%d", mapkey, testBucketSeq.Add(1)),
		done:     make(chan struct{}),
		ready:    make(chan struct{}),
		In:       make(chan *pipeline.Event),
		Suicide:  make(chan bool, 1),
		Queue:    pipeline.NewQueue(10),
		Limiter:  &rate.AlwaysFull{},
		mutex:    &sync.Mutex{},
		Duration: duration,
		Factory:  &BucketFactory{Spec: BucketSpec{Name: scenario}},
		logger:   testLogger(),
	}
}

func finishBucket(l *Leaky) {
	l.markReady()
	l.markDone()
}

func TestLeakGuardPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		store  *BucketStore
		policy LeakPolicy
		wantIs error
	}{
		{"nil store", nil, DefaultLeakPolicy(), ErrLeakPolicy},
		{"negative grace", NewBucketStore(), LeakPolicy{Grace: -time.Second, MaxPerPass: 1}, ErrLeakPolicy},
		{"negative max per pass", NewBucketStore(), LeakPolicy{MaxPerPass: -1}, ErrLeakPolicy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			guard, err := NewLeakGuard(tc.store, tc.policy, nil)
			require.ErrorIs(t, err, tc.wantIs)
			require.Nil(t, guard)
		})
	}

	guard, err := NewLeakGuard(NewBucketStore(), DefaultLeakPolicy(), nil)
	require.NoError(t, err)
	require.NotNil(t, guard)
}

func TestDefaultLeakPolicy(t *testing.T) {
	p := DefaultLeakPolicy()
	require.Equal(t, time.Minute, p.Grace)
	require.Equal(t, 2*time.Second, p.StopTimeout)
	require.Equal(t, 512, p.MaxPerPass)
	require.False(t, p.Now().IsZero())
}

func TestLeakHealthMatchesBucketState(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l := newTestBucket("k", "scenario", time.Minute)
	l.markReady()

	gate := &noopGate{}
	Pour(l, gate, pipeline.Event{Parsed: map[string]string{"a": "b"}})
	Pour(l, gate, pipeline.Event{Parsed: map[string]string{"c": "d"}})

	h := l.Health()
	require.Equal(t, l.Mapkey, h.Mapkey)
	require.Equal(t, "scenario", h.Scenario)
	require.Equal(t, 2, h.Poured)
	require.Equal(t, len(l.Queue.GetQueue()), h.Queued)
	require.True(t, h.Ready)
	require.False(t, h.Finished)
	require.False(t, h.OverflowedAt.After(now))

	// no factory, no logger: scenario is empty and nothing panics
	bare := &Leaky{Mapkey: "bare", Queue: pipeline.NewQueue(1), mutex: &sync.Mutex{}}
	h = bare.Health()
	require.Empty(t, h.Scenario)
	require.False(t, h.Ready)
	require.False(t, h.Finished)
}

type noopGate struct{}

func (*noopGate) BeginPour() func() { return func() {} }

func TestLeakGuardScanClassifies(t *testing.T) {
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	// orphaned: done closed, never overflowed
	orphaned := newTestBucket("orphaned-key", "scenario-a", time.Minute)
	orphaned.First_ts = now.Add(-time.Hour)
	finishBucket(orphaned)

	// stalled: alive, no overflow, past duration + grace
	stalled := newTestBucket("stalled-key", "scenario-b", time.Minute)
	stalled.First_ts = now.Add(-time.Hour)
	stalled.Last_ts = now.Add(-time.Minute * 30)
	stalled.markReady()

	// both conditions hold: orphaned wins
	both := newTestBucket("both-key", "scenario-c", time.Minute)
	both.First_ts = now.Add(-time.Hour)
	both.Last_ts = now.Add(-time.Minute * 30)
	finishBucket(both)

	// healthy: recent pour, no overflow
	healthy := newTestBucket("healthy-key", "scenario-d", time.Minute)
	healthy.First_ts = now
	healthy.Last_ts = now
	healthy.markReady()

	// protected: overflowed
	overflowed := newTestBucket("overflowed-key", "scenario-e", time.Minute)
	overflowed.First_ts = now.Add(-time.Hour)
	overflowed.Ovflw_ts = now.Add(-time.Minute)
	finishBucket(overflowed)

	// protected: pending overflow, still running
	pending := newTestBucket("pending-key", "scenario-f", time.Minute)
	pending.First_ts = now.Add(-time.Hour)
	pending.pendingOverflow = pending.Queue
	pending.markReady()

	// protected: not ready yet
	notReady := newTestBucket("not-ready-key", "scenario-g", time.Minute)
	notReady.First_ts = now.Add(-time.Hour)

	// protected: no first pour and younger than Grace
	fresh := newTestBucket("fresh-key", "scenario-h", time.Minute)
	fresh.markReady()

	store := NewBucketStore()
	for _, b := range []*Leaky{orphaned, stalled, both, healthy, overflowed, pending, notReady, fresh} {
		store.LoadOrStore(b.Mapkey, b)
	}

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: 30 * time.Second, MaxPerPass: 100, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	report := guard.Scan()
	require.Equal(t, 8, report.Scanned)
	require.Equal(t, 0, report.Deferred)

	got := map[string]LeakClass{}
	for _, rec := range report.Records {
		got[rec.Mapkey] = rec.Class
		require.Equal(t, now, rec.Detected)
	}

	require.Equal(t, map[string]LeakClass{
		"orphaned-key": LeakClassOrphaned,
		"stalled-key":  LeakClassStalled,
		"both-key":     LeakClassOrphaned,
	}, got)

	// records are sorted by class, then mapkey
	require.Equal(t, []LeakClass{LeakClassOrphaned, LeakClassOrphaned, LeakClassStalled},
		[]LeakClass{report.Records[0].Class, report.Records[1].Class, report.Records[2].Class})
	require.Equal(t, "both-key", report.Records[0].Mapkey)
	require.Equal(t, "orphaned-key", report.Records[1].Mapkey)

	// overflowed, pending, not ready and fresh are protected
	require.Equal(t, 4, report.Protected)

	// health fields ride along
	var orphanedRec LeakRecord
	for _, rec := range report.Records {
		if rec.Mapkey == "orphaned-key" {
			orphanedRec = rec
		}
	}

	require.Equal(t, time.Hour, orphanedRec.Age)
	require.Equal(t, "scenario-a", orphanedRec.Scenario)
	require.NotEmpty(t, orphanedRec.BucketID)
}

func TestLeakGuardScanTruncatesByAge(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	store := NewBucketStore()

	ages := []time.Duration{5 * time.Minute, 3 * time.Hour, 30 * time.Minute, time.Hour, 2 * time.Hour}
	keys := []string{"m-0", "m-1", "m-2", "m-3", "m-4"}

	for i, age := range ages {
		b := newTestBucket(keys[i], "scenario", time.Minute)
		b.First_ts = now.Add(-age)
		finishBucket(b)
		store.LoadOrStore(b.Mapkey, b)
	}

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, MaxPerPass: 2, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	report := guard.Scan()
	require.Equal(t, 5, report.Scanned)
	require.Len(t, report.Records, 2)
	require.Equal(t, 3, report.Deferred)

	// the two oldest survive
	require.Equal(t, []string{"m-1", "m-4"}, []string{report.Records[0].Mapkey, report.Records[1].Mapkey})
}

func TestLeakGuardReclaimIsIdempotent(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)

	before := testutil.ToFloat64(metrics.BucketsReclaimed.With(prometheus.Labels{"name": "scenario-x", "class": string(LeakClassOrphaned)}))
	beforeLeaked := testutil.ToFloat64(metrics.BucketsLeaked.With(prometheus.Labels{"name": "scenario-x", "class": string(LeakClassOrphaned)}))

	store := NewBucketStore()
	b := newTestBucket("reclaim-key", "scenario-x", time.Minute)
	b.First_ts = now.Add(-time.Hour)
	finishBucket(b)
	store.LoadOrStore(b.Mapkey, b)

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, StopTimeout: time.Second, MaxPerPass: 10, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	report := guard.Scan()
	require.Len(t, report.Records, 1)

	res := guard.Reclaim(report.Records)
	require.Equal(t, 1, res.Reclaimed)
	require.Equal(t, 0, res.Skipped)
	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.ByClass[LeakClassOrphaned])
	require.LessOrEqual(t, store.Len(), 0)

	require.InDelta(t, before+1, testutil.ToFloat64(metrics.BucketsReclaimed.With(prometheus.Labels{"name": "scenario-x", "class": string(LeakClassOrphaned)})), 0)
	require.InDelta(t, beforeLeaked+1, testutil.ToFloat64(metrics.BucketsLeaked.With(prometheus.Labels{"name": "scenario-x", "class": string(LeakClassOrphaned)})), 0)

	again := guard.Reclaim(report.Records)
	require.Equal(t, 0, again.Reclaimed)
	require.Equal(t, 1, again.Skipped)
	require.Empty(t, again.Errors)
}

func TestLeakGuardReclaimSkipsReplacedBucket(t *testing.T) {
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	store := NewBucketStore()
	old := newTestBucket("shared-key", "scenario", time.Minute)
	old.First_ts = now.Add(-time.Hour)
	finishBucket(old)
	store.LoadOrStore(old.Mapkey, old)

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, StopTimeout: time.Second, MaxPerPass: 10, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	records := guard.Scan().Records
	require.Len(t, records, 1)

	// a fresh bucket took over the same key
	replacement := newTestBucket("shared-key", "scenario", time.Minute)
	replacement.First_ts = now
	replacement.markReady()
	var canceled atomic.Bool
	replacement.cancel = func() { canceled.Store(true) }
	store.Delete(old.Mapkey)
	store.LoadOrStore(replacement.Mapkey, replacement)

	res := guard.Reclaim(records)
	require.Equal(t, 0, res.Reclaimed)
	require.Equal(t, 1, res.Skipped)
	require.Empty(t, res.Errors)
	require.False(t, canceled.Load())

	live, ok := store.Load(replacement.Mapkey)
	require.True(t, ok)
	require.Same(t, replacement, live)
}

func TestLeakGuardReclaimUnknownClass(t *testing.T) {
	guard, err := NewLeakGuard(NewBucketStore(), DefaultLeakPolicy(), testLogger())
	require.NoError(t, err)

	res := guard.Reclaim([]LeakRecord{{Mapkey: "x", Class: LeakClass("bogus")}})
	require.Equal(t, 0, res.Reclaimed)
	require.Equal(t, 1, res.Skipped)
	require.Len(t, res.Errors, 1)
	require.ErrorIs(t, res.Errors[0], ErrUnknownLeakClass)

	empty := guard.Reclaim(nil)
	require.Zero(t, empty.Reclaimed)
	require.Zero(t, empty.Skipped)
	require.Empty(t, empty.Errors)
}

func TestLeakGuardReclaimCallsCancelAndWaitsDone(t *testing.T) {
	now := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

	store := NewBucketStore()
	b := newTestBucket("cancel-key", "scenario", time.Minute)
	b.First_ts = now.Add(-time.Hour)
	b.markReady()

	var canceled atomic.Bool
	b.cancel = func() {
		require.False(t, canceled.Swap(true))
		go func() {
			time.Sleep(20 * time.Millisecond)
			b.markDone()
		}()
	}
	store.LoadOrStore(b.Mapkey, b)

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, StopTimeout: time.Second, MaxPerPass: 10, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	records := guard.Scan().Records
	require.Len(t, records, 1)
	require.Equal(t, LeakClassStalled, records[0].Class)

	res := guard.Reclaim(records)
	require.Equal(t, 1, res.Reclaimed)
	require.Empty(t, res.Errors)
	require.True(t, canceled.Load())
	require.True(t, chanClosed(b.done))
}

func TestLeakGuardReclaimTimeoutStillDeletes(t *testing.T) {
	now := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)

	store := NewBucketStore()
	b := newTestBucket("stuck-key", "scenario", time.Minute)
	b.First_ts = now.Add(-time.Hour)
	b.markReady()
	b.cancel = func() {}
	store.LoadOrStore(b.Mapkey, b)

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, StopTimeout: 20 * time.Millisecond, MaxPerPass: 10, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	res := guard.Reclaim(guard.Scan().Records)
	require.Equal(t, 1, res.Reclaimed)
	require.Len(t, res.Errors, 1)
	require.ErrorIs(t, res.Errors[0], ErrReclaimTimeout)
	require.Zero(t, store.Len())

	// the routine finishing late must not resurrect anything
	b.markDone()
	require.Zero(t, store.Len())
}

// TestLeakGuardConcurrent drives a real bucket routine while scanning and
// reclaiming, to be run under -race.
func TestLeakGuardConcurrent(t *testing.T) {
	holders := []BucketFactory{
		{
			Spec: BucketSpec{
				Name:        "concurrent",
				Description: "concurrent leak guard test",
				Type:        "leaky",
				Capacity:    100000,
				LeakSpeed:   "1h",
				Filter:      "true",
				Debug:       false,
			},
		},
	}

	response := make(chan pipeline.Event, 4096)
	holders[0].ret = response
	require.NoError(t, holders[0].LoadBucket())
	require.NoError(t, holders[0].Validate())

	go func() {
		for range response {
		}
	}()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	store := NewBucketStore()

	guard, err := NewLeakGuard(store, LeakPolicy{
		Grace:       time.Minute,
		StopTimeout: time.Second,
		MaxPerPass:  4,
		Now:         func() time.Time { return time.Now().UTC() },
	}, testLogger())
	require.NoError(t, err)

	event := pipeline.Event{ExpectMode: pipeline.LIVE, Meta: map[string]string{"source_ip": "1.2.3.4"}}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		for range 2000 {
			if _, err := PourItemToHolders(ctx, event, holders, store, nil); err != nil {
				return
			}
		}
	}()

	for range 200 {
		guard.Reclaim(guard.Scan().Records)
		time.Sleep(time.Millisecond)
	}

	wg.Wait()
}

// TestLeakGuardReclaimedBucketStopsEmitting checks that a reclaimed orphan no
// longer sends overflows once its goroutine would have finished.
func TestLeakGuardReclaimedBucketStopsEmitting(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)

	out := make(chan pipeline.Event, 8)

	store := NewBucketStore()
	// a bucket whose routine already exited without emitting: orphaned
	b := newTestBucket("quiet-key", "scenario", time.Minute)
	b.AllOut = out
	b.First_ts = now.Add(-time.Hour)
	finishBucket(b)
	store.LoadOrStore(b.Mapkey, b)

	guard, err := NewLeakGuard(store, LeakPolicy{Grace: time.Minute, StopTimeout: time.Second, MaxPerPass: 10, Now: func() time.Time { return now }}, testLogger())
	require.NoError(t, err)

	res := guard.Reclaim(guard.Scan().Records)
	require.Equal(t, 1, res.Reclaimed)

	select {
	case evt := <-out:
		t.Fatalf("reclaimed bucket emitted an event: %+v", evt)
	case <-time.After(50 * time.Millisecond):
	}
}

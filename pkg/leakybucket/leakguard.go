package leakybucket

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

// LeakClass tells why a bucket is considered leaked.
type LeakClass string

const (
	// LeakClassOrphaned is a bucket whose goroutine is gone but whose entry is
	// still in the store: it will never be poured into nor cleaned up again.
	LeakClassOrphaned LeakClass = "orphaned"
	// LeakClassStalled is a bucket that outlived its duration (plus grace)
	// without ever overflowing.
	LeakClassStalled LeakClass = "stalled"
)

var (
	ErrLeakPolicy       = errors.New("invalid leak guard policy")
	ErrReclaimTimeout   = errors.New("timed out waiting for bucket goroutine to stop")
	ErrUnknownLeakClass = errors.New("unknown leak class")
)

// LeakRecord describes a bucket leak found by a guard scan.
type LeakRecord struct {
	Mapkey   string        `json:"mapkey" yaml:"mapkey"`
	Scenario string        `json:"scenario" yaml:"scenario"`
	BucketID string        `json:"bucket_id" yaml:"bucket_id"`
	Class    LeakClass     `json:"class" yaml:"class"`
	Age      time.Duration `json:"age" yaml:"age"`
	Poured   int           `json:"poured" yaml:"poured"`
	Queued   int           `json:"queued" yaml:"queued"`
	Detected time.Time     `json:"detected" yaml:"detected"`
}

// LeakPolicy tunes how a LeakGuard decides and reclaims.
type LeakPolicy struct {
	// Grace is the extra delay granted to a bucket before it is considered leaked.
	Grace time.Duration
	// StopTimeout bounds how long Reclaim waits for a bucket goroutine to stop.
	StopTimeout time.Duration
	// MaxPerPass caps the number of records returned by a Scan.
	MaxPerPass int
	// Now is the only clock used by the guard.
	Now func() time.Time
}

func DefaultLeakPolicy() LeakPolicy {
	return LeakPolicy{
		Grace:       time.Minute,
		StopTimeout: 2 * time.Second,
		MaxPerPass:  512,
		Now:         func() time.Time { return time.Now().UTC() },
	}
}

// LeakHealth is a consistent snapshot of a bucket's state.
type LeakHealth struct {
	Mapkey          string
	Scenario        string
	BucketID        string
	FirstPour       time.Time
	LastPour        time.Time
	OverflowedAt    time.Time
	Poured          int
	Queued          int
	Ready           bool
	Finished        bool
	PendingOverflow bool
}

// Health returns a snapshot of the bucket state. It takes the bucket mutex, so
// it is safe to call while the bucket goroutine pours or while it exits.
func (l *Leaky) Health() LeakHealth {
	h := LeakHealth{
		Mapkey:   l.Mapkey,
		BucketID: l.Uuid,
		Finished: chanClosed(l.done),
		Ready:    chanClosed(l.ready),
	}
	if l.Factory != nil {
		h.Scenario = l.Factory.Spec.Name
	}

	l.lockState()
	h.FirstPour = l.First_ts
	h.LastPour = l.Last_ts
	h.OverflowedAt = l.Ovflw_ts
	h.Poured = l.Total_count
	h.PendingOverflow = l.pendingOverflow != nil
	if l.Queue != nil {
		h.Queued = len(l.Queue.GetQueue())
	}
	l.unlockState()

	return h
}

// LeakReport is the result of a LeakGuard scan.
type LeakReport struct {
	Scanned   int
	Protected int
	Deferred  int
	Records   []LeakRecord
}

// ReclaimResult is the result of a LeakGuard reclaim pass.
type ReclaimResult struct {
	Reclaimed int
	Skipped   int
	ByClass   map[LeakClass]int
	Errors    []error
}

// LeakGuard finds and reclaims buckets that leaked out of the store.
type LeakGuard struct {
	store  *BucketStore
	policy LeakPolicy
	logger *log.Entry
}

func NewLeakGuard(store *BucketStore, policy LeakPolicy, logger *log.Entry) (*LeakGuard, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil bucket store", ErrLeakPolicy)
	}
	if policy.Grace < 0 {
		return nil, fmt.Errorf("%w: negative grace %s", ErrLeakPolicy, policy.Grace)
	}
	if policy.MaxPerPass < 0 {
		return nil, fmt.Errorf("%w: negative max per pass %d", ErrLeakPolicy, policy.MaxPerPass)
	}
	if policy.Now == nil {
		policy.Now = time.Now
	}
	if logger == nil {
		logger = log.WithField("component", "leakguard")
	}

	return &LeakGuard{store: store, policy: policy, logger: logger}, nil
}

// Scan reports leaked buckets without modifying the store or its buckets.
func (g *LeakGuard) Scan() LeakReport {
	// Snapshot only: a scan must not freeze pours.
	snap := g.store.Snapshot()
	now := g.policy.Now()

	report := LeakReport{}

	for key, l := range snap {
		report.Scanned++

		// The entry may have been removed or replaced since the snapshot: a
		// missing bucket is only skipped, never reported.
		if l == nil {
			continue
		}

		h := l.Health()
		class, protected, ok := g.classify(l, h, now)

		if protected || !ok {
			if protected {
				report.Protected++
			}
			continue
		}

		var age time.Duration
		if !h.FirstPour.IsZero() {
			age = now.Sub(h.FirstPour)
		}

		report.Records = append(report.Records, LeakRecord{
			Mapkey:   key,
			Scenario: h.Scenario,
			BucketID: h.BucketID,
			Class:    class,
			Age:      age,
			Poured:   h.Poured,
			Queued:   h.Queued,
			Detected: now,
		})
	}

	slices.SortFunc(report.Records, compareRecords)

	if len(report.Records) > g.policy.MaxPerPass {
		report.Deferred = len(report.Records) - g.policy.MaxPerPass

		// Keep the oldest leaks, the ones with the most time to do damage.
		slices.SortFunc(report.Records, func(a, b LeakRecord) int {
			if a.Age != b.Age {
				if a.Age > b.Age {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Mapkey, b.Mapkey)
		})

		report.Records = report.Records[:g.policy.MaxPerPass]
		slices.SortFunc(report.Records, compareRecords)
	}

	return report
}

func compareRecords(a, b LeakRecord) int {
	if a.Class != b.Class {
		return strings.Compare(string(a.Class), string(b.Class))
	}
	return strings.Compare(a.Mapkey, b.Mapkey)
}

// Reclaim stops and removes the buckets described by records. Each record is
// re-checked against the live store, so a stale or already reclaimed record is
// skipped rather than acted upon.
func (g *LeakGuard) Reclaim(records []LeakRecord) ReclaimResult {
	if len(records) == 0 {
		return ReclaimResult{}
	}

	resume := g.store.FreezePours()
	defer resume()

	// Take the snapshot before the clock, so every judgement uses the same view.
	snap := g.store.Snapshot()
	now := g.policy.Now()

	res := ReclaimResult{ByClass: map[LeakClass]int{}}

	for _, rec := range records {
		if rec.Class != LeakClassOrphaned && rec.Class != LeakClassStalled {
			res.Skipped++
			res.Errors = append(res.Errors, fmt.Errorf("%w: %q", ErrUnknownLeakClass, rec.Class))
			continue
		}

		cur, ok := snap[rec.Mapkey]
		if !ok || cur == nil {
			// already reclaimed, or removed by its owner
			res.Skipped++
			continue
		}

		if cur.Uuid != rec.BucketID {
			// the key now holds a different bucket: leave the newcomer alone
			res.Skipped++
			continue
		}

		// The entry may have been swapped after the snapshot: check the live one.
		if live, found := g.store.Load(rec.Mapkey); !found || live != cur {
			res.Skipped++
			continue
		}

		h := cur.Health()
		class, protected, ok := g.classify(cur, h, now)
		if !ok || protected || class != rec.Class {
			res.Skipped++
			continue
		}

		if cur.cancel != nil {
			cur.cancel()
		}

		if !waitClosed(cur.done, g.policy.StopTimeout) {
			res.Errors = append(res.Errors, fmt.Errorf("%w: %s", ErrReclaimTimeout, rec.Mapkey))
		}

		g.store.Delete(rec.Mapkey)
		orderEventDelete(rec.Mapkey)

		labels := prometheus.Labels{"name": h.Scenario, "class": string(class)}
		metrics.BucketsLeaked.With(labels).Inc()
		metrics.BucketsReclaimed.With(labels).Inc()

		res.Reclaimed++
		res.ByClass[class]++

		g.logger.Debugf("reclaimed %s bucket %s (scenario %q)", class, rec.Mapkey, h.Scenario)
	}

	return res
}

// classify returns the leak class of a bucket. protected means the bucket is
// still owned by a live path and must not be touched; ok is false when the
// bucket is healthy.
func (g *LeakGuard) classify(l *Leaky, h LeakHealth, now time.Time) (class LeakClass, protected bool, ok bool) {
	var age time.Duration
	if !h.FirstPour.IsZero() {
		age = now.Sub(h.FirstPour)
	}

	// Still owned by a live path: an overflow is being turned into an alert, a
	// routine is starting up, or the bucket is younger than the grace period.
	if !h.OverflowedAt.IsZero() || h.PendingOverflow || !h.Ready {
		return "", true, false
	}

	if h.FirstPour.IsZero() && age < g.policy.Grace {
		return "", true, false
	}

	// The routine is gone: nothing will ever pour into or clean up this bucket.
	if h.Finished {
		return LeakClassOrphaned, false, true
	}

	if l.Duration > 0 && !h.FirstPour.IsZero() && h.OverflowedAt.IsZero() &&
		now.After(h.LastPour.Add(l.Duration).Add(g.policy.Grace)) {
		return LeakClassStalled, false, true
	}

	return "", false, false
}

func chanClosed(ch chan struct{}) bool {
	if ch == nil {
		return false
	}

	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func waitClosed(ch chan struct{}, timeout time.Duration) bool {
	if ch == nil {
		return false
	}

	if chanClosed(ch) {
		return true
	}

	if timeout <= 0 {
		return false
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

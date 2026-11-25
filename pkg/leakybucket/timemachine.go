package leakybucket

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TimeMachinePour(l *Leaky, _ pourGate, msg pipeline.Event) {
	var (
		d   time.Time
		err error
	)
	if msg.MarshaledTime == "" {
		log.WithFields(log.Fields{
			"evt_type": msg.Line.Labels["type"],
			"evt_src":  msg.Line.Src,
			"scenario": l.Factory.Spec.Name,
		}).Warningf("Trying to process event without evt.StrTime. Event cannot be poured to scenario")
		return
	}

	err = d.UnmarshalText([]byte(msg.MarshaledTime))
	if err != nil {
		log.Warningf("Failed to parse event time (%s) : %v", msg.MarshaledTime, err)
		return
	}

	l.lockState()
	l.Total_count += 1
	if l.First_ts.IsZero() {
		l.logger.Debugf("First event, bucket creation time : %s", d)
		l.First_ts = d
	}
	l.Last_ts = d

	allowed := l.Limiter.AllowN(d, 1) || l.conditionalOverflow

	overflowed := false

	if allowed {
		l.Queue.Add(msg)
	} else {
		l.Ovflw_ts = d
		l.Queue.Add(msg)
		l.pendingOverflow = l.Queue
		overflowed = true
	}
	l.unlockState()

	if allowed {
		l.logger.Tracef("Time-Pouring event %s (tokens:%f)", d, l.Limiter.GetTokensCount())
	}

	if overflowed {
		l.logger.Debugf("Bucket overflow at %s", d)
	}
}

func NewTimeMachine(f *BucketFactory) *Leaky {
	l := NewLeakyFromFactory(f)
	f.logger.Tracef("Instantiating timeMachine bucket")
	l.Pour = TimeMachinePour
	l.Mode = pipeline.TIMEMACHINE
	return l
}

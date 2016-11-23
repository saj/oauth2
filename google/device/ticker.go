package device

import (
	"sync"
	"time"
)

// backoffTicker returns channels that deliver 'ticks' of a clock at variable
// intervals.  The tick interval may be increased by calling BackOff().  The
// tick interval may not be decreased.  The first call to C() will return a
// channel ready for an immediate receive; subsequent calls will return a
// channel that will deliver ticks at the determined interval.
type backoffTicker struct {
	ticker      *time.Ticker
	interval    time.Duration
	sentInitial bool
	mtx         sync.Mutex
}

func newBackoffTicker(d time.Duration) *backoffTicker {
	return &backoffTicker{
		ticker:   time.NewTicker(d),
		interval: d,
	}
}

func (t *backoffTicker) C() <-chan time.Time {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if !t.sentInitial {
		c := make(chan time.Time, 1)
		c <- time.Now()
		close(c)
		t.sentInitial = true
		return c
	}
	return t.ticker.C
}

func (t *backoffTicker) BackOff() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.ticker.Stop()
	t.interval = time.Duration(t.interval.Seconds()*1.5) * time.Second
	t.ticker = time.NewTicker(t.interval)
}

func (t *backoffTicker) Stop() {
	t.ticker.Stop()
}

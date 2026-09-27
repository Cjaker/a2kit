package main

import (
	"log/slog"
	"slices"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// lagEvery is how often lag logs, when frames keep coming.
const lagEvery = 5 * time.Second

type lag struct {
	log   *slog.Logger
	now   func() time.Time
	seen  []time.Duration
	since time.Time
}

func newLag(log *slog.Logger, now func() time.Time) *lag {
	return &lag{log: log, now: now, since: now()}
}

func (l *lag) note(f wire.Frame) {
	now := l.now()
	l.seen = append(l.seen, now.Sub(f.Time))
	if now.Sub(l.since) >= lagEvery {
		l.report()
		l.since = now
	}
}

func (l *lag) report() {
	n := len(l.seen)
	if n == 0 {
		return
	}
	slices.Sort(l.seen)
	round := func(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
	l.log.Info("capture lag", "frames", n,
		"min", round(l.seen[0]), "p50", round(l.seen[n/2]), "p90", round(l.seen[n*9/10]), "max", round(l.seen[n-1]))
	l.seen = l.seen[:0]
}

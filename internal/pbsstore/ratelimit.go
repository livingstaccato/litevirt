package pbsstore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter paces a backup's data movement. WaitN is called after n bytes
// have been read from the source (or sent to a sink) and blocks until moving
// them is within the limit. Implementations must be safe for concurrent use:
// a per-target limiter is shared by every job writing to that target.
type RateLimiter interface {
	WaitN(ctx context.Context, n int) error
}

// Throttle is a RateLimiter holding a byte rate. It reserves time slots in
// order — each WaitN pushes the next free slot n/rate further out and sleeps
// until its own slot ends — so N bytes through one Throttle take at least
// N/rate in total, however many goroutines share it. Idle time banks no
// credit: a job that was quiet does not then burst at line rate.
//
// The granularity is whatever the caller charges at once (a 4 MiB chunk), so
// over a short window the instantaneous rate can exceed the limit; over a
// backup it does not.
type Throttle struct {
	rate float64 // bytes per second

	mu   sync.Mutex
	next time.Time

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// MinRate is the lowest bandwidth limit: 64 KiB/s. Below it one 4 MiB
// chunk would reserve over a minute and a typo (--bwlimit 1) days; a lower
// limit is refused where it is parsed and raised to this where it arrives
// over the wire.
const MinRate = 64 << 10

// NewThrottle returns a Throttle of bytesPerSec, or nil (no limit) for a
// non-positive rate. A positive rate below MinRate is raised to it. A nil
// *Throttle is a valid no-op RateLimiter.
func NewThrottle(bytesPerSec int64) *Throttle {
	if bytesPerSec <= 0 {
		return nil
	}
	if bytesPerSec < MinRate {
		bytesPerSec = MinRate
	}
	return &Throttle{rate: float64(bytesPerSec), now: time.Now, sleep: sleepCtx}
}

// Rate returns the throttle's limit in bytes per second (0 for nil).
func (t *Throttle) Rate() int64 {
	if t == nil {
		return 0
	}
	return int64(t.rate)
}

// WaitN implements RateLimiter.
func (t *Throttle) WaitN(ctx context.Context, n int) error {
	if t == nil || n <= 0 {
		return ctx.Err()
	}
	cost := time.Duration(float64(n) / t.rate * float64(time.Second))
	t.mu.Lock()
	now := t.now()
	if t.next.Before(now) {
		t.next = now
	}
	t.next = t.next.Add(cost)
	wake := t.next
	t.mu.Unlock()
	if err := t.sleep(ctx, wake.Sub(now)); err != nil {
		t.refund(wake, cost)
		return err
	}
	return nil
}

// refund gives back the part of a cancelled reservation [wake-cost, wake]
// that has not elapsed, so a cancelled job does not hold up the jobs that
// share the throttle (reservations after it move earlier by as much).
func (t *Throttle) refund(wake time.Time, cost time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	unused := wake.Sub(now)
	if unused > cost {
		unused = cost
	}
	if unused <= 0 {
		return
	}
	t.next = t.next.Add(-unused)
	if t.next.Before(now) {
		t.next = now
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

// multiLimiter waits on each of its limiters in turn, so the slowest wins.
type multiLimiter []RateLimiter

func (m multiLimiter) WaitN(ctx context.Context, n int) error {
	for _, l := range m {
		if err := l.WaitN(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// CombineLimiters returns a RateLimiter that honours every non-nil limiter
// given (e.g. a job's own limit and its target's), or nil when there is none.
func CombineLimiters(ls ...RateLimiter) RateLimiter {
	var out multiLimiter
	for _, l := range ls {
		if l == nil {
			continue
		}
		if th, ok := l.(*Throttle); ok && th == nil {
			continue
		}
		out = append(out, l)
	}
	switch len(out) {
	case 0:
		return nil
	case 1:
		return out[0]
	default:
		return out
	}
}

// waitRate charges a push's limiter, if it has one.
func (o *PushOptions) waitRate(ctx context.Context, n int) error {
	if o.RateLimit == nil {
		return nil
	}
	return o.RateLimit.WaitN(ctx, n)
}

// ParseRate parses a bandwidth limit in bytes per second: a plain number of
// bytes, or a number with a binary K/M/G/T suffix, optionally written as KiB,
// MB, MiB/s and so on (all binary: 1M = 1 MiB). "" and "0" mean no limit.
func ParseRate(s string) (int64, error) {
	return parseBytes(s, true)
}

// ParseSize parses a byte size the same way ("16G", "512MiB", a byte count),
// without a "/s".
func ParseSize(s string) (int64, error) {
	return parseBytes(s, false)
}

func parseBytes(s string, rate bool) (int64, error) {
	orig := s
	s = strings.ToUpper(strings.TrimSpace(s))
	if rate {
		s = strings.TrimSuffix(s, "/S")
	}
	s = strings.TrimSuffix(s, "IB")
	s = strings.TrimSuffix(s, "B")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K':
		mult = 1 << 10
	case 'M':
		mult = 1 << 20
	case 'G':
		mult = 1 << 30
	case 'T':
		mult = 1 << 40
	}
	if mult != 1 {
		s = strings.TrimSpace(s[:len(s)-1])
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		if rate {
			return 0, fmt.Errorf("invalid bandwidth limit %q (want e.g. 50MiB, 512K or a byte count per second)", orig)
		}
		return 0, fmt.Errorf("invalid size %q (want e.g. 16G, 512MiB or a byte count)", orig)
	}
	if n > 0 && n > (1<<63-1)/mult {
		return 0, fmt.Errorf("%q overflows", orig)
	}
	if rate && n*mult > 0 && n*mult < MinRate {
		return 0, fmt.Errorf("bandwidth limit %q is below the minimum of 64KiB/s (use 0 for no limit)", orig)
	}
	return n * mult, nil
}

// FormatRate renders bytes per second for messages ("50MiB/s").
func FormatRate(bps int64) string {
	switch {
	case bps <= 0:
		return "unlimited"
	case bps%(1<<30) == 0:
		return fmt.Sprintf("%dGiB/s", bps>>30)
	case bps%(1<<20) == 0:
		return fmt.Sprintf("%dMiB/s", bps>>20)
	case bps%(1<<10) == 0:
		return fmt.Sprintf("%dKiB/s", bps>>10)
	default:
		return fmt.Sprintf("%dB/s", bps)
	}
}

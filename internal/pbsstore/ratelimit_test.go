package pbsstore

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock drives a Throttle without real sleeps: sleep advances now.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept time.Duration
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.t = c.t.Add(d)
		c.slept += d
	}
	return nil
}

func newFakeThrottle(rate int64) (*Throttle, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := NewThrottle(rate)
	th.now = c.now
	th.sleep = c.sleep
	return th, c
}

// Moving N bytes through a Throttle of R bytes/s takes at least N/R.
func TestThrottle_PacesToRate(t *testing.T) {
	th, c := newFakeThrottle(1 << 20) // 1 MiB/s
	for i := 0; i < 3; i++ {
		if err := th.WaitN(context.Background(), 4<<20); err != nil {
			t.Fatal(err)
		}
	}
	if c.slept < 12*time.Second-time.Millisecond {
		t.Fatalf("12 MiB at 1 MiB/s slept %v, want >= 12s", c.slept)
	}
}

// Idle time does not bank credit: after a long pause, the next bytes are
// still paced (a job that was quiet does not then burst at line rate).
func TestThrottle_NoCreditForIdle(t *testing.T) {
	th, c := newFakeThrottle(1 << 20)
	_ = th.WaitN(context.Background(), 1<<20)
	c.mu.Lock()
	c.t = c.t.Add(time.Hour)
	before := c.slept
	c.mu.Unlock()
	_ = th.WaitN(context.Background(), 2<<20)
	if got := c.slept - before; got < 2*time.Second-time.Millisecond {
		t.Fatalf("after an idle hour, 2 MiB at 1 MiB/s slept %v, want >= 2s", got)
	}
}

// One Throttle shared by concurrent jobs (a per-target limit) bounds their
// combined rate, not each job's. The clock is frozen, so every reservation is
// made at the same instant: shared slots end at 1s, 2s, ... 8s, while a
// throttle that paced each caller alone would hand every one of them 1s.
func TestThrottle_SharedAcrossJobs(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	th := NewThrottle(1 << 20)
	th.now = func() time.Time { return start }
	var mu sync.Mutex
	var longest time.Duration
	th.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		if d > longest {
			longest = d
		}
		mu.Unlock()
		return nil
	}
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2; i++ {
				_ = th.WaitN(context.Background(), 1<<20)
			}
		}()
	}
	wg.Wait()
	if longest < 8*time.Second-time.Millisecond {
		t.Fatalf("4 jobs x 2 MiB through a shared 1 MiB/s throttle: last slot ends after %v, want >= 8s", longest)
	}
}

func TestThrottle_NilAndZeroAreUnlimited(t *testing.T) {
	if NewThrottle(0) != nil || NewThrottle(-5) != nil {
		t.Fatal("a non-positive rate must mean no throttle")
	}
	var th *Throttle
	if err := th.WaitN(context.Background(), 1<<30); err != nil {
		t.Fatal(err)
	}
	if CombineLimiters(nil, (*Throttle)(nil)) != nil {
		t.Fatal("combining only no-ops must give no limiter")
	}
}

func TestThrottle_CancelledContext(t *testing.T) {
	th := NewThrottle(1) // 1 byte/s: a real sleep of ~forever
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := th.WaitN(ctx, 1<<20); err == nil {
		t.Fatal("WaitN on a cancelled context returned nil")
	}
}

func TestCombineLimiters_AppliesEach(t *testing.T) {
	a, ca := newFakeThrottle(1 << 20)
	b, cb := newFakeThrottle(2 << 20)
	l := CombineLimiters(a, nil, b)
	if err := l.WaitN(context.Background(), 4<<20); err != nil {
		t.Fatal(err)
	}
	if ca.slept < 4*time.Second-time.Millisecond || cb.slept < 2*time.Second-time.Millisecond {
		t.Fatalf("combined limiter did not wait on both: a=%v b=%v", ca.slept, cb.slept)
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]int64{
		"":          0,
		"0":         0,
		"1048576":   1 << 20,
		"512K":      512 << 10,
		"50M":       50 << 20,
		"50MiB":     50 << 20,
		"50MiB/s":   50 << 20,
		"1G":        1 << 30,
		"1gib/s":    1 << 30,
		" 10 MB/s ": 10 << 20,
	} {
		got, err := ParseRate(in)
		if err != nil || got != want {
			t.Errorf("ParseRate(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"fast", "-1M", "10X", "1.5M", "99999999999999999999T"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) accepted", bad)
		}
	}
}

// recordingLimiter counts the bytes a push asks to move.
type recordingLimiter struct {
	mu    sync.Mutex
	bytes int64
}

func (r *recordingLimiter) WaitN(_ context.Context, n int) error {
	r.mu.Lock()
	r.bytes += int64(n)
	r.mu.Unlock()
	return nil
}

// Every push path charges the limiter for exactly the bytes it reads from the
// source — a hole or an inherited clean chunk costs nothing.
func TestPush_ChargesLimiterForBytesRead(t *testing.T) {
	ctx := context.Background()
	src := randomBytes(t, ChunkSize*3+1234)

	t.Run("PushDisk", func(t *testing.T) {
		r, _ := Init(t.TempDir())
		lim := &recordingLimiter{}
		if _, err := PushDisk(ctx, r, bytes.NewReader(src), PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z", RateLimit: lim,
		}); err != nil {
			t.Fatal(err)
		}
		if lim.bytes != int64(len(src)) {
			t.Fatalf("charged %d, read %d", lim.bytes, len(src))
		}
	})

	t.Run("PushFromSource", func(t *testing.T) {
		r, _ := Init(t.TempDir())
		lim := &recordingLimiter{}
		// Only the second chunk window is allocated.
		ext := [][2]int64{{ChunkSize, ChunkSize}}
		if _, err := PushFromSource(ctx, r, bytes.NewReader(src), int64(len(src)), ext, nil, PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z", RateLimit: lim,
		}); err != nil {
			t.Fatal(err)
		}
		if lim.bytes != ChunkSize {
			t.Fatalf("charged %d for one allocated %d-byte window", lim.bytes, ChunkSize)
		}
	})

	t.Run("PushIncrementalSeek", func(t *testing.T) {
		r, _ := Init(t.TempDir())
		parent, err := PushDisk(ctx, r, bytes.NewReader(src), PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		lim := &recordingLimiter{}
		bm := NewRangeBitmap([][2]int64{{0, 10}}) // first window dirty only
		if _, err := PushIncremental(ctx, r, bytes.NewReader(src), parent, bm, PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T02:00:00Z", RateLimit: lim,
		}); err != nil {
			t.Fatal(err)
		}
		if lim.bytes != ChunkSize {
			t.Fatalf("charged %d for one dirty window", lim.bytes)
		}
	})

	t.Run("SyncManifest", func(t *testing.T) {
		srcRepo, _ := Init(t.TempDir())
		m, err := PushDisk(ctx, srcRepo, bytes.NewReader(src), PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		dst, _ := Init(t.TempDir())
		lim := &recordingLimiter{}
		if _, err := SyncManifestLimited(ctx, srcRepo, m, RepoSink(dst), lim); err != nil {
			t.Fatal(err)
		}
		if lim.bytes != int64(len(src)) {
			t.Fatalf("sync charged %d for %d bytes sent", lim.bytes, len(src))
		}
	})
}

// m-9: a limit below 64 KiB/s is refused where it is parsed and raised to
// the floor where it arrives over the wire.
func TestRate_Minimum(t *testing.T) {
	for _, bad := range []string{"1", "63K", "1000"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) accepted a limit below the minimum", bad)
		}
	}
	if n, err := ParseRate("64K"); err != nil || n != MinRate {
		t.Errorf("64K: %d %v", n, err)
	}
	if n, err := ParseRate("0"); err != nil || n != 0 {
		t.Errorf("0 (no limit): %d %v", n, err)
	}
	if NewThrottle(1).Rate() != MinRate {
		t.Errorf("a 1 B/s throttle was not raised to the minimum")
	}
}

// m-9: a cancelled job's unslept reservation is given back, so the jobs
// sharing its throttle are not held up by it.
func TestThrottle_RefundOnCancel(t *testing.T) {
	th, c := newFakeThrottle(1 << 20)
	cancelled := true
	var last time.Duration
	th.sleep = func(ctx context.Context, d time.Duration) error {
		if cancelled {
			return context.Canceled
		}
		last = d
		return c.sleep(ctx, d)
	}
	if err := th.WaitN(context.Background(), 4<<20); err == nil {
		t.Fatal("want the cancellation")
	}
	cancelled = false
	if err := th.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatal(err)
	}
	if last > time.Second+time.Millisecond {
		t.Fatalf("after a cancelled 4 MiB reservation, 1 MiB waited %v; the reservation was not refunded", last)
	}
}

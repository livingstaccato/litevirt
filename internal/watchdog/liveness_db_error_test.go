package watchdog

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// probeLog records what a DB probe returned.
type probeLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *probeLog) add(err error) {
	l.mu.Lock()
	l.errs = append(l.errs, err)
	l.mu.Unlock()
}

func (l *probeLog) snapshot() []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]error(nil), l.errs...)
}

// Only a probe that returns nil moves the DB counter: a timeout, an
// interrupted query and SQLITE_BUSY/LOCKED leave it standing.
//
// Mutation: bump dbDone on every return in runDB and the error cases go red.
func TestRunDB_OnlyANilProbeCountsAsProgress(t *testing.T) {
	for name, probe := range map[string]func(context.Context) error{
		"completed": func(context.Context) error { return nil },
		"timeout":   func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		"canceled":  func(context.Context) error { return context.Canceled },
		"busy":      func(context.Context) error { return errors.New("query: database is locked (5) (SQLITE_BUSY)") },
		"locked":    func(context.Context) error { return errors.New("query: database table is locked (6) (SQLITE_LOCKED)") },
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Uint64
			g := &livenessGate{}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				g.runDB(ctx, func(ctx context.Context) error { err := probe(ctx); calls.Add(1); return err }, 6*time.Millisecond)
				close(done)
			}()
			time.Sleep(100 * time.Millisecond)
			cancel()
			<-done
			n := calls.Load()
			if n < 3 {
				t.Fatalf("the probe ran %d times in 100 ms", n)
			}
			want := uint64(0)
			if name == "completed" {
				want = n
			}
			if got := g.dbDone.Load(); got != want {
				t.Fatalf("dbDone = %d after %d probe returns, want %d", got, n, want)
			}
		})
	}
}

// On the state store's real client, a probe that gets the client's lock and
// then fails is no progress: one whose timeout expires behind a writer that
// keeps taking the lock back, one whose query is interrupted, and one that
// returns SQLITE_BUSY/LOCKED (a fake: SELECT 1 touches no table, so the real
// client cannot produce them for it) each self-fence the gate within its
// window although the probe keeps returning. A probe that completes keeps the
// watchdog petted.
//
// Mutation: bump dbDone on every return in runDB and the failing cases go red.
func TestHeartbeat_LivenessGateCountsOnlyCompletedRoundTrips(t *testing.T) {
	// fences runs the gate on probe and requires it to self-fence while the
	// probe keeps returning, never nil and at least three times with an error
	// that want accepts (a probe the gate's stop cancels returns another).
	fences := func(t *testing.T, probe func(context.Context) error, want func(error) bool) {
		t.Helper()
		var log probeLog
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetDBProbe(func(ctx context.Context) error { err := probe(ctx); log.add(err); return err })
		})
		time.Sleep(300 * time.Millisecond)
		errs := log.snapshot()
		matched := 0
		for _, err := range errs {
			if err == nil {
				t.Fatal("the probe completed a round trip; the case needs one that only fails")
			}
			if want(err) {
				matched++
			}
		}
		if matched < 3 {
			t.Fatalf("the probe returned the failure this case is about %d times in 300 ms (%v)", matched, errs)
		}
		if !ctrl.Fenced() {
			t.Fatalf("%d failed round trips (%v) kept the gate from self-fencing", len(errs), errs[0])
		}
		if grows(t, dev, 60*time.Millisecond) {
			t.Fatal("petting continued with no round trip completing")
		}
	}

	t.Run("timeout after the lock", func(t *testing.T) {
		verifiedDevice(t)
		db := corrosion.NewTestClientT(t)
		// A writer holds the client's lock until each probe's timeout has
		// expired, lets the probe through, and takes the lock back once it
		// has returned: every probe gets the lock and then times out.
		mu := db.Mu()
		mu.Lock()
		entered, returned := make(chan context.Context), make(chan struct{})
		stop, exited := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(exited)
			locked := true
			defer func() {
				if locked {
					mu.Unlock()
				}
			}()
			for {
				var pctx context.Context
				select {
				case <-stop:
					return
				case pctx = <-entered:
				}
				select {
				case <-stop:
					return
				case <-pctx.Done():
				}
				mu.Unlock()
				locked = false
				select {
				case <-stop:
					return
				case <-returned:
				}
				mu.Lock()
				locked = true
			}
		}()
		t.Cleanup(func() { close(stop); <-exited })
		fences(t, func(ctx context.Context) error {
			select {
			case entered <- ctx:
			case <-stop:
			}
			_, err := db.Query(ctx, "SELECT 1")
			select {
			case returned <- struct{}{}:
			case <-stop:
			}
			return err
		}, func(err error) bool { return errors.Is(err, context.DeadlineExceeded) })
	})

	t.Run("interrupted query", func(t *testing.T) {
		verifiedDevice(t)
		db := corrosion.NewTestClientT(t)
		const slow = `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1000000000) SELECT count(*) FROM n`
		// The lock is free and the query runs for seconds, so the cancel
		// lands while it executes: SQLite interrupts it.
		fences(t, func(ctx context.Context) error {
			qctx, cancel := context.WithCancel(ctx)
			defer cancel()
			time.AfterFunc(time.Millisecond, cancel)
			_, err := db.Query(qctx, slow)
			return err
		}, func(err error) bool { return errors.Is(err, context.Canceled) })
	})

	for name, msg := range map[string]string{
		"SQLITE_BUSY":   "query: database is locked (5) (SQLITE_BUSY)",
		"SQLITE_LOCKED": "query: database table is locked (6) (SQLITE_LOCKED)",
	} {
		t.Run(name, func(t *testing.T) {
			verifiedDevice(t)
			fences(t, func(context.Context) error { return errors.New(msg) },
				func(err error) bool { return err.Error() == msg })
		})
	}

	t.Run("completed round trip keeps petting", func(t *testing.T) {
		verifiedDevice(t)
		db := corrosion.NewTestClientT(t)
		var log probeLog
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetDBProbe(func(ctx context.Context) error {
				_, err := db.Query(ctx, "SELECT 1")
				log.add(err)
				return err
			})
		})
		time.Sleep(300 * time.Millisecond)
		errs := log.snapshot()
		if len(errs) < 3 {
			t.Fatalf("the probe returned %d times in 300 ms", len(errs))
		}
		for _, err := range errs {
			if err != nil {
				t.Fatalf("SELECT 1 on an idle client failed: %v", err)
			}
		}
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("completed round trips did not keep the watchdog petted")
		}
	})
}

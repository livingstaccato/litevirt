package fencessh

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ReevaluateTimeout bounds one Reevaluate when Config.ReevaluateTimeout is
// zero: its sshd evaluation (one `sshd -T` per peer), the self-check login
// (probeTimeout) and the publish.
const ReevaluateTimeout = 40 * time.Second

// Reevaluate runs one fresh sync for this request and reports whether it
// proves this host's row: the sync STARTED after Reevaluate was called,
// evaluated sshd anew in it (the acceptTTL cache is skipped, and with
// SelfCheck the running sshd is logged in to), the evaluation did not fail,
// and the row was published or was already identical. why says why not.
//
// Concurrent calls share a sync only when it starts after each of them
// arrived: a call that arrives while a fresh sync runs joins the NEXT one,
// which starts when the running one ends. So there is at most one fresh sync
// running and one pending, whatever the number of callers. A call gives up,
// unproven, at ctx's deadline or ReevaluateTimeout, whichever is sooner; a
// sync never outlives the latest of its callers' bounds. A sync wedged
// inside Sync therefore costs its callers a false, never a hang.
//
// It takes no lock across the sync but syncMu, which Sync itself takes.
func (a *Agent) Reevaluate(ctx context.Context) (bool, string) {
	limit := a.cfg.ReevaluateTimeout
	if limit <= 0 {
		limit = ReevaluateTimeout
	}
	until := time.Now().Add(limit)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	r := a.reeval.join(until, a.runReevaluations)
	wctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	select {
	case <-r.done:
		return r.ok, r.why
	case <-wctx.Done():
		return false, "no fresh sync finished in time (its agent may be wedged in a sync): " + wctx.Err().Error()
	}
}

// reevalRun is one fresh sync and the callers sharing it.
type reevalRun struct {
	done chan struct{}
	// until is the latest bound of its callers; it is only raised, under
	// reevalQueue.mu, while the run is pending.
	until time.Time
	// ok and why are set before done closes.
	ok  bool
	why string
}

// reevalQueue is the fresh sync running, and the one pending behind it.
type reevalQueue struct {
	mu      sync.Mutex
	running *reevalRun
	next    *reevalRun
}

// join returns the run a caller arriving now shares: a new one started at
// once when none runs, else the pending one (created if need be), which
// starts only after the running one ends.
func (q *reevalQueue) join(until time.Time, start func(*reevalRun)) *reevalRun {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.running == nil {
		r := &reevalRun{done: make(chan struct{}), until: until}
		q.running = r
		go start(r)
		return r
	}
	if q.next == nil {
		q.next = &reevalRun{done: make(chan struct{})}
	}
	if until.After(q.next.until) {
		q.next.until = until
	}
	return q.next
}

// runReevaluations runs r, then each run pending behind it, until none is.
func (a *Agent) runReevaluations(r *reevalRun) {
	q := &a.reeval
	for r != nil {
		r.ok, r.why = a.freshSync(r.until)
		close(r.done)
		q.mu.Lock()
		r, q.next = q.next, nil
		q.running = r
		q.mu.Unlock()
	}
}

// freshSync is one Sync marked fresh (freshSyncOf), bounded by until.
func (a *Agent) freshSync(until time.Time) (bool, string) {
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	if ctx.Err() != nil {
		return false, "every caller's bound passed before the sync could start"
	}
	f := &freshSyncState{}
	if err := a.Sync(context.WithValue(ctx, freshSyncKey{}, f)); err != nil {
		slog.Info("fence ssh: a requested re-evaluation failed", "error", err)
		return false, "the sync failed: " + err.Error()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case !f.ran:
		return false, "the sync evaluated no sshd (no row is published from this host: release feature, mode, " +
			"certificate or fence address)"
	case f.evalErr != nil:
		return false, "sshd could not be evaluated: " + f.evalErr.Error()
	case !f.pub:
		return false, "the sync published no row"
	}
	return true, ""
}

// freshSyncKey marks a Sync's context as Reevaluate's: sshdAccepting then
// skips its cache and records that it evaluated, and publish that it
// published.
type freshSyncKey struct{}

type freshSyncState struct {
	mu      sync.Mutex
	ran     bool
	evalErr error
	pub     bool
}

// freshSyncOf is ctx's fresh-sync record, nil for an ordinary sync.
func freshSyncOf(ctx context.Context) *freshSyncState {
	f, _ := ctx.Value(freshSyncKey{}).(*freshSyncState)
	return f
}

func (f *freshSyncState) evaluated(err error) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.ran = true
	if err != nil && f.evalErr == nil {
		f.evalErr = err
	}
	f.mu.Unlock()
}

func (f *freshSyncState) published() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.pub = true
	f.mu.Unlock()
}

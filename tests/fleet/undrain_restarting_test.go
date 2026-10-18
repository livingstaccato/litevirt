// Fleet scenario: `lv host undrain` on a host that is restarting (lab 1,
// 2026-10-17).
//
// node-3's daemon was stopped gracefully, which records the host 'upgrading'
// and gives it a restart allowance. It was undrained 19 s before its new
// daemon served: UndrainHost wrote 'active' over 'upgrading', which ended the
// allowance, and the failover coordinator fenced it 13 s later on the failing
// run left from the stop — 0.4 s after its gRPC server listened.
//
// Two guards. UndrainHost Pings an 'upgrading' host first, and refuses when it
// does not answer. And the coordinator gives a failing run that began while
// the host was 'upgrading' the rest of its restart allowance, whoever recorded
// it active, which covers an undrain handled by a node on an older build.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// stateOn is d's state as node n reads it.
func (f *restartFleet) stateOn(t *testing.T, n *Node) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), n.DB, f.d.Name)
	if err != nil || h == nil {
		t.Fatalf("read %s on %s: %v", f.d.Name, n.Name, err)
	}
	return h.State
}

// noFenceFor waits d and asserts it is not fenced meanwhile.
func (f *restartFleet) noFenceFor(t *testing.T, d time.Duration, what string) {
	t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if fs := f.fences(); len(fs) != 0 {
			t.Fatalf("d was fenced %s: %d fences", what, len(fs))
		}
	}
}

// serve brings d's daemon up: its probes and its Ping answer. It returns the
// moment before they do, as answer does.
func (f *restartFleet) serve(restorePing func()) time.Time {
	at := time.Now() // before it answers (answer)
	restorePing()
	f.down.Store(false)
	return at
}

// TestFleet_UndrainOfARestartingHostIsRefusedUntilItServes: d is stopped
// gracefully and its observers count it past the fence threshold. Undrain of
// d, from a, while d does not answer, is refused with FailedPrecondition; d
// stays 'upgrading' and is not fenced through the next 30 s. Once d serves,
// undrain records it active, and it is still not fenced.
//
// Mutation: drop the 'upgrading' check from UndrainHost — the undrain
// succeeds and records d active. With the coordinator's guard dropped too, d
// is fenced about 13 s later, as on lab 1.
func TestFleet_UndrainOfARestartingHostIsRefusedUntilItServes(t *testing.T) {
	f := newRestartFleet(t, 3411)
	ctx := context.Background()
	restorePing := f.d.DoNotImplement("Ping")
	f.gracefulStop(t)

	_, err := f.c.SelfClient(f.a).UndrainHost(ctx, &pb.UndrainHostRequest{Name: f.d.Name})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("undrain of d while it restarts: err=%v, want FailedPrecondition", err)
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "turns active by itself once its daemon serves") {
		t.Errorf("refusal %q does not say d turns active by itself", msg)
	}
	f.noFenceFor(t, 30*time.Second, "after a refused undrain, while it restarts")
	for _, n := range append([]*Node{f.d}, f.observers...) {
		if got := f.stateOn(t, n); got != "upgrading" {
			t.Fatalf("d is recorded %q on %s after a refused undrain, want 'upgrading'", got, n.Name)
		}
	}

	f.serve(restorePing)
	if _, err := f.c.SelfClient(f.a).UndrainHost(ctx, &pb.UndrainHostRequest{Name: f.d.Name}); err != nil {
		t.Fatalf("undrain of d once it serves: %v", err)
	}
	eventually(t, convergeTimeout, "d recorded active everywhere", func() bool {
		for _, n := range append([]*Node{f.d}, f.observers...) {
			if f.stateOn(t, n) != "active" {
				return false
			}
		}
		return true
	})
	f.noFenceFor(t, 5*time.Second, "once it served and was undrained")
}

// TestFleet_RestartingHostRecordedActiveByAnotherWriterKeepsItsAllowance: the
// coordinator's guard alone. d is stopped gracefully, and is recorded active
// while it does not answer — as an undrain handled by a node on an older
// build, which has no serving check, records it. Its observers' run began
// while it was 'upgrading', so it keeps the rest of its restart allowance: it
// is not fenced through the next 30 s, and once it serves it is not fenced.
//
// Mutation: drop the restart allowance of a run begun while 'upgrading'
// (failover.upgradingLifeGrace) — d is fenced about 13 s after the write.
func TestFleet_RestartingHostRecordedActiveByAnotherWriterKeepsItsAllowance(t *testing.T) {
	f := newRestartFleet(t, 3412)
	ctx := context.Background()
	restorePing := f.d.DoNotImplement("Ping")
	f.gracefulStop(t)

	// What UndrainHost wrote before the serving check, on any node.
	if err := corrosion.UpdateHostState(ctx, f.a.DB, f.d.Name, "active"); err != nil {
		t.Fatalf("an older node's undrain: %v", err)
	}
	f.noFenceFor(t, 30*time.Second, "after it was recorded active mid-restart")

	served := f.serve(restorePing)
	eventually(t, convergeTimeout, "every observer to see d answer", func() bool {
		for _, n := range f.observers {
			if got, at, ok := observedFailures(n, f.d.Name); !ok || got != 0 || !at.After(served) {
				return false
			}
		}
		return true
	})
	f.noFenceFor(t, 2*time.Second, "once it served")
}

package health

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type recordedEvent struct{ vm, typ, result, detail string }

// orphanedHeldStart is lab 2's node-3 after its daemon restarted with a held
// start of st not cancelled (339a79f4, B2 concern 2): st's row says starting
// with the held start's detail, and its start lease names this host's
// operator start, taken a moment ago, so its TTL has most of ten minutes to
// run. running says whether libvirt has since started the domain.
func orphanedHeldStart(t *testing.T, running bool) (*Reconciler, *corrosion.Client, *libvirtfake.Fake, func() []recordedEvent) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	asked := time.Date(2026, 10, 15, 10, 45, 37, 0, time.UTC)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "st", HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "starting", StateDetail: HeldStartDetail(asked),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if by, err := TryVMStartLease(ctx, db, OperatorStartLockHolder("host-a"), "st", time.Now()); err != nil || by != OperatorStartLockHolder("host-a") {
		t.Fatalf("take the held start's lease: %q %v", by, err)
	}
	f := libvirtfake.New()
	if err := f.DefineDomain("<domain><name>st</name></domain>"); err != nil {
		t.Fatal(err)
	}
	if running {
		if err := f.StartDomain("st"); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("host-a", t.TempDir(), db, f)
	var mu sync.Mutex
	var evs []recordedEvent
	r.SetVMEventRecorder(func(_ context.Context, vm, typ, result, detail string) {
		mu.Lock()
		evs = append(evs, recordedEvent{vm, typ, result, detail})
		mu.Unlock()
	})
	return r, db, f, func() []recordedEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedEvent(nil), evs...)
	}
}

// Lab 2 (339a79f4, B2 concern 2): the daemon that held st's start restarted
// before libvirt answered it. libvirtd started the domain when the storage
// came back, but the row stayed starting for six more minutes, until the
// held start's lease ran out (the reconciler skipped st every pass, "VM lock
// held by another host"), and no vm.started event was recorded. With no start
// of st left in this daemon and the domain running, the reconciler now takes
// the lease over at once, records st running, and records the start's
// outcome, once.
//
// Mutations: no takeover: st stays starting: red. The event not recorded:
// none: red.
func TestReconcile_AHeldStartWhoseDaemonRestartedIsRecordedOnceLibvirtStartsIt(t *testing.T) {
	r, db, _, events := orphanedHeldStart(t, true)
	r.SetHeldStartProbe(func(string) bool { return false })
	ctx := context.Background()

	r.reconcile(ctx)
	vm, err := corrosion.GetVM(ctx, db, "st")
	if err != nil || vm.State != "running" {
		t.Fatalf("st after a pass: %+v %v, want running", vm, err)
	}
	r.reconcile(ctx)
	got := events()
	if len(got) != 1 || got[0].typ != "vm.started" || got[0].result != "ok" ||
		!strings.Contains(got[0].detail, "2026-10-15T10:45:37Z") || !strings.Contains(got[0].detail, "restarted") {
		t.Fatalf("events: %+v, want one vm.started ok naming the start and the restart", got)
	}
	if holder, _, ok, err := ReadVMStartLease(ctx, db, "st"); err != nil || ok {
		t.Errorf("st's start lease after the pass: %q %v %v, want none", holder, ok, err)
	}
}

// The lease is taken over only on positive evidence: while a start of st is
// still in flight in this daemon (the lease is its), or while the domain does
// not run (a start may still be queued; shut off proves nothing), the
// reconciler leaves the lease and the row alone, as before.
//
// Mutations: the probe not consulted: st is recorded running under a start
// still in flight here: red. Any answer taken as evidence: the shut-off
// domain's lease is taken over and the start re-driven: red. The holder not
// checked: another holder's lease is taken over: red.
func TestReconcile_AHeldStartsLeaseIsTakenOverOnlyOnEvidence(t *testing.T) {
	ctx := context.Background()
	t.Run("start in flight here", func(t *testing.T) {
		r, db, _, events := orphanedHeldStart(t, true)
		r.SetHeldStartProbe(func(name string) bool { return name == "st" })
		r.reconcile(ctx)
		if vm, _ := corrosion.GetVM(ctx, db, "st"); vm.State != "starting" {
			t.Errorf("st: %s, want starting (the start in flight records it)", vm.State)
		}
		if len(events()) != 0 {
			t.Errorf("events: %+v, want none", events())
		}
	})
	for _, other := range []string{OperatorStartLockHolder("host-b"), RepairLockHolder("host-a")} {
		t.Run("lease names "+other, func(t *testing.T) {
			r, db, _, events := orphanedHeldStart(t, true)
			r.SetHeldStartProbe(func(string) bool { return false })
			ReleaseVMStartLease(ctx, db, OperatorStartLockHolder("host-a"), "st")
			if by, err := TryVMStartLease(ctx, db, other, "st", time.Now()); err != nil || by != other {
				t.Fatalf("take the lease as %s: %q %v", other, by, err)
			}
			r.reconcile(ctx)
			if vm, _ := corrosion.GetVM(ctx, db, "st"); vm.State != "starting" {
				t.Errorf("st: %s, want starting (the lease is %s's)", vm.State, other)
			}
			if holder, _, ok, _ := ReadVMStartLease(ctx, db, "st"); !ok || holder != other {
				t.Errorf("st's lease: %q %v, want %s's", holder, ok, other)
			}
			if len(events()) != 0 {
				t.Errorf("events: %+v, want none", events())
			}
		})
	}
	t.Run("domain not running", func(t *testing.T) {
		r, db, f, events := orphanedHeldStart(t, false)
		r.SetHeldStartProbe(func(string) bool { return false })
		r.reconcile(ctx)
		if vm, _ := corrosion.GetVM(ctx, db, "st"); vm.State != "starting" {
			t.Errorf("st: %s, want starting", vm.State)
		}
		if holder, _, ok, _ := ReadVMStartLease(ctx, db, "st"); !ok || holder != OperatorStartLockHolder("host-a") {
			t.Errorf("st's lease: %q %v, want the held start's", holder, ok)
		}
		for _, e := range f.EventLog() {
			if e.Domain == "st" && e.Op != "define" {
				t.Errorf("st was acted on with no evidence the held start answered: %+v", e)
			}
		}
		if len(events()) != 0 {
			t.Errorf("events: %+v, want none", events())
		}
	})
}

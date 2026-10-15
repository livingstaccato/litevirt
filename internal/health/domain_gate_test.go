package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// hungDomainFake is lab 2's node-3 (339a79f4, B2): libvirt hangs on st, whose
// start waits on a dead NFS export, and answers for every other domain. The
// start itself is a call naming st outstanding on the daemon's connection,
// which libvirtd serves five at a time. Every domain named runs.
func hungDomainFake(t *testing.T, names ...string) (*libvirtfake.Fake, func()) {
	t.Helper()
	f := libvirtfake.New()
	for _, n := range names {
		if err := f.DefineDomain("<domain><name>" + n + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		if err := f.StartDomain(n); err != nil {
			t.Fatal(err)
		}
	}
	f.SetConnRequests(5)
	release := f.HangDomain("st")
	t.Cleanup(release)
	go func() { _, _ = f.DomainState("st") }() // the start's own call
	deadline := time.Now().Add(5 * time.Second)
	for f.ConnInFlight() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the start's call is not in flight on the daemon's connection")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return f, release
}

func passWithin(t *testing.T, limit time.Duration, what string, pass func()) time.Duration {
	t.Helper()
	done := make(chan struct{})
	t0 := time.Now()
	go func() {
		pass()
		close(done)
	}()
	select {
	case <-done:
		return time.Since(t0)
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v: it waits on a domain libvirt does not answer for", what, limit)
	}
	return 0
}

func rowState(t *testing.T, db *corrosion.Client, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %+v %v", name, vm, err)
	}
	return vm.State
}

// Lab 2 (339a79f4, B2) and lsunknown review I-1: with libvirt hung on st,
// the reconcile walk asked libvirt about st on the daemon's connection and
// waited for the answer, so the walk — and every pass after it — never got
// past st, and its call held one of the connection's five requests. A
// domain libvirt has not answered for is now skipped: the walk asks for its
// state on a reader connection, within a bound, decides nothing about it,
// and goes on to the other VMs. The ask is latched, so a later pass costs
// no wait. Once libvirt answers, st is reconciled as usual.
//
// Mutation: no latch (each ask waits anew): the second pass takes a wait:
// red. (The walk's own gate is pinned by the next test: here st's starting
// row reaches startPendingVM, whose gate also holds.)
func TestReconcile_ADomainLibvirtHangsOnIsSkippedAndTheOthersReconciled(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	f, release := hungDomainFake(t, "ok", "st")
	for _, vm := range []corrosion.VMRecord{
		{Name: "ok", HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "error", StateDetail: "failover start failed"},
		{Name: "st", HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "starting", StateDetail: "operator start: libvirt has not answered the start asked for at 2026-10-15T10:45:37Z"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("host-a", t.TempDir(), db, f)
	r.virtWait.wait = 200 * time.Millisecond

	passWithin(t, 5*time.Second, "the reconcile walk", func() { r.reconcile(ctx) })
	if got := rowState(t, db, "ok"); got != "running" {
		t.Errorf("ok (error row, domain running): %s, want running", got)
	}
	if got := rowState(t, db, "st"); got != "starting" {
		t.Errorf("st (libvirt does not answer): %s, want starting, untouched", got)
	}
	if n := f.MainConnCallsFor("st"); n != 1 {
		t.Errorf("calls naming st on the daemon's connection: %d, want only the start's own", n)
	}
	for _, e := range f.EventLog() {
		if e.Domain == "st" && e.Op != "define" && e.Op != "start" {
			t.Errorf("st was acted on while libvirt did not answer for it: %+v", e)
		}
	}

	if took := passWithin(t, 5*time.Second, "the second walk", func() { r.reconcile(ctx) }); took >= r.virtWait.wait {
		t.Errorf("the second walk took %v: it waited on st again instead of skipping it at once", took)
	}

	release()
	deadline := time.Now().Add(5 * time.Second)
	for rowState(t, db, "st") != "running" {
		if time.Now().After(deadline) {
			t.Fatalf("st after libvirt answered: %s, want running (domain already present)", rowState(t, db, "st"))
		}
		time.Sleep(20 * time.Millisecond)
		r.reconcile(ctx)
	}
}

// The sweeps after the walk (self-fence, owner-assert, adopt, orphan report)
// list every domain, and libvirt lists only once it can look at each, so a
// domain it hangs on held the list, the sweep and the pass. The list is
// asked on a reader connection within a bound now; a sweep whose list
// libvirt has not answered is skipped. The whole pass returns, and nothing
// is asked on the daemon's connection for st or for the list.
//
// Mutations: the self-fence list asked on the daemon's connection,
// unbounded: the pass does not return: red. No gate in the walk (st's
// running row asks DomainExists on the daemon's connection): likewise: red.
func TestReconcileOnce_ASweepWhoseListLibvirtDoesNotAnswerIsSkipped(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	f, _ := hungDomainFake(t, "ok", "st")
	for _, vm := range []corrosion.VMRecord{
		{Name: "ok", HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "running"},
		{Name: "st", HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "running"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("host-a", t.TempDir(), db, f)
	r.virtWait.wait = 200 * time.Millisecond
	r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) { return RuntimeAbsent, nil })

	passWithin(t, 5*time.Second, "the reconcile pass", func() { r.ReconcileOnce(ctx) })
	if n := f.MainConnCallsFor(""); n != 0 {
		t.Errorf("domain lists on the daemon's connection: %d, want 0", n)
	}
	if n := f.MainConnCallsFor("st"); n != 1 {
		t.Errorf("calls naming st on the daemon's connection: %d, want only the start's own", n)
	}
}

// The VM checker's restart pass asked libvirt for each stopped VM's state on
// the daemon's connection, so a domain libvirt hangs on held the pass and
// every pass after it. It is skipped now — neither healed nor restarted —
// and the other VMs are checked as before: ok, stopped with its domain
// running, is healed to running.
//
// Mutation: no gate in the restart pass: the sweep does not return: red.
func TestVMChecker_ADomainLibvirtHangsOnIsSkippedAndTheOthersChecked(t *testing.T) {
	db := testStartDB(t)
	seedRestartPolicyVM(t, db, "ok", "node1")
	seedRestartPolicyVM(t, db, "st", "node1")
	f, _ := hungDomainFake(t, "ok", "st")
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	v.virt = f
	v.virtWait.wait = 200 * time.Millisecond

	passWithin(t, 5*time.Second, "the VM checker's sweep", func() { v.SweepOnce(context.Background()) })
	if got := rowState(t, db, "ok"); got != "running" {
		t.Errorf("ok (stopped row, domain running): %s, want running", got)
	}
	if got := rowState(t, db, "st"); got != "stopped" {
		t.Errorf("st (libvirt does not answer): %s, want stopped, untouched", got)
	}
	if got := restartAttempts(t, db, "st"); got != 0 {
		t.Errorf("st restart attempts: %d, want 0", got)
	}
	if n := f.MainConnCallsFor("st"); n != 1 {
		t.Errorf("calls naming st on the daemon's connection: %d, want only the start's own", n)
	}
}

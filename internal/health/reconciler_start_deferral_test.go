package health

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// deferredStartErr is what the Server's start preparation answers when Ceph
// did not answer, or there was no time left to ask it: Unavailable to a gRPC
// caller, ErrStartDeferred to the reconciler.
func deferredStartErr(vm string) error {
	return fmt.Errorf("%w: %w", ErrStartDeferred,
		status.Errorf(codes.Unavailable, "start %q: Ceph did not answer within 8s; the start is retried", vm))
}

// deferringPreparer defers the start of the named VMs the first `times`
// times each is prepared, then lets it start; it records the order VMs are
// prepared in.
type deferringPreparer struct {
	mu      sync.Mutex
	pending map[string]int
	order   []string
}

func (p *deferringPreparer) prepare(_ context.Context, vm *corrosion.VMRecord) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.order = append(p.order, vm.Name)
	if p.pending[vm.Name] > 0 {
		p.pending[vm.Name]--
		return func() {}, deferredStartErr(vm.Name)
	}
	return func() {}, nil
}

func (p *deferringPreparer) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.order...)
}

func requireState(t *testing.T, db *corrosion.Client, name, want string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	if vm.State != want {
		t.Fatalf("%s: state %q (%q), want %q", name, vm.State, vm.StateDetail, want)
	}
	return vm
}

// I-R3-1. A proof-less LOCAL recovery — a self-heal of a running row whose
// domain is gone, an onboot autostart, the re-drive of an interrupted start
// — whose Ceph probe is deferred (or Ceph did not answer) is NOT parked in
// error: it waits in "starting", which the reconciler re-drives, and starts
// on the next pass. Main would have started it; parked in error it stayed
// down until an operator acted.
func TestReconciler_DeferredCephStartIsRedriven(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		spec  string
		first func(r *Reconciler, ctx context.Context)
	}{
		{"self-heal", "running", `{"name":"vm1"}`, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }},
		{"starting re-drive", "starting", `{"name":"vm1"}`, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }},
		{"onboot", "stopped", `{"name":"vm1","onboot":true}`, func(r *Reconciler, ctx context.Context) { r.StartOnbootVMs(ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", State: tc.state, Spec: tc.spec}, nil, nil); err != nil {
				t.Fatal(err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			p := &deferringPreparer{pending: map[string]int{"vm1": 1}}
			r.SetHardwareStartPreparer(p.prepare)

			tc.first(r, ctx)
			if hwStarted(fake, "vm1") {
				t.Fatal("a deferred start started the domain")
			}
			vm := requireState(t, db, "vm1", "starting")
			if !strings.Contains(vm.StateDetail, "Ceph") {
				t.Errorf("state detail %q does not say why the start waits", vm.StateDetail)
			}

			r.reconcile(ctx)
			if !hwStarted(fake, "vm1") {
				t.Fatalf("the deferred start was not re-driven: calls %v", p.calls())
			}
			requireState(t, db, "vm1", "running")
		})
	}
}

// I-R3-1. A failover carrying a proof whose Ceph probe is deferred goes back
// to pending with its proof still in_progress, for the same executor to
// re-claim on the next pass — never terminalized.
func TestReconciler_DeferredCephFailoverKeepsItsProof(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-x", HostName: "host-b", State: "running", Spec: `{"name":"vm-x"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-x", DestHost: "host-a", Coordinator: "host-c"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm-x", "host-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("host-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	p := &deferringPreparer{pending: map[string]int{"vm-x": 1}}
	r.SetHardwareStartPreparer(p.prepare)

	r.reconcile(ctx)
	vm := requireState(t, db, "vm-x", "pending")
	if vm.PendingActionID != "p1" {
		t.Fatalf("marker %q, want p1 kept", vm.PendingActionID)
	}
	if pr, ok, _ := corrosion.GetActionProof(ctx, db, "p1"); !ok || pr.Status != corrosion.ProofInProgress {
		t.Fatalf("proof %+v, want in_progress", pr)
	}
	r.reconcile(ctx)
	if !hwStarted(fake, "vm-x") {
		t.Fatalf("the deferred failover never started: calls %v", p.calls())
	}
}

// I-R3-2. A VM whose start was deferred is walked FIRST on the next pass, so
// the same VMs cannot come last — and be deferred — on every pass. vm-a is
// ahead of vm-z in the walk's own order (by name and by insertion), and only
// needs a start from the second pass on.
func TestReconciler_DeferredStartsAreWalkedFirst(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-a", HostName: "node-a", State: "stopped", Spec: `{"name":"vm-a"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-z", HostName: "node-a", State: "running", Spec: `{"name":"vm-z"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	p := &deferringPreparer{pending: map[string]int{"vm-z": 1}}
	r.SetHardwareStartPreparer(p.prepare)
	r.reconcile(ctx)
	if got := p.calls(); strings.Join(got, ",") != "vm-z" {
		t.Fatalf("fixture: first pass prepared %v, want vm-z only", got)
	}
	requireState(t, db, "vm-z", "starting")
	// vm-a now needs a start too: a running row whose domain is gone.
	if err := corrosion.UpdateVMState(ctx, db, "vm-a", "running", "test"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	if got := p.calls()[1:]; strings.Join(got, ",") != "vm-z,vm-a" {
		t.Fatalf("second pass prepared %v, want the deferred vm-z first", got)
	}
}

// I-R3-2. The reconciler asks whether a VM's start would be deferred BEFORE
// it does anything for it: no lock, no claim of its proof, no define. The VM
// is left exactly as it was, and walked first on the next pass.
func TestReconciler_StartDeferralLeavesTheVMUntouched(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-x", HostName: "host-b", State: "running", Spec: `{"name":"vm-x"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-x", DestHost: "host-a", Coordinator: "host-c"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm-x", "host-a"); err != nil {
		t.Fatal(err)
	}
	before, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	fake := libvirtfake.New()
	r := NewReconciler("host-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	deferIt := true
	r.SetStartDeferral(func(_ context.Context, vm *corrosion.VMRecord) error {
		if deferIt {
			return deferredStartErr(vm.Name)
		}
		return nil
	})

	r.reconcile(ctx)
	if pr, _, _ := corrosion.GetActionProof(ctx, db, "p1"); pr.Status != before.Status {
		t.Fatalf("proof %q → %q: a deferred start claimed it", before.Status, pr.Status)
	}
	if startedOrDefined(fake, "vm-x") {
		t.Fatal("a deferred start defined the domain")
	}
	requireState(t, db, "vm-x", "pending")
	if !r.startDeferredHas("vm-x") {
		t.Fatal("the deferred VM is not remembered to walk first")
	}

	deferIt = false
	r.reconcile(ctx)
	if !hwStarted(fake, "vm-x") {
		t.Fatal("the VM never started once there was time")
	}
}

// I-R3-2 / I-R3-1. An onboot autostart deferred before any work (its row
// stays "stopped": only the onboot retry starts it) is retried FIRST on the
// next pass, not after every other VM.
func TestReconciler_DeferredOnbootRetryGoesFirst(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-z", HostName: "node-a", State: "stopped", Spec: `{"name":"vm-z","onboot":true}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	p := &deferringPreparer{pending: map[string]int{}}
	r.SetHardwareStartPreparer(p.prepare)
	deferZ := true
	r.SetStartDeferral(func(_ context.Context, vm *corrosion.VMRecord) error {
		if deferZ && vm.Name == "vm-z" {
			return deferredStartErr(vm.Name)
		}
		return nil
	})
	r.StartOnbootVMs(ctx)
	requireState(t, db, "vm-z", "stopped")
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-a", HostName: "node-a", State: "running", Spec: `{"name":"vm-a"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	deferZ = false
	r.reconcile(ctx)
	if got := p.calls(); len(got) < 2 || got[0] != "vm-z" {
		t.Fatalf("prepared %v, want the deferred onboot vm-z first", got)
	}
	if !hwStarted(fake, "vm-z") {
		t.Fatal("the deferred onboot VM never started")
	}
}

// startDeferredHas reports whether name is remembered to walk first.
func (r *Reconciler) startDeferredHas(name string) bool {
	r.startDeferred.mu.Lock()
	defer r.startDeferred.mu.Unlock()
	return r.startDeferred.m[name]
}

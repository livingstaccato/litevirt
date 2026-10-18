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

// kindPreparer defers each named VM once, with the given kind of deferral,
// and records the order VMs are prepared in.
type kindPreparer struct {
	mu    sync.Mutex
	once  map[string]error
	order []string
	turns []bool
}

func (p *kindPreparer) prepare(ctx context.Context, vm *corrosion.VMRecord) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.order = append(p.order, vm.Name)
	if err, ok := p.once[vm.Name]; ok {
		delete(p.once, vm.Name)
		return func() {}, err
	}
	return func() {}, nil
}

func kindErr(vm string, kind error) error {
	return fmt.Errorf("%w: %w", kind, status.Errorf(codes.Unavailable, "start %q: deferred", vm))
}

// I-R4-1, R-3. The next walk takes the VMs deferred for TIME first (they had
// no chance to ask their storage), then the rest, and only then those whose
// storage did not answer — a VM whose own probe failed last of all. A VM
// whose storage keeps failing therefore never spends the budget the VMs
// behind it need, however many keys are down: with two, a probe of one of
// them in every pass used to leave the rest of the walk about 2 s.
//
// Mutation "failed storage before the rest" (the R-5 ranks): red.
func TestReconciler_DeferredStartsAreOrderedByWhyTheyWaited(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	for _, n := range []string{"vm-a", "vm-f", "vm-s", "vm-t"} {
		state := "running"
		if n == "vm-a" {
			state = "stopped"
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: n, HostName: "node-a", State: state, Spec: `{"name":"` + n + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	p := &kindPreparer{once: map[string]error{
		"vm-f": kindErr("vm-f", ErrStartProbeFailed),
		"vm-s": kindErr("vm-s", ErrStartStorageDown),
		"vm-t": kindErr("vm-t", ErrStartDeferred),
	}}
	r.SetHardwareStartPreparer(p.prepare)
	r.reconcile(ctx)
	if got := strings.Join(p.order, ","); got != "vm-f,vm-s,vm-t" {
		t.Fatalf("fixture: first pass prepared %s", got)
	}
	if err := corrosion.UpdateVMState(ctx, db, "vm-a", "running", "test"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	if got := strings.Join(p.order[3:], ","); got != "vm-t,vm-a,vm-s,vm-f" {
		t.Fatalf("second pass prepared %s, want time-deferred, then the rest, then storage down, then own probe failed", got)
	}
}

// I-R4-1. Each pass's walk carries ONE probe turn: the first probe asked
// for in a pass is granted it, whatever time is left, and later ones are
// not. The next pass has a turn of its own. A call outside a walk has none.
func TestReconcilePass_GivesItsWalkOneProbeTurn(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	for _, n := range []string{"vm-a", "vm-b"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: n, HostName: "node-a", State: "running", Spec: `{"name":"` + n + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	var mu sync.Mutex
	var turns []string
	r.SetHardwareStartPreparer(func(ctx context.Context, vm *corrosion.VMRecord) (func(), error) {
		mu.Lock()
		defer mu.Unlock()
		turns = append(turns, fmt.Sprintf("%s:%v:%v", vm.Name, InReconcilerWalk(ctx), TakeWalkProbeTurn(ctx)))
		return func() {}, kindErr(vm.Name, ErrStartDeferred)
	})
	r.ReconcileOnce(ctx)
	r.ReconcileOnce(ctx)
	if got := strings.Join(turns, ","); got != "vm-a:true:true,vm-b:true:false,vm-a:true:true,vm-b:true:false" {
		t.Fatalf("turns %s, want one per pass, to the first that asks", got)
	}
	if InReconcilerWalk(ctx) || TakeWalkProbeTurn(ctx) {
		t.Fatal("a context outside a walk has a probe turn")
	}
}

// I-R4-1. An onboot autostart whose storage did not answer is retried after
// the walk, not before it: the VMs deferred for time — walked first — go
// ahead of it, as they do of any VM whose storage did not answer.
func TestReconciler_OnbootWhoseStorageFailedGoesAfterTimeDeferred(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-a", HostName: "node-a", State: "stopped", Spec: `{"name":"vm-a","onboot":true}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-z", HostName: "node-a", State: "running", Spec: `{"name":"vm-z"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	p := &kindPreparer{once: map[string]error{"vm-z": kindErr("vm-z", ErrStartDeferred)}}
	r.SetHardwareStartPreparer(p.prepare)
	failA := true
	r.SetStartDeferral(func(_ context.Context, vm *corrosion.VMRecord) error {
		if failA && vm.Name == "vm-a" {
			return kindErr(vm.Name, ErrStartProbeFailed)
		}
		return nil
	})
	r.StartOnbootVMs(ctx)
	r.reconcile(ctx)
	if got := strings.Join(p.order, ","); got != "vm-z" {
		t.Fatalf("fixture: first pass prepared %s, want vm-z (deferred for time)", got)
	}
	failA = false
	r.reconcile(ctx)
	if got := strings.Join(p.order[1:], ","); got != "vm-z,vm-a" {
		t.Fatalf("second pass prepared %s, want the time-deferred vm-z before the onboot vm-a whose storage failed", got)
	}
}

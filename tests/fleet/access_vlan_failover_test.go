package fleet

// A VM with an access-port NIC (trunk: with one VLAN) can start only on a host
// whose bridge for it filters VLANs. Each host names its bridges that do not
// (bridge_vlan_filtering_off), and failover recovers the VM onto a host whose
// bridge is not named while one qualifies. With none left, it is placed on a
// named host anyway, and that host's start preflight refuses it there.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
)

const accVLANVM = "vlanvm"

// accVLANBridge is one node's bridge for accVLANVM's NIC: whether it exists
// there (absent: litevirt would create it, without VLAN filtering), and
// whether it filters VLANs.
type accVLANBridge struct {
	mu     sync.Mutex
	absent bool
	on     bool
}

func (b *accVLANBridge) read(bridge string) (isBridge, on bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.absent && bridge == network.FlatBridgeName("accnet"), b.on, nil
}

func (b *accVLANBridge) exists(bridge string) bool {
	isBridge, _, _ := b.read(bridge)
	return isBridge
}

func (b *accVLANBridge) set(on bool) {
	b.mu.Lock()
	b.absent, b.on = false, on
	b.mu.Unlock()
}

// wire makes b node n's bridge.
func (b *accVLANBridge) wire(n *Node) {
	n.Server.SetBridgeVLANFiltering(b.read)
	n.Server.SetBridgeExists(b.exists)
}

// accVLANFleet seeds a three-node fleet in which the victim runs accVLANVM,
// whose one NIC is an access port on VLAN 30 of network accnet, on shared
// storage; filteringA and filteringB say whether survivor a's and b's bridges
// filter VLANs. Every node judges its bridges once before the victim is
// isolated.
func accVLANFleet(t *testing.T, clock *VirtualClock, filteringA, filteringB bool) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	return accVLANFleetWith(t, clock, &accVLANBridge{on: filteringA}, &accVLANBridge{on: filteringB})
}

// accVLANFleetWith is accVLANFleet with survivor a's and b's bridges given.
func accVLANFleetWith(t *testing.T, clock *VirtualClock, brA, brB *accVLANBridge) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	ctx := context.Background()
	disk := filepath.Join(t.TempDir(), accVLANVM+"-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		for n, br := range map[*Node]*accVLANBridge{a: brA, b: brB, victim: {on: true}} {
			br.wire(n)
		}
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: accVLANVM, HostName: victim.Name, State: "running",
			CPUActual: 1, MemActual: 256,
			Spec: vmSpecJSON(t, &pb.VMSpec{Name: accVLANVM, Cpu: 1, MemoryMib: 256,
				Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:ac:00:01", Trunk: []int32{30}}}})},
			nil, []corrosion.DiskRecord{{VMName: accVLANVM, DiskName: "root", HostName: victim.Name, Path: disk, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		for _, n := range []*Node{a, b, victim} {
			n.Server.ReconcileAccessVLANBridges(ctx)
		}
	})
}

// accVLANStart runs n's reconciler once, wired as the daemon wires it.
func accVLANStart(t *testing.T, ctx context.Context, n *Node) {
	t.Helper()
	rec := n.Reconciler()
	rec.SetHardwareStartPreparer(n.Server.PrepareHardwareForStart)
	rec.ReconcileOnce(ctx)
}

// The survivor that placement prefers (a: equal hosts, the first by name)
// has a bridge that does not filter VLANs, and says so; b's does. The VM is
// recovered onto b and starts there.
//
// Mutation: drop vlanView.avoid from the failover placement — red (the VM is
// recovered onto a, and its start there is refused).
func TestFleet_AccessVLANFailoverPassesOverAHostWhoseBridgeDoesNotFilter(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := accVLANFleet(t, clock, false, true)

	subject := health.AccessVLANSubject(network.FlatBridgeName("accnet"), a.Name)
	cond, ok, err := corrosion.GetHealthCondition(ctx, b.DB, health.AccessVLANEvaluator, health.CondBridgeVLANFilteringOff, "host", subject)
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, accVLANVM) {
		t.Fatalf("%s does not see %s's bridge named: %+v (found %v, %v)", b.Name, a.Name, cond, ok, err)
	}
	if _, ok, _ := corrosion.GetHealthCondition(ctx, a.DB, health.AccessVLANEvaluator, health.CondBridgeVLANFilteringOff,
		"host", health.AccessVLANSubject(network.FlatBridgeName("accnet"), b.Name)); ok {
		t.Fatalf("%s's bridge, which filters VLANs, is named", b.Name)
	}

	pciFoFailOver(t, ctx, c, clock, a, b)
	if vm := vmOn(t, a, accVLANVM); vm == nil || vm.HostName != b.Name {
		t.Fatalf("%s on %+v; want it recovered onto %s, whose bridge filters VLANs", accVLANVM, vm, b.Name)
	}
	accVLANStart(t, ctx, b)
	if vm := vmOn(t, b, accVLANVM); vm == nil || vm.State != "running" {
		t.Fatalf("%s did not start on %s: %+v", accVLANVM, b.Name, vm)
	}
	if st, _ := b.Virt.DomainState(accVLANVM); st != "running" {
		t.Fatalf("%s's domain on %s is %q, want running", accVLANVM, b.Name, st)
	}
}

// Neither survivor's bridge filters VLANs: the VM is still placed on one, and
// that host refuses its start, naming the bridge, and its domain is not
// running. The VM is not parked in error: it waits there, re-tried every
// pass, and once the bridge filters VLANs it starts by itself, its access
// VLAN on its tap before it runs (NB-3: "waits for the fix").
//
// Mutations: drop accessVLANStartPreflight from PrepareHardwareForStart — red
// (the VM starts on the unfiltered bridge); return the refusal as a plain
// FailedPrecondition, not a deferral — red (the VM is in error and never
// starts after the fix).
func TestFleet_AccessVLANFailoverWithNoFilteringHostWaitsForTheFix(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	brA, brB := &accVLANBridge{}, &accVLANBridge{}
	c, a, b, victim := accVLANFleetWith(t, clock, brA, brB)

	pciFoFailOver(t, ctx, c, clock, a, b)
	vm := vmOn(t, a, accVLANVM)
	if vm == nil || vm.HostName == victim.Name {
		t.Fatalf("%s on %+v; want it placed on a survivor, whose start then refuses it", accVLANVM, vm)
	}
	target, br := a, brA
	if vm.HostName == b.Name {
		target, br = b, brB
	}
	accVLANStart(t, ctx, target)
	if st, _ := target.Virt.DomainState(accVLANVM); st == "running" {
		t.Fatalf("%s started on %s, whose bridge does not filter VLANs", accVLANVM, target.Name)
	}
	got := vmOn(t, target, accVLANVM)
	if got == nil || (got.State != "pending" && got.State != "starting") || !strings.Contains(got.StateDetail, "does not filter VLANs") {
		t.Fatalf("%s on %s after the refused start: %+v; want it waiting (pending or starting), naming the bridge", accVLANVM, target.Name, got)
	}
	accVLANStart(t, ctx, target)
	if got := vmOn(t, target, accVLANVM); got == nil || got.State == "error" || got.State == "running" {
		t.Fatalf("%s on %s after a second pass with the bridge unchanged: %+v; want it still waiting", accVLANVM, target.Name, got)
	}

	br.set(true)
	accVLANStart(t, ctx, target)
	if got := vmOn(t, target, accVLANVM); got == nil || got.State != "running" {
		t.Fatalf("%s on %s once its bridge filters VLANs: %+v; want it started by the next pass", accVLANVM, target.Name, got)
	}
	assertVLANBeforeRun(t, target, accVLANVM, "vlan=30")
}

// assertVLANBeforeRun fails unless vm came to n paused (a start, or a
// migration's arrival), had the VLAN (a vlan-tap note containing want) put on
// its tap, and only then was resumed.
func assertVLANBeforeRun(t *testing.T, n *Node, vm, want string) {
	t.Helper()
	var ops []string
	for _, e := range n.Virt.EventLog() {
		if e.Domain == vm {
			ops = append(ops, e.Op+" "+e.Note)
		}
	}
	at := func(prefix string) int {
		for i := len(ops) - 1; i >= 0; i-- { // the last run
			if strings.HasPrefix(ops[i], prefix) {
				return i
			}
		}
		return -1
	}
	// The guest comes to be here by a start, or by a migration's arrival.
	start, resume := at("start"), at("resume")
	if in := at("migrate-in"); in > start {
		start = in
	}
	tap := -1
	for i := start + 1; start >= 0 && i < len(ops); i++ {
		if strings.HasPrefix(ops[i], "vlan-tap") && strings.Contains(ops[i], want) {
			tap = i
			break
		}
	}
	if start < 0 || tap < 0 || resume < tap {
		t.Fatalf("%s on %s: ops %q; want a paused start, its VLAN (%s) on its tap, then the resume", vm, n.Name, ops, want)
	}
	if st, _ := n.Virt.DomainState(vm); st != "running" {
		t.Fatalf("%s on %s is %q, want running", vm, n.Name, st)
	}
}

// A failover start — the reconciler's, not `lv start` — puts the access VLAN
// on the tap before the guest runs (B-1: before, it booted on VLAN 1 and
// stayed there until someone restarted it).
//
// Mutation: NICStartGuard not pausing for tap VLANs — red.
func TestFleet_AccessVLANFailoverStartPutsTheVLANOnBeforeTheGuestRuns(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := accVLANFleet(t, clock, false, true)
	pciFoFailOver(t, ctx, c, clock, a, b)
	accVLANStart(t, ctx, b)
	assertVLANBeforeRun(t, b, accVLANVM, "bridge="+network.FlatBridgeName("accnet")+" mac=52:54:00:ac:00:01 vlan=30")
}

// A survivor that has no bridge for the VM's network is passed over too
// (NB-2): a start there would have litevirt create the bridge, without VLAN
// filtering, and be refused. a (preferred, first by name) has none; b's
// filters. The VM is recovered onto b and starts there.
//
// Mutation: do not name an absent bridge in ReconcileAccessVLANBridges — red
// (the VM is recovered onto a).
func TestFleet_AccessVLANFailoverPassesOverAHostWithoutTheBridge(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := accVLANFleetWith(t, clock, &accVLANBridge{absent: true}, &accVLANBridge{on: true})
	pciFoFailOver(t, ctx, c, clock, a, b)
	if vm := vmOn(t, a, accVLANVM); vm == nil || vm.HostName != b.Name {
		t.Fatalf("%s on %+v; want it recovered onto %s, not %s, which has no bridge for it", accVLANVM, vm, b.Name, a.Name)
	}
	accVLANStart(t, ctx, b)
	assertVLANBeforeRun(t, b, accVLANVM, "vlan=30")
}

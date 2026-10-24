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

// accVLANBridge is one node's bridge for accVLANVM's NIC, as far as its VLAN
// filtering goes.
type accVLANBridge struct {
	mu sync.Mutex
	on bool
}

func (b *accVLANBridge) read(bridge string) (isBridge, on bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bridge == network.FlatBridgeName("accnet"), b.on, nil
}

// accVLANFleet seeds a three-node fleet in which the victim runs accVLANVM,
// whose one NIC is an access port on VLAN 30 of network accnet, on shared
// storage; filteringA and filteringB say whether survivor a's and b's bridges
// filter VLANs. Every node judges its bridges once before the victim is
// isolated.
func accVLANFleet(t *testing.T, clock *VirtualClock, filteringA, filteringB bool) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	ctx := context.Background()
	disk := filepath.Join(t.TempDir(), accVLANVM+"-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		for n, on := range map[*Node]bool{a: filteringA, b: filteringB, victim: true} {
			n.Server.SetBridgeVLANFiltering((&accVLANBridge{on: on}).read)
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
// running.
//
// Mutation: drop accessVLANStartPreflight from PrepareHardwareForStart — red
// (the VM starts on the unfiltered bridge).
func TestFleet_AccessVLANFailoverWithNoFilteringHostIsRefusedAtStart(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := accVLANFleet(t, clock, false, false)

	pciFoFailOver(t, ctx, c, clock, a, b)
	vm := vmOn(t, a, accVLANVM)
	if vm == nil || vm.HostName == victim.Name {
		t.Fatalf("%s on %+v; want it placed on a survivor, whose start then refuses it", accVLANVM, vm)
	}
	target := a
	if vm.HostName == b.Name {
		target = b
	}
	accVLANStart(t, ctx, target)
	if st, _ := target.Virt.DomainState(accVLANVM); st == "running" {
		t.Fatalf("%s started on %s, whose bridge does not filter VLANs", accVLANVM, target.Name)
	}
	got := vmOn(t, target, accVLANVM)
	if got == nil || got.State != "error" || !strings.Contains(got.StateDetail, "does not filter VLANs") {
		t.Fatalf("%s on %s after the refused start: %+v; want error naming the bridge", accVLANVM, target.Name, got)
	}
}

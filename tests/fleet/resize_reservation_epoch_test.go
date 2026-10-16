package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A live memory grow frees its host reservation when it completes, so the
// next grow on a host with little free memory is admitted.
//
// The VM is made by the real create path, so it holds owner epoch 1, as
// every VM does since creates assign one. Each grow enters on a node that
// does not own the VM and is forwarded to the owner. The owner's free memory
// fits both grows only if the first grow's reservation ended with it: a
// reservation that outlives its operation refuses the second grow, and it
// replicates, so every replica counts it against the owner.
//
// Mutations (each red): write the resize's operation header at epoch 0
// (admitResizeReservation), and the second grow is refused.
func TestFleet_LiveMemoryGrowTwiceOnATightHost(t *testing.T) {
	ctx := context.Background()
	c, gates := latchedFleet(t, 3, 1015)
	owner, entry := c.Nodes[0], c.Nodes[1]

	// Memory hot-add is a release feature: latch the release token first,
	// through an unrelated feature, as the HA monitor does in production.
	info, _ := capabilities.LookupFeature(capabilities.FeatureUSBMountsMemory)
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		capabilities.FeatureUSBMountsMemory: info,
		"widgets":                           {Token: capabilities.ReleaseToken, Description: "Widgets"},
	}))
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, n.Name+" to latch the release token", func() bool {
			return writeFeature(ctx, n, "widgets") == nil
		})
	}
	// A resize reserves capacity only on the coordinated path.
	latchOperationProtocol(t, c, gates)
	seedImageOn(t, owner)

	// 3456 MiB: after the default 1024 MiB reserve and the VM's 1024 MiB plus
	// 128 MiB overhead, 1280 MiB is free. Two +512 MiB grows fit; with the
	// first grow's 512 MiB still reserved, the second does not.
	setHostCapacity(t, c, owner.Name, 8, 3456)
	for _, n := range c.Nodes[1:] {
		setHostCapacity(t, c, n.Name, 32, 65536)
	}
	c.WaitConverged(t, convergeTimeout)

	spec := &pb.VMSpec{Name: "grow", Image: "test", Cpu: 1, MemoryMib: 1024, MemoryHotplugMaxMib: 2048,
		Disks:     []*pb.DiskSpec{{Name: "root"}},
		Placement: &pb.PlacementSpec{Host: owner.Name}}
	var last error
	seen := ""
	eventually(t, 30*time.Second, "the hot-add create to be accepted", func() bool {
		_, last = c.SelfClient(owner).CreateVM(ctx, &pb.CreateVMRequest{Spec: proto.Clone(spec).(*pb.VMSpec)})
		if last != nil && strings.Contains(last.Error(), "already exists") {
			return true
		}
		if last != nil && last.Error() != seen {
			seen = last.Error()
			t.Logf("create: %v", last)
		}
		return last == nil
	})
	eventually(t, 30*time.Second, "grow to run on "+owner.Name, func() bool {
		vm := vmOn(t, owner, "grow")
		return vm != nil && vm.State == "running" && vm.ActiveOperationID == ""
	})
	if vm := vmOn(t, owner, "grow"); vm.OwnerEpoch < 1 {
		t.Fatalf("a created VM is at owner epoch %d, want at least 1", vm.OwnerEpoch)
	}
	c.WaitConverged(t, convergeTimeout)
	if _, free, ok, err := corrosion.HostFreeCapacity(ctx, owner.DB, owner.Name); err != nil || !ok || free < 1024 || free >= 1536 {
		t.Fatalf("free memory on %s before the grows = %d (ok=%v err=%v), want 1024 <= free < 1536 — the sizing no longer tells a leak apart",
			owner.Name, free, ok, err)
	}

	for _, target := range []int32{1536, 2048} {
		if _, err := c.SelfClient(entry).SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "grow", TargetMib: target}); err != nil {
			t.Fatalf("grow to %d MiB through %s: %v", target, entry.Name, err)
		}
		if vm := vmOn(t, owner, "grow"); vm.ActiveOperationID != "" {
			t.Fatalf("the grow to %d MiB left the barrier held by %q", target, vm.ActiveOperationID)
		}
	}

	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		cpu, mem, err := corrosion.HostReserved(ctx, n.DB, owner.Name)
		if err != nil {
			t.Fatalf("HostReserved on %s: %v", n.Name, err)
		}
		if cpu != 0 || mem != 0 {
			t.Errorf("%s still counts %d vCPU/%d MiB reserved on %s after both grows completed, want 0/0",
				n.Name, cpu, mem, owner.Name)
		}
	}
}

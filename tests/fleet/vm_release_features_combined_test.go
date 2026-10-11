// Integration checklist M9: vm_limits (cpu), vm_disk_nic_io (io) and
// usb_mounts_memory (passthrough) are written at the same call sites (createVM,
// the UpdateVM spec write, a restore's auto-define, a clone). A spec carrying
// several of them takes EVERY grant it needs, each through its own gate, and is
// written by one writer that checks them all
// (corrosion.InsertVMWithReleaseFeatures / MutateDesiredSpecWithReleaseFeatures).
package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// rowOnEveryReplica waits for vm's row on every node. A created VM runs, so
// its row keeps changing and a whole-table convergence wait is the wrong one.
func rowOnEveryReplica(t *testing.T, c *Cluster, vm string) {
	t.Helper()
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, vm+" on "+n.Name, func() bool {
			rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
			return err == nil && rec != nil
		})
	}
}

var vmSpecFeatures = []capabilities.Feature{
	capabilities.FeatureVMLimits, capabilities.FeatureVMDiskNICIO, capabilities.FeatureUSBMountsMemory,
}

// combinedFleet is a latched three-node fleet whose release token has latched
// through an unrelated feature (as the HA monitor drives it in production), so
// none of the three VM-spec features is recorded used yet.
func combinedFleet(t *testing.T, seed int64) *Cluster {
	t.Helper()
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, seed)
	set := map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "Widgets"},
	}
	for _, f := range vmSpecFeatures {
		info, _ := capabilities.LookupFeature(f)
		set[f] = info
	}
	t.Cleanup(capabilities.OverrideFeaturesForTest(set))
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, n.Name+" to latch the release token", func() bool {
			return writeFeature(ctx, n, "widgets") == nil
		})
		for _, f := range vmSpecFeatures {
			if featureUsedOn(t, n, capabilities.ReleaseToken, string(f)) {
				t.Fatalf("%s holds a use of %s before any write of it", n.Name, f)
			}
		}
	}
	return c
}

// watchRecordedBeforeData fails the test if any replica holds a row of vm whose
// spec contains marker while it lacks the used record of one of features.
func watchRecordedBeforeData(t *testing.T, c *Cluster, vm, marker string, features []capabilities.Feature) (stop func()) {
	t.Helper()
	ctx := context.Background()
	var violation atomic.Value
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-quit:
				return
			default:
			}
			for _, n := range c.Nodes {
				rec, err := corrosion.GetVM(ctx, n.DB, vm)
				if err != nil || rec == nil || !strings.Contains(rec.Spec, marker) {
					continue
				}
				for _, f := range features {
					if used, uerr := corrosion.ReleaseFeatureUsed(ctx, n.DB, capabilities.ReleaseToken, string(f)); uerr == nil && !used {
						violation.Store(n.Name + " / " + string(f))
					}
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	return func() {
		close(quit)
		<-done
		if v := violation.Load(); v != nil {
			t.Fatalf("%s: a replica saw %s's data before it held that feature's used record", v, vm)
		}
	}
}

func seedImageOn(t *testing.T, n *Node) {
	t.Helper()
	// Through the registered writer: a raw statement is an unknown replicated
	// shape, which back-pressures the replication stream on a multi-node fleet.
	if err := corrosion.InsertImage(context.Background(), n.DB, corrosion.ImageRecord{
		Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	// A real (empty) qcow2: a named root disk is an overlay on it.
	if err := os.MkdirAll(filepath.Dir(n.Server.ImagePathForTests("test")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(n.Server.ImagePathForTests("test"), 64<<20, nil); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
}

// A create whose spec carries CPU limits, disk tuning and memory hot-add
// records all three features, and no replica sees the VM before it holds all
// three records. A create carrying only a limit records only vm_limits.
//
// Mutations (each red): drop any one grant from the create's vmSpecGrants
// (internal/grpcapi/vm.go) — the combined writer refuses the create; drop one
// needs check from corrosion.InsertVMWithReleaseFeatures together with that
// grant — the create succeeds without that feature's gate and the record check
// goes red.
func TestFleet_M9_ACreateCarryingThreeFeaturesTakesEveryGrant(t *testing.T) {
	c := combinedFleet(t, 9301)
	ctx := context.Background()
	owner := c.Nodes[0]
	seedImageOn(t, owner)

	stop := watchRecordedBeforeData(t, c, "combo", "cpu_limit", vmSpecFeatures)
	spec := &pb.VMSpec{Name: "combo", Image: "test", Cpu: 2, MemoryMib: 1024,
		CpuLimit: 1, MemoryHotplugMaxMib: 2048,
		Disks:     []*pb.DiskSpec{{Name: "root", Discard: "unmap"}},
		Placement: &pb.PlacementSpec{Host: owner.Name}}
	var last error
	seen := ""
	eventually(t, 30*time.Second, "the combined create to be accepted", func() bool {
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
	rowOnEveryReplica(t, c, "combo")
	stop()
	for _, n := range c.Nodes {
		for _, f := range vmSpecFeatures {
			if !featureUsedOn(t, n, capabilities.ReleaseToken, string(f)) {
				t.Errorf("%s does not hold the %s use record after the combined create", n.Name, f)
			}
		}
		sp := specIOOn(t, n, "combo")
		if sp == nil || sp.CpuLimit != 1 || sp.MemoryHotplugMaxMib != 2048 || len(sp.Disks) == 0 || sp.Disks[0].Discard != "unmap" {
			t.Errorf("%s: stored spec = %+v, want the limit, the hot-add ceiling and the discard", n.Name, sp)
		}
	}
}

func TestFleet_M9_ACreateCarryingOneFeatureTakesOnlyItsGrant(t *testing.T) {
	c := combinedFleet(t, 9302)
	ctx := context.Background()
	owner := c.Nodes[0]
	seedImageOn(t, owner)

	spec := &pb.VMSpec{Name: "solo", Image: "test", Cpu: 2, MemoryMib: 1024, CpuLimit: 1,
		Placement: &pb.PlacementSpec{Host: owner.Name}}
	var last error
	seen := ""
	eventually(t, 30*time.Second, "the limit-only create to be accepted", func() bool {
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
	rowOnEveryReplica(t, c, "solo")
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureVMLimits)) {
			t.Errorf("%s does not hold the vm_limits use record", n.Name)
		}
		for _, f := range []capabilities.Feature{capabilities.FeatureVMDiskNICIO, capabilities.FeatureUSBMountsMemory} {
			if featureUsedOn(t, n, capabilities.ReleaseToken, string(f)) {
				t.Errorf("%s holds a use of %s after a create that carried only a limit", n.Name, f)
			}
		}
	}
}

// An UpdateVM that adds a limit, disk tuning and memory hot-add to a stopped
// VM in one request records all three before the spec carrying them is
// written anywhere.
//
// Mutation (red): drop the vm_limits grant (limitsG) from the UpdateVM spec
// write's MutateDesiredSpecWithReleaseFeatures call — the update is refused.
func TestFleet_M9_AnUpdateCarryingThreeFeaturesTakesEveryGrant(t *testing.T) {
	c := combinedFleet(t, 9303)
	ctx := context.Background()
	owner, entry := c.Nodes[0], c.Nodes[1]
	seedStoppedVM(t, c, owner)

	stop := watchRecordedBeforeData(t, c, "hv", "cpu_limit", vmSpecFeatures)
	req := &pb.UpdateVMRequest{Name: "hv", Cpu: 2, CpuLimit: proto.Float64(1),
		MemoryHotplugMaxMib: proto.Int32(4096),
		DiskTuning:          []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}
	var last error
	eventually(t, 30*time.Second, "the combined update to be accepted", func() bool {
		_, last = c.SelfClient(entry).UpdateVM(ctx, req)
		return last == nil
	})
	c.WaitConverged(t, convergeTimeout)
	stop()
	for _, n := range c.Nodes {
		for _, f := range vmSpecFeatures {
			if !featureUsedOn(t, n, capabilities.ReleaseToken, string(f)) {
				t.Errorf("%s does not hold the %s use record after the combined update", n.Name, f)
			}
		}
		sp := specIOOn(t, n, "hv")
		if sp == nil || sp.CpuLimit != 1 || sp.MemoryHotplugMaxMib != 4096 || len(sp.Disks) == 0 || sp.Disks[0].Discard != "unmap" {
			t.Errorf("%s: stored spec = %+v, want the limit, the hot-add ceiling and the discard", n.Name, sp)
		}
	}
}

// A clone, once the release token has latched, takes the grant of every
// feature its source's spec carries (limits, disk/NIC tuning, memory hot-add)
// and records each: the clone writes that data again under a new name.
//
// Mutation (red): delete the clone's ioGrant (or passthroughGrant) block in
// CloneVM — the clone is written without that feature's record.
func TestFleet_M9_ACloneOfAThreeFeatureVMTakesEveryGrant(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, src := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, src.Name, 64, 65536)
	src.Server.SetBridgeEnsure(src.Net.EnsureBridge)
	latchRelease(t, c)
	spec := tunedSpec("tpl")
	spec.CpuLimit = 1
	spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib = 1024, 512 // a hot-add VM records its boot cell
	seedCloneSourceSpec(t, c, src, spec)
	for _, f := range vmSpecFeatures {
		if featureUsedOn(t, src, capabilities.ReleaseToken, string(f)) {
			t.Fatalf("%s is recorded before the clone", f)
		}
	}
	var last error
	eventually(t, 30*time.Second, "the clone to be accepted", func() bool {
		_, last = cloneAt(t, c, entry, "tpl", "kid")
		return last == nil || strings.Contains(last.Error(), "already exists")
	})
	for _, f := range vmSpecFeatures {
		if !featureUsedOn(t, src, capabilities.ReleaseToken, string(f)) {
			t.Errorf("the clone carrying %s did not record it", f)
		}
	}
	if sp := specIOOn(t, src, "kid"); sp == nil || sp.CpuLimit != 1 || sp.MemoryHotplugMaxMib != 1024 || sp.Disks[0].Discard != "unmap" {
		t.Errorf("clone spec = %+v, want the source's limit, hot-add ceiling and discard", sp)
	}
}

package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func specIOOn(t *testing.T, n *Node, vm string) *pb.VMSpec {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || rec == nil {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatalf("parse spec on %s: %v", n.Name, err)
	}
	return spec
}

// The disk/NIC tuning writes go through the shared release token's feature
// gate. While one host is still on the previous build the token cannot latch
// and every way of writing tuning is refused with the release gate's text, and
// nothing is recorded or stored. Once the fleet is uniform the first write
// records the feature's use, every replica holds the record, and only then does
// the tuning land in the spec: a peer never sees tuning without the record.
//
// Mutations: drop the grant acquisition in SetDiskIO (and the writer's check) —
// the refusal stage goes red; skip the owner's grant (entry's gate alone) — the
// recorded-by-the-writer check goes red.
func TestFleet_DiskNICIOReleaseToken_RefusedThenRecordedBeforeData(t *testing.T) {
	c, _ := latchedFleet(t, 3, 4417)
	ctx := context.Background()
	owner, entry, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedTunableVM(t, c, owner)

	// 1. One host on the previous build: refused, nothing recorded, nothing stored.
	old.Server.SetWALQuarantined(func() bool { return true })
	want := "the cluster upgrade must finish first (vm_disk_nic_io needs " + capabilities.ReleaseToken + ")"
	_, err := c.SelfClient(entry).SetDiskIO(ctx, &pb.SetDiskIORequest{
		VmName: "far", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 250}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("SetDiskIO with %s on the old build: %v, want FailedPrecondition %q", old.Name, err, want)
	}
	_, err = c.SelfClient(entry).UpdateVM(ctx, &pb.UpdateVMRequest{Name: "far",
		DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("UpdateVM tuning with %s on the old build: %v, want FailedPrecondition %q", old.Name, err, want)
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureVMDiskNICIO)) {
			t.Fatalf("%s holds a use of vm_disk_nic_io after only refusals", n.Name)
		}
		if sp := specIOOn(t, n, "far"); sp == nil || sp.Disks[0].Io != nil || sp.Disks[0].Discard != "" {
			t.Fatalf("%s: a refused write stored tuning: %+v", n.Name, sp)
		}
	}

	// 2. Uniform fleet: the write goes through. A peer that can see the tuning
	// must already hold the use record. First the latch is driven on every node
	// by an unrelated feature, as the HA monitor does in production, so the
	// entry node's check is the cheap local hint and only the node that WRITES
	// (the owner) records the use.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	info, _ := capabilities.LookupFeature(capabilities.FeatureVMDiskNICIO)
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		capabilities.FeatureVMDiskNICIO: info,
		"widgets":                       {Token: capabilities.ReleaseToken, Description: "Widgets"},
	}))
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, n.Name+" to latch the release token", func() bool {
			return writeFeature(ctx, n, "widgets") == nil
		})
	}
	if featureUsedOn(t, owner, capabilities.ReleaseToken, string(capabilities.FeatureVMDiskNICIO)) {
		t.Fatal("vm_disk_nic_io was recorded before any write of it")
	}
	var violation atomic.Value
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, n := range c.Nodes {
				sp, perr := corrosion.GetVM(ctx, n.DB, "far")
				if perr != nil || sp == nil || !strings.Contains(sp.Spec, "total_iops_sec") {
					continue
				}
				if used, uerr := corrosion.ReleaseFeatureUsed(ctx, n.DB, capabilities.ReleaseToken, string(capabilities.FeatureVMDiskNICIO)); uerr == nil && !used {
					violation.Store(n.Name)
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	var last error
	eventually(t, 20*time.Second, "SetDiskIO to be accepted on a uniform fleet", func() bool {
		_, last = c.SelfClient(entry).SetDiskIO(ctx, &pb.SetDiskIORequest{
			VmName: "far", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 250}})
		return last == nil
	})
	c.WaitConverged(t, convergeTimeout)
	close(stop)
	<-done
	if v := violation.Load(); v != nil {
		t.Fatalf("%s saw disk tuning in a spec before it held the use record", v)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureVMDiskNICIO)) {
			t.Errorf("%s does not hold the vm_disk_nic_io use record", n.Name)
		}
		// The request entered on `entry` but the owner wrote the spec, so the
		// owner's gate ran: its own record is the latest one.
		uses, _ := corrosion.ListReleaseFeatureUses(ctx, n.DB)
		for _, u := range uses {
			if u.Feature == string(capabilities.FeatureVMDiskNICIO) && u.RecordedBy != owner.Name {
				t.Errorf("%s: the use was last recorded by %s, want the writing node %s", n.Name, u.RecordedBy, owner.Name)
			}
		}
		if sp := specIOOn(t, n, "far"); sp == nil || sp.Disks[0].Io.GetTotalIopsSec() != 250 {
			t.Errorf("%s: spec after the write = %+v, want total_iops_sec 250", n.Name, sp)
		}
	}
}

// N1: the entry check keeps the release UX and drives the latch, but records
// nothing. With one host on the previous build the refusal names that host and
// ends with the `lv cluster upgrade-status` pointer; once every host is on the
// release the SAME call succeeds with the HA monitor idle (the check drove the
// latch), and no host holds a use of the feature afterwards.
//
// Mutations: make ioFeatureGate return a fixed text — the host-naming check goes
// red; make it read the local hint only — the latch-driven success goes red; run
// the real gate (WithReleaseFeature) in it — the no-record check goes red.
func TestFleet_DiskNICIOEntryCheck_NamesHostsDrivesTheLatchRecordsNothing(t *testing.T) {
	c, _ := latchedFleet(t, 3, 4418)
	ctx := context.Background()
	entry, old := c.Nodes[1], c.Nodes[2]
	f := capabilities.FeatureVMDiskNICIO
	// A request for a VM that does not exist: it passes (or fails) the entry check
	// and then stops at NotFound, so any record would come from the check itself.
	probe := func() error {
		_, err := c.SelfClient(entry).SetDiskIO(ctx, &pb.SetDiskIORequest{
			VmName: "ghost", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
		return err
	}

	old.Server.SetWALQuarantined(func() bool { return true })
	err := probe()
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (vm_disk_nic_io needs "+capabilities.ReleaseToken+")") ||
		!strings.Contains(err.Error(), old.Name) || !strings.Contains(err.Error(), "lv cluster upgrade-status") {
		t.Fatalf("refusal with %s on the old build = %v, want the release text naming %s and the upgrade-status pointer", old.Name, err, old.Name)
	}

	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	eventually(t, 20*time.Second, "the entry check to latch the token and pass", func() bool {
		return status.Code(probe()) == codes.NotFound
	})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(f)) {
			t.Errorf("%s holds a use of vm_disk_nic_io after only entry checks", n.Name)
		}
	}
}

// N3: a plain create must never perform the feature's first use. The release
// token is latched everywhere (driven by an unrelated feature) but vm_disk_nic_io
// is not recorded used: a compose deploy of an untuned VM stores no discard and
// leaves no use record.
//
// Mutation: have CreateVM take s.ioGrant instead of s.ioGrantIfUsed for the
// default — the use record and the stored discard appear, red.
func TestFleet_DiskNICIOPlainCreateNeverPerformsTheFirstUse(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	if !gates[node.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
		t.Fatal("failover_scope_v1 did not latch")
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureVMDiskNICIO)
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		capabilities.FeatureVMDiskNICIO: info,
		"widgets":                       {Token: capabilities.ReleaseToken, Description: "Widgets"},
	}))
	eventually(t, 20*time.Second, "the release token to latch", func() bool { return writeFeature(ctx, node, "widgets") == nil })
	if _, err := client.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	deployClean(t, ctx, client, composeNoTuning)
	waitRunning(t, ctx, node, "db")
	if featureUsedOn(t, node, capabilities.ReleaseToken, string(capabilities.FeatureVMDiskNICIO)) {
		t.Fatal("a plain create recorded the first use of vm_disk_nic_io")
	}
	for _, d := range storedSpec(t, ctx, node, "db").Disks {
		if d.Discard != "" {
			t.Errorf("a plain create before the feature's first use stored discard %q", d.Discard)
		}
	}
}

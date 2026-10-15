package fleet

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// guardHotplugCluster is a two-node cluster with NIC guards, the daemon's
// firewall on every node, operation_protocol_v1 and hardware_v2 latched, and a
// running VM "web" on node 0 with one guarded NIC on lan.
//
// The source's fake lands a migrated domain on the target's, running.
func guardHotplugCluster(t *testing.T) (*Cluster, *Node, *Node, map[string]*health.Checker) {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		wireNodeFirewall(t, n)
	}
	latchOperationProtocol(t, c, gates)
	src, dst := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(src).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: src.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Ip: "10.30.0.41", Mac: "52:54:00:78:00:01"}},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	latchHardwareV2(t, c, gates)
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		x, err := src.Virt.DumpXML(name)
		if err != nil {
			return err
		}
		if err := dst.Virt.DefineDomain(x); err != nil {
			return err
		}
		dst.Virt.SetState(name, libvirtfake.StateRunning)
		return nil
	}
	return c, src, dst, gates
}

// refreshGuardQuorum beats every node's checker and reseeds its peers, as
// failback_test's refreshQuorum does: nothing beats in the fleet, and a
// migration is gated on quorum.
func refreshGuardQuorum(c *Cluster, gates map[string]*health.Checker) {
	for _, n := range c.Nodes {
		gates[n.Name].QuorumProof(context.Background())
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
}

// guardMACs is the MACs vm has a live guard record for, sorted.
func guardMACs(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	recs, err := corrosion.ListNICGuards(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		if r.VMName == vm {
			out = append(out, strings.ToLower(r.MAC))
		}
	}
	sort.Strings(out)
	return out
}

// nicMACs is the MACs of vm's live NIC rows, sorted.
func nicMACs(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	var out []string
	for _, x := range liveNICs(t, n, vm) {
		out = append(out, strings.ToLower(x.MAC))
	}
	sort.Strings(out)
	return out
}

func requireGuardsMatchNICs(t *testing.T, n *Node, vm, when string) {
	t.Helper()
	g, nics := guardMACs(t, n, vm), nicMACs(t, n, vm)
	if strings.Join(g, ",") != strings.Join(nics, ",") {
		t.Errorf("%s: guard records %v, NICs %v: the guard table must match the NIC set", when, g, nics)
	}
}

// moveStopStart migrates web to dst, then stops and starts it there.
func moveStopStart(t *testing.T, c *Cluster, gates map[string]*health.Checker, src, dst *Node) {
	t.Helper()
	ctx := context.Background()
	refreshGuardQuorum(c, gates)
	if err := migrateAt(t, c, src, "web", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := c.SelfClient(dst).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if _, err := c.SelfClient(dst).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after detach: %v", err)
	}
}

// TestFleet_NICGuard_DetachRetiresItsRecord (lab 2, C3): a hot-detach retires
// the NIC's guard record with the NIC, so the VM's guards stay satisfiable:
// a later attach, a live migration and a start all succeed, and the guard
// records match the NIC set after each step.
func TestFleet_NICGuard_DetachRetiresItsRecord(t *testing.T) {
	c, src, dst, gates := guardHotplugCluster(t)
	requireGuardsMatchNICs(t, src, "web", "created")

	x := mustAttachNIC(t, c, src, "web", "lan")
	requireGuardsMatchNICs(t, src, "web", "attached")
	mustDetachNIC(t, c, src, "web", x.MAC)
	requireGuardsMatchNICs(t, src, "web", "detached")

	mustAttachNIC(t, c, src, "web", "lan")
	requireGuardsMatchNICs(t, src, "web", "attached after a detach")

	moveStopStart(t, c, gates, src, dst)
	requireGuardsMatchNICs(t, dst, "web", "migrated, stopped, started")
}

// TestFleet_NICGuard_RefusedAttachLeavesNoRecord: an attach that fails after
// its guard record was written takes the record back with the NIC, so the
// failure does not make every later arm of the VM unsatisfiable.
func TestFleet_NICGuard_RefusedAttachLeavesNoRecord(t *testing.T) {
	c, src, dst, gates := guardHotplugCluster(t)
	src.Virt.FailAttachNIC = func(string, string, string, string) error { return errors.New("injected: no PCI slot") }
	if _, err := attachNIC(c, src, "web", "lan"); err == nil {
		t.Fatal("the injected attach failure did not fail the attach")
	}
	src.Virt.FailAttachNIC = nil
	requireGuardsMatchNICs(t, src, "web", "after a failed attach")

	mustAttachNIC(t, c, src, "web", "lan")
	moveStopStart(t, c, gates, src, dst)
	requireGuardsMatchNICs(t, dst, "web", "migrated, stopped, started")
}

// leakRecords gives web what a previous build left after a detach and a
// refused attach: the detached NIC's record live (written before its row's
// tombstone) and a refused attach's record with no row ever.
func leakRecords(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	ctx := context.Background()
	x := mustAttachNIC(t, c, n, "web", "lan")
	rec, err := corrosion.GetNICGuard(ctx, n.DB, "web", x.MAC)
	if err != nil || rec == nil {
		t.Fatalf("fixture: no record for the attached NIC: %v", err)
	}
	mustDetachNIC(t, c, n, "web", x.MAC)
	grant := capabilities.GrantForTest(t, capabilities.FeatureNICGuards)
	leaked := *rec
	leaked.Deleted = false
	if err := corrosion.PutNICGuard(ctx, n.DB, grant, leaked, "old-build"); err != nil {
		t.Fatal(err)
	}
	// The old detach tombstoned the row after the record was written.
	if err := corrosion.TombstoneNIC(ctx, n.DB, "web", corrosion.DeterministicNICID("web", x.MAC)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, n.DB, grant, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:78:00:99",
		Mode: corrosion.NICGuardOn, VMUUID: rec.VMUUID, Network: "lan", Ordinal: 1}, "old-build"); err != nil {
		t.Fatal(err)
	}
	if got := guardMACs(t, n, "web"); len(got) != 3 {
		t.Fatalf("fixture: want the NIC's and two leaked records, got %v", got)
	}
}

// TestFleet_NICGuard_LeakedRecordsAreRepairedByAttach: a VM left with leaked
// records is not stuck: an attach succeeds and retires them, and a migration
// and a start follow.
func TestFleet_NICGuard_LeakedRecordsAreRepairedByAttach(t *testing.T) {
	c, src, dst, gates := guardHotplugCluster(t)
	leakRecords(t, c, src)
	mustAttachNIC(t, c, src, "web", "lan")
	requireGuardsMatchNICs(t, src, "web", "attached on a VM with leaked records")
	moveStopStart(t, c, gates, src, dst)
	requireGuardsMatchNICs(t, dst, "web", "migrated, stopped, started")
}

// TestFleet_NICGuard_LeakedRecordsAreRepairedByMigration: with no attach, the
// migration of such a VM succeeds and retires them, and so does a start.
func TestFleet_NICGuard_LeakedRecordsAreRepairedByMigration(t *testing.T) {
	c, src, dst, gates := guardHotplugCluster(t)
	leakRecords(t, c, src)
	moveStopStart(t, c, gates, src, dst)
	requireGuardsMatchNICs(t, dst, "web", "migrated, stopped, started")
}

// TestFleet_NICGuard_LeakedRecordsAreRepairedByStart: a stopped VM with
// leaked records starts, and the start retires them.
func TestFleet_NICGuard_LeakedRecordsAreRepairedByStart(t *testing.T) {
	c, src, _, gates := guardHotplugCluster(t)
	ctx := context.Background()
	leakRecords(t, c, src)
	refreshGuardQuorum(c, gates)
	if _, err := c.SelfClient(src).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM with leaked records: %v", err)
	}
	requireGuardsMatchNICs(t, src, "web", "started")
}

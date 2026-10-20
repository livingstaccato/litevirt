package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Per-NIC MTU across a migration: the source sends each NIC's MTU as its live
// definition resolved it, the target checks its own bridge, and a mismatch
// refuses the move before anything goes.

// latchNICMTU opens the nic_mtu gate for real on every node, and returns a
// function that refreshes every node's quorum view before a gated step (the
// fleet runs no HA monitor to keep it fresh; see fbScenario.refreshQuorum).
func latchNICMTU(t *testing.T, c *Cluster) (refreshQuorum func()) {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, n.Name+" to open the nic_mtu gate", func() bool {
			return n.Server.WithReleaseFeature(ctx, capabilities.FeatureNICMTU,
				func(_ context.Context, g capabilities.FeatureGrant) error {
					return g.Check(capabilities.FeatureNICMTU)
				}) == nil
		})
	}
	return func() {
		for _, n := range c.Nodes {
			gates[n.Name].QuorumProof(ctx)
			peers := map[string]bool{}
			for _, o := range c.Nodes {
				if o != n {
					peers[o.Name] = true
				}
			}
			gates[n.Name].SeedPeersForTests(peers)
		}
	}
}

// mtuCluster is two nodes with nic_mtu latched, the flat bridge "lan" at
// srcMTU on the source and dstMTU on the target, and a migration that lands
// the source's live definition on the target, as libvirt would.
func mtuCluster(t *testing.T, srcMTU, dstMTU int) (*Cluster, *Node, *Node, func()) {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	src.Virt.SetBridgeMTU("lan", srcMTU)
	dst.Virt.SetBridgeMTU("lan", dstMTU)
	refresh := latchNICMTU(t, c)
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		x, err := src.Virt.DumpXML(name)
		if err != nil {
			return err
		}
		if err := dst.Virt.DefineDomain(x); err != nil {
			return err
		}
		dst.Virt.SetState(name, libvirtfake.StateRunning)
		src.Virt.VanishDomain(name)
		return nil
	}
	return c, src, dst, refresh
}

func createMTUVM(t *testing.T, c *Cluster, at *Node, name string, mtu int32) {
	t.Helper()
	if _, err := c.SelfClient(at).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: at.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mtu: mtu}},
	}}); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if x := at.Virt.DefinedXML(name); !strings.Contains(x, `<mtu size="9000">`) {
		t.Fatalf("%s was defined without its MTU:\n%s", name, x)
	}
}

// An explicit-MTU NIC and a `bridge` NIC (resolved at 9000 on the source)
// each refuse a move to a node whose bridge is 1500, before the migration
// starts: the guest stays where it was, and nothing is defined on the target.
//
// Mutation: have the source ignore the target's nic_mtu_problem — both go red.
func TestFleet_NICMTU_MigrateToAMismatchedBridgeIsRefused(t *testing.T) {
	for name, mtu := range map[string]int32{"explicit": 9000, "bridge": compose.NICMTUBridge} {
		t.Run(name, func(t *testing.T) {
			c, src, dst, refresh := mtuCluster(t, 9000, 1500)
			createMTUVM(t, c, src, "vm-"+name, mtu)
			refresh()
			err := migrateAt(t, c, src, "vm-"+name, dst.Name)
			want := "NIC 0 MTU 9000 does not match bridge lan MTU 1500 on host " + dst.Name
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
				t.Fatalf("migrate = %v, want FailedPrecondition containing %q", err, want)
			}
			if x := dst.Virt.DefinedXML("vm-" + name); x != "" {
				t.Errorf("the refused move defined the guest on the target:\n%s", x)
			}
			if st, _ := src.Virt.RawState("vm-" + name); st != libvirtfake.StateRunning {
				t.Errorf("the guest is %v on the source after a refused move, want running", st)
			}
		})
	}
}

// A target whose bridge matches takes the guest, and the definition that
// lands there carries the MTU.
func TestFleet_NICMTU_MigrateToAMatchedBridgeLandsWithTheMTU(t *testing.T) {
	c, src, dst, refresh := mtuCluster(t, 9000, 9000)
	createMTUVM(t, c, src, "vm-ok", compose.NICMTUBridge)
	refresh()
	if err := migrateAt(t, c, src, "vm-ok", dst.Name); err != nil {
		t.Fatalf("migrate to a matched bridge: %v", err)
	}
	if x := dst.Virt.DefinedXML("vm-ok"); !strings.Contains(x, "mtu size='9000'") && !strings.Contains(x, `mtu size="9000"`) {
		t.Errorf("the guest landed without its MTU:\n%s", x)
	}
}

// A drain cold-moves a running VM with a local disk, shutting it down first.
// A target whose bridge does not carry its NIC MTU is refused while the guest
// still runs: it is never shut down, and stays where it was.
//
// Mutation: drop the MTU check from coldMovePreflight — the guest is shut
// down (and started again) and the test goes red.
func TestFleet_NICMTU_DrainColdRefusesBeforeTheShutdown(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	const mac = "52:54:00:00:40:01"
	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mac: mac, Mtu: 9000}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = 'os1'`, string(spec), sc.src.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertInterface(ctx, sc.src.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: mac}); err != nil {
		t.Fatal(err)
	}
	x, err := sc.src.Virt.DumpXMLInactive("os1")
	if err != nil {
		t.Fatal(err)
	}
	sc.src.Virt.SetInactiveXML("os1", strings.Replace(x, "</devices>",
		"<interface type='bridge'><mac address='"+mac+"'/><source bridge='lan'/><model type='virtio'/><mtu size='9000'/></interface></devices>", 1))
	sc.src.Virt.SetBridgeMTU("lan", 9000)
	sc.dst.Virt.SetBridgeMTU("lan", 1500)
	sc.makeRunning(t)

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	want := "NIC 0 MTU 9000 does not match bridge lan MTU 1500 on host " + sc.dst.Name
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "left running on "+sc.src.Name) || !strings.Contains(p.Error, want) {
		t.Fatalf("drain progress for os1 = %+v, want failed: left running, %q", p, want)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Errorf("os1 was shut down %d time(s) for a move its NIC MTU refuses", n)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1's domain is not running on %s", sc.src.Name)
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is defined on %s", sc.dst.Name)
	}
}

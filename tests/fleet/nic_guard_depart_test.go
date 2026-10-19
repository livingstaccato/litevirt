package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/nictap"
)

// TestFleet_NICGuard_DepartedVMStopsBeingDrawn: a guarded VM that ran on A and
// migrated to B is no longer drawn in A's per-NIC table at A's next pass (not
// after armTTL), and a migration back to A has the guard in force on A when the
// guest arrives, with no window where A drew nothing for it.
func TestFleet_NICGuard_DepartedVMStopsBeingDrawn(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]
	nfts := map[string]*recordingNft{}
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		nfts[n.Name] = wireNodeFirewall(t, n)
	}
	const mac = "52:54:00:77:00:02"
	guardChain := "chain guard_" + nictap.Name(mac) + " {"
	drawn := func(n *Node) bool { return strings.Contains(nfts[n.Name].nicTable(), guardChain) }
	reload := func(n *Node) {
		t.Helper()
		if _, err := c.SelfClient(n).ReloadFirewall(ctx, &emptypb.Empty{}); err != nil {
			t.Fatalf("reload %s: %v", n.Name, err)
		}
	}
	// libvirt carries the guest over: the domain runs on the target and is
	// gone from the source.
	carry := func(from, to *Node) {
		from.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
			x, err := from.Virt.DumpXML(name)
			if err != nil {
				return err
			}
			if err := to.Virt.DefineDomain(x); err != nil {
				return err
			}
			to.Virt.SetState(name, libvirtfake.StateRunning)
			from.Virt.SetState(name, libvirtfake.StateShutdown)
			return nil
		}
	}
	carry(a, b)
	carry(b, a)
	// A's table sampled again once the guest has landed, before the commit.
	afterCarry := true
	inner := b.Virt.OnMigrateToTarget
	b.Virt.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := inner(name, uri, p); err != nil {
			return err
		}
		afterCarry = drawn(a)
		return nil
	}
	if _, err := c.SelfClient(a).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: a.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Ip: "10.30.0.42", Mac: mac}},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	reload(a) // the pass that sees it running here
	if !drawn(a) {
		t.Fatalf("not drawn on its host:\n%s", nfts[a.Name].nicTable())
	}

	if err := migrateAt(t, c, a, "web", b.Name); err != nil {
		t.Fatalf("migrate away: %v", err)
	}
	reload(a)
	if drawn(a) {
		t.Fatalf("the source still draws a VM that left:\n%s", nfts[a.Name].nicTable())
	}
	if !drawn(b) {
		t.Fatalf("the target does not draw it")
	}

	backInForce := false
	b.Virt.FailMigrateToTarget = func(string, string) error {
		backInForce = drawn(a)
		return nil
	}
	if err := migrateAt(t, c, b, "web", a.Name); err != nil {
		t.Fatalf("migrate back: %v", err)
	}
	if !backInForce {
		t.Errorf("the guard was not in force on the returning host when the guest arrived:\n%s", nfts[a.Name].nicTable())
	}
	if !afterCarry {
		t.Errorf("A did not draw the guard after the guest landed:\n%s", nfts[a.Name].nicTable())
	}
	reload(a)
	if !drawn(a) {
		t.Fatalf("not drawn again after the return:\n%s", nfts[a.Name].nicTable())
	}
}

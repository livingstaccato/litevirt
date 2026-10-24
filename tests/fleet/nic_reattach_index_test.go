// Fleet scenario: NIC operations reach a NIC that was detached and attached
// again.
//
// A NIC ordinal is never reused, so a NIC detached and attached again under
// its MAC takes a fresh ordinal, past every NIC the VM ever had and often past
// the end of its spec's network list. Lab 2 (dombld P2): `lv update
// --nic-mtu` could not reach such a NIC, and a stack network move skipped it
// for good.
//
// Multi-node by construction: the attach, detach and update are sent to the
// node that does NOT own the VM and reach the owner over real gRPC; the move
// is recorded in the replicated spec from that node and done by the owner's
// network reconcile pass.
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

const (
	riMACA = "52:54:00:6e:00:0a"
	riMACB = "52:54:00:6e:00:0b"
	riMACC = "52:54:00:6e:00:0c"
	riMACT = "52:54:00:6e:00:1e"
)

// riFleet is a two-node fleet with hardware_v2 and the release token's
// features open, and bridge networks names, each at MTU 9000 on every node.
func riFleet(t *testing.T, names ...string) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	for i, name := range names {
		def := compose.NetworkDef{Type: "bridge", Subnet: "10.71." + string(rune('0'+i)) + ".0/24", DHCP: true}
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, c.Nodes[0].DB, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
		for _, n := range c.Nodes {
			n.Virt.SetBridgeMTU(network.BridgeName(name, def), 9000)
		}
	}
	gates := gateAll(t, c)
	latchHardwareV2(t, c, gates)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	return c
}

// riReattach detaches the NIC with mac and attaches it again on netName,
// both through n.
func riReattach(t *testing.T, c *Cluster, n *Node, vm, mac, netName string) {
	t.Helper()
	mustDetachNIC(t, c, n, vm, mac)
	if _, err := c.SelfClient(n).AttachDevice(context.Background(), &pb.AttachDeviceRequest{
		VmName: vm, Nic: &pb.NetworkAttachment{Name: netName, Mac: mac},
	}); err != nil {
		t.Fatalf("attach %s again on %s: %v", mac, netName, err)
	}
}

func riOrdinal(t *testing.T, n *Node, vm, mac string) int {
	t.Helper()
	for _, r := range liveNICs(t, n, vm) {
		if strings.EqualFold(r.MAC, mac) {
			return r.Ordinal
		}
	}
	t.Fatalf("%s has no NIC %s", vm, mac)
	return -1
}

func riSpec(t *testing.T, n *Node, vm string) *pb.VMSpec {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || rec == nil {
		t.Fatalf("GetVM %s: %v", vm, err)
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func riEntry(spec *pb.VMSpec, mac string) *pb.NetworkAttachment {
	for _, e := range spec.GetNetwork() {
		if strings.EqualFold(e.GetMac(), mac) {
			return e
		}
	}
	return nil
}

func riMTU(x, mac string) int {
	for _, n := range lv.InterfaceMTUs(x) {
		if strings.EqualFold(n.MAC, mac) {
			return n.MTU
		}
	}
	return 0
}

// `lv update --nic-mtu N=` (nic_by_list_position) names the NIC at position N
// of the VM's NIC list,
// whatever its ordinal: A, attached again (ordinal 2), is NIC 1 after B; C,
// hot-plugged and attached again (ordinal 4), is NIC 2 and has no spec entry
// until the update makes one. Main set NIC 1's MTU on B's entry (index 1) and
// made a second entry for A for NIC 2.
//
// Mutation: read N as the spec entry's index again — B takes the MTU, red.
func TestFleet_NICMTUReachesNICsAttachedAgain(t *testing.T) {
	ctx := context.Background()
	c := riFleet(t, "rxa", "rxb")
	own, entry := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(entry).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rx", Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: own.Name},
		Network: []*pb.NetworkAttachment{
			{Name: "rxa", Mac: riMACA, Model: "virtio"},
			{Name: "rxb", Mac: riMACB, Model: "virtio"},
		},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	riReattach(t, c, entry, "rx", riMACA, "rxa")
	if _, err := c.SelfClient(entry).AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "rx", Nic: &pb.NetworkAttachment{Name: "rxb", Mac: riMACC},
	}); err != nil {
		t.Fatalf("attach C: %v", err)
	}
	riReattach(t, c, entry, "rx", riMACC, "rxb")
	if a, cc := riOrdinal(t, own, "rx", riMACA), riOrdinal(t, own, "rx", riMACC); a != 2 || cc != 4 {
		t.Fatalf("ordinals A=%d C=%d, want 2 and 4 (never reused)", a, cc)
	}

	allow := true
	if _, err := c.SelfClient(entry).UpdateVM(ctx, &pb.UpdateVMRequest{Name: "rx", AllowRestart: &allow, NicByListPosition: true,
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: 9000}, {Ordinal: 2, Mtu: 9000}}}); err != nil {
		t.Fatalf("--nic-mtu 1=9000 --nic-mtu 2=9000: %v", err)
	}
	spec := riSpec(t, own, "rx")
	if len(spec.Network) != 3 {
		t.Fatalf("stored network = %+v, want A, B and a new entry for C", spec.Network)
	}
	for mac, want := range map[string]int32{riMACA: 9000, riMACB: 0, riMACC: 9000} {
		if e := riEntry(spec, mac); e == nil || e.GetMtu() != want {
			t.Errorf("entry for %s = %+v, want mtu %d", mac, e, want)
		}
	}
	x := own.Virt.DefinedXML("rx")
	for mac, want := range map[string]int{riMACA: 9000, riMACB: 0, riMACC: 9000} {
		if got := riMTU(x, mac); got != want {
			t.Errorf("%s renders <mtu> %d, want %d:\n%s", mac, got, want, x)
		}
	}
}

// A stack network move reaches a NIC attached again past the end of the
// spec: its entry is found by its MAC. Main indexed the spec by the NIC's
// ordinal, skipped any NIC at or past len(spec.Network), and left T on the
// stack's flat bridge for good.
//
// Mutation: index the spec by the NIC's ordinal in pendingNICRetargets
// again — T stays on prod_lan, red.
func TestFleet_NetworkMoveReachesANICAttachedAgain(t *testing.T) {
	ctx := context.Background()
	c := riFleet(t, "prod_lan", "lan")
	own, entry := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(entry).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "edge", Cpu: 1, MemoryMib: 256, StackName: "prod",
		Placement: &pb.PlacementSpec{Host: own.Name},
		Network:   []*pb.NetworkAttachment{{Name: "prod_lan", Mac: riMACT, Model: "virtio"}},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	riReattach(t, c, entry, "edge", riMACT, "prod_lan")
	if o := riOrdinal(t, own, "edge", riMACT); o != 1 {
		t.Fatalf("T's ordinal = %d, want 1: past the spec's one entry", o)
	}

	// The legacy shape: prod_lan is a record-less flat bridge, and the deploy
	// of the same file has recorded the move of the file's NIC to lan.
	if err := corrosion.DeleteNetwork(ctx, entry.DB, "prod_lan"); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := corrosion.MutateDesiredSpec(ctx, entry.DB, "edge", func(old string) (string, error) {
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(old), spec); err != nil {
			return "", err
		}
		spec.Network[0].Name = "lan"
		b, err := json.Marshal(spec)
		return string(b), err
	}); err != nil || !ok {
		t.Fatalf("record the move: applied=%v err=%v", ok, err)
	}

	if err := own.Server.ReconcileNetworksOnce(ctx); err != nil {
		t.Fatalf("ReconcileNetworksOnce on %s: %v", own.Name, err)
	}
	var onLan bool
	for _, r := range liveNICs(t, own, "edge") {
		onLan = onLan || (strings.EqualFold(r.MAC, riMACT) && r.NetworkName == "lan")
	}
	if !onLan {
		t.Fatalf("T after the move: %+v, want it on lan", liveNICs(t, own, "edge"))
	}
	if !hasVMEvent(t, own, "edge", "vm.nic_moved", "ok") {
		t.Error("no vm.nic_moved event for edge")
	}
	// The owner re-plugged T itself onto lan's bridge.
	want := "mac=" + riMACT + " bridge=" + network.BridgeName("lan", compose.NetworkDef{Type: "bridge"})
	var replugged bool
	for _, e := range own.Virt.EventLog() {
		replugged = replugged || (e.Op == "set-nic-bridge" && e.Domain == "edge" && strings.EqualFold(e.Note, want))
	}
	if !replugged {
		t.Errorf("no set-nic-bridge %q on %s", want, own.Name)
	}
}

// riReattachedFleet is a fleet whose VM rx on node-0 lists A (rxa) and B
// (rxb), with A detached and attached again through node-1: its NIC list is
// B (ordinal 1), A (ordinal 2), and C (rxc, ordinal 3) has no spec entry.
func riReattachedFleet(t *testing.T) (*Cluster, *Node, *Node) {
	t.Helper()
	ctx := context.Background()
	c := riFleet(t, "rxa", "rxb", "rxc")
	own, entry := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(entry).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rx", Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: own.Name},
		Network: []*pb.NetworkAttachment{
			{Name: "rxa", Mac: riMACA, Model: "virtio"},
			{Name: "rxb", Mac: riMACB, Model: "virtio"},
		},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	riReattach(t, c, entry, "rx", riMACA, "rxa")
	if _, err := c.SelfClient(entry).AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "rx", Nic: &pb.NetworkAttachment{Name: "rxc", Mac: riMACC},
	}); err != nil {
		t.Fatalf("attach C: %v", err)
	}
	if _, err := c.SelfClient(entry).StopVM(ctx, &pb.StopVMRequest{Name: "rx", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	return c, own, entry
}

// Review I-1: a request without nic_by_list_position — what an older lv or
// an older deploy node sends — means spec indices on this owner too: entry 0
// is A, though A is at position 1.
//
// Mutation: read a request without the field by list position — B takes the
// MTU, red.
func TestFleet_NICNumbersWithoutListPositionAreSpecIndices(t *testing.T) {
	ctx := context.Background()
	c, own, entry := riReattachedFleet(t)
	if _, err := c.SelfClient(entry).UpdateVM(ctx, &pb.UpdateVMRequest{Name: "rx",
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}}); err != nil {
		t.Fatalf("UpdateVM by spec index: %v", err)
	}
	if a, b := riEntry(riSpec(t, own, "rx"), riMACA), riEntry(riSpec(t, own, "rx"), riMACB); a.GetMtu() != 9000 || b.GetMtu() != 0 {
		t.Errorf("A %+v, B %+v; want the MTU on A (entry 0)", a, b)
	}
	if x := own.Virt.DefinedXML("rx"); riMTU(x, riMACA) != 9000 || riMTU(x, riMACB) != 0 {
		t.Errorf("want <mtu> 9000 on A only:\n%s", x)
	}
}

// An owner whose Ping lacks nic_list_position reads NIC numbers as spec
// indices, which can name another NIC: lv update's positions are refused for
// it, naming the owner, and nothing changes.
//
// Mutation: forward positions unchanged to the older owner — B takes the
// MTU, red.
func TestFleet_NICPositionsToAnOlderOwnerAreRefused(t *testing.T) {
	ctx := context.Background()
	c, own, entry := riReattachedFleet(t)
	own.Server.SetPingWithoutNICListPositionForTest(true)
	_, err := c.SelfClient(entry).UpdateVM(ctx, &pb.UpdateVMRequest{Name: "rx", NicByListPosition: true,
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: 9000}}})
	if err == nil || !strings.Contains(err.Error(), "runs an older build") {
		t.Fatalf("--nic-mtu 1=9000 to the older owner: %v, want a refusal naming it", err)
	}
	if a, b := riEntry(riSpec(t, own, "rx"), riMACA), riEntry(riSpec(t, own, "rx"), riMACB); a.GetMtu() != 0 || b.GetMtu() != 0 {
		t.Errorf("A %+v, B %+v; want no MTU from a refused update", a, b)
	}
}

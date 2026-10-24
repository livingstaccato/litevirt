package fleet

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// vlanMover seeds a running diskless VM "vmover" on src whose one NIC is an
// access port on VLAN 30 of network vt_acc, and gives each node in bridges
// that bridge state (accVLANBridge); a node not named has a filtering bridge.
func vlanMover(t *testing.T, c *Cluster, src *Node, bridges map[*Node]*accVLANBridge) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetGatewayAnnouncer(func(string, netip.Addr) (bool, error) { return false, nil })
		br, ok := bridges[n]
		if !ok {
			br = &accVLANBridge{on: true}
		}
		read := func(bridge string) (bool, bool, error) {
			isBridge, on, err := br.read(network.FlatBridgeName("accnet"))
			return isBridge && bridge == network.FlatBridgeName("vt_acc"), on, err
		}
		n.Server.SetBridgeVLANFiltering(read)
		n.Server.SetBridgeExists(func(bridge string) bool { ok, _, _ := read(bridge); return ok })
	}
	spec := `{"name":"vmover","cpu":1,"memory_mib":512,"network":[{"name":"vt_acc","mac":"52:54:00:47:02:03","trunk":[30]}]}`
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "vmover", HostName: src.Name, State: "running", Spec: spec, CPUActual: 1, MemActual: 512,
	}, []corrosion.InterfaceRecord{{VMName: "vmover", NetworkName: "vt_acc", Ordinal: 0, MAC: "52:54:00:47:02:03"}}, nil); err != nil {
		t.Fatal(err)
	}
	src.Virt.SetState("vmover", "running")
	c.WaitConverged(t, convergeTimeout)
}

// migratedTo reports whether n's fake saw vmover arrive.
func migratedTo(n *Node) bool {
	for _, e := range n.Virt.EventLog() {
		if e.Domain == "vmover" && e.Op == "migrate-in" {
			return true
		}
	}
	return false
}

// B-3: `lv migrate` refuses to move an access-VLAN VM onto a host whose bridge
// for it does not filter VLANs, or does not exist (litevirt would create it
// without filtering): the guest would join the bridge's untagged segment. The
// target refuses it in EnsureDisks, before anything is created there, and the
// guest keeps running on its source. A target that filters takes it.
//
// Mutation: drop accessVLANMoveRefusal from EnsureDisks — red.
func TestFleet_MigrateOfAnAccessVLANVMOntoAnUnfitBridgeIsRefused(t *testing.T) {
	for name, br := range map[string]*accVLANBridge{
		"not filtering": {on: false},
		"absent":        {absent: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			src, dst := c.Nodes[0], c.Nodes[1]
			vlanMover(t, c, src, map[*Node]*accVLANBridge{dst: br})
			src.LandMigrationsOn(dst)
			err := migrateAt(t, c, src, "vmover", dst.Name)
			if err == nil || !strings.Contains(err.Error(), "VLAN 30") {
				t.Fatalf("migrate onto %s (%s): %v; want a refusal naming VLAN 30", dst.Name, name, err)
			}
			if migratedTo(dst) {
				t.Fatalf("the refused move reached %s", dst.Name)
			}
			if st, _ := src.Virt.DomainState("vmover"); st != "running" {
				t.Fatalf("the guest on %s is %q after the refused move, want running", src.Name, st)
			}
			if vm := vmOn(t, src, "vmover"); vm == nil || vm.HostName != src.Name || vm.State != "running" {
				t.Fatalf("vmover after the refused move: %+v", vm)
			}

			br.set(true)
			if err := migrateAt(t, c, src, "vmover", dst.Name); err != nil {
				t.Fatalf("migrate once %s's bridge filters VLANs: %v", dst.Name, err)
			}
			assertVLANBeforeRun(t, dst, "vmover", "vlan=30")
		})
	}
}

// B-3: a drain does not choose a host whose bridge cannot carry an access-VLAN
// VM (bridge_vlan_filtering_off) as its target: a (first by name, so
// placement's pick) does not filter, b does, and the VM is drained onto b.
// With no fit host left, the VM stays where it is, the drain naming why.
//
// Mutation: drop vlanView.exclude from the drain — red (it chooses a, which
// refuses the move, and the VM stays on the source).
func TestFleet_DrainPassesOverAHostWhoseBridgeCannotCarryAnAccessVLANVM(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	src, a, b := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	brA, brB := &accVLANBridge{on: false}, &accVLANBridge{on: true}
	vlanMover(t, c, src, map[*Node]*accVLANBridge{a: brA, b: brB})
	for _, n := range c.Nodes {
		n.Server.ReconcileAccessVLANBridges(ctx)
	}
	c.WaitConverged(t, convergeTimeout)
	src.LandMigrationsOn(b)

	drain := func() string {
		st, err := c.SelfClient(src).DrainHost(ctx, &pb.DrainHostRequest{Name: src.Name})
		if err != nil {
			t.Fatal(err)
		}
		var frames []string
		for {
			p, rerr := st.Recv()
			if rerr == io.EOF || rerr != nil {
				if rerr != io.EOF {
					frames = append(frames, "end: "+rerr.Error())
				}
				return strings.Join(frames, "; ")
			}
			frames = append(frames, p.GetVmName()+" "+p.GetStatus()+" "+p.GetTargetHost()+" "+p.GetError())
		}
	}

	brB.set(false)
	for _, n := range c.Nodes {
		n.Server.ReconcileAccessVLANBridges(ctx)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := drain(); !strings.Contains(got, "no eligible target") || !strings.Contains(got, "access-VLAN") {
		t.Fatalf("drain with no host that can carry the VM: %q; want no eligible target, naming the access-VLAN bridge", got)
	}
	if migratedTo(a) || migratedTo(b) {
		t.Fatal("the VM was moved onto a bridge that cannot carry it")
	}
	if err := corrosion.UpdateHostState(ctx, src.DB, src.Name, "active"); err != nil {
		t.Fatal(err)
	}

	brB.set(true)
	for _, n := range c.Nodes {
		n.Server.ReconcileAccessVLANBridges(ctx)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := drain(); !strings.Contains(got, "vmover") || !strings.Contains(got, b.Name) {
		t.Fatalf("drain: %q; want vmover moved to %s", got, b.Name)
	}
	eventually(t, 10*time.Second, "vmover on "+b.Name, func() bool {
		vm := vmOn(t, src, "vmover")
		return vm != nil && vm.HostName == b.Name
	})
	if migratedTo(a) {
		t.Fatalf("the drain moved the VM onto %s, whose bridge does not filter VLANs", a.Name)
	}
	assertVLANBeforeRun(t, b, "vmover", "vlan=30")
}

// Rolling upgrade: a target on a build before NIC guards answers
// ArmNICFirewall Unimplemented and cannot hold a guest paused for its tap
// VLANs. An unguarded VLAN guest then moves as it did before — not paused, so
// it is not left paused with nothing to resume it — and this build's backstop
// (AnnounceMigratedGuest; ConvergeTapVLANs) still puts its VLAN on.
//
// Mutation: keep am.paused on an Unimplemented arm — red (the guest is handed
// over paused to a target that cannot resume it).
func TestFleet_VLANGuestToATargetWithoutHandOverIsNotPaused(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	vlanMover(t, c, src, nil)
	src.LandMigrationsOn(dst)
	defer dst.DoNotImplement("ArmNICFirewall")()
	if err := migrateAt(t, c, src, "vmover", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, e := range src.Virt.EventLog() {
		if e.Domain == "vmover" && e.Op == "migrate" && strings.Contains(e.Note, "paused=true") {
			t.Fatalf("handed over paused to a target that cannot resume it: %q", e.Note)
		}
	}
	eventually(t, 10*time.Second, "the access VLAN on "+dst.Name+"'s tap", func() bool {
		for _, e := range dst.Virt.EventLog() {
			if e.Domain == "vmover" && e.Op == "vlan-tap" && strings.Contains(e.Note, "vlan=30") {
				return true
			}
		}
		return false
	})
	if st, _ := dst.Virt.DomainState("vmover"); st != "running" {
		t.Fatalf("vmover on %s is %q, want running", dst.Name, st)
	}
}

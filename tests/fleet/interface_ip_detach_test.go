package fleet

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// An address recorded for a VM's network lands only on the live NIC it is for.
// The legacy vm_interfaces row is keyed by (vm, network), and a detach after
// the hardware_v2 latch tombstones only vm_nics, so an unfiltered IP write on
// that row brought a detached NIC back, and the hardware bridge then copied it
// into vm_nics for good; on a NIC detached before the latch and re-attached
// after it under the same MAC, it bumped the old tombstone over the live row
// and hid a running NIC.
//
// Each node has its own replica, so "stays detached" is asserted on every node
// after the writes replicated and after one bridge pass on every node.
//
// Mutations, each turning a test here red: the legacy write ignoring the MAC
// (DetachedNICStaysDetached), ignoring deleted_at (ReattachedNICStaysVisible),
// the target ignoring a tombstoned winner (DetachedNICStaysDetached), and an
// IP write rewriting vm_nics (DetachRacingAnOffOwnerWrite,
// KeepsASecurityGroupBind).

const ifaceIPNet = "na"

func ifaceIPCluster(t *testing.T) (*Cluster, map[string]*health.Checker) {
	t.Helper()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)
	if _, err := c.SelfClient(c.Nodes[0]).CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: ifaceIPNet, Type: "isolated", Subnet: "172.16.81.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return c, gates
}

// bridgeEverywhere runs one hardware bridge pass for vm on every node, which
// is what each node's 30-second RunHardwareBridge tick does per VM, and waits
// for what it wrote to replicate.
func bridgeEverywhere(t *testing.T, c *Cluster, vm string) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := corrosion.BridgeVMNICs(context.Background(), n.DB, vm); err != nil {
			t.Fatalf("BridgeVMNICs on %s: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, 30*time.Second)
}

// latchHardwareV2Converged is latchHardwareV2 on independent replicas: the
// backfill runs once each node holds the cluster's rows, and the latch is
// awaited rather than read once.
func latchHardwareV2Converged(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	c.WaitConverged(t, 30*time.Second)
	backfillAll(t, c)
	for _, n := range c.Nodes {
		eventually(t, 15*time.Second, "hardware_v2 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.HardwareV2)
		})
	}
}

func setVMIP(t *testing.T, c *Cluster, n *Node, vm, ip string) {
	t.Helper()
	if _, err := c.SelfClient(n).SetVMIP(context.Background(), &pb.SetVMIPRequest{
		Name: vm, Ip: ip, NetworkName: ifaceIPNet,
	}); err != nil {
		t.Fatalf("SetVMIP %s on %s through %s: %v", ip, vm, n.Name, err)
	}
}

// requireNICs fails unless, on every node, vm's live NICs are exactly want
// (MAC → IP; "?" accepts any address).
func requireNICs(t *testing.T, c *Cluster, vm, when string, want map[string]string) {
	t.Helper()
	for _, n := range c.Nodes {
		got := map[string]string{}
		for _, r := range liveNICs(t, n, vm) {
			mac := strings.ToLower(r.MAC)
			got[mac] = r.IP
			if want[mac] == "?" {
				got[mac] = "?"
			}
		}
		if !sameNICSet(got, want) {
			t.Errorf("%s: live NICs of %s on %s = %v, want %v", when, vm, n.Name, got, want)
		}
	}
}

func TestFleet_IPWrite_DetachedNICStaysDetached(t *testing.T) {
	c, gates := ifaceIPCluster(t)
	ctx := context.Background()
	home, other := c.Nodes[0], c.Nodes[1]
	mustCreateNICLessVM(t, c, home, "web")

	// Attached before the latch, so the NIC has a legacy row as well.
	x := strings.ToLower(mustAttachNIC(t, c, home, "web", ifaceIPNet).MAC)
	latchHardwareV2Converged(t, c, gates)
	mustDetachNIC(t, c, home, "web", x)
	ifaces, err := corrosion.GetVMInterfaces(ctx, home.DB, "web")
	if err != nil || len(ifaces) != 1 || !strings.EqualFold(ifaces[0].MAC, x) {
		t.Fatalf("fixture: a latched detach must leave the legacy row live, got %+v (%v)", ifaces, err)
	}
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after the detach", map[string]string{})

	// An address reported for the network while no NIC is on it.
	setVMIP(t, c, other, "web", "172.16.81.50")
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after an IP write with no NIC on the network", map[string]string{})
	bridgeEverywhere(t, c, "web")
	requireNICs(t, c, "web", "after a bridge pass", map[string]string{})

	// A new NIC on the same network takes the address; the detached one stays gone.
	// A new NIC on the same network (vm_nics only) is not written either: the
	// IP path writes the legacy row only, and that row is the detached NIC's.
	yNIC := mustAttachNIC(t, c, home, "web", ifaceIPNet)
	y := strings.ToLower(yNIC.MAC)
	c.WaitConverged(t, 30*time.Second)
	setVMIP(t, c, other, "web", "172.16.81.51")
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after an IP write with the new NIC attached", map[string]string{y: yNIC.IP})
	bridgeEverywhere(t, c, "web")
	requireNICs(t, c, "web", "after a bridge pass", map[string]string{y: yNIC.IP})
}

func TestFleet_IPWrite_ReattachedNICStaysVisible(t *testing.T) {
	c, gates := ifaceIPCluster(t)
	ctx := context.Background()
	home, other := c.Nodes[0], c.Nodes[1]
	mustCreateNICLessVM(t, c, home, "web")

	// Attached and detached before the latch: both tables carry a tombstone.
	x := strings.ToLower(mustAttachNIC(t, c, home, "web", ifaceIPNet).MAC)
	mustDetachNIC(t, c, home, "web", x)
	latchHardwareV2Converged(t, c, gates)

	// Back under the same MAC after the latch: vm_nics only.
	if _, err := c.SelfClient(home).AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "web", Nic: &pb.NetworkAttachment{Name: ifaceIPNet, Mac: x},
	}); err != nil {
		t.Fatalf("re-attach %s: %v", x, err)
	}
	if ifaces, err := corrosion.GetVMInterfaces(ctx, home.DB, "web"); err != nil || len(ifaces) != 0 {
		t.Fatalf("fixture: the legacy row must still be the old tombstone, got live %+v (%v)", ifaces, err)
	}
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after the re-attach", map[string]string{x: "?"})

	// The old tombstone is not written either: bumped past the live row, it
	// is what hides the NIC on any replica that has it and not the vm_nics
	// write behind it.
	tombstone := legacyStamp(t, home, "web")
	setVMIP(t, c, other, "web", "172.16.81.60")
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after an IP write", map[string]string{x: "?"})
	for _, n := range c.Nodes {
		if got := legacyStamp(t, n, "web"); got != tombstone {
			t.Errorf("the legacy tombstone on %s was written by the IP write: %q, was %q", n.Name, got, tombstone)
		}
	}
	bridgeEverywhere(t, c, "web")
	requireNICs(t, c, "web", "after a bridge pass", map[string]string{x: "?"})
}

// legacyStamp is the updated_at of vm's legacy row on the fleet network.
func legacyStamp(t *testing.T, n *Node, vm string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT updated_at FROM vm_interfaces WHERE vm_name = ? AND network_name = ?`, vm, ifaceIPNet)
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy row of %s on %s: %d rows, %v", vm, n.Name, len(rows), err)
	}
	return rows[0].String("updated_at")
}

// SetVMIP through a node that has not yet received the owner's detach of a
// vm_nics-only NIC does not rewrite that NIC's row live over the tombstone:
// the IP path never writes vm_nics.
func TestFleet_IPWrite_DetachRacingAnOffOwnerWrite(t *testing.T) {
	c, gates := ifaceIPCluster(t)
	home, other, third := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	mustCreateNICLessVM(t, c, home, "web")
	latchHardwareV2Converged(t, c, gates)
	y := strings.ToLower(mustAttachNIC(t, c, home, "web", ifaceIPNet).MAC)
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after the attach", map[string]string{y: "?"})

	// The detach does not reach the other nodes yet.
	c.SetLinkFault(home, other, LinkFault{Block: true})
	c.SetLinkFault(home, third, LinkFault{Block: true})
	mustDetachNIC(t, c, home, "web", y)
	if _, live := liveNICSet(t, other, "web")[y]; !live {
		t.Fatalf("fixture: %s already has the detach of %s", other.Name, y)
	}

	setVMIP(t, c, other, "web", "172.16.81.70")
	c.ClearLinkFaults()
	c.WaitConverged(t, 30*time.Second)
	requireNICs(t, c, "web", "after the racing IP write", map[string]string{})
	bridgeEverywhere(t, c, "web")
	requireNICs(t, c, "web", "after a bridge pass", map[string]string{})
}

// An IP write never changes a vm_nics column on any node: a security-group
// bind made through one node survives an IP write made through another,
// for a NIC carried in both tables and for one carried in vm_nics only.
func TestFleet_IPWrite_KeepsASecurityGroupBind(t *testing.T) {
	c, gates := ifaceIPCluster(t)
	ctx := context.Background()
	home, other, third := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(home).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "nb", Type: "isolated", Subnet: "172.16.82.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork nb: %v", err)
	}
	mustCreateNICLessVM(t, c, home, "web")
	x := strings.ToLower(mustAttachNIC(t, c, home, "web", ifaceIPNet).MAC) // both tables
	latchHardwareV2Converged(t, c, gates)
	y := strings.ToLower(mustAttachNIC(t, c, home, "web", "nb").MAC) // vm_nics only
	c.WaitConverged(t, 30*time.Second)
	for _, net := range []string{ifaceIPNet, "nb"} {
		if _, err := c.SelfClient(third).BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
			VmName: "web", NetworkName: net, SecurityGroups: []string{"isolate"},
		}); err != nil {
			t.Fatalf("BindSecurityGroups %s: %v", net, err)
		}
	}
	c.WaitConverged(t, 30*time.Second)
	before := map[string][]corrosion.NICRecord{}
	for _, n := range c.Nodes {
		before[n.Name] = vmNICsRows(t, n, "web")
	}

	setVMIP(t, c, other, "web", "172.16.81.80")
	if _, err := c.SelfClient(other).SetVMIP(ctx, &pb.SetVMIPRequest{Name: "web", Ip: "172.16.82.80", NetworkName: "nb"}); err != nil {
		t.Fatalf("SetVMIP nb: %v", err)
	}
	c.WaitConverged(t, 30*time.Second)
	for _, n := range c.Nodes {
		after := vmNICsRows(t, n, "web")
		if len(after) != len(before[n.Name]) {
			t.Fatalf("vm_nics rows on %s: %d → %d", n.Name, len(before[n.Name]), len(after))
		}
		for i := range after {
			if after[i] != before[n.Name][i] {
				t.Errorf("vm_nics row on %s changed by an IP write:\n before %+v\n after  %+v", n.Name, before[n.Name][i], after[i])
			}
		}
	}
	// The bridge copies X's now-newer legacy row (which carries the bind too)
	// into vm_nics, as it always has; the bind survives that as well.
	bridgeEverywhere(t, c, "web")
	for _, n := range c.Nodes {
		for _, r := range liveNICs(t, n, "web") {
			if mac := strings.ToLower(r.MAC); (mac == x || mac == y) && !strings.Contains(r.SecurityGroups, "isolate") {
				t.Errorf("%s on %s lost its security-group bind: %+v", mac, n.Name, r)
			}
		}
		ifaces, err := corrosion.GetVMInterfaces(ctx, n.DB, "web")
		if err != nil || len(ifaces) != 1 || !strings.EqualFold(ifaces[0].MAC, x) || ifaces[0].IP != "172.16.81.80" {
			t.Errorf("legacy rows on %s = %+v (%v), want %s at 172.16.81.80", n.Name, ifaces, err, x)
		}
	}
}

func vmNICsRows(t *testing.T, n *Node, vm string) []corrosion.NICRecord {
	t.Helper()
	rows, err := corrosion.GetVMNICsRaw(context.Background(), n.DB, "vm_nics", vm)
	if err != nil {
		t.Fatalf("vm_nics of %s on %s: %v", vm, n.Name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
}

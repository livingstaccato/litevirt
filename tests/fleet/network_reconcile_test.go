package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// The lab failure's second half: `lv network create hc --type isolated
// --subnet 172.16.50.0/24 --dhcp` set up br-iso-hc and its dnsmasq on node-1,
// where the command ran, and nowhere else. An isolated network is host-local
// and serves DHCP on every host (docs/networking.md), so every host converges
// on the networks table: a network is provisioned on each node once the row
// reaches it, again after a restart, and torn down on each node once the
// tombstone reaches it — including a node that was down for the delete.
func TestFleet_NetworkLifecycleReachesEveryHost(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	want := network.IsolatedBridgeName("hc")

	if _, err := c.SelfClient(n0).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork on %s: %v", n0.Name, err)
	}
	if dev, ok := n0.Net.Up("hc"); !ok || dev != want {
		t.Fatalf("%s (creating node): hc provisioned=%v on %q, want %s", n0.Name, ok, dev, want)
	}

	// The row replicates to the other two nodes (one of them standing in for a
	// node that joins after the create). Each one's own pass sets it up.
	dump := pullDump(t, c, n0)
	for _, n := range []*Node{n1, n2} {
		n.DB.MergeStateBytesLWW(dump)
		reconcileNetworks(t, n)
		if dev, ok := n.Net.Up("hc"); !ok || dev != want {
			t.Errorf("%s: hc provisioned=%v on %q after the row reached it, want %s", n.Name, ok, dev, want)
		}
	}

	// An unchanged network is not provisioned again every pass.
	reconcileNetworks(t, n1)
	if got := n1.Net.Provisions("hc"); got != 1 {
		t.Errorf("%s: hc provisioned %d times over two passes, want 1", n1.Name, got)
	}

	// A restart: dnsmasq died with the daemon, and the new process remembers
	// nothing. The first pass brings the network back.
	n1.Net = NewNetProvFake()
	n1.Server.SetNetworkProvisioner(n1.Net)
	n1.Server.ForgetNetworkReconcileForTests()
	reconcileNetworks(t, n1)
	if dev, ok := n1.Net.Up("hc"); !ok || dev != want {
		t.Errorf("%s: hc provisioned=%v on %q after a restart, want %s", n1.Name, ok, dev, want)
	}

	// Delete on n0. n1 is up and gets the tombstone; n2 is down.
	if _, err := c.SelfClient(n0).DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "hc"}); err != nil {
		t.Fatalf("DeleteNetwork on %s: %v", n0.Name, err)
	}
	if _, ok := n0.Net.Up("hc"); ok {
		t.Errorf("%s (deleting node): hc still provisioned after the delete", n0.Name)
	}
	dump = pullDump(t, c, n0)
	n1.DB.MergeStateBytesLWW(dump)
	reconcileNetworks(t, n1)
	if _, ok := n1.Net.Up("hc"); ok {
		t.Errorf("%s: hc still provisioned after the tombstone reached it", n1.Name)
	}
	reconcileNetworks(t, n1)
	if got := n1.Net.Deprovisions("hc"); got != 1 {
		t.Errorf("%s: hc torn down %d times over two passes, want 1", n1.Name, got)
	}

	// n2 comes back: a restart (the bridge survived it) and then the
	// tombstone arrives. It tears down what the delete could not reach.
	n2.Server.ForgetNetworkReconcileForTests()
	n2.DB.MergeStateBytesLWW(dump)
	reconcileNetworks(t, n2)
	if _, ok := n2.Net.Up("hc"); ok {
		t.Errorf("%s: hc still provisioned after it came back and saw the delete", n2.Name)
	}
}

// A host that loses what provisioning set up — dnsmasq died, or someone
// deleted the bridge — gets it back on the next pass, not at the next
// restart. A network that is still intact is left alone.
func TestFleet_NetworkReconcileHealsAHostThatLostTheNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	want := network.IsolatedBridgeName("hc")

	for _, name := range []string{"hc", "other"} {
		if _, err := c.SelfClient(n0).CreateNetwork(ctx, &pb.CreateNetworkRequest{
			Name: name, Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
		}); err != nil {
			t.Fatalf("CreateNetwork %s: %v", name, err)
		}
	}
	n1.DB.MergeStateBytesLWW(pullDump(t, c, n0))
	reconcileNetworks(t, n1)

	n1.Net.Lose("hc")
	reconcileNetworks(t, n1)
	if dev, ok := n1.Net.Up("hc"); !ok || dev != want {
		t.Errorf("%s: hc provisioned=%v on %q after the host lost it, want it back on %s", n1.Name, ok, dev, want)
	}
	if got := n1.Net.Provisions("hc"); got != 2 {
		t.Errorf("%s: hc provisioned %d times, want 2 (once, then once more after the loss)", n1.Name, got)
	}
	if got := n1.Net.Provisions("other"); got != 1 {
		t.Errorf("%s: intact network other provisioned %d times, want 1", n1.Name, got)
	}
}

// A deleted network whose device a live network still uses is not torn down:
// that would pull the bridge, gateway or dnsmasq out from under the live one.
func TestFleet_NetworkReconcileSparesADeviceALiveNetworkUses(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()

	for _, nr := range []corrosion.NetworkRecord{
		{Name: "old", Type: "bridge", Config: `{"interface":"br0"}`},
		{Name: "new", Type: "bridge", Config: `{"interface":"br0"}`},
		{Name: "gone", Type: "isolated", Config: `{}`},
	} {
		if err := corrosion.UpsertNetwork(ctx, n.DB, nr); err != nil {
			t.Fatalf("seed %s: %v", nr.Name, err)
		}
	}
	reconcileNetworks(t, n)
	for _, name := range []string{"old", "new", "gone"} {
		if _, ok := n.Net.Up(name); !ok {
			t.Fatalf("%s not provisioned by the first pass", name)
		}
	}
	for _, name := range []string{"old", "gone"} {
		if err := corrosion.DeleteNetwork(ctx, n.DB, name); err != nil {
			t.Fatalf("delete %s: %v", name, err)
		}
	}
	reconcileNetworks(t, n)
	if got := n.Net.Deprovisions("old"); got != 0 {
		t.Errorf("old was torn down %d times while new still uses its bridge br0", got)
	}
	if got := n.Net.Deprovisions("gone"); got != 1 {
		t.Errorf("gone (sharing nothing) torn down %d times, want 1", got)
	}
}

func reconcileNetworks(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Server.ReconcileNetworksOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileNetworksOnce on %s: %v", n.Name, err)
	}
}

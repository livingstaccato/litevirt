package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Lab finding N3. `lv network rm --force` of a network a guest is still on
// deletes the network and DEFERS its teardown on that host until nothing there
// uses it — by design, so the guest keeps its DHCP and gateway. A create of a
// new network on the same subnet then failed on that host with nothing but
// dnsmasq's own exit (`dnsmasq … exited immediately: exit status 2`): the
// deleted network's dnsmasq still holds the gateway address.
//
// The create keeps doing what it did — the new network is recorded, and this
// host provisions it once the old teardown finishes — but the error now says
// which deleted network holds the subnet and what still uses it.
func TestFleet_SameSubnetCreateNamesTheForceDeletedNetworkStillHoldingIt(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	cl := c.SelfClient(n)
	n.Net.SetDHCPConflicts(true)

	const subnet = "10.88.0.0/24"
	// An earlier network on the same subnet, deleted with nothing on it and
	// torn down at once: it holds nothing, and must not be the one named.
	if _, err := cl.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "aaold", Type: "bridge", Subnet: subnet,
	}); err != nil {
		t.Fatalf("create aaold: %v", err)
	}
	if _, err := cl.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "aaold"}); err != nil {
		t.Fatalf("delete aaold: %v", err)
	}
	if _, err := cl.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "olda", Type: "bridge", Subnet: subnet,
	}); err != nil {
		t.Fatalf("create olda: %v", err)
	}
	// A guest is still plugged into olda's bridge on this host.
	n.Net.SetGuestPorts("olda", "vnet7")

	if _, err := cl.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "olda", Force: true}); err != nil {
		t.Fatalf("force delete olda: %v", err)
	}
	if got := n.Net.Deprovisions("olda"); got != 0 {
		t.Fatalf("olda torn down %d times while vnet7 is on it; the teardown must wait", got)
	}

	_, err := cl.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "newb", Type: "bridge", Subnet: subnet})
	if err == nil {
		t.Fatal("create newb on the subnet the deferred olda still serves succeeded on this host")
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{`"olda"`, "vnet7", subnet} {
		if !strings.Contains(msg, want) {
			t.Errorf("create newb error does not name %s; an operator cannot tell what holds the subnet:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, `"aaold"`) {
		t.Errorf("create newb error names aaold, which was torn down and holds nothing:\n%s", msg)
	}
	if code := status.Code(err); code != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition (the cause is a state the operator can change)", code)
	}

	// As before: the network was recorded, and once the guest leaves, one
	// reconcile pass tears olda down and provisions newb here.
	if _, err := cl.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "newb"}); err != nil {
		t.Fatalf("newb was not recorded: %v", err)
	}
	n.Net.SetGuestPorts("olda")
	reconcileNetworks(t, n)
	if got := n.Net.Deprovisions("olda"); got != 1 {
		t.Errorf("olda torn down %d times after its guest left, want 1", got)
	}
	if _, ok := n.Net.Up("newb"); !ok {
		t.Errorf("newb not provisioned here after olda's teardown finished")
	}
}

// The explanation is a diagnosis, so it must not be attached to a failure the
// deferred teardown cannot have caused (review M3): a provision error that is
// not about dnsmasq, a new network that starts no DHCP server, and a deleted
// network whose device a live network shares (the reconciler never tears that
// one down, so "once that teardown finishes" would never come). Each keeps the
// plain error, as on main.
func TestFleet_DeferredTeardownExplanationIsSelective(t *testing.T) {
	const subnet = "10.89.0.0/24"
	setup := func(t *testing.T, iface string) (*Node, pb.LiteVirtClient) {
		t.Helper()
		c := New(t, Options{Nodes: 1})
		n := c.Nodes[0]
		cl := c.SelfClient(n)
		if _, err := cl.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
			Name: "olda", Type: "bridge", Subnet: subnet, Iface: iface,
		}); err != nil {
			t.Fatalf("create olda: %v", err)
		}
		bridge := "olda"
		if iface != "" {
			bridge = iface
		}
		n.Net.SetGuestPorts(bridge, "vnet7")
		if _, err := cl.DeleteNetwork(context.Background(), &pb.DeleteNetworkRequest{Name: "olda", Force: true}); err != nil {
			t.Fatalf("force delete olda: %v", err)
		}
		return n, cl
	}
	plain := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("create newb succeeded; the scenario needs it to fail")
		}
		if msg := status.Convert(err).Message(); strings.Contains(msg, "deleted network") {
			t.Errorf("a failure the deferred teardown did not cause was blamed on it:\n%s", msg)
		}
		if code := status.Code(err); code != codes.Internal {
			t.Errorf("code = %v, want Internal (the plain provision failure, as on main)", code)
		}
	}

	t.Run("a provision error that is not about DHCP", func(t *testing.T) {
		n, cl := setup(t, "")
		n.Net.FailProvision("newb", errors.New(`network "newb" provisioning rolled back: host lost connectivity to gateway 192.0.2.1 after 3 failed checks`))
		_, err := cl.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{Name: "newb", Type: "bridge", Subnet: subnet})
		plain(t, err)
	})

	t.Run("a new network that starts no DHCP server (on a VLAN)", func(t *testing.T) {
		n, cl := setup(t, "")
		n.Net.FailProvision("newb", errors.New("start DHCP on newb: dnsmasq on newb exited immediately: exit status 2"))
		_, err := cl.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{Name: "newb", Type: "bridge", Subnet: subnet, Vlan: 30})
		plain(t, err)
	})

	t.Run("a deleted network whose device a live network shares", func(t *testing.T) {
		n, cl := setup(t, "brshr")
		if _, err := cl.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{Name: "keep", Type: "bridge", Iface: "brshr"}); err != nil {
			t.Fatalf("create keep: %v", err)
		}
		n.Net.FailProvision("newb", errors.New("start DHCP on newb: dnsmasq on newb exited immediately: exit status 2"))
		_, err := cl.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{Name: "newb", Type: "bridge", Subnet: subnet})
		plain(t, err)
	})
}

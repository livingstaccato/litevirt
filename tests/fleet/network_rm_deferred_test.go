package fleet

import (
	"context"
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

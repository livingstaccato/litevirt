package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_ReleaseSwitch_FirewallFeatures (merge checklist M8) runs the
// firewall branch's two release features through the real gate. While one
// host is on the previous build the release token cannot latch: an IPv6 rule
// is refused with the release text, an IPv4 rule is written as on main, and a
// new VM is created with its NIC unguarded, as on main. Once every host runs
// this build, the IPv6 rule is written and a new NIC is guarded, and each
// feature's use is on every replica by the time its data is written.
func TestFleet_ReleaseSwitch_FirewallFeatures(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1131)
	a, old := c.Nodes[0], c.Nodes[2]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	cl := c.SelfClient(a)
	rule := func(cidr string) *pb.CreateClusterFirewallRuleRequest {
		return &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: "accept"}}
	}
	createVM := func(name, mac string) {
		t.Helper()
		if _, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: a.Name},
			Network: []*pb.NetworkAttachment{{Name: "lan", Mac: mac}},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
	}

	old.Server.SetWALQuarantined(func() bool { return true }) // the previous build
	_, err := cl.CreateClusterFirewallRule(ctx, rule("2001:db8::/32"))
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (firewall_ipv6 needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("an IPv6 rule mid-roll: %v, want the release refusal", err)
	}
	if _, err := cl.CreateClusterFirewallRule(ctx, rule("10.1.0.0/16")); err != nil {
		t.Fatalf("an IPv4 rule mid-roll: %v", err)
	}
	createVM("pre", "52:54:00:00:0b:01")
	if rec, err := corrosion.GetNICGuard(ctx, a.DB, "pre", "52:54:00:00:0b:01"); err != nil || rec != nil {
		t.Fatalf("a NIC created mid-roll has a guard record: %+v (%v); it must be created as on main", rec, err)
	}
	if _, err := cl.SetNICGuard(ctx, &pb.SetNICGuardRequest{VmName: "pre", Mac: "52:54:00:00:0b:01", Mode: "on"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (nic_guards needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("`nic-guard set` mid-roll: %v, want the release refusal", err)
	}
	for _, n := range c.Nodes {
		for _, f := range []string{"firewall_ipv6", "nic_guards"} {
			if featureUsedOn(t, n, capabilities.ReleaseToken, f) {
				t.Fatalf("%s holds a %s use although every write was refused", n.Name, f)
			}
		}
	}

	old.Server.SetWALQuarantined(old.DB.WALQuarantined) // every host on this build
	eventually(t, 10*time.Second, "an IPv6 rule to be accepted on a uniform fleet", func() bool {
		_, err = cl.CreateClusterFirewallRule(ctx, rule("2001:db8::/32"))
		return err == nil
	})
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "firewall_ipv6") {
			t.Fatalf("%s does not hold the firewall_ipv6 use although the IPv6 rule was written", n.Name)
		}
	}
	createVM("post", "52:54:00:00:0b:02")
	if rec, err := corrosion.GetNICGuard(ctx, a.DB, "post", "52:54:00:00:0b:02"); err != nil || rec == nil || !rec.Guarded() {
		t.Fatalf("a NIC created after the release latched is not guarded: %+v (%v)", rec, err)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "nic_guards") {
			t.Fatalf("%s does not hold the nic_guards use although a guard was written", n.Name)
		}
	}
}

// openNICGuards opens on n what a NIC guard record needs once a cluster has
// finished its upgrade: the cluster_policies gate, and a release-feature gate
// that grants every feature. The fleet's guard tests use it; the real gate is
// TestFleet_ReleaseSwitch_FirewallFeatures's.
func openNICGuards(t *testing.T, n *Node) {
	t.Helper()
	n.DB.SetClusterPolicyGate(func() bool { return true })
	n.Server.SetReleaseFeatureGate(grantAllGate{t: t})
}

// grantAllGate is a release-feature gate past the latch with every use
// recorded: it runs each write with its feature's grant. lagging models a
// node whose own durable latch has not formed yet (FeatureAvailable false).
type grantAllGate struct {
	t       testing.TB
	lagging bool
}

func (g grantAllGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g grantAllGate) FeatureAvailable(capabilities.Feature) bool { return !g.lagging }

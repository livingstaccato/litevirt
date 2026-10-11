package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestFirewallIPv6_ThroughTheReleaseGate: an IPv6 firewall rule is written
// only with a firewall_ipv6 grant from the release-feature gate the daemon
// wires (svc.SetReleaseFeatureGate(d.checker)): refused while a peer runs a
// build without the release token, written once it has latched, with the
// use recorded before the rule. The writer with no grant refuses an IPv6
// rule and writes an IPv4 one, as on main. (firewall_ipv6_v1, which this
// replaced, is retired: capabilities.RetiredFirewallIPv6V1.)
func TestFirewallIPv6_ThroughTheReleaseGate(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	for _, h := range []string{"host-a", "host-b"} {
		if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active", Role: "worker"}); err != nil {
			t.Fatalf("register host: %v", err)
		}
	}
	db.SetClusterPolicyGate(func() bool { return true })
	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetActivationMarker(health.ActivationMarkerBase(t.TempDir()))
	peerOld := true
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		if peerOld {
			var older []string
			for _, tok := range capabilities.Supported() {
				if tok != capabilities.ReleaseToken {
					older = append(older, tok)
				}
			}
			return older, time.Time{}, nil
		}
		return capabilities.Supported(), time.Time{}, nil
	})
	checker.SetReleaseUseConfirmer(func(context.Context, string, string, string) (bool, error) { return true, nil })

	v6 := corrosion.FirewallRule{ID: "r6", Direction: "ingress", Proto: "tcp", PortRange: "22", CIDR: "2001:db8::/32", Action: "accept"}
	write := func(ctx context.Context, g capabilities.FeatureGrant) error {
		return corrosion.InsertClusterFirewallRuleWithGrant(ctx, db, g, v6)
	}
	if err := corrosion.InsertClusterFirewallRule(ctx, db, v6); !errors.Is(err, corrosion.ErrFirewallIPv6GateClosed) {
		t.Errorf("an IPv6 rule with no grant: %v, want ErrFirewallIPv6GateClosed", err)
	}
	v4 := corrosion.FirewallRule{ID: "r4", Direction: "ingress", Proto: "tcp", PortRange: "22", CIDR: "10.0.0.0/8", Action: "accept"}
	if err := corrosion.InsertClusterFirewallRule(ctx, db, v4); err != nil {
		t.Errorf("an IPv4 rule with no grant: %v", err)
	}
	err := checker.WithFeature(ctx, capabilities.FeatureFirewallIPv6, write)
	if err == nil || !strings.Contains(err.Error(), "the cluster upgrade must finish first (firewall_ipv6 needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("an IPv6 rule with a peer on the previous build: %v, want the release refusal", err)
	}
	peerOld = false
	deadline := time.Now().Add(20 * time.Second)
	for err = checker.WithFeature(ctx, capabilities.FeatureFirewallIPv6, write); err != nil && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond) // the latch forms on a later look
		err = checker.WithFeature(ctx, capabilities.FeatureFirewallIPv6, write)
	}
	if err != nil {
		t.Fatalf("an IPv6 rule once every host runs the release: %v", err)
	}
	used, err := corrosion.ReleaseFeatureUsed(ctx, db, capabilities.ReleaseToken, string(capabilities.FeatureFirewallIPv6))
	if err != nil || !used {
		t.Errorf("the IPv6 rule was written with no firewall_ipv6 use recorded: %v %v", used, err)
	}
}

package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// relGate is a release-feature gate that is closed (the release token has not
// latched: it refuses with the gate's text) or open (it records each use
// before it runs the write with a grant), as health.Checker does.
type relGate struct {
	t    testing.TB
	open bool
	used []capabilities.Feature
	// refuseFirstUse: latched, but a first use is refused (a host rolled back
	// after the latch holds it off).
	refuseFirstUse bool
	// calls counts WithFeature calls: a refusal pings every lagging host.
	calls int
}

func (g *relGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.calls++
	if !g.open || g.refuseFirstUse {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s): host old runs an older build",
			f, capabilities.ReleaseToken)
	}
	g.used = append(g.used, f)
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *relGate) FeatureAvailable(capabilities.Feature) bool { return g.open }

func fwReleaseRefusal(f capabilities.Feature) string {
	return fmt.Sprintf("the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
}

// TestReleaseSwitch_NICGuards (merge checklist M8): every NIC guard record
// is written through nic_guards. Before the release token latches, a NIC's
// default guard is not recorded — it is created unguarded, as on main — and
// an explicit guard setting is refused with the release text. After, both
// are written, the use recorded first.
func TestReleaseSwitch_NICGuards(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	admin := adminCtxWithEngine(t, s)
	const mac = "52:54:00:00:0a:01"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running",
		Spec: `{"name":"web","uuid":"u-web"}`}, []corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
	def := []corrosion.NICGuardRecord{{VMName: "web", MAC: mac, Mode: corrosion.NICGuardOn, VMUUID: "u-web", Network: "lan"}}

	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Fatalf("a default guard before the latch refused the create: %v", err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", mac); rec != nil {
		t.Errorf("a default guard was recorded before the release token latched: %+v", rec)
	}
	if g.calls != 0 {
		t.Errorf("a create mid-roll asked the release gate %d time(s); each refusal pings every lagging host, "+
			"so a default guard reads FeatureAvailable first", g.calls)
	}
	off := []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	if _, err := s.admitNICGuards(admin, "web2", off, admitNew); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureNICGuards)) {
		t.Errorf("an explicit guard setting before the latch: %v, want the release refusal", err)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", Mac: mac, Mode: "on"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureNICGuards)) {
		t.Errorf("`nic-guard set` before the latch: %v, want the release refusal", err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", mac); rec != nil {
		t.Errorf("a refused guard was written: %+v", rec)
	}

	// Latched, but a host rolled back after the latch holds the first use
	// off: a default guard is left out as before the latch (the create goes
	// ahead, as on main), and a record that is not the default fails the
	// create rather than go unrecorded.
	g.open, g.refuseFirstUse = true, true
	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Errorf("a default guard refused by the gate failed the create: %v", err)
	}
	relaxed := []corrosion.NICGuardRecord{{VMName: "web", MAC: mac, Mode: corrosion.NICGuardOff, VMUUID: "u-web", Network: "lan"}}
	if err := s.writeNewNICGuards(ctx, relaxed); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a non-default guard refused by the gate: %v, want the refusal", err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", mac); rec != nil {
		t.Errorf("a guard was written although the gate refused it: %+v", rec)
	}

	g.refuseFirstUse = false
	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Fatal(err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", mac); rec == nil || !rec.Guarded() {
		t.Errorf("after the latch the default guard was not recorded: %+v", rec)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", Mac: mac, Mode: "off"}); err != nil {
		t.Errorf("`nic-guard set` after the latch: %v", err)
	}
	if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureNICGuards, capabilities.FeatureNICGuards}) {
		t.Errorf("uses recorded = %v, want nic_guards ahead of each write", g.used)
	}
}

// TestReleaseSwitch_IPv6Rules (merge checklist M8): an IPv6 security-group,
// cluster or host rule and an IPv6 ip-set element are written through
// firewall_ipv6, refused with the release text before the latch; an IPv4 one
// never touches the gate, as on main.
func TestReleaseSwitch_IPv6Rules(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	rule := func(cidr, proto string) *pb.FirewallRule {
		return &pb.FirewallRule{Direction: "ingress", Proto: proto, Port: "22", Cidr: cidr, Action: "accept"}
	}
	writes := func(cidr, proto string) map[string]func() error {
		return map[string]func() error{
			"cluster rule": func() error {
				_, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule(cidr, proto)})
				return err
			},
			"host rule": func() error {
				r := rule(cidr, proto)
				r.HostName = s.hostName
				_, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: r})
				return err
			},
			"sg rule": func() error {
				_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{
					Rule: &pb.SecurityGroupRule{SgId: sg.GetId(), Direction: "ingress", Proto: proto, Port: "22", Cidr: cidr, Action: "accept"}})
				return err
			},
			"ip set": func() error {
				_, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "set-" + strings.NewReplacer(":", "", "/", "", ".", "").Replace(cidr) + proto, Cidrs: []string{cidr}})
				return err
			},
		}
	}
	for what, w := range writes("10.1.0.0/16", "tcp") {
		if err := w(); err != nil {
			t.Errorf("an IPv4 %s with the release token not latched: %v", what, err)
		}
	}
	if len(g.used) != 0 {
		t.Errorf("an IPv4 write went through the release gate: %v", g.used)
	}
	for what, w := range writes("2001:db8::/32", "tcp") {
		if err := w(); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallIPv6)) {
			t.Errorf("an IPv6 %s before the latch: %v, want the release refusal", what, err)
		}
	}
	g.open = true
	for what, w := range writes("2001:db8::/32", "tcp") {
		if err := w(); err != nil {
			t.Errorf("an IPv6 %s after the latch: %v", what, err)
		}
	}
	if len(g.used) != 4 || slices.ContainsFunc(g.used, func(f capabilities.Feature) bool { return f != capabilities.FeatureFirewallIPv6 }) {
		t.Errorf("uses recorded = %v, want firewall_ipv6 ahead of each of the four writes", g.used)
	}
}

// TestReleaseSwitch_StackIPv6Rules (merge checklist M8): a stack's IPv6
// security-group rule, ip-set element and cluster rule go through
// firewall_ipv6 too; an IPv4-only stack never touches the gate.
func TestReleaseSwitch_StackIPv6Rules(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	parse := func(cidr string) *compose.File {
		t.Helper()
		f, err := compose.ParseBytes([]byte(`
name: v6stack
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "` + cidr + `", action: accept}
ipsets:
  admins:
    cidrs: ["` + cidr + `"]
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + cidr + `", action: accept}
`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(ctx, parse("10.0.0.0/24")); err != nil || len(g.used) != 0 {
		t.Fatalf("an IPv4 stack firewall with the release not latched: %v (uses %v)", err, g.used)
	}
	if err := s.persistStackFirewall(ctx, parse("2001:db8::/32")); err == nil || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallIPv6)) {
		t.Errorf("an IPv6 stack firewall before the latch: %v, want the release refusal", err)
	}
	g.open = true
	if err := s.persistStackFirewall(ctx, parse("2001:db8::/32")); err != nil {
		t.Fatalf("an IPv6 stack firewall after the latch: %v", err)
	}
	if len(g.used) != 3 {
		t.Errorf("uses recorded = %v, want firewall_ipv6 ahead of each of the three IPv6 rows", g.used)
	}
}

package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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
	// refuseCode is the code of a first-use refusal (FailedPrecondition when
	// unset); a first use's ack wait that runs out is Unavailable.
	refuseCode codes.Code
	// block: WithFeature waits for its context to end (an ack that never
	// comes).
	block bool
	// lagging: this node's own durable latch has not formed
	// (FeatureAvailable false); WithFeature drives it, so it still grants.
	lagging bool
	// refusals counts FeatureRefusal calls (the non-recording entry check).
	refusals int
}

func (g *relGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.calls++
	if g.block {
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	}
	if !g.open {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s): host old runs an older build",
			f, capabilities.ReleaseToken)
	}
	if g.refuseFirstUse {
		code := g.refuseCode
		if code == codes.OK {
			code = codes.FailedPrecondition
		}
		return status.Errorf(code, "the cluster upgrade must finish first (%s needs %s): not yet acknowledged by host-c",
			f, capabilities.ReleaseToken)
	}
	g.used = append(g.used, f)
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *relGate) FeatureAvailable(capabilities.Feature) bool { return g.open && !g.lagging }

func (g *relGate) FeatureRefusal(_ context.Context, f capabilities.Feature) error {
	g.refusals++
	if g.open {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s): host old runs an older build",
		f, capabilities.ReleaseToken)
}

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
	// One up front, before the stack's old rows are torn down (re-review
	// N2), then one ahead of each of the three IPv6 rows.
	if len(g.used) != 4 {
		t.Errorf("uses recorded = %v, want firewall_ipv6 before the teardown and ahead of each of the three IPv6 rows", g.used)
	}
}

func r6VM(t *testing.T, s *Server, name, mac string) []corrosion.NICGuardRecord {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running",
		Spec: `{"name":"` + name + `","uuid":"u-` + name + `"}`}, []corrosion.InterfaceRecord{{VMName: name, NetworkName: "lan", MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
	return []corrosion.NICGuardRecord{{VMName: name, MAC: mac, Mode: corrosion.NICGuardOn, VMUUID: "u-" + name, Network: "lan"}}
}

// TestSwitchFix_DefaultGuardNeverFailsACreate (switch review I1): after the
// latch, a default guard whose first use the gate cannot complete — any
// refusal, Unavailable included, or an ack that never comes — leaves the NIC
// unguarded, as main created it, within a bounded wait: the create never
// fails or stalls for it.
func TestSwitchFix_DefaultGuardNeverFailsACreate(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	g := guardRelease(s)
	g.refuseFirstUse, g.refuseCode = true, codes.Unavailable
	def := r6VM(t, s, "web", "52:54:00:00:0c:01")
	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Errorf("a default guard the gate refused with Unavailable failed the create: %v", err)
	}
	g.refuseFirstUse, g.block = false, true
	start := time.Now()
	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Errorf("a default guard whose ack never came failed the create: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a default guard held the create for %v; its gate call is bounded at %v", d, defaultGuardGateBudget)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:0c:01"); rec != nil {
		t.Errorf("a guard was recorded although the gate never granted: %+v", rec)
	}
}

// TestSwitchFix_UsedFeatureGoesThroughTheGate (switch review I2): on a node
// whose own release latch lags (a host that just joined, or just after the
// roll), once nic_guards is recorded used a create goes through the gate —
// which forms the latch there — rather than drop the guard; and a guard
// carried by a re-create is never dropped: a gate that still refuses fails
// the re-create.
func TestSwitchFix_UsedFeatureGoesThroughTheGate(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	g := guardRelease(s)
	g.lagging = true
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken, string(capabilities.FeatureNICGuards), "peer", false); err != nil {
		t.Fatal(err)
	}
	carried := r6VM(t, s, "rebuilt", "52:54:00:00:0c:02")
	// What a re-create's decision makes of the replaced incarnation's record.
	d := guardDecision{carry: &carried[0]}
	rec := d.record("rebuilt", "u-rebuilt", 0, "52:54:00:00:0c:02", &pb.NetworkAttachment{Name: "lan"})
	if rec == nil || !rec.Carried {
		t.Fatalf("a re-create's carried record is not marked carried: %+v", rec)
	}
	carried[0] = *rec
	if err := s.writeNewNICGuards(ctx, carried); err != nil {
		t.Fatalf("a carried guard on a lagging node: %v", err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "rebuilt", "52:54:00:00:0c:02"); rec == nil || !rec.Guarded() {
		t.Errorf("a re-create on a lagging node dropped its carried guard: %+v", rec)
	}
	fresh := r6VM(t, s, "fresh", "52:54:00:00:0c:03")
	if err := s.writeNewNICGuards(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "fresh", "52:54:00:00:0c:03"); rec == nil {
		t.Error("a new NIC on a lagging node in a cluster that uses guards was left unguarded")
	}

	g.refuseFirstUse = true
	again := r6VM(t, s, "again", "52:54:00:00:0c:04")
	again[0].Carried = true
	if err := s.writeNewNICGuards(ctx, again); err == nil {
		t.Error("a carried guard the gate refused was dropped silently; the re-create must fail instead")
	}
}

// TestSwitchFix_SetValidatesBeforeTheGrant (switch review m1): a malformed
// allowed address is refused before the gate records any use.
func TestSwitchFix_SetValidatesBeforeTheGrant(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	g := guardRelease(s)
	admin := adminCtxWithEngine(t, s)
	r6VM(t, s, "web", "52:54:00:00:0c:05")
	_, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", Mac: "52:54:00:00:0c:05", Mode: "on",
		AllowedAddresses: []string{"10.0.0.1; drop"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("a malformed allowed address: %v, want InvalidArgument", err)
	}
	if g.calls != 0 || len(g.used) != 0 {
		t.Errorf("a refused request reached the gate (%d calls, uses %v)", g.calls, g.used)
	}
	_ = ctx
}

// TestSwitchFix_StackGatesBeforeTeardown (switch review m2, m5): a stack
// redeploy validates every firewall row and asks the release gate for an
// IPv6 one before it touches the stack's existing rows: a refusal leaves
// them as they were, and its text is the gate's, not a nested rpc error. A
// malformed row is refused before any use is recorded.
func TestSwitchFix_StackGatesBeforeTeardown(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	parse := func(rules string) *compose.File {
		t.Helper()
		// ParseStored: the daemon's own refusal is under test, and the compose
		// validator now refuses a malformed row before it ever reaches it.
		f, err := compose.ParseStored([]byte("name: st\nsecurity-groups:\n  web:\n    rules:\n" + rules))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
`)); err != nil {
		t.Fatal(err)
	}
	before, _ := corrosion.ListSecurityGroups(ctx, s.db, "st")
	err := s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
      - {direction: ingress, proto: tcp, port: "443", cidr: "2001:db8::/32", action: accept}
`))
	if status.Code(err) != codes.FailedPrecondition || strings.Contains(status.Convert(err).Message(), "rpc error") ||
		!strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallIPv6)) {
		t.Errorf("an IPv6 stack row mid-roll: %v, want the gate's refusal, unnested", err)
	}
	after, _ := corrosion.ListSecurityGroups(ctx, s.db, "st")
	if len(before) != 1 || len(after) != 1 || after[0].ID != before[0].ID {
		t.Errorf("a refused redeploy changed the stack's firewall: before %+v, after %+v", before, after)
	} else if rules, _ := corrosion.ListSGRules(ctx, s.db, after[0].ID); len(rules) != 1 {
		t.Errorf("a refused redeploy changed the stack's rules: %+v", rules)
	}
	g.open = true
	err = s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "443", cidr: "2001:db8::/32", action: accept}
      - {direction: ingress, proto: tcp, port: "22", cidr: "2001:db8::/300", action: accept}
`))
	if err == nil || len(g.used) != 0 {
		t.Errorf("a stack with a malformed row: %v (uses %v); want refused before any use", err, g.used)
	}
	g.open = false
	err = stackFirewallErr(s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "443", cidr: "2001:db8::/32", action: accept}
`)))
	if status.Code(err) != codes.FailedPrecondition || strings.Contains(status.Convert(err).Message(), "rpc error") ||
		!strings.HasPrefix(status.Convert(err).Message(), "firewall config: "+fwReleaseRefusal(capabilities.FeatureFirewallIPv6)) {
		t.Errorf("the deploy's error = %v, want the gate's refusal under \"firewall config:\" with no nested rpc error", err)
	}
}

// TestSwitchFix_MainShapesMidRoll (switch review m3): the rule shapes main
// accepted — icmpv6 with no CIDR or an IPv4 one — are written mid-roll with
// no gate, as on main; an IPv6 ip-set element, which main's renderer could not
// express, stays the feature's.
func TestSwitchFix_MainShapesMidRoll(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	for _, cidr := range []string{"", "10.0.0.0/8"} {
		for _, proto := range []string{"icmpv6", "ipv6-icmp"} {
			if _, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
				Direction: "ingress", Proto: proto, Cidr: cidr, Action: "accept"}}); err != nil {
				t.Errorf("proto %s cidr %q, a shape main accepted, mid-roll: %v", proto, cidr, err)
			}
		}
	}
	if g.calls != 0 {
		t.Errorf("a shape main accepted went through the release gate (%d calls)", g.calls)
	}
	if _, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "v6", Cidrs: []string{"2001:db8::/32"}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an IPv6 ip-set element mid-roll: %v, want the release refusal", err)
	}
}

// TestSwitchFix_EntryCheckUsesTheGatesRefusal (switch review m4): the entry
// check for an explicit guard setting is the gate's non-recording refusal
// (it names the lagging hosts and drives the latch), not a synthesized text.
func TestSwitchFix_EntryCheckUsesTheGatesRefusal(t *testing.T) {
	s := guardServer(t, true)
	g := guardRelease(s)
	g.open = false
	off := []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	_, err := s.admitNICGuards(adminCtxWithEngine(t, s), "vm", off, admitNew)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "host old runs an older build") || g.refusals != 1 {
		t.Errorf("explicit setting mid-roll: %v (%d FeatureRefusal calls), want the gate's refusal", err, g.refusals)
	}
	if len(g.used) != 0 {
		t.Errorf("the entry check recorded a use: %v", g.used)
	}
}

// TestSwitchFix_GateFailureKeepsItsCode (switch review m5): a guard refused
// by the gate fails a NIC hot-attach with the gate's code and message, not
// Internal around a nested rpc error.
func TestSwitchFix_GateFailureKeepsItsCode(t *testing.T) {
	code, cause := gateFailure(status.Error(codes.Unavailable, "not yet acknowledged by host-c"))
	if code != codes.Unavailable || cause.Error() != "not yet acknowledged by host-c" {
		t.Errorf("gateFailure = %v, %q", code, cause)
	}
	if code, _ := gateFailure(errors.New("disk full")); code != codes.Internal {
		t.Errorf("a plain error: %v, want Internal", code)
	}
}

// policyLatchGate is a server gate whose failover_scope_v1 latch forms when
// it is driven (Enforced), as a host that just joined forms it.
type policyLatchGate struct {
	fakeServerGate
	latched *bool
	driven  int
}

func (g *policyLatchGate) Enforced(_ context.Context, token string) bool {
	if token == capabilities.FailoverScopeV1 {
		g.driven++
		*g.latched = true
		return true
	}
	return false
}

// TestSwitchFix2_CarriedNeverDroppedBeforeThePolicyLatch (switch re-review
// N1): on a host whose own failover_scope_v1 latch has not formed (one that
// just joined), a carried guard is not dropped: the latch is driven here, and
// if it still cannot form the re-create is refused. A default guard is left
// out, as before.
func TestSwitchFix2_CarriedNeverDroppedBeforeThePolicyLatch(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	latched := false
	s.db.SetClusterPolicyGate(func() bool { return latched })

	carried := r6VM(t, s, "rebuilt", "52:54:00:00:0d:01")
	d := guardDecision{carry: &carried[0]}
	rec := d.record("rebuilt", "u-rebuilt", 0, "52:54:00:00:0d:01", &pb.NetworkAttachment{Name: "lan"})
	if err := s.writeNewNICGuards(ctx, []corrosion.NICGuardRecord{*rec}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a carried guard before this host's policy latch, latch not formable: %v, want FailedPrecondition", err)
	}
	def := r6VM(t, s, "fresh", "52:54:00:00:0d:02")
	if err := s.writeNewNICGuards(ctx, def); err != nil {
		t.Errorf("a default guard before the policy latch failed the create: %v", err)
	}

	g := &policyLatchGate{latched: &latched}
	s.SetGate(g)
	if err := s.writeNewNICGuards(ctx, []corrosion.NICGuardRecord{*rec}); err != nil {
		t.Fatalf("a carried guard once the policy latch can form here: %v", err)
	}
	if got, _ := corrosion.GetNICGuard(ctx, s.db, "rebuilt", "52:54:00:00:0d:01"); got == nil || g.driven == 0 {
		t.Errorf("the carried guard was not written after driving the latch (driven %d): %+v", g.driven, got)
	}
}

// TestSwitchFix2_ExplicitNeverDropped (switch re-review N3): a guard the
// request asked for — `spoof_guard: on`, even with no relaxation, so with the
// default's shape — is never dropped: a gate that fails its first use fails
// the create. Only an implicit default falls back.
func TestSwitchFix2_ExplicitNeverDropped(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	g := guardRelease(s)
	g.refuseFirstUse, g.refuseCode = true, codes.Unavailable
	r6VM(t, s, "asked", "52:54:00:00:0d:03")
	var d guardDecision
	rec := d.record("asked", "u-asked", 0, "52:54:00:00:0d:03", &pb.NetworkAttachment{Name: "lan", SpoofGuard: "on"})
	if err := s.writeNewNICGuards(ctx, []corrosion.NICGuardRecord{*rec}); err == nil {
		t.Error("an explicit `spoof_guard: on` the gate refused was dropped silently; the create must fail")
	}
	implicit := d.record("asked", "u-asked", 0, "52:54:00:00:0d:03", &pb.NetworkAttachment{Name: "lan"})
	if err := s.writeNewNICGuards(ctx, []corrosion.NICGuardRecord{*implicit}); err != nil {
		t.Errorf("an implicit default the gate refused failed the create: %v", err)
	}
}

// TestSwitchFix2_StackFirstUseBeforeTeardown (switch re-review N2): a stack
// redeploy holding an IPv6 row takes the firewall_ipv6 first use before it
// tears anything down: a first use the gate cannot complete (a recipient that
// never acks) leaves every old row, default-deny included, as it was.
func TestSwitchFix2_StackFirstUseBeforeTeardown(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	parse := func(cidr string) *compose.File {
		t.Helper()
		f, err := compose.ParseBytes([]byte(`
name: dd
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
      - {direction: ingress, proto: tcp, port: "443", cidr: "` + cidr + `", action: accept}
firewall:
  default-deny: true
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "10.0.0.0/8", action: accept}
`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(ctx, parse("10.1.0.0/16")); err != nil {
		t.Fatal(err)
	}
	g.refuseFirstUse, g.refuseCode = true, codes.Unavailable
	if err := s.persistStackFirewall(ctx, parse("2001:db8::/32")); err == nil {
		t.Fatal("a redeploy whose IPv6 first use was refused reported success")
	}
	def, err := corrosion.GetFirewallDefault(ctx, s.db, "cluster")
	if err != nil || def == nil || !def.DefaultDeny {
		t.Errorf("the stack's default-deny was torn down by a refused redeploy: %+v %v", def, err)
	}
	sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "dd")
	rules, _ := corrosion.ListClusterFirewallRules(ctx, s.db)
	if len(sgs) != 1 || len(rules) != 1 {
		t.Errorf("a refused redeploy changed the stack's rows: groups %+v, cluster rules %+v", sgs, rules)
	} else if r, _ := corrosion.ListSGRules(ctx, s.db, sgs[0].ID); len(r) != 2 {
		t.Errorf("a refused redeploy changed the stack's rules: %+v", r)
	}
}

// TestSwitchFix3_StackDefaultNeverFailsOpen (switch re-review 2, R1): a
// redeploy of a stack with default-deny whose row rewrite fails part way —
// here the second security-group rule insert — leaves the cluster default
// denying: the default is not torn down with the rows.
func TestSwitchFix3_StackDefaultNeverFailsOpen(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	f, err := compose.ParseBytes([]byte(`
name: dd
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
      - {direction: ingress, proto: tcp, port: "443", cidr: "10.0.0.0/8", action: accept}
firewall:
  default-deny: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(ctx, f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.DB().ExecContext(ctx, `CREATE TRIGGER r1_fail_second BEFORE INSERT ON sg_rules
		WHEN (SELECT COUNT(*) FROM sg_rules WHERE deleted_at IS NULL) >= 1
		BEGIN SELECT RAISE(ABORT, 'injected write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(ctx, f); err == nil {
		t.Fatal("fixture: the redeploy did not fail")
	}
	if def, err := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); err != nil || def == nil || !def.DefaultDeny {
		t.Errorf("a redeploy that failed part way left the cluster default-allow: %+v %v", def, err)
	}
	// A redeploy that drops default-deny removes the stack's default once its
	// rows are written.
	if _, err := s.db.DB().ExecContext(ctx, `DROP TRIGGER r1_fail_second`); err != nil {
		t.Fatal(err)
	}
	f2, err := compose.ParseBytes([]byte(`
name: dd
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(ctx, f2); err != nil {
		t.Fatal(err)
	}
	if def, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); def != nil {
		t.Errorf("a redeploy that dropped default-deny kept the stack's default: %+v", def)
	}
}

// r3GuardedVM is a VM on this host whose NIC has a guard record, on a host
// whose own failover_scope_v1 latch has not formed and cannot form here.
func r3GuardedVM(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	const mac = "52:54:00:00:0e:01"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"lan"}]}`},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: "web", MAC: mac, Mode: corrosion.NICGuardOn, VMUUID: "u-web", Network: "lan"}, "t"); err != nil {
		t.Fatal(err)
	}
	s.db.SetClusterPolicyGate(func() bool { return false })
}

// TestSwitchFix3_CarriedGuardRefusedBeforeTheDelete (switch re-review 2, R2):
// a rebuild or a stack's re-create of a VM whose guard this host could not
// carry (its own failover_scope_v1 latch cannot form) is refused before the
// old incarnation is deleted, so the VM is left as it was.
func TestSwitchFix3_CarriedGuardRefusedBeforeTheDelete(t *testing.T) {
	ctx := adminCtx()
	for _, how := range []string{"rebuild", "recreate"} {
		t.Run(how, func(t *testing.T) {
			s := guardServer(t, true)
			s.virt = libvirtfake.New()
			s.dataDir = t.TempDir()
			s.images = image.NewStore(s.dataDir)
			_ = s.images.Init()
			r3GuardedVM(t, s)
			var err error
			if how == "rebuild" {
				_, err = s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"})
			} else {
				spec := &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Network: []*pb.NetworkAttachment{{Name: "lan"}}}
				err = (&serverOps{s: s}).RecreateVM(ctx, "web", spec)
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "failover_scope_v1") {
				t.Errorf("%s of a guarded VM this host could not carry: %v, want a FailedPrecondition naming failover_scope_v1", how, err)
			}
			if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil {
				t.Errorf("the %s was refused after the old incarnation was deleted", how)
			}
		})
	}
	// The create's own admission refuses a carried guard it cannot write,
	// before it claims anything.
	s := guardServer(t, true)
	r3GuardedVM(t, s)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	_, err := s.admitNICGuards(withReplacedVM(ctx, vm), "web",
		[]*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:0e:01"}}, admitRecreate)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "failover_scope_v1") {
		t.Errorf("admitting a re-create carrying a guard this host cannot write: %v, want FailedPrecondition", err)
	}
}

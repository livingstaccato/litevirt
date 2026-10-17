package grpcapi

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// tagRuleServer is a server with release gate g (closed), a security group
// "app", and handlers writing one rule of each tier with cidr and action.
func tagRuleServer(t *testing.T) (*Server, *relGate, context.Context, func(cidr, action string) map[string]func() error) {
	t.Helper()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "app"})
	if err != nil {
		t.Fatal(err)
	}
	writes := func(cidr, action string) map[string]func() error {
		rule := func() *pb.FirewallRule {
			return &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "5432", Cidr: cidr, Action: action}
		}
		return map[string]func() error{
			"cluster rule": func() error {
				_, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule()})
				return err
			},
			"host rule": func() error {
				r := rule()
				r.HostName = s.hostName
				_, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: r})
				return err
			},
			"sg rule": func() error {
				_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
					SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Port: "5432", Cidr: cidr, Action: action}})
				return err
			},
		}
	}
	return s, g, ctx, writes
}

// tagRuleCount is the number of stored rules of every tier whose cidr is
// cidr.
func tagRuleCount(t *testing.T, s *Server, cidr string) int {
	t.Helper()
	bg := context.Background()
	n := 0
	cl, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil {
		t.Fatal(err)
	}
	ho, err := corrosion.ListHostFirewallRules(bg, s.db, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range append(cl, ho...) {
		if r.CIDR == cidr {
			n++
		}
	}
	sgs, err := corrosion.ListSecurityGroups(bg, s.db, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range sgs {
		rules, err := corrosion.ListSGRules(bg, s.db, sg.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.CIDR == cidr {
				n++
			}
		}
	}
	return n
}

func setTagGroup(t *testing.T, s *Server, name string) {
	t.Helper()
	if err := corrosion.SetFirewallTagGroup(context.Background(), s.db, capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups),
		name, &corrosion.FirewallTagGroupDef{Match: map[string]string{"role": name}}, "test"); err != nil {
		t.Fatal(err)
	}
}

// D5a: a rule with tag:<name> goes through the firewall_tag_groups gate at
// every rule handler: before the latch it is refused with the release text;
// after it, a rule naming a group this replica does not hold (never set, or
// removed) is refused (FailedPrecondition) and nothing is stored, and one
// naming a group that exists — readable or not — is written, its use
// recorded.
//
// Mutations: drop refuseUnknownTagGroup from any handler — tag:nope is
// stored there, red; ask it before the gate — the pre-latch refusal is the
// unknown-group text, red; treat an unreadable group as missing — tag:bad is
// refused, red.
func TestTagRule_UnknownGroupRefusedAtEveryHandler(t *testing.T) {
	s, g, ctx, writes := tagRuleServer(t)

	for what, w := range writes("tag:web", "accept") {
		err := w()
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
			t.Errorf("before the latch: %s: %v, want the release refusal", what, err)
		}
	}

	g.open = true
	setTagGroup(t, s, "gone")
	if err := corrosion.SetFirewallTagGroup(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups), "gone", nil, "test"); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"tag:nope", "tag:gone"} {
		for what, w := range writes(cidr, "drop") {
			err := w()
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not exist") {
				t.Errorf("%s: %s: %v, want FailedPrecondition \"does not exist\"", what, cidr, err)
			}
		}
		if n := tagRuleCount(t, s, cidr); n != 0 {
			t.Errorf("%s: %d rule(s) stored for a group that does not exist", cidr, n)
		}
	}

	setTagGroup(t, s, "web")
	if err := s.db.Execute(context.Background(),
		`INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES ('firewall_tag_group/bad', '{', 'x', 't')`); err != nil {
		t.Fatal(err)
	}
	g.used = nil
	for _, cidr := range []string{"tag:web", "tag:bad"} {
		for what, w := range writes(cidr, "accept") {
			if err := w(); err != nil {
				t.Errorf("%s: %s: %v", what, cidr, err)
			}
		}
		if n := tagRuleCount(t, s, cidr); n != 3 {
			t.Errorf("%s: %d rule(s) stored, want one per tier", cidr, n)
		}
	}
	if len(g.used) != 6 || slices.ContainsFunc(g.used, func(f capabilities.Feature) bool { return f != capabilities.FeatureFirewallTagGroups }) {
		t.Errorf("uses recorded = %v, want firewall_tag_groups for each rule", g.used)
	}
}

// D5a (D4 re-review m-C): no rule handler stores a cidr referencing a
// reserved set — a tag group's own set, bare or negated, IPv6 companion
// included, or any other lv_* set. Each is refused as InvalidArgument before
// any gate is asked; a tag group's set is refused naming tag:<group>.
//
// Mutation: drop the reserved-prefix check from rulefield.SetName and the
// tag-group branch from rulefield's set reference check — red.
func TestTagRule_ReservedSetReferenceRefused(t *testing.T) {
	s, g, _, writes := tagRuleServer(t)
	g.open = true
	setTagGroup(t, s, "web")
	for cidr, want := range map[string]string{
		"@lv_tg_web":       "tag:web",
		"!= @lv_tg_web":    "tag:web",
		"@lv_tg_web_v6":    "tag:web",
		"ne @lv_tg_web_v6": "tag:web",
		"@lv_gw4":          `"lv_"`,
		"!= @lv_office":    `"lv_"`,
	} {
		for what, w := range writes(cidr, "drop") {
			err := w()
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %s: %v, want InvalidArgument naming %s", what, cidr, err, want)
			}
		}
		if n := tagRuleCount(t, s, cidr); n != 0 {
			t.Errorf("%s: %d rule(s) stored", cidr, n)
		}
	}
	if g.calls != 0 {
		t.Errorf("a refused reference asked the gate %d time(s)", g.calls)
	}
}

// D5a: CreateIpSet refuses a set named lv_* as InvalidArgument naming the
// reserved prefix, before any gate is asked; another name is created as
// before.
//
// Mutation: drop the reserved-prefix check from rulefield.SetName — red.
func TestCreateIpSet_ReservedPrefixRefused(t *testing.T) {
	s, g, ctx, _ := tagRuleServer(t)
	g.open = true
	for _, name := range []string{"lv_gw4", "lv_tg_web", "lv_tg_web_v6", "lv_office"} {
		_, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: name, Cidrs: []string{"2001:db8::/32"}})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), `"lv_"`) {
			t.Errorf("%s: %v, want InvalidArgument naming the reserved prefix", name, err)
		}
	}
	if g.calls != 0 {
		t.Errorf("the release gate was asked for a refused set (%d calls)", g.calls)
	}
	if _, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "office", Cidrs: []string{"10.0.0.0/8"}}); err != nil {
		t.Errorf("office: %v", err)
	}
}

// D5a: a stack deploy naming a tag group that does not exist is refused
// before its rows are torn down; before the latch it is refused with the
// release text, rows kept; naming one that exists it deploys.
//
// Mutation: drop the stack's unknown-group check — tag:nope is stored, red;
// move it after the teardown — the old rule is gone, red.
func TestStackFirewall_UnknownTagGroupRefusedBeforeTeardown(t *testing.T) {
	s, g, _, _ := tagRuleServer(t)
	bg := context.Background()
	parse := func(sgCIDR, clusterCIDR string) *compose.File {
		t.Helper()
		f, err := compose.ParseStored([]byte(`
name: fwstack
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "` + sgCIDR + `", action: accept}
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + clusterCIDR + `", action: drop}
`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(bg, parse("10.0.0.0/8", "10.1.0.0/16")); err != nil {
		t.Fatal(err)
	}
	before, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil || len(before) != 1 {
		t.Fatalf("stack rules = %v, %v", before, err)
	}
	kept := func(when string) {
		t.Helper()
		after, err := corrosion.ListClusterFirewallRules(bg, s.db)
		if err != nil || len(after) != 1 || after[0].ID != before[0].ID {
			t.Errorf("%s: stack rules = %v, %v; want the old rule kept", when, after, err)
		}
	}
	if err := s.persistStackFirewall(bg, parse("tag:web", "10.1.0.0/16")); err == nil ||
		!strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Errorf("before the latch: %v, want the release refusal", err)
	}
	kept("before the latch")

	g.open = true
	setTagGroup(t, s, "web")
	for _, c := range []struct {
		f     *compose.File
		where string
	}{{parse("tag:nope", "10.1.0.0/16"), `security-group "web" rule: `}, {parse("tag:web", "tag:nope"), "cluster rule: "}} {
		err := s.persistStackFirewall(bg, c.f)
		if err == nil || !strings.Contains(err.Error(), `tag group "nope" does not exist`) {
			t.Errorf("an unknown group: %v, want refused", err)
		}
		kept("an unknown group")
		// As the deploy returns it (review m-2): the code, which rule, and
		// no rpc error nested in the message.
		st := status.Convert(stackFirewallErr(err))
		if st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), c.where+`cidr "tag:nope": tag group "nope" does not exist`) ||
			strings.Contains(st.Message(), "rpc error") {
			t.Errorf("deploy error = %v, want FailedPrecondition naming %q", st.Err(), c.where)
		}
	}
	if err := s.persistStackFirewall(bg, parse("tag:web", "tag:web")); err != nil {
		t.Fatalf("a known group: %v", err)
	}
	if n := tagRuleCount(t, s, "tag:web"); n != 2 {
		t.Errorf("tag:web rules = %d, want the sg and the cluster rule", n)
	}
}

// firstUseWatch is a relGate that runs onUse when a feature's first use is
// granted, before the write it guards.
type firstUseWatch struct {
	*relGate
	onUse func(capabilities.Feature)
}

func (g *firstUseWatch) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return g.relGate.WithFeature(ctx, f, func(ctx context.Context, grant capabilities.FeatureGrant) error {
		g.onUse(f)
		return write(ctx, grant)
	})
}

// D5b (spec §4.8): a stack deploy holding a tag: cidr takes the
// firewall_tag_groups first use before it tears the stack's rows down, as
// for IPv6. A first use the gate cannot complete (a recipient that never
// acks) leaves every old row, default-deny included, as it was; one that
// completes is taken while the old rows are still there.
//
// Mutations: the preflight takes no first use (the per-row write takes it,
// after the teardown) — red; the default-deny written ahead of the first use
// — red for an old stack without one (review m-4).
func TestStackFirewall_TagFirstUseBeforeTeardown(t *testing.T) {
	bg := context.Background()
	parse := func(sgCIDR, clusterCIDR string, deny bool) *compose.File {
		t.Helper()
		f, err := compose.ParseStored([]byte(`
name: dd
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
      - {direction: ingress, proto: tcp, port: "443", cidr: "` + sgCIDR + `", action: drop}
firewall:
  default-deny: ` + strconv.FormatBool(deny) + `
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + clusterCIDR + `", action: accept}
`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	for _, c := range []struct {
		name, sgCIDR, clusterCIDR string
		oldDeny                   bool
	}{
		{"in a security-group rule", "tag:web", "10.0.0.0/8", true},
		{"in a cluster rule", "10.1.0.0/16", "tag:web", true},
		{"over a stack without default-deny", "tag:web", "10.0.0.0/8", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, g, _, _ := tagRuleServer(t)
			g.open = true
			setTagGroup(t, s, "web")
			if err := s.persistStackFirewall(bg, parse("10.1.0.0/16", "10.0.0.0/8", c.oldDeny)); err != nil {
				t.Fatal(err)
			}
			oldSG, _ := corrosion.ListSecurityGroups(bg, s.db, "dd")
			oldRules, _ := corrosion.ListClusterFirewallRules(bg, s.db)
			if len(oldSG) != 1 || len(oldRules) != 1 {
				t.Fatalf("premise: groups %+v, cluster rules %+v", oldSG, oldRules)
			}
			unchanged := func() bool {
				sgs, _ := corrosion.ListSecurityGroups(bg, s.db, "dd")
				rules, _ := corrosion.ListClusterFirewallRules(bg, s.db)
				def, err := corrosion.GetFirewallDefault(bg, s.db, "cluster")
				if err != nil || (def != nil && def.DefaultDeny) != c.oldDeny {
					return false
				}
				if len(sgs) != 1 || sgs[0].ID != oldSG[0].ID || len(rules) != 1 || rules[0].ID != oldRules[0].ID {
					return false
				}
				r, _ := corrosion.ListSGRules(bg, s.db, sgs[0].ID)
				return len(r) == 2
			}

			g.refuseFirstUse, g.refuseCode = true, codes.Unavailable
			err := s.persistStackFirewall(bg, parse(c.sgCIDR, c.clusterCIDR, true))
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
				t.Fatalf("a redeploy whose tag-group first use was refused: %v, want Unavailable with the tag-group release text", err)
			}
			if !unchanged() {
				t.Error("a redeploy whose tag-group first use was refused changed the stack's rows or its default-deny")
			}
			if tagRuleCount(t, s, "tag:web") != 0 {
				t.Error("a refused redeploy stored a tag: rule")
			}

			g.refuseFirstUse = false
			taken := false
			s.SetReleaseFeatureGate(&firstUseWatch{relGate: g, onUse: func(f capabilities.Feature) {
				if f == capabilities.FeatureFirewallTagGroups && !taken {
					taken = true
					if !unchanged() {
						t.Error("the tag-group first use was taken after the stack's rows were torn down")
					}
				}
			}})
			if err := s.persistStackFirewall(bg, parse(c.sgCIDR, c.clusterCIDR, c.oldDeny)); err != nil {
				t.Fatalf("the redeploy once the first use completes: %v", err)
			}
			if !taken || !slices.Contains(g.used, capabilities.FeatureFirewallTagGroups) {
				t.Errorf("no tag-group first use recorded: %v", g.used)
			}
			if n := tagRuleCount(t, s, "tag:web"); n != 1 {
				t.Errorf("tag:web rules = %d, want 1", n)
			}
		})
	}
}

// D5a (0-F): the sweep's probes include firewall_tag_groups' data. A tag
// rule an older entry daemon stored verbatim, with no recorded use, has its
// use recorded by the lease holder's sweep; with no data nothing is recorded.
//
// Mutation: leave releaseUseProbes without the tag-group probe — red.
func TestReleaseUseSweep_TagGroupsProbe(t *testing.T) {
	s, g, _, _ := sweepServer(t, "")
	g.open = true
	ctx := context.Background()
	s.sweepReleaseUses(ctx, releaseUseProbes)
	if len(g.used) != 0 {
		t.Fatalf("with no data the sweep recorded %v", g.used)
	}
	if err := s.db.Execute(ctx, `INSERT INTO host_firewall_rules (id, host_name, direction, proto, port_range, cidr, action, priority, comment, created_at, updated_at)
		VALUES ('h', 'node-0', 'ingress', 'tcp', '', 'tag:web', 'drop', 100, '', 't', 't')`); err != nil {
		t.Fatal(err)
	}
	s.sweepReleaseUses(ctx, releaseUseProbes)
	if !slices.Contains(g.used, capabilities.FeatureFirewallTagGroups) {
		t.Errorf("uses recorded = %v, want firewall_tag_groups", g.used)
	}
}

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
	"github.com/litevirt/litevirt/internal/corrosion"
)

// D6 (spec §4.2, §4.8): the tag-group RPCs.

func tagGroupReq(name string, match map[string]string, sgs ...string) *pb.SetFirewallTagGroupRequest {
	return &pb.SetFirewallTagGroupRequest{Group: &pb.FirewallTagGroup{Name: name, Match: match, SecurityGroups: sgs}}
}

func tagGroupExists(t *testing.T, s *Server, name string) bool {
	t.Helper()
	_, ok, err := corrosion.GetFirewallTagGroup(context.Background(), s.db, name)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// tagGroupMember gives VM name, on network prod (10.0.0.0/24), the identity
// id and tags role=web; with ip set, a live allocator lease of ip on its NIC.
func tagGroupMember(t *testing.T, s *Server, name, id, mac, ip string) {
	t.Helper()
	ctx := context.Background()
	insertTestVM(t, adminCtx(), s.db, name, s.hostName, "running")
	setVMSpec(t, s, name, fmt.Sprintf(`{"name":%q,"firewall_id":%q}`, name, id))
	if err := s.db.Execute(ctx, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, updated_at) VALUES (?, 'prod', 0, ?, '', 't')`,
		name, mac); err != nil {
		t.Fatal(err)
	}
	if ip != "" {
		if err := s.db.Execute(ctx, `INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			VALUES ('prod', ?, ?, ?, 'vm', '', 't', 't')`, ip, mac, name); err != nil {
			t.Fatal(err)
		}
	}
	seedTagsFor(t, s, corrosion.TagMemberVM, id, map[string]string{"role": "web"}, name, "")
}

func tagGroupSG(t *testing.T, s *Server, name string) {
	t.Helper()
	if _, err := s.CreateSecurityGroup(adminCtx(), &pb.CreateSecurityGroupRequest{Name: name}); err != nil {
		t.Fatal(err)
	}
}

func tagGroupNetwork(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO networks (name, type, config, created_at, updated_at) VALUES ('prod', 'bridge', '{"Subnet":"10.0.0.0/24"}', 't', 't')`); err != nil {
		t.Fatal(err)
	}
}

// `tag-group set` and `rm` need sg.write at the cluster root (Operator is
// refused, and nothing is written), and are audited with the group before
// and after.
//
// Mutations: drop requireSGWrite from set or rm — Operator writes: red; drop
// either audit row, or record the wrong before — red.
func TestFirewallTagGroup_NeedsSGWriteAndIsAudited(t *testing.T) {
	s, _ := tagsServer(t)
	op := boundCtx(t, s, "olga", "admin", "Operator")
	if _, err := s.SetFirewallTagGroup(op, tagGroupReq("web", map[string]string{"role": "web"})); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Operator tag-group set: %v, want PermissionDenied", err)
	}
	if tagGroupExists(t, s, "web") {
		t.Fatal("a refused tag-group set wrote the group")
	}

	ctx := boundCtx(t, s, "nina", "viewer", "NetworkAdmin")
	out, err := s.SetFirewallTagGroup(ctx, tagGroupReq("web", map[string]string{"role": "web"}))
	if err != nil {
		t.Fatalf("NetworkAdmin tag-group set: %v", err)
	}
	if out.GetName() != "web" || out.GetMatch()["role"] != "web" || out.GetSetBy() != "nina" {
		t.Fatalf("tag-group set answered %+v", out)
	}
	wantAudit(t, s, "firewall.tag_group.set", "nina", "web",
		"before=none after={match={role=web} networks=[] security_groups=[]}")

	tagGroupNetwork(t, s)
	tagGroupSG(t, s, "web-in")
	req := tagGroupReq("web", map[string]string{"role": "web", "env": ""}, "web-in")
	req.Group.Networks = []string{"prod"}
	if _, err := s.SetFirewallTagGroup(ctx, req); err != nil {
		t.Fatalf("tag-group set (update): %v", err)
	}
	wantAudit(t, s, "firewall.tag_group.set", "nina", "web",
		"before={match={role=web} networks=[] security_groups=[]} after={match={env role=web} networks=[prod] security_groups=[web-in]}")

	if _, err := s.DeleteFirewallTagGroup(op, &pb.DeleteFirewallTagGroupRequest{Name: "web"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Operator tag-group rm: %v, want PermissionDenied", err)
	}
	if !tagGroupExists(t, s, "web") {
		t.Fatal("a refused tag-group rm removed the group")
	}
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web"}); err != nil {
		t.Fatalf("tag-group rm: %v", err)
	}
	if tagGroupExists(t, s, "web") {
		t.Fatal("tag-group rm left the group")
	}
	wantAudit(t, s, "firewall.tag_group.rm", "nina", "web",
		"before={match={env role=web} networks=[prod] security_groups=[web-in]} after=none")

	// Listing needs sg.read, which Operator holds.
	if _, err := s.ListFirewallTagGroups(op, &pb.ListFirewallTagGroupsRequest{}); err != nil {
		t.Fatalf("Operator tag-group ls: %v", err)
	}
}

// Refused until the release latch with the release text, writing nothing; a
// first use the gate cannot complete is refused with its own code.
//
// Mutations: drop the entry check and the gate from set — the group is
// written before the latch: red; from rm — red.
func TestFirewallTagGroup_RefusedBeforeTheLatch(t *testing.T) {
	s, g := tagsServer(t)
	setTagGroup(t, s, "db")
	g.open = false
	_, err := s.SetFirewallTagGroup(adminCtx(), tagGroupReq("web", map[string]string{"role": "web"}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Fatalf("tag-group set before the latch: %v", err)
	}
	if tagGroupExists(t, s, "web") {
		t.Fatal("a tag-group set before the latch wrote the group")
	}
	_, err = s.DeleteFirewallTagGroup(adminCtx(), &pb.DeleteFirewallTagGroupRequest{Name: "db"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Fatalf("tag-group rm before the latch: %v", err)
	}
	if !tagGroupExists(t, s, "db") {
		t.Fatal("a tag-group rm before the latch removed the group")
	}

	// Latched, but the first use is not acknowledged in time.
	g.open, g.refuseFirstUse, g.refuseCode = true, true, codes.Unavailable
	_, err = s.SetFirewallTagGroup(adminCtx(), tagGroupReq("web", map[string]string{"role": "web"}))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Fatalf("tag-group set whose first use was refused: %v, want Unavailable with the release text", err)
	}
	if tagGroupExists(t, s, "web") {
		t.Fatal("a tag-group set whose first use was refused wrote the group")
	}
	_, err = s.DeleteFirewallTagGroup(adminCtx(), &pb.DeleteFirewallTagGroupRequest{Name: "db"})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Fatalf("tag-group rm whose first use was refused: %v, want Unavailable with the release text", err)
	}
	if !tagGroupExists(t, s, "db") {
		t.Fatal("a tag-group rm whose first use was refused removed the group")
	}
}

// rm of a group this replica does not hold is NotFound before the release
// gate is asked, so a mistyped name records no first use (review m-3).
//
// Mutation: look the group up only inside the gate — the gate is asked: red.
func TestDeleteFirewallTagGroup_NotFoundRecordsNoUse(t *testing.T) {
	s, g := tagsServer(t)
	_, err := s.DeleteFirewallTagGroup(adminCtx(), &pb.DeleteFirewallTagGroupRequest{Name: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("rm of a missing group: %v, want NotFound", err)
	}
	if g.calls != 0 || len(g.used) != 0 {
		t.Fatalf("rm of a missing group asked the gate %d time(s), used %v", g.calls, g.used)
	}
}

// set refuses a binding to a security group or network this replica does
// not hold, and to a security-group name two groups hold (review m-5).
//
// Mutations: skip the security-group check — red; skip the duplicate count
// — red; skip the network check — red.
func TestSetFirewallTagGroup_RefusesUnknownBindings(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := adminCtx()
	tagGroupNetwork(t, s)
	tagGroupSG(t, s, "web-in")
	// Two groups of one name: the handler refuses a second, but two hosts
	// can each create one before either sees the other's.
	for _, id := range []string{"twice-1", "twice-2"} {
		if err := corrosion.InsertSecurityGroup(context.Background(), s.db, corrosion.SecurityGroup{ID: id, Name: "twice"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, want string
		req        *pb.SetFirewallTagGroupRequest
	}{
		{"unknown sg", `no security group named "nope"`, tagGroupReq("a", map[string]string{"role": "a"}, "web-in", "nope")},
		{"duplicate sg", `2 security groups are named "twice"`, tagGroupReq("b", map[string]string{"role": "b"}, "twice")},
		{"unknown network", `no network named "dev"`, func() *pb.SetFirewallTagGroupRequest {
			r := tagGroupReq("c", map[string]string{"role": "c"}, "web-in")
			r.Group.Networks = []string{"prod", "dev"}
			return r
		}()},
	} {
		_, err := s.SetFirewallTagGroup(ctx, c.req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want FailedPrecondition containing %q", c.name, err, c.want)
		}
		if tagGroupExists(t, s, c.req.Group.Name) {
			t.Errorf("%s: the group was written", c.name)
		}
	}
	req := tagGroupReq("ok", map[string]string{"role": "ok"}, "web-in")
	req.Group.Networks = []string{"prod"}
	if _, err := s.SetFirewallTagGroup(ctx, req); err != nil {
		t.Fatalf("set with known bindings: %v", err)
	}
}

// rm without --force is refused while a workload whose tags row cannot be
// read has a NIC on a network the group binds: its membership is unknown,
// and its NICs there are held at drop only while the group binds (review
// m-4). --force overrides it.
//
// Mutation: skip the unreadable workloads — red.
func TestDeleteFirewallTagGroup_UnreadableTagsOnABoundNetwork(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := adminCtx()
	tagGroupNetwork(t, s)
	tagGroupSG(t, s, "web-in")
	tagGroupMember(t, s, "odd-1", fwA, "52:54:00:00:00:01", "10.0.0.5")
	if err := s.db.Execute(context.Background(), `UPDATE cluster_policies SET value = '{' WHERE key = ?`,
		corrosion.FirewallTagsKeyPrefix+corrosion.TagMemberVM+"/"+fwA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFirewallTagGroup(ctx, tagGroupReq("web", map[string]string{"role": "web"}, "web-in")); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "VM odd-1 on prod") || !strings.Contains(err.Error(), "membership is unknown") {
		t.Fatalf("rm while an unreadable-tags workload sits on a bound network: %v", err)
	}
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("rm --force: %v", err)
	}
}

// tagGroupRefServer is a latched server holding group web and a security
// group "app".
func tagGroupRefServer(t *testing.T) (*Server, context.Context) {
	t.Helper()
	s, _ := tagsServer(t)
	ctx := adminCtxWithEngine(t, s)
	setTagGroup(t, s, "web")
	if _, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "app"}); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

// tagRuleAt writes a rule with cidr and action through one tier's handler and
// returns its id.
func tagRuleAt(t *testing.T, s *Server, ctx context.Context, tier, cidr, action string) string {
	t.Helper()
	rule := &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "5432", Cidr: cidr, Action: action}
	switch tier {
	case "cluster":
		r, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetId()
	case "host":
		rule.HostName = "node-x" // another host's tier: every host's rules count
		r, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: rule})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetId()
	default:
		sgs, err := corrosion.ListSecurityGroups(context.Background(), s.db, "")
		if err != nil || len(sgs) != 1 {
			t.Fatalf("security groups: %v %v", sgs, err)
		}
		r, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
			SgId: sgs[0].ID, Direction: "ingress", Proto: "tcp", Port: "5432", Cidr: cidr, Action: action}})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetId()
	}
}

// `rm` is refused while a rule in any tier references the group, naming the
// rule; --force passes when every reference accepts, and is refused while a
// drop or reject references it.
//
// Mutations: skip the reference check — rm with an accept reference passes:
// red; let --force override a drop — red; read one tier only — red for the
// others.
func TestDeleteFirewallTagGroup_RefusedWhileReferenced(t *testing.T) {
	for _, tier := range []string{"cluster", "host", "sg"} {
		t.Run(tier+" accept", func(t *testing.T) {
			s, ctx := tagGroupRefServer(t)
			id := tagRuleAt(t, s, ctx, tier, "tag:web", "accept")
			_, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web"})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("rm with an accept referencing the group: %v, want FailedPrecondition naming %s", err, id)
			}
			if !tagGroupExists(t, s, "web") {
				t.Fatal("a refused rm removed the group")
			}
			if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web", Force: true}); err != nil {
				t.Fatalf("rm --force with accept-only references: %v", err)
			}
			if tagGroupExists(t, s, "web") {
				t.Fatal("rm --force left the group")
			}
			wantAudit(t, s, "firewall.tag_group.rm", "alice", "web",
				"before={match={role=web} networks=[] security_groups=[]} after=none force")
		})
		for _, action := range []string{"drop", "reject"} {
			t.Run(tier+" "+action, func(t *testing.T) {
				s, ctx := tagGroupRefServer(t)
				tagRuleAt(t, s, ctx, tier, "tag:web", "accept")
				id := tagRuleAt(t, s, ctx, tier, "tag:web", action)
				for _, force := range []bool{false, true} {
					_, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web", Force: force})
					if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "delete the rule first") {
						t.Fatalf("rm (force=%v) with a %s referencing the group: %v, want FailedPrecondition naming %s", force, action, err, id)
					}
					if !tagGroupExists(t, s, "web") {
						t.Fatalf("rm (force=%v) removed a group a %s references", force, action)
					}
				}
			})
		}
	}
}

// A stored reference in a form the writers refuse now (an older build's) is
// a reference too: TAG:web in another case, and the group's set referenced
// directly, negated or not, or its IPv6 companion.
//
// Mutation: match only the exact tag:<name> — red.
func TestDeleteFirewallTagGroup_OlderReferenceFormsCount(t *testing.T) {
	for _, cidr := range []string{" TAG:web", "@lv_tg_web", "!= @lv_tg_web", "@lv_tg_web_v6"} {
		t.Run(cidr, func(t *testing.T) {
			s, ctx := tagGroupRefServer(t)
			if err := s.db.Execute(context.Background(), `INSERT INTO cluster_firewall_rules
				(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
				VALUES ('old-1', 'ingress', 'tcp', '5432', ?, 'drop', 100, '', '', 't', 't')`, cidr); err != nil {
				t.Fatal(err)
			}
			_, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web", Force: true})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "old-1") {
				t.Fatalf("rm --force with a drop on %q: %v", cidr, err)
			}
		})
	}
	// Another group's references do not count.
	s, ctx := tagGroupRefServer(t)
	setTagGroup(t, s, "webx")
	tagRuleAt(t, s, ctx, "cluster", "tag:webx", "drop")
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web"}); err != nil {
		t.Fatalf("rm of a group only another group's rule references: %v", err)
	}
}

// `rm` is refused while the group binds security groups to a member's NICs,
// and --force overrides that; an unreadable group's bindings are unknown, so
// it needs --force too.
//
// Mutations: skip the binding check — red; treat an unreadable group as
// binding nothing — red.
func TestDeleteFirewallTagGroup_BindingInUse(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := adminCtx()
	tagGroupNetwork(t, s)
	tagGroupMember(t, s, "web-1", fwA, "52:54:00:00:00:01", "10.0.0.5")
	tagGroupSG(t, s, "web-in")
	if _, err := s.SetFirewallTagGroup(ctx, tagGroupReq("web", map[string]string{"role": "web"}, "web-in")); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "VM web-1 on prod") {
		t.Fatalf("rm of a group binding a member's NIC: %v", err)
	}
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("rm --force of a group binding a member's NIC: %v", err)
	}

	// A group with no security groups binds nothing.
	if _, err := s.SetFirewallTagGroup(ctx, tagGroupReq("plain", map[string]string{"role": "web"})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "plain"}); err != nil {
		t.Fatalf("rm of a group that binds nothing: %v", err)
	}

	if err := s.db.Execute(context.Background(), `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, '{', 'x', 't')`,
		corrosion.FirewallTagGroupKeyPrefix+"bad"); err != nil {
		t.Fatal(err)
	}
	_, err = s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "bad"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("rm of an unreadable group: %v", err)
	}
	if _, err := s.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: "bad", Force: true}); err != nil {
		t.Fatalf("rm --force of an unreadable group: %v", err)
	}
	if tagGroupExists(t, s, "bad") {
		t.Fatal("rm --force left the unreadable group")
	}
}

// `set` is refused over a user ip set named lv_tg_<n> or lv_tg_<n>_v6 (an
// older build's), and for a name whose set is another group's IPv6
// companion, or would have one: <x>_v6, or <x> while <x>_v6 exists.
//
// Mutations: skip the ip-set check — red; compare only lv_tg_<n> — the _v6
// case is red; drop either _v6 refusal — red.
func TestSetFirewallTagGroup_RefusedOverAUserSetOrACompanion(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := adminCtx()
	for _, set := range []string{"lv_tg_web", "lv_tg_db_v6"} {
		if err := s.db.Execute(context.Background(), `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
			VALUES (?, ?, '["10.9.0.0/24"]', '', 't', 't')`, "id-"+set, set); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"web", "db"} {
		_, err := s.SetFirewallTagGroup(ctx, tagGroupReq(name, map[string]string{"role": name}))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "an ip set named") {
			t.Fatalf("set %s over a user set: %v", name, err)
		}
		if tagGroupExists(t, s, name) {
			t.Fatalf("set %s over a user set wrote the group", name)
		}
	}
	if _, err := s.SetFirewallTagGroup(ctx, tagGroupReq("app", map[string]string{"role": "app"})); err != nil {
		t.Fatalf("set app: %v", err)
	}

	_, err := s.SetFirewallTagGroup(ctx, tagGroupReq("app_v6", map[string]string{"role": "app"}))
	if status.Code(err) != codes.InvalidArgument || tagGroupExists(t, s, "app_v6") {
		t.Fatalf("set app_v6: %v", err)
	}
	// A group <x>_v6 an earlier build of this branch wrote.
	setTagGroup(t, s, "cache_v6")
	_, err = s.SetFirewallTagGroup(ctx, tagGroupReq("cache", map[string]string{"role": "cache"}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cache_v6") || tagGroupExists(t, s, "cache") {
		t.Fatalf("set cache while cache_v6 exists: %v", err)
	}
}

// `ls --members` shows each member's leased addresses, or that it has no
// allocated address; without --members no member is read.
//
// Mutations: drop the note — red; list the NIC-row address — red.
func TestListFirewallTagGroups_Members(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := adminCtx()
	tagGroupNetwork(t, s)
	tagGroupMember(t, s, "web-1", fwA, "52:54:00:00:00:01", "10.0.0.5")
	tagGroupMember(t, s, "web-2", fwB, "52:54:00:00:00:02", "")
	if _, err := s.SetFirewallTagGroup(ctx, tagGroupReq("web", map[string]string{"role": "web"})); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListFirewallTagGroups(ctx, &pb.ListFirewallTagGroupsRequest{Members: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetGroups()) != 1 || resp.GetGroups()[0].GetName() != "web" {
		t.Fatalf("groups = %+v", resp.GetGroups())
	}
	got := map[string]string{}
	for _, m := range resp.GetGroups()[0].GetMembers() {
		got[m.GetKind()+"/"+m.GetWorkload()] = strings.Join(m.GetAddresses(), ",") + "|" + m.GetAddressNote()
	}
	want := map[string]string{"vm/web-1": "10.0.0.5|", "vm/web-2": "|no allocated address"}
	if len(got) != len(want) || got["vm/web-1"] != want["vm/web-1"] || got["vm/web-2"] != want["vm/web-2"] {
		t.Fatalf("members = %v, want %v", got, want)
	}

	resp, err = s.ListFirewallTagGroups(ctx, &pb.ListFirewallTagGroupsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetGroups()) != 1 || len(resp.GetGroups()[0].GetMembers()) != 0 ||
		!slices.Equal([]string{resp.GetGroups()[0].GetMatch()["role"]}, []string{"web"}) {
		t.Fatalf("ls without --members = %+v", resp.GetGroups())
	}
}

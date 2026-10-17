package grpcapi

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// Tag groups (firewall extras spec §4.2): `lv firewall tag-group set|ls|rm`.
//
// A group is one cluster_policies row. Writing or removing one needs sg.write
// at the cluster root and waits for the firewall_tag_groups release latch;
// both are audited with the group before and after. A removal is refused
// while a rule references the group or while its binding is in use, and
// --force overrides only the second and accept rules: a drop or reject on the
// group always refuses it (DECISION T-6).

// tagGroupNoAddress is how a member with no qualifying lease is shown.
const tagGroupNoAddress = "no allocated address"

// tagGroupV6Suffix ends the IPv6 companion of a group's set (lv_tg_<g>_v6).
const tagGroupV6Suffix = "_v6"

// tagGroupText is a group as an audit row shows it.
func tagGroupText(g corrosion.FirewallTagGroup, ok bool, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case !ok:
		return corrosion.AuditStateNone
	case g.Unreadable:
		return "unreadable"
	}
	var match []string
	for _, k := range slices.Sorted(maps.Keys(g.Def.Match)) {
		if v := g.Def.Match[k]; v != "" {
			match = append(match, k+"="+v)
		} else {
			match = append(match, k)
		}
	}
	return "{match={" + strings.Join(match, " ") + "} networks=[" + strings.Join(g.Def.Networks, ",") +
		"] security_groups=[" + strings.Join(g.Def.SecurityGroups, ",") + "]}"
}

func toPbTagGroup(g corrosion.FirewallTagGroup) *pb.FirewallTagGroup {
	return &pb.FirewallTagGroup{Name: g.Name, Match: maps.Clone(g.Def.Match), Networks: slices.Clone(g.Def.Networks),
		SecurityGroups: slices.Clone(g.Def.SecurityGroups), SetBy: g.SetBy, UpdatedAt: g.UpdatedAt}
}

// ListFirewallTagGroups lists the tag groups as this host's replica holds
// them, with each group's members and their addresses when asked. Needs
// sg.read at the cluster root. A group whose row cannot be read is listed
// with no match.
func (s *Server) ListFirewallTagGroups(ctx context.Context, req *pb.ListFirewallTagGroupsRequest) (*pb.ListFirewallTagGroupsResponse, error) {
	if err := s.RequirePerm(ctx, "/", sgReadVerb, "viewer"); err != nil {
		return nil, err
	}
	out := &pb.ListFirewallTagGroupsResponse{}
	if !req.GetMembers() {
		groups, err := corrosion.ListFirewallTagGroups(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list tag groups: %v", err)
		}
		for _, g := range groups {
			out.Groups = append(out.Groups, toPbTagGroup(g))
		}
		return out, nil
	}
	m, err := corrosion.ListTagGroupMembers(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tag group members: %v", err)
	}
	for _, v := range m.Groups {
		g := toPbTagGroup(v.Group)
		for _, mb := range v.Members {
			pm := &pb.FirewallTagMember{Kind: pbFWTagKind(mb.Kind), Workload: mb.Name, Host: mb.Host}
			for _, a := range mb.Addrs {
				pm.Addresses = append(pm.Addresses, a.Addr.String())
			}
			if len(pm.Addresses) == 0 {
				pm.AddressNote = tagGroupNoAddress
			}
			g.Members = append(g.Members, pm)
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

// SetFirewallTagGroup writes a tag group (an upsert). Needs sg.write at the
// cluster root; refused until the firewall_tag_groups release latch; audited
// as firewall.tag_group.set with the group before and after.
//
// It is refused when nft could not declare the group's set: a user ip set
// named lv_tg_<name> or lv_tg_<name>_v6 exists (an older build's; writers
// refuse lv_ names now), the name ends in _v6 (the IPv6 companion of another
// group's set), or a group <name>_v6 exists, whose set would be this one's
// companion.
func (s *Server) SetFirewallTagGroup(ctx context.Context, req *pb.SetFirewallTagGroupRequest) (*pb.FirewallTagGroup, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	in := req.GetGroup()
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "group required")
	}
	name := in.GetName()
	if !corrosion.ValidFirewallTagGroupName(name) {
		return nil, status.Errorf(codes.InvalidArgument, "tag group name %q: want [a-z][a-z0-9_]{0,30}", name)
	}
	if base, ok := strings.CutSuffix(name, tagGroupV6Suffix); ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"tag group name %q: a name ending in %s is refused, since its set %s%s is the IPv6 companion of group %q's set",
			name, tagGroupV6Suffix, firewall.TagGroupSetPrefix, name, base)
	}
	def := corrosion.FirewallTagGroupDef{Match: maps.Clone(in.GetMatch()), Networks: slices.Clone(in.GetNetworks()),
		SecurityGroups: slices.Clone(in.GetSecurityGroups())}
	if err := corrosion.ValidateFirewallTagGroupDef(def); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tag group %s: %v", name, err)
	}
	if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureFirewallTagGroups); err != nil {
		return nil, err
	}
	if err := s.refuseTagGroupSetClash(ctx, name); err != nil {
		return nil, err
	}
	if err := s.refuseTagGroupUnknownBindings(ctx, name, def); err != nil {
		return nil, err
	}

	actor := s.repairActor(ctx)
	var before string
	err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallTagGroups, func(ctx context.Context, g capabilities.FeatureGrant) error {
		before = tagGroupText(corrosion.GetFirewallTagGroup(ctx, s.db, name))
		if err := corrosion.SetFirewallTagGroup(ctx, s.db, g, name, &def, actor); err != nil {
			return tagGroupWriteErr(err, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	stored, ok, rerr := corrosion.GetFirewallTagGroup(ctx, s.db, name)
	s.auditAs(context.WithoutCancel(ctx), actor, "firewall.tag_group.set", name,
		corrosion.AuditChange(before, tagGroupText(stored, ok, rerr)), "ok")
	s.reconcileLocal(ctx)
	if rerr != nil || !ok {
		return &pb.FirewallTagGroup{Name: name, Match: def.Match, Networks: def.Networks, SecurityGroups: def.SecurityGroups, SetBy: actor}, nil
	}
	return toPbTagGroup(stored), nil
}

// refuseTagGroupSetClash refuses group name when its set, or the set's IPv6
// companion, could not be declared beside what this replica holds.
func (s *Server) refuseTagGroupSetClash(ctx context.Context, name string) error {
	sets, err := corrosion.ListIPSets(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Internal, "list ip sets: %v", err)
	}
	set := firewall.TagGroupSetPrefix + name
	for _, ip := range sets {
		if ip.Name == set || ip.Name == set+tagGroupV6Suffix {
			return status.Errorf(codes.FailedPrecondition,
				"tag group %s: an ip set named %q (id %s) exists, and the group's set would have the same name, which nft refuses; "+
					"recreate that ip set under a name not starting with lv_ (lv firewall ipset rm %s), then retry",
				name, ip.Name, ip.ID, ip.ID)
		}
	}
	if _, exists, err := corrosion.GetFirewallTagGroup(ctx, s.db, name+tagGroupV6Suffix); err != nil {
		return status.Errorf(codes.Internal, "read tag group %s%s: %v", name, tagGroupV6Suffix, err)
	} else if exists {
		return status.Errorf(codes.FailedPrecondition,
			"tag group %s: a group named %s%s exists, whose set would be the IPv6 companion of this one's; remove it first (lv firewall tag-group rm %s%s)",
			name, name, tagGroupV6Suffix, name, tagGroupV6Suffix)
	}
	return nil
}

// refuseTagGroupUnknownBindings refuses a binding to a security group or a
// network this replica does not hold, or to a security-group name two live
// groups hold: the renderer would leave the first out silently and hold the
// members' NICs at drop for the second. It catches mistakes; it is not
// atomic with a later delete of the group or network.
func (s *Server) refuseTagGroupUnknownBindings(ctx context.Context, name string, def corrosion.FirewallTagGroupDef) error {
	if len(def.SecurityGroups) > 0 {
		sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "")
		if err != nil {
			return status.Errorf(codes.Internal, "list security groups: %v", err)
		}
		holders := map[string]int{}
		for _, g := range sgs {
			holders[g.Name]++
		}
		for _, sg := range def.SecurityGroups {
			switch holders[sg] {
			case 0:
				return status.Errorf(codes.FailedPrecondition,
					"tag group %s: no security group named %q exists; create it first (lv sg create %s)", name, sg, sg)
			case 1:
			default:
				return status.Errorf(codes.FailedPrecondition,
					"tag group %s: %d security groups are named %q, and a NIC bound to that name is held at drop; "+
						"remove all but one first (lv sg rm <sg-id>)", name, holders[sg], sg)
			}
		}
	}
	for _, n := range def.Networks {
		rec, err := corrosion.GetNetwork(ctx, s.db, n)
		if err != nil {
			return status.Errorf(codes.Internal, "read network %s: %v", n, err)
		}
		if rec == nil {
			return status.Errorf(codes.FailedPrecondition, "tag group %s: no network named %q exists", name, n)
		}
	}
	return nil
}

// tagGroupWriteErr maps a refused group write onto a status.
func tagGroupWriteErr(err error, name string) error {
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Errorf(firewallWriteCode(err, codes.Internal), "write tag group %s: %v", name, err)
}

// tagGroupRef is a live rule that references a tag group.
type tagGroupRef struct {
	what   string // "cluster rule <id>", "host rule <id> on <host>", "security-group rule <id> in <sg>"
	accept bool
}

// refersToTagGroup reports whether a stored cidr references group: tag:<g>
// in any case or padding (the renderer treats any such form as a tag
// reference), or a reference to the group's set or its IPv6 companion
// (@lv_tg_<g>, != @lv_tg_<g>), stored before writes refused those.
func refersToTagGroup(cidr, group string) bool {
	v := strings.TrimSpace(cidr)
	if len(v) >= len(rulefield.TagCIDRPrefix) && strings.EqualFold(v[:len(rulefield.TagCIDRPrefix)], rulefield.TagCIDRPrefix) {
		return strings.EqualFold(strings.TrimSpace(v[len(rulefield.TagCIDRPrefix):]), group)
	}
	if set, ok := rulefield.SetRef(cidr); ok {
		set = strings.ToLower(set)
		own := firewall.TagGroupSetPrefix + group
		return set == own || set == own+tagGroupV6Suffix
	}
	return false
}

// acceptsAction reports whether a stored action accepts, as the renderer
// judges it ("" is accept; a logged accept is an accept; a bare "+log" is
// not). Anything else is handled as a deny.
func acceptsAction(action string) bool { return firewall.AcceptsAction(action) }

// tagGroupRefs lists every live rule, in every tier and on every host, that
// references group.
func (s *Server) tagGroupRefs(ctx context.Context, group string) ([]tagGroupRef, error) {
	var refs []tagGroupRef
	cluster, err := corrosion.ListClusterFirewallRules(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("list cluster rules: %w", err)
	}
	for _, r := range cluster {
		if refersToTagGroup(r.CIDR, group) {
			refs = append(refs, tagGroupRef{what: "cluster rule " + r.ID + " (" + r.Action + ")", accept: acceptsAction(r.Action)})
		}
	}
	host, err := corrosion.ListHostFirewallRules(ctx, s.db, "")
	if err != nil {
		return nil, fmt.Errorf("list host rules: %w", err)
	}
	for _, r := range host {
		if refersToTagGroup(r.CIDR, group) {
			refs = append(refs, tagGroupRef{what: "host rule " + r.ID + " on " + r.HostName + " (" + r.Action + ")", accept: acceptsAction(r.Action)})
		}
	}
	sgRules, err := corrosion.ListAllSGRules(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("list security-group rules: %w", err)
	}
	for _, r := range sgRules {
		if refersToTagGroup(r.CIDR, group) {
			refs = append(refs, tagGroupRef{what: "security-group rule " + r.ID + " in " + r.SGID + " (" + r.Action + ")", accept: acceptsAction(r.Action)})
		}
	}
	return refs, nil
}

// tagGroupBindingsInUse names the members whose NICs the group binds
// security groups to now; unknown is true when the group's row cannot be
// read here, so its bindings are not known.
func (s *Server) tagGroupBindingsInUse(ctx context.Context, group string) (users []string, unknown bool, err error) {
	m, err := corrosion.ListTagGroupMembers(ctx, s.db)
	if err != nil {
		return nil, false, err
	}
	for _, v := range m.Groups {
		if v.Group.Name != group {
			continue
		}
		if v.Group.Unreadable {
			return nil, true, nil
		}
		if len(v.Group.Def.SecurityGroups) == 0 {
			return nil, false, nil
		}
		// A workload whose tags row cannot be read may be a member: its NICs
		// on the networks the group binds are held at drop while it binds
		// (spec §4.6, T-7), and removing it lifts that hold.
		for _, w := range m.TagsUnreadable {
			var on []string
			for _, n := range w.Networks {
				if v.Group.BindsNetwork(n) {
					on = append(on, n)
				}
			}
			if len(on) == 0 {
				continue
			}
			who := "VM " + w.Name
			if w.Kind == corrosion.TagMemberCT {
				who = "container " + w.Host + "/" + w.Name
			}
			users = append(users, who+" on "+strings.Join(on, ",")+" (its tags cannot be read, so its membership is unknown)")
		}
		for _, mb := range v.Members {
			if len(mb.Bound) == 0 {
				continue
			}
			who := "VM " + mb.Name
			if mb.Kind == corrosion.TagMemberCT {
				who = "container " + mb.Host + "/" + mb.Name
			}
			users = append(users, who+" on "+strings.Join(mb.Bound, ","))
		}
	}
	return users, false, nil
}

// DeleteFirewallTagGroup removes a tag group. Needs sg.write at the cluster
// root; audited as firewall.tag_group.rm with the group before. Refused while
// a live rule references the group, or while the group binds security groups
// to members' NICs (or its row cannot be read, so its bindings are unknown);
// force overrides only the bindings and accept rules. A drop or reject rule
// referencing the group always refuses it: delete that rule first.
func (s *Server) DeleteFirewallTagGroup(ctx context.Context, req *pb.DeleteFirewallTagGroupRequest) (*emptypb.Empty, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	name := req.GetName()
	if !corrosion.ValidFirewallTagGroupName(name) {
		return nil, status.Errorf(codes.InvalidArgument, "tag group name %q: want [a-z][a-z0-9_]{0,30}", name)
	}
	if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureFirewallTagGroups); err != nil {
		return nil, err
	}
	// A group this replica does not hold is NotFound before the gate, which
	// would record the feature's first use for a removal of nothing.
	if _, ok, err := corrosion.GetFirewallTagGroup(ctx, s.db, name); err != nil {
		return nil, status.Errorf(codes.Internal, "read tag group %s: %v", name, err)
	} else if !ok {
		return nil, status.Errorf(codes.NotFound, "tag group %q not found", name)
	}
	actor := s.repairActor(ctx)
	var before string
	err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallTagGroups, func(ctx context.Context, g capabilities.FeatureGrant) error {
		cur, ok, err := corrosion.GetFirewallTagGroup(ctx, s.db, name)
		if err != nil {
			return status.Errorf(codes.Internal, "read tag group %s: %v", name, err)
		}
		if !ok {
			return status.Errorf(codes.NotFound, "tag group %q not found", name)
		}
		before = tagGroupText(cur, true, nil)
		refs, err := s.tagGroupRefs(ctx, name)
		if err != nil {
			return status.Errorf(codes.Internal, "tag group %s: %v", name, err)
		}
		var denies, accepts []string
		for _, r := range refs {
			if r.accept {
				accepts = append(accepts, r.what)
			} else {
				denies = append(denies, r.what)
			}
		}
		if len(denies) > 0 {
			return status.Errorf(codes.FailedPrecondition,
				"tag group %s: a drop or reject rule references it, and removing the group would make that rule deny "+
					"everything else it names; delete the rule first (--force does not override this): %s",
				name, strings.Join(denies, "; "))
		}
		users, unknown, err := s.tagGroupBindingsInUse(ctx, name)
		if err != nil {
			return status.Errorf(codes.Internal, "tag group %s: list members: %v", name, err)
		}
		if !req.GetForce() {
			var why []string
			if len(accepts) > 0 {
				why = append(why, "rules reference it: "+strings.Join(accepts, "; "))
			}
			if len(users) > 0 {
				why = append(why, "it binds security groups to the NICs of "+strings.Join(users, "; "))
			}
			if unknown {
				why = append(why, "its row cannot be read on this host's replica, so the security groups it binds are not known")
			}
			if len(why) > 0 {
				return status.Errorf(codes.FailedPrecondition, "tag group %s: %s; remove those first, or pass --force",
					name, strings.Join(why, "; and "))
			}
		}
		if err := corrosion.SetFirewallTagGroup(ctx, s.db, g, name, nil, actor); err != nil {
			return tagGroupWriteErr(err, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	detail := corrosion.AuditChange(before, corrosion.AuditStateNone)
	if req.GetForce() {
		detail += " force"
	}
	s.auditAs(context.WithoutCancel(ctx), actor, "firewall.tag_group.rm", name, detail, "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

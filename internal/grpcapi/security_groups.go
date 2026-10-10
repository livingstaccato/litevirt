package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Security-group CRUD, the per-NIC firewall tier (colonelpanik/litevirt#182).
//
// `lv sg create/rm/rule-add/rule-rm` used to open the host's Corrosion database
// in the CLI process and write it there. That skipped the daemon's
// authorization entirely, and it left no audit row, because only the daemon
// holds the host's audit sub-chain tail and signing key. These RPCs are what
// the CLI calls now, and the web UI's security-group pages call them too, with
// the session's bearer, so the two surfaces cannot authorize the same change
// differently. Each checks sg.write at the cluster root (security groups are
// cluster-global, bound to NICs by name) and records who, what, and the group
// or rule before and after.
//
// sg.write is held by Admin (`*`) and NetworkAdmin (`sg.*`); Operator holds
// sg.read only. A cluster with no role bindings falls back to the legacy
// operator role.

const (
	sgWriteVerb = "sg.write"
	sgReadVerb  = "sg.read"
)

func (s *Server) requireSGWrite(ctx context.Context) error {
	return s.RequirePerm(ctx, "/", sgWriteVerb, "operator")
}

func toPbSecurityGroup(g corrosion.SecurityGroup) *pb.SecurityGroup {
	return &pb.SecurityGroup{Id: g.ID, Name: g.Name, StackName: g.StackName, CreatedAt: g.CreatedAt}
}

func toPbSGRule(r corrosion.SGRule) *pb.SecurityGroupRule {
	return &pb.SecurityGroupRule{
		Id: r.ID, SgId: r.SGID, Direction: r.Direction, Proto: r.Proto,
		Port: r.PortRange, Cidr: r.CIDR, Action: r.Action, Priority: int32(r.Priority),
	}
}

// CreateSecurityGroup creates an empty security group. `lv sg create`.
func (s *Server) CreateSecurityGroup(ctx context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// One live group per name. The firewall cannot tell which of two same-name
	// groups a NIC meant, so it holds every NIC bound to such a name at drop;
	// refusing here keeps that from being created. Best effort only — two
	// nodes can race, and the CRDT has no UNIQUE — which is why the reconciler
	// still fails closed on a duplicate that exists anyway.
	if held, err := liveSGNamed(ctx, s.db, req.Name, ""); err != nil {
		return nil, status.Errorf(codes.Unavailable, "check for a security group named %q: %v", req.Name, err)
	} else if held != nil {
		return nil, status.Errorf(codes.AlreadyExists,
			"security group %q already exists (id %s); names must be unique, because a NIC bound to a name two groups hold is held at drop",
			req.Name, held.ID)
	}
	row := corrosion.SecurityGroup{ID: randid.New(), Name: req.Name, StackName: req.StackName}
	if err := corrosion.InsertSecurityGroup(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Internal, "create security group: %v", err)
	}
	// The same after-state the UI records for a new group: it has no rules yet.
	s.audit(ctx, "sg.add", row.Name, corrosion.AuditChange(corrosion.AuditStateNone, row.AuditText(nil)), "ok")
	s.reconcileLocal(ctx)
	if stored, err := corrosion.GetSecurityGroup(ctx, s.db, row.ID); err == nil && stored != nil {
		row = *stored
	}
	return toPbSecurityGroup(row), nil
}

// liveSGNamed returns a live security group named name, ignoring the groups
// of stack exceptStack ("" ignores none), or nil when there is none.
func liveSGNamed(ctx context.Context, db *corrosion.Client, name, exceptStack string) (*corrosion.SecurityGroup, error) {
	sgs, err := corrosion.ListSecurityGroups(ctx, db, "")
	if err != nil {
		return nil, err
	}
	for i := range sgs {
		if sgs[i].Name == name && (exceptStack == "" || sgs[i].StackName != exceptStack) {
			return &sgs[i], nil
		}
	}
	return nil, nil
}

// resolveSecurityGroup finds the live group a caller means by ref, which is a
// group id or a group name (`lv sg ls` shows both). An id wins over a name. A
// name two live groups hold is refused rather than guessed: the firewall will
// not render such a group either.
func (s *Server) resolveSecurityGroup(ctx context.Context, ref string) (*corrosion.SecurityGroup, error) {
	sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list security groups: %v", err)
	}
	var byName []corrosion.SecurityGroup
	for i := range sgs {
		if sgs[i].ID == ref {
			return &sgs[i], nil
		}
		if sgs[i].Name == ref {
			byName = append(byName, sgs[i])
		}
	}
	switch len(byName) {
	case 0:
		return nil, status.Errorf(codes.NotFound, "no security group with id or name %q (lv sg ls shows them)", ref)
	case 1:
		return &byName[0], nil
	}
	return nil, status.Errorf(codes.FailedPrecondition,
		"%d security groups are named %q; use the group id (lv sg ls shows ids)", len(byName), ref)
}

// sgNameCounts counts live groups per name, for ListSGRulesFor's legacyByName.
func sgNameCounts(sgs []corrosion.SecurityGroup) map[string]int {
	m := make(map[string]int, len(sgs))
	for _, g := range sgs {
		m[g.Name]++
	}
	return m
}

// DeleteSecurityGroup tombstones a security group and every rule in it.
// `lv sg rm`.
func (s *Server) DeleteSecurityGroup(ctx context.Context, req *pb.DeleteSecurityGroupRequest) (*emptypb.Empty, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	// Read what is about to go, rules included: after this the audit row is
	// the only record of which traffic they allowed or refused.
	before := corrosion.SecurityGroupAuditState(ctx, s.db, req.Id)
	if before == corrosion.AuditStateNone {
		// An id that matches no live group (a group's name, a typo) would
		// tombstone nothing and still record an "ok" removal.
		return nil, status.Errorf(codes.NotFound, "no security group with id %q (lv sg ls shows ids)", req.Id)
	}
	if err := corrosion.DeleteSGRules(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete security group rules: %v", err)
	}
	// Rules an older client stored under the group's name are read as the
	// group's own (ListSGRulesFor), so they go with it; left behind they would
	// attach to a later group of the same name.
	if g, gerr := corrosion.GetSecurityGroup(ctx, s.db, req.Id); gerr == nil && g != nil && g.Name != "" {
		if all, lerr := corrosion.ListSecurityGroups(ctx, s.db, ""); lerr == nil && sgNameCounts(all)[g.Name] == 1 {
			if err := corrosion.DeleteSGRules(ctx, s.db, g.Name); err != nil {
				return nil, status.Errorf(codes.Internal, "delete security group rules: %v", err)
			}
		}
	}
	if err := corrosion.DeleteSecurityGroup(ctx, s.db, req.Id); err != nil {
		// The rules are already gone, so the change is recorded even though
		// the group row itself was not tombstoned.
		s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		s.reconcileLocal(ctx)
		return nil, status.Errorf(codes.Internal, "delete security group: %v", err)
	}
	s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// AddSecurityGroupRule appends a rule to a security group. `lv sg rule-add`.
func (s *Server) AddSecurityGroupRule(ctx context.Context, req *pb.AddSecurityGroupRuleRequest) (*pb.SecurityGroupRule, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.SgId == "" || r.Direction == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with sg_id and direction required")
	}
	// The rule belongs to a group, named by id or by (unique) name. Storing the
	// argument verbatim is how `lv sg rule-add <name>` used to write a rule no
	// group owned: the firewall renders rules by group id, so it never applied.
	sg, rerr := s.resolveSecurityGroup(ctx, r.SgId)
	if rerr != nil {
		return nil, rerr
	}
	row := corrosion.SGRule{
		ID: randid.New(), SGID: sg.ID, Direction: r.Direction, Proto: r.Proto,
		PortRange: r.Port, CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority),
	}
	if err := corrosion.InsertSGRule(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "add security group rule: %v", err)
	}
	// Read back, so the "after" (and the reply) is the rule as stored: the
	// insert fills in defaults for an empty proto, action and priority.
	stored, gerr := corrosion.GetSGRule(ctx, s.db, row.ID)
	s.audit(ctx, "sg.rule.add", row.SGID,
		corrosion.AuditChange(corrosion.AuditStateNone, corrosion.SGRuleAuditState(stored, gerr)), "ok")
	s.reconcileLocal(ctx)
	if gerr == nil && stored != nil {
		row = *stored
	}
	return toPbSGRule(row), nil
}

// RemoveSecurityGroupRule tombstones one rule, by the RULE id. `lv sg rule-rm`.
func (s *Server) RemoveSecurityGroupRule(ctx context.Context, req *pb.RemoveSecurityGroupRuleRequest) (*emptypb.Empty, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	before := corrosion.SGRuleAuditState(corrosion.GetSGRule(ctx, s.db, req.Id))
	if before == corrosion.AuditStateNone {
		return nil, status.Errorf(codes.NotFound, "no security group rule with id %q (lv sg rule-ls shows ids)", req.Id)
	}
	if err := corrosion.DeleteSGRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "remove security group rule: %v", err)
	}
	s.audit(ctx, "sg.rule.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ListSecurityGroups lists security groups and, with include_rules, every rule
// of the groups it lists. It checks sg.read at the cluster root, the path the
// writes check sg.write at: every built-in role holding *.read or sg.read
// passes, and a token scoped below "/" does not, since a group is
// cluster-global and its rules name addresses and ports anywhere in the
// cluster. The web UI's security-group page and Add-NIC modal read through
// this with the session's bearer.
func (s *Server) ListSecurityGroups(ctx context.Context, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	if err := s.RequirePerm(ctx, "/", sgReadVerb, "viewer"); err != nil {
		return nil, err
	}
	groups, err := corrosion.ListSecurityGroups(ctx, s.db, req.GetStackName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list security groups: %v", err)
	}
	all, err := corrosion.ListSecurityGroups(ctx, s.db, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list security groups: %v", err)
	}
	counts := sgNameCounts(all)
	resp := &pb.ListSecurityGroupsResponse{Groups: make([]*pb.SecurityGroup, 0, len(groups))}
	for _, g := range groups {
		resp.Groups = append(resp.Groups, toPbSecurityGroup(g))
		if !req.GetIncludeRules() {
			continue
		}
		rules, err := corrosion.ListSGRulesFor(ctx, s.db, g, counts[g.Name] == 1)
		if err != nil {
			// A page that showed the group with no rules would read as "this
			// group allows nothing", which is not what the host enforces.
			return nil, status.Errorf(codes.Internal, "list rules of security group %s: %v", g.ID, err)
		}
		for _, r := range rules {
			resp.Rules = append(resp.Rules, toPbSGRule(r))
		}
	}
	return resp, nil
}

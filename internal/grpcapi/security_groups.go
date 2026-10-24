package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
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
//
// A group owned by a project (docs/design/security-group-projects.md) is
// authorized on its own path under that project instead (sgRBACPath), so a
// project-scoped NetworkAdmin manages its project's groups and no others; a
// global group stays at the root.

const (
	sgWriteVerb = "sg.write"
	sgReadVerb  = "sg.read"
)

func (s *Server) requireSGWrite(ctx context.Context) error {
	return s.RequirePerm(ctx, "/", sgWriteVerb, "operator")
}

// sgRBACPath is a security group's RBAC path: the cluster root for a global
// group, /projects/<project>/security_groups/<name> for a project's.
func sgRBACPath(project, name string) string {
	if project == "" {
		return "/"
	}
	return projectRBACBase(project) + "/security_groups/" + safeRBACSegment(name)
}

// requireSGWriteOn checks sg.write on g's own path.
func (s *Server) requireSGWriteOn(ctx context.Context, g *corrosion.SecurityGroup) error {
	return s.RequirePerm(ctx, sgRBACPath(g.Project, g.Name), sgWriteVerb, "operator")
}

// sgReadable reports whether the caller may read g: sg.read on its path.
func (s *Server) sgReadable(ctx context.Context, g *corrosion.SecurityGroup) bool {
	return s.RequirePerm(ctx, sgRBACPath(g.Project, g.Name), sgReadVerb, "viewer") == nil
}

func toPbSecurityGroup(g corrosion.SecurityGroup) *pb.SecurityGroup {
	return &pb.SecurityGroup{Id: g.ID, Name: g.Name, StackName: g.StackName, CreatedAt: g.CreatedAt, Project: g.Project}
}

// toPbSGRule is a stored rule as the API shows it: a logged rule's plain
// verdict and log, never the stored suffix (spec m-13).
func toPbSGRule(r corrosion.SGRule) *pb.SecurityGroupRule {
	action, logged := corrosion.SplitLoggedAction(r.Action)
	return &pb.SecurityGroupRule{
		Id: r.ID, SgId: r.SGID, Direction: r.Direction, Proto: r.Proto,
		Port: r.PortRange, Cidr: r.CIDR, Action: action, Priority: int32(r.Priority), Log: logged,
	}
}

// CreateSecurityGroup creates an empty security group, global or owned by
// req.Project. `lv sg create [--project]`.
func (s *Server) CreateSecurityGroup(ctx context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	project := req.GetProject()
	if project != "" {
		if _, err := safename.CanonicalProjectName(project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: %v", project, err)
		}
	}
	if project != "" && req.StackName != "" {
		// A stack's groups are global and go with the stack; a project's
		// group must not be removed by another stack's teardown.
		return nil, status.Error(codes.InvalidArgument, "a project's security group cannot belong to a stack; give one or the other")
	}
	if err := s.RequirePerm(ctx, sgRBACPath(project, req.Name), sgWriteVerb, "operator"); err != nil {
		return nil, err
	}
	if project != "" {
		// The group is stored under the project's own name, the one its
		// workloads carry, so it must name a project that exists: a spelling
		// such as "acme/" would bind no workload, and a group of a deleted
		// project would pass to a later project of that name.
		p, perr := corrosion.GetProject(ctx, s.db, project)
		if perr != nil {
			return nil, status.Errorf(codes.Unavailable, "look up project %q: %v", project, perr)
		}
		if p == nil {
			return nil, status.Errorf(codes.NotFound, "project %q not found (lv project ls shows them)", project)
		}
		project = p.Name
	}
	// One live group per name. The firewall cannot tell which of two same-name
	// groups a NIC meant, so it holds every NIC bound to such a name at drop;
	// refusing here keeps that from being created. Best effort only — two
	// nodes can race, and the CRDT has no UNIQUE — which is why the reconciler
	// still fails closed on a duplicate that exists anyway.
	if held, err := liveSGNamed(ctx, s.db, req.Name, ""); err != nil {
		return nil, status.Errorf(codes.Unavailable, "check for a security group named %q: %v", req.Name, err)
	} else if held != nil {
		if !s.sgReadable(ctx, held) {
			// Names are unique across projects, so the refusal itself says
			// the name is taken; the id of a group the caller may not read
			// is not its to know.
			return nil, status.Errorf(codes.AlreadyExists,
				"security group %q already exists; names must be unique across projects, because a NIC bound to a name two groups hold is held at drop",
				req.Name)
		}
		return nil, status.Errorf(codes.AlreadyExists,
			"security group %q already exists (id %s); names must be unique, because a NIC bound to a name two groups hold is held at drop",
			req.Name, held.ID)
	}
	row := corrosion.SecurityGroup{ID: randid.New(), Name: req.Name, StackName: req.StackName, Project: project}
	if project == "" {
		if err := corrosion.InsertSecurityGroup(ctx, s.db, row); err != nil {
			return nil, status.Errorf(codes.Internal, "create security group: %v", err)
		}
	} else if err := s.WithReleaseFeature(ctx, capabilities.FeatureSGProjects, func(ctx context.Context, g capabilities.FeatureGrant) error {
		// The project column is a shape a previous-release peer cannot
		// decode: the release feature waits for the release token and
		// records the use first (docs/design/security-group-projects.md).
		return corrosion.InsertProjectSecurityGroup(ctx, s.db, g, row)
	}); err != nil {
		if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
			return nil, err
		}
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

// DeleteSecurityGroup tombstones a security group and every rule in it.
// `lv sg rm`.
func (s *Server) DeleteSecurityGroup(ctx context.Context, req *pb.DeleteSecurityGroupRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	// Authorized on the group's own project. An id no live group has needs
	// the root, as every delete did before groups had projects.
	owner, oerr := corrosion.GetSecurityGroup(ctx, s.db, req.Id)
	if oerr != nil {
		return nil, status.Errorf(codes.Unavailable, "look up security group %q: %v", req.Id, oerr)
	}
	if owner != nil {
		if err := s.requireSGWriteOn(ctx, owner); err != nil {
			return nil, err
		}
	} else if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
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
	if derr := corrosion.DeleteSecurityGroup(ctx, s.db, req.Id); derr != nil {
		// The id-keyed rules are already gone, so the change is recorded even
		// though the group row itself was not tombstoned.
		s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditUnknown(derr)), "error")
		s.reconcileLocal(ctx)
		return nil, status.Errorf(codes.Internal, "delete security group: %v", derr)
	}
	s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// AddSecurityGroupRule appends a rule to a security group. `lv sg rule-add`.
func (s *Server) AddSecurityGroupRule(ctx context.Context, req *pb.AddSecurityGroupRuleRequest) (*pb.SecurityGroupRule, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
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
	if err := s.requireSGWriteOn(ctx, sg); err != nil {
		return nil, err
	}
	row := corrosion.SGRule{
		ID: randid.New(), SGID: sg.ID, Direction: r.Direction, Proto: r.Proto,
		PortRange: r.Port, CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority),
	}
	row.Proto, row.PortRange, row.Action = rulefield.NormaliseRule(row.Proto, row.PortRange, row.Action)
	need, invalid := ruleRowFeatures(row.Direction, row.Proto, row.PortRange, row.CIDR, row.Action, "")
	row.Action, need = logRow(row.Action, r.Log, need, invalid)
	if sg.Project != "" && len(need) > 0 {
		// A rule that needs a release feature (an IPv6, logged or tag-group
		// rule) records that feature's cluster-wide used bit, and a logged
		// rule writes host logs: both reach beyond the project, so they stay
		// with sg.write at the cluster root.
		if err := s.requireSGWrite(ctx); err != nil {
			return nil, status.Errorf(codes.PermissionDenied,
				"a rule that needs %v on a project's security group needs sg.write at the cluster root: %s",
				need, status.Convert(err).Message())
		}
	}
	if err := s.writeFirewallRow(ctx, need, invalid, func(ctx context.Context, g firewallGrants) error {
		if err := s.refuseUnknownTagGroup(ctx, row.CIDR); err != nil {
			return err
		}
		return corrosion.InsertSGRuleWithGrant(ctx, s.db, g.IPv6, g.Log, g.Tag, row)
	}); err != nil {
		return nil, firewallWriteErr(err, codes.InvalidArgument, "add security group rule")
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
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	rule, rerr := corrosion.GetSGRule(ctx, s.db, req.Id)
	if err := s.requireSGRuleWrite(ctx, rule, rerr); err != nil {
		return nil, err
	}
	before := corrosion.SGRuleAuditState(rule, rerr)
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

// requireSGRuleWrite checks sg.write for a rule on the path of the group that
// owns it. A rule no live group owns (an orphan) is judged at the root.
func (s *Server) requireSGRuleWrite(ctx context.Context, rule *corrosion.SGRule, rerr error) error {
	if rerr != nil || rule == nil {
		return s.requireSGWrite(ctx)
	}
	g, err := corrosion.GetSecurityGroup(ctx, s.db, rule.SGID)
	if err != nil {
		return status.Errorf(codes.Unavailable, "look up the group of rule %q: %v", rule.ID, err)
	}
	if g == nil {
		return s.requireSGWrite(ctx)
	}
	return s.requireSGWriteOn(ctx, g)
}

// ListSecurityGroups lists security groups and, with include_rules, the rules
// of the groups it lists. sg.read at the cluster root sees every group and
// rule. Below the root each project group is listed when the caller holds
// sg.read on its path; with req.Project named (and sg.read on that project)
// the global groups are listed too, without their rules, because that
// project's workloads may bind them while their rules — addresses and ports
// anywhere in the cluster — stay readable at the root only. req.Project
// narrows any listing to that project's groups plus the global ones. The web
// UI's security-group page and Add-NIC modal read through this with the
// session's bearer.
func (s *Server) ListSecurityGroups(ctx context.Context, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	project := req.GetProject()
	// Validated before any authorization, for every caller: the CLI probes
	// with a malformed project, and only a build that reads the field gives
	// this answer (cmd/litevirt sgProjectsProbe).
	if project != "" {
		if _, err := safename.CanonicalProjectName(project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: %v", project, err)
		}
	}
	root := s.RequirePerm(ctx, "/", sgReadVerb, "viewer") == nil
	if project != "" && !root {
		if err := s.RequirePerm(ctx, projectRBACBase(project)+"/security_groups", sgReadVerb, "viewer"); err != nil {
			return nil, err
		}
	}
	listed, err := corrosion.ListSecurityGroups(ctx, s.db, req.GetStackName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list security groups: %v", err)
	}
	// rulesOf says whose rules the caller may read: every listed group's at
	// the root, a project group's once it is listed.
	rulesOf := map[string]bool{}
	var groups []corrosion.SecurityGroup
	for _, g := range listed {
		switch {
		case project != "" && g.Project != "" && g.Project != project:
			continue
		case root:
			rulesOf[g.ID] = true
		case g.Project == "":
			if project == "" {
				continue
			}
		case !s.sgReadable(ctx, &g):
			continue
		default:
			rulesOf[g.ID] = true
		}
		groups = append(groups, g)
	}
	resp := &pb.ListSecurityGroupsResponse{Groups: make([]*pb.SecurityGroup, 0, len(groups))}
	for _, g := range groups {
		resp.Groups = append(resp.Groups, toPbSecurityGroup(g))
		if !req.GetIncludeRules() || !rulesOf[g.ID] {
			continue
		}
		rules, err := corrosion.ListSGRules(ctx, s.db, g.ID)
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

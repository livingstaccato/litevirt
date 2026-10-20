package grpcapi

import (
	"context"
	"errors"
	"log/slog"
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
	"github.com/litevirt/litevirt/internal/randid"
)

// Distributed-firewall management RPCs for the cluster/host tiers, ip sets, and
// the default-deny policy (v21). The per-NIC tier is managed via the security
// group RPCs + BindSecurityGroups. After a mutation the connected host
// re-reconciles immediately so `lv firewall …` changes are visible at once;
// every other host picks them up on its own 30s reconcile tick.

// toPbFirewallRule is a stored rule as the API shows it: a logged rule's
// plain verdict and log, never the stored suffix (spec m-13).
func toPbFirewallRule(r corrosion.FirewallRule) *pb.FirewallRule {
	action, logged := corrosion.SplitLoggedAction(r.Action)
	return &pb.FirewallRule{
		Id: r.ID, HostName: r.HostName, Direction: r.Direction, Proto: r.Proto,
		Port: r.PortRange, Cidr: r.CIDR, Action: action, Priority: int32(r.Priority),
		Comment: r.Comment, StackName: r.StackName, Log: logged,
	}
}

func toPbIpSet(s corrosion.IPSet) *pb.IpSet {
	return &pb.IpSet{Id: s.ID, Name: s.Name, Cidrs: s.CIDRs, StackName: s.StackName}
}

// firewallGrants are the release-feature grants a firewall row's writer
// takes, one per feature (capabilities DECISION 0-E).
type firewallGrants struct {
	IPv6, Log, Tag capabilities.FeatureGrant
}

// firewallGrantOrder is the order writeFirewallRow nests the gates in,
// IPv6 outermost.
var firewallGrantOrder = []capabilities.Feature{
	capabilities.FeatureFirewallIPv6,
	capabilities.FeatureFirewallLog,
	capabilities.FeatureFirewallTagGroups,
}

// writeFirewallRow writes one firewall row. A row needing no release feature
// is written with no grant, as on main; otherwise each feature it needs is
// taken through its own gate — one WithReleaseFeature per feature, nested with
// IPv6 outermost — each of which refuses until the release token has latched
// and records the use first. need and invalid are the row's ruleRowFeatures
// (or the ip set's ipSetRowFeatures): a malformed row is refused as such
// before any gate is asked.
func (s *Server) writeFirewallRow(ctx context.Context, need []capabilities.Feature, invalid error, write func(context.Context, firewallGrants) error) error {
	if invalid != nil {
		return invalid
	}
	var ordered []capabilities.Feature
	for _, f := range firewallGrantOrder {
		if slices.Contains(need, f) {
			ordered = append(ordered, f)
		}
	}
	for _, f := range need {
		if !slices.Contains(firewallGrantOrder, f) {
			return status.Errorf(codes.Internal, "firewall row needs release feature %s, which no firewall writer takes", f)
		}
	}
	var gs firewallGrants
	var nest func(ctx context.Context, i int) error
	nest = func(ctx context.Context, i int) error {
		if i == len(ordered) {
			return write(ctx, gs)
		}
		return s.WithReleaseFeature(ctx, ordered[i], func(ctx context.Context, g capabilities.FeatureGrant) error {
			switch ordered[i] {
			case capabilities.FeatureFirewallIPv6:
				gs.IPv6 = g
			case capabilities.FeatureFirewallLog:
				gs.Log = g
			case capabilities.FeatureFirewallTagGroups:
				gs.Tag = g
			}
			return nest(ctx, i+1)
		})
	}
	return nest(ctx, 0)
}

// ipSetFeatures is an ip set's release features: firewall_ipv6 when it holds
// an IPv6 element.
func ipSetFeatures(cidrs []string) ([]capabilities.Feature, error) {
	v6, err := corrosion.IPSetFamily(cidrs)
	if err != nil || !v6 {
		return nil, err
	}
	return []capabilities.Feature{capabilities.FeatureFirewallIPv6}, nil
}

// ruleRowFeatures is the check every rule a client sends passes before any
// release gate is asked or anything is stored, and the release features its
// write then needs (the writeFirewallRow need and invalid arguments). In
// order: a form a client may not send (a "+" action suffix:
// corrosion.RefuseClientRuleForm), then the grammar the renderer writes into
// an nft script (finding F-1, with the tag-group cidr tag:<group>), then the
// row's features (corrosion.FirewallRowFeatures).
func ruleRowFeatures(direction, proto, port, cidr, action, comment string) ([]capabilities.Feature, error) {
	if err := corrosion.RefuseClientRuleForm(cidr, action); err != nil {
		return nil, err
	}
	if err := firewall.ValidateRuleFields(direction, proto, port, cidr, action, comment); err != nil {
		return nil, err
	}
	return corrosion.FirewallRowFeatures(cidr, proto, action)
}

// logRow is a client rule's stored action and release features once its log
// field is applied: a rule asked to log (log=true) is stored with the
// server's suffix (corrosion.LoggedAction) and needs firewall_log. It is
// applied only to a rule ruleRowFeatures took, which refused a client's own
// "+" suffix.
func logRow(action string, log bool, need []capabilities.Feature, invalid error) (string, []capabilities.Feature) {
	if !log || invalid != nil {
		return action, need
	}
	return corrosion.LoggedAction(action), append(slices.Clone(need), capabilities.FeatureFirewallLog)
}

// ipSetRowFeatures is ruleRowFeatures for an ip set: the grammar, then
// ipSetFeatures.
func ipSetRowFeatures(name string, cidrs []string) ([]capabilities.Feature, error) {
	if err := rulefield.IPSet(name, cidrs); err != nil {
		return nil, err
	}
	return ipSetFeatures(cidrs)
}

// refuseUnknownTagGroup refuses a new rule whose cidr names a tag group this
// replica does not hold (removed, or never set). A rule written ahead of its
// group would match nothing as an accept and lose its address as a deny
// (spec §4.6) from the moment it is stored. It is asked once the
// firewall_tag_groups gate has granted, so before the latch the refusal is
// the release text. A group whose row cannot be read exists.
func (s *Server) refuseUnknownTagGroup(ctx context.Context, cidr string) error {
	name, ok := rulefield.TagCIDRName(cidr)
	if !ok {
		return nil
	}
	_, exists, err := corrosion.GetFirewallTagGroup(ctx, s.db, name)
	if err != nil {
		return status.Errorf(codes.Internal, "read tag group %s: %v", name, err)
	}
	if !exists {
		return status.Errorf(codes.FailedPrecondition, "cidr %q: tag group %q does not exist; set the group before a rule references it", cidr, name)
	}
	return nil
}

// firewallWriteErr is a firewall-row write's error as the handler returns it:
// the release gate's refusal unchanged, anything else as "<what>: <err>" with
// firewallWriteCode's code.
func firewallWriteErr(err error, def codes.Code, what string) error {
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	return status.Errorf(firewallWriteCode(err, def), "%s: %v", what, err)
}

// firewallWriteCode maps a firewall-row write error to its gRPC code: a rule
// refused for want of a release feature's grant is a precondition (it will
// succeed once every host is upgraded), anything else keeps def.
func firewallWriteCode(err error, def codes.Code) codes.Code {
	if errors.Is(err, corrosion.ErrFirewallIPv6GateClosed) || errors.Is(err, corrosion.ErrFirewallLogGateClosed) ||
		errors.Is(err, corrosion.ErrFirewallTagGroupsGateClosed) {
		return codes.FailedPrecondition
	}
	var fe *rulefield.FieldError
	if errors.As(err, &fe) {
		return codes.InvalidArgument
	}
	return def
}

// reconcileLocal triggers an immediate best-effort re-render on the connected
// host so an operator's change is live without waiting for the poll tick.
func (s *Server) reconcileLocal(ctx context.Context) {
	if s.fwRec() == nil {
		return
	}
	if err := s.fwRec().Reconcile(ctx); err != nil {
		slog.Warn("firewall: immediate reconcile after change failed", "error", err)
	}
}

// ── Audit states (colonelpanik/litevirt#182) ──
//
// Each mutation below records who made it (s.audit takes the caller from ctx),
// what it touched (the target), and the policy before and after it. The
// "before" is read ahead of the write, because a delete tombstones the row and
// the audit log is then the only place left that can say what it was. A read
// that fails is recorded as unknown, never as none.

func ruleState(r *corrosion.FirewallRule, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case r == nil:
		return corrosion.AuditStateNone
	}
	return r.AuditText()
}

func ipSetState(set *corrosion.IPSet, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case set == nil:
		return corrosion.AuditStateNone
	}
	return set.AuditText()
}

func defaultState(d *corrosion.FirewallDefault, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case d == nil:
		return corrosion.AuditStateUnset
	}
	return verdictOf(d.DefaultDeny)
}

func verdictOf(deny bool) string {
	if deny {
		return "deny"
	}
	return "accept"
}

// requireFirewallWrite is the authority a write of cluster firewall policy
// takes: cluster and host rules, ip sets and default policies are global
// rows every host enforces, so each needs sg.write at the cluster root, as
// a stack's firewall does (stackFirewallRefusal). Admin and NetworkAdmin
// hold it; Operator holds sg.read only. With no role bindings the legacy
// operator role passes. A refusal for a missing grant names the grant.
func (s *Server) requireFirewallWrite(ctx context.Context, what string) error {
	err := s.requireSGWrite(ctx)
	if err == nil || status.Code(err) != codes.PermissionDenied {
		return err
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "lacks") {
		return status.Errorf(codes.PermissionDenied, "%s needs sg.write at the cluster root: %s", what, msg)
	}
	return status.Errorf(codes.PermissionDenied,
		"%s needs sg.write at the cluster root (%s). An administrator can grant it with "+
			"`lv role grant NetworkAdmin %s --path / --propagate`", what, msg, "user:"+callerPrincipal(ctx))
}

// ── Cluster-tier rules ──

func (s *Server) CreateClusterFirewallRule(ctx context.Context, req *pb.CreateClusterFirewallRuleRequest) (*pb.FirewallRule, error) {
	if err := s.requireFirewallWrite(ctx, "adding a cluster rule"); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.Direction == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with direction required")
	}
	row := corrosion.FirewallRule{
		ID: randid.New(), Direction: r.Direction, Proto: r.Proto, PortRange: r.Port,
		CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority), Comment: r.Comment,
	}
	row.Proto, row.PortRange, row.Action = rulefield.NormaliseRule(row.Proto, row.PortRange, row.Action)
	need, invalid := ruleRowFeatures(row.Direction, row.Proto, row.PortRange, row.CIDR, row.Action, row.Comment)
	row.Action, need = logRow(row.Action, r.Log, need, invalid)
	if err := s.writeFirewallRow(ctx, need, invalid, func(ctx context.Context, g firewallGrants) error {
		if err := s.refuseUnknownTagGroup(ctx, row.CIDR); err != nil {
			return err
		}
		return corrosion.InsertClusterFirewallRuleWithGrant(ctx, s.db, g.IPv6, g.Log, g.Tag, row)
	}); err != nil {
		return nil, firewallWriteErr(err, codes.InvalidArgument, "create cluster rule")
	}
	// The "after" is read back so it is the rule as stored and enforced — the
	// insert fills in defaults for an empty proto, action and priority.
	s.audit(ctx, "firewall.cluster-rule.add", row.ID,
		corrosion.AuditChange(corrosion.AuditStateNone, ruleState(corrosion.GetClusterFirewallRule(ctx, s.db, row.ID))), "ok")
	s.reconcileLocal(ctx)
	return toPbFirewallRule(row), nil
}

func (s *Server) ListClusterFirewallRules(ctx context.Context, _ *pb.ListClusterFirewallRulesRequest) (*pb.ListClusterFirewallRulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rules, err := corrosion.ListClusterFirewallRules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list cluster rules: %v", err)
	}
	resp := &pb.ListClusterFirewallRulesResponse{}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, toPbFirewallRule(r))
	}
	return resp, nil
}

func (s *Server) DeleteClusterFirewallRule(ctx context.Context, req *pb.DeleteClusterFirewallRuleRequest) (*emptypb.Empty, error) {
	if err := s.requireFirewallWrite(ctx, "removing a cluster rule"); err != nil {
		return nil, err
	}
	before := ruleState(corrosion.GetClusterFirewallRule(ctx, s.db, req.Id))
	if err := corrosion.DeleteClusterFirewallRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete cluster rule: %v", err)
	}
	s.audit(ctx, "firewall.cluster-rule.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── Host-tier rules ──

func (s *Server) CreateHostFirewallRule(ctx context.Context, req *pb.CreateHostFirewallRuleRequest) (*pb.FirewallRule, error) {
	if err := s.requireFirewallWrite(ctx, "adding a host rule"); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.Direction == "" || r.HostName == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with host_name and direction required")
	}
	row := corrosion.FirewallRule{
		ID: randid.New(), HostName: r.HostName, Direction: r.Direction, Proto: r.Proto,
		PortRange: r.Port, CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority), Comment: r.Comment,
	}
	row.Proto, row.PortRange, row.Action = rulefield.NormaliseRule(row.Proto, row.PortRange, row.Action)
	need, invalid := ruleRowFeatures(row.Direction, row.Proto, row.PortRange, row.CIDR, row.Action, row.Comment)
	row.Action, need = logRow(row.Action, r.Log, need, invalid)
	if err := s.writeFirewallRow(ctx, need, invalid, func(ctx context.Context, g firewallGrants) error {
		if err := s.refuseUnknownTagGroup(ctx, row.CIDR); err != nil {
			return err
		}
		return corrosion.InsertHostFirewallRuleWithGrant(ctx, s.db, g.IPv6, g.Log, g.Tag, row)
	}); err != nil {
		return nil, firewallWriteErr(err, codes.InvalidArgument, "create host rule")
	}
	s.audit(ctx, "firewall.host-rule.add", row.ID,
		corrosion.AuditChange(corrosion.AuditStateNone, ruleState(corrosion.GetHostFirewallRule(ctx, s.db, row.ID))), "ok")
	s.reconcileLocal(ctx)
	return toPbFirewallRule(row), nil
}

func (s *Server) ListHostFirewallRules(ctx context.Context, req *pb.ListHostFirewallRulesRequest) (*pb.ListHostFirewallRulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rules, err := corrosion.ListHostFirewallRules(ctx, s.db, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list host rules: %v", err)
	}
	resp := &pb.ListHostFirewallRulesResponse{}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, toPbFirewallRule(r))
	}
	return resp, nil
}

func (s *Server) DeleteHostFirewallRule(ctx context.Context, req *pb.DeleteHostFirewallRuleRequest) (*emptypb.Empty, error) {
	if err := s.requireFirewallWrite(ctx, "removing a host rule"); err != nil {
		return nil, err
	}
	before := ruleState(corrosion.GetHostFirewallRule(ctx, s.db, req.Id))
	if err := corrosion.DeleteHostFirewallRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete host rule: %v", err)
	}
	s.audit(ctx, "firewall.host-rule.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── IP sets ──

func (s *Server) CreateIpSet(ctx context.Context, req *pb.CreateIpSetRequest) (*pb.IpSet, error) {
	if err := s.requireFirewallWrite(ctx, "adding an ip set"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// `--cidr 10.0.0.1,10.0.0.2` is two elements (rulefield.NormaliseSetElements).
	row := corrosion.IPSet{ID: randid.New(), Name: req.Name, CIDRs: rulefield.NormaliseSetElements(req.Cidrs)}
	need, invalid := ipSetRowFeatures(row.Name, row.CIDRs)
	if invalid == nil {
		// Before any gate is asked: a set named as another's IPv6 companion
		// would make every host refuse its ruleset.
		invalid = corrosion.IPSetCompanionClash(ctx, s.db, "", []corrosion.IPSet{row})
	}
	if err := s.writeFirewallRow(ctx, need, invalid, func(ctx context.Context, g firewallGrants) error {
		return corrosion.InsertIPSetWithGrant(ctx, s.db, g.IPv6, row)
	}); err != nil {
		return nil, firewallWriteErr(err, codes.Internal, "create ipset")
	}
	s.audit(ctx, "firewall.ipset.add", row.Name,
		corrosion.AuditChange(corrosion.AuditStateNone, ipSetState(corrosion.GetIPSet(ctx, s.db, row.ID))), "ok")
	s.reconcileLocal(ctx)
	return toPbIpSet(row), nil
}

func (s *Server) ListIpSets(ctx context.Context, _ *pb.ListIpSetsRequest) (*pb.ListIpSetsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	sets, err := corrosion.ListIPSets(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list ipsets: %v", err)
	}
	resp := &pb.ListIpSetsResponse{}
	for _, st := range sets {
		resp.Ipsets = append(resp.Ipsets, toPbIpSet(st))
	}
	return resp, nil
}

func (s *Server) DeleteIpSet(ctx context.Context, req *pb.DeleteIpSetRequest) (*emptypb.Empty, error) {
	if err := s.requireFirewallWrite(ctx, "removing an ip set"); err != nil {
		return nil, err
	}
	before := ipSetState(corrosion.GetIPSet(ctx, s.db, req.Id))
	if err := corrosion.DeleteIPSet(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete ipset: %v", err)
	}
	s.audit(ctx, "firewall.ipset.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── Default-deny policy ──

func (s *Server) SetFirewallDefault(ctx context.Context, req *pb.SetFirewallDefaultRequest) (*emptypb.Empty, error) {
	if err := s.requireFirewallWrite(ctx, "setting a default policy"); err != nil {
		return nil, err
	}
	scope, err := s.defaultDenyScope(ctx, req.GetScope())
	if err != nil {
		return nil, err
	}
	before := defaultState(corrosion.GetFirewallDefault(ctx, s.db, scope))
	if err := corrosion.SetFirewallDefault(ctx, s.db, scope, req.DefaultDeny, ""); err != nil {
		return nil, status.Errorf(codes.Internal, "set default policy: %v", err)
	}
	s.audit(ctx, "firewall.default-deny", scope, corrosion.AuditChange(before, verdictOf(req.DefaultDeny)), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// defaultDenyScope is the firewall_defaults scope of a default-deny request:
// "" is the cluster ("cluster"), and any other scope a host this replica
// knows, as for `lv firewall synflood --scope`. "cluster" still means the
// cluster (the web UI and older clients send it) until a host has that name: the
// two then share one key, and the scope is refused rather than guessed.
func (s *Server) defaultDenyScope(ctx context.Context, scope string) (string, error) {
	if scope == "" {
		return "cluster", nil
	}
	h, err := corrosion.GetHost(ctx, s.db, scope)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "look up host %s: %v", scope, err)
	}
	switch {
	case scope == "cluster" && h != nil:
		return "", status.Error(codes.FailedPrecondition,
			"a host is named cluster, and default-deny cannot tell its policy from the cluster's: "+
				"leave out --scope for the cluster-wide policy; host cluster cannot have its own")
	case scope == "cluster":
		return "cluster", nil
	case h == nil:
		return "", status.Errorf(codes.NotFound,
			"no host named %q has joined, as this node sees it: --scope takes a host (lv host ls); leave it out for the cluster-wide policy", scope)
	}
	return scope, nil
}

func (s *Server) ListFirewallDefaults(ctx context.Context, _ *pb.ListFirewallDefaultsRequest) (*pb.ListFirewallDefaultsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	defaults, err := corrosion.ListFirewallDefaults(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list defaults: %v", err)
	}
	resp := &pb.ListFirewallDefaultsResponse{}
	for _, d := range defaults {
		resp.Defaults = append(resp.Defaults, &pb.FirewallDefault{Scope: d.Scope, DefaultDeny: d.DefaultDeny, StackName: d.StackName})
	}
	return resp, nil
}

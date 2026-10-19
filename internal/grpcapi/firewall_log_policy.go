package grpcapi

// The firewall log policy (docs/firewall.md, "Logging"): whether each guest
// NIC's default verdict is logged, and the per-NIC-side log budget. Role
// operator, audited as firewall.log_policy, written through the release
// feature firewall_log.

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// logPolicyHost is the corrosion scope of an API scope: "" is the cluster,
// and every other scope, "cluster" included, is a host (Track B4's rule), so
// a host named cluster has a reachable row.
func logPolicyHost(scope string) string { return scope }

// logPolicyAuditCluster is the cluster scope's audit target.
const logPolicyAuditCluster = "(cluster)"

// logPolicyState is a scope's policy for an audit row.
func logPolicyState(p corrosion.FirewallLogPolicy, recorded bool, err error) string {
	switch {
	case err != nil && !errors.Is(err, corrosion.ErrUnreadableFirewallPolicy):
		return corrosion.AuditUnknown(err)
	case err != nil:
		return "unreadable"
	case !recorded:
		return corrosion.AuditStateUnset
	}
	return fmt.Sprintf("%s rate=%d burst=%d", p.Default, p.Rate, p.Burst)
}

// SetFirewallLogPolicy sets one scope's log policy: on or off (logging the
// default verdict or not, with the per-NIC-side budget; 0 is the default),
// or, for a host, inherit (clear its row).
func (s *Server) SetFirewallLogPolicy(ctx context.Context, req *pb.SetFirewallLogPolicyRequest) (*pb.FirewallLogPolicy, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	host := logPolicyHost(req.GetScope())
	var p corrosion.FirewallLogPolicy
	switch req.GetMode() {
	case corrosion.LogPolicyOn, corrosion.LogPolicyOff:
		p = corrosion.FirewallLogPolicy{Default: req.GetMode(), Rate: int(req.GetRate()), Burst: int(req.GetBurst())}
		if p.Rate == 0 {
			p.Rate = corrosion.LogPolicyDefaultRate
		}
		if p.Burst == 0 {
			p.Burst = corrosion.LogPolicyDefaultBurst
		}
		if p.Rate > corrosion.LogPolicyMax || p.Burst > corrosion.LogPolicyMax {
			return nil, status.Errorf(codes.InvalidArgument, "--rate and --burst must each be %d-%d", corrosion.LogPolicyMin, corrosion.LogPolicyMax)
		}
	case "inherit":
		if host == "" {
			return nil, status.Error(codes.InvalidArgument, "inherit needs a host scope: the cluster policy is on or off")
		}
		if req.GetRate() != 0 || req.GetBurst() != 0 {
			return nil, status.Error(codes.InvalidArgument, "inherit takes no --rate or --burst")
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "mode %q: want on, off or inherit", req.GetMode())
	}
	if host != "" {
		h, err := corrosion.GetHost(ctx, s.db, host)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read host %s: %v", host, err)
		}
		if h == nil {
			return nil, status.Errorf(codes.InvalidArgument, "no host named %q: --scope takes a host (lv host ls); leave it out for the cluster-wide policy", req.GetScope())
		}
	}
	// "(cluster)" is no host name, so the cluster scope's audit rows cannot
	// be read as those of a host named cluster.
	target := logPolicyAuditCluster
	if host != "" {
		target = host
	}
	before := logPolicyState(corrosion.GetFirewallLogPolicy(ctx, s.db, host))
	after := corrosion.AuditStateUnset
	if p.Default != "" {
		after = logPolicyState(p, true, nil)
	}
	err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallLog, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return corrosion.SetFirewallLogPolicy(ctx, s.db, g, host, p, callerUsername(ctx))
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		s.audit(ctx, "firewall.log_policy", target, corrosion.AuditChange(before, after), "error")
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "set log policy: %v", err)
	}
	s.audit(ctx, "firewall.log_policy", target, corrosion.AuditChange(before, after), "ok")
	s.reconcileLocal(ctx)
	if host == "" {
		return s.logPolicyOf(ctx, "", nil)
	}
	return s.logPolicyOf(ctx, host, nil)
}

// logPolicyOf is scope's policy as the API shows it: the cluster's (host ""),
// or a host's own row, else the cluster's marked inherited. cluster is the
// cluster's, when already read.
func (s *Server) logPolicyOf(ctx context.Context, host string, cluster *pb.FirewallLogPolicy) (*pb.FirewallLogPolicy, error) {
	row, recorded, err := corrosion.GetFirewallLogPolicyRow(ctx, s.db, host)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableFirewallPolicy) {
		return nil, status.Errorf(codes.Internal, "read log policy: %v", err)
	}
	scope := corrosion.LogPolicyScopeCluster
	if host != "" {
		scope = host
	}
	if !recorded {
		if host == "" {
			return &pb.FirewallLogPolicy{Scope: scope, Rate: corrosion.LogPolicyDefaultRate, Burst: corrosion.LogPolicyDefaultBurst}, nil
		}
		if cluster == nil {
			if cluster, err = s.logPolicyOf(ctx, "", nil); err != nil {
				return nil, err
			}
		}
		return &pb.FirewallLogPolicy{Scope: scope, DefaultPolicy: cluster.GetDefaultPolicy(), Rate: cluster.GetRate(),
			Burst: cluster.GetBurst(), Inherited: true}, nil
	}
	if err != nil {
		// Unreadable: rate and burst 0, which no readable row has, so a
		// reader can tell it from an off row (read as off at the default
		// budget; the condition firewall.policy.unreadable names the key).
		return &pb.FirewallLogPolicy{Scope: scope, SetBy: row.SetBy, UpdatedAt: row.UpdatedAt}, nil
	}
	p := row.Policy
	return &pb.FirewallLogPolicy{Scope: scope, DefaultPolicy: p.On(), Rate: uint32(p.Rate), Burst: uint32(p.Burst),
		SetBy: row.SetBy, UpdatedAt: row.UpdatedAt}, nil
}

// GetFirewallLogPolicy lists the cluster policy, then every host's by name:
// its own row, or the cluster's (inherited).
func (s *Server) GetFirewallLogPolicy(ctx context.Context, _ *pb.GetFirewallLogPolicyRequest) (*pb.GetFirewallLogPolicyResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	cluster, err := s.logPolicyOf(ctx, "", nil)
	if err != nil {
		return nil, err
	}
	out := &pb.GetFirewallLogPolicyResponse{Policies: []*pb.FirewallLogPolicy{cluster}}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	for _, h := range hosts {
		p, err := s.logPolicyOf(ctx, h.Name, cluster)
		if err != nil {
			return nil, err
		}
		out.Policies = append(out.Policies, p)
	}
	return out, nil
}

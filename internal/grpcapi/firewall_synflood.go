package grpcapi

// SYN-flood protection on guest NICs (docs/firewall.md, "SYN-flood
// protection"): the policy RPCs behind `lv firewall synflood`.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// synfloodModeInherit clears a host's own policy (SetFirewallSynfloodRequest).
const synfloodModeInherit = "inherit"

// SetFirewallSynflood writes the cluster's SYN-flood policy (scope "") or one
// known host's. Operator; refused until the firewall_synflood release
// feature's latch; audited as firewall.synflood with the scope as target and
// the policy before and after.
func (s *Server) SetFirewallSynflood(ctx context.Context, req *pb.SetFirewallSynfloodRequest) (*pb.FirewallSynfloodPolicy, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	host := req.GetScope()
	target := host
	if host == "" {
		target = corrosion.FirewallSynfloodScopeCluster
	} else {
		h, err := corrosion.GetHost(ctx, s.db, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "look up host %s: %v", host, err)
		}
		if h == nil {
			return nil, status.Errorf(codes.NotFound,
				"no host named %q: --scope takes a host (lv host ls); leave it out for the cluster-wide policy", host)
		}
	}
	var p corrosion.FirewallSynflood
	switch req.GetMode() {
	case corrosion.SynfloodOn:
		p = corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: int(req.GetRate()), Burst: int(req.GetBurst())}
		if p.Rate == 0 {
			p.Rate = corrosion.SynfloodDefaultRate
		}
		if p.Burst == 0 {
			p.Burst = corrosion.SynfloodDefaultBurst
		}
		if p.Rate > corrosion.SynfloodMax || p.Burst > corrosion.SynfloodMax {
			return nil, status.Errorf(codes.InvalidArgument, "rate %d and burst %d must each be %d-%d",
				p.Rate, p.Burst, corrosion.SynfloodMin, corrosion.SynfloodMax)
		}
	case corrosion.SynfloodOff:
		if req.GetRate() != 0 || req.GetBurst() != 0 {
			return nil, status.Error(codes.InvalidArgument, "off takes no rate or burst")
		}
		p = corrosion.FirewallSynflood{Mode: corrosion.SynfloodOff}
	case synfloodModeInherit:
		if host == "" {
			return nil, status.Error(codes.InvalidArgument, "inherit clears a host's own policy: name the host (--scope <host>)")
		}
		if req.GetRate() != 0 || req.GetBurst() != 0 {
			return nil, status.Error(codes.InvalidArgument, "inherit takes no rate or burst")
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "mode %q: want on, off or inherit", req.GetMode())
	}

	actor := callerUsername(ctx)
	var before string
	err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallSynflood, func(ctx context.Context, g capabilities.FeatureGrant) error {
		before = synfloodAuditText(corrosion.GetFirewallSynflood(ctx, s.db, host))
		if err := corrosion.SetFirewallSynflood(ctx, s.db, g, host, p, actor); err != nil {
			if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return status.Errorf(codes.FailedPrecondition, "%v", err)
			}
			return status.Errorf(codes.Internal, "write the SYN-flood policy of %s: %v", target, err)
		}
		return nil
	})
	after := synfloodAuditText(p, p.Mode != "", nil)
	if err != nil {
		if before != "" {
			s.audit(ctx, "firewall.synflood", target, corrosion.AuditChange(before, after), "error")
		}
		return nil, err
	}
	s.audit(ctx, "firewall.synflood", target, corrosion.AuditChange(before, after), "ok")
	slog.Info("firewall SYN-flood policy set", "scope", target, "policy", after, "by", actor)
	s.reconcileLocal(ctx)
	return s.synfloodPolicy(ctx, host)
}

// synfloodAuditText is a policy as an audit row records it.
func synfloodAuditText(p corrosion.FirewallSynflood, recorded bool, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case !recorded:
		return corrosion.AuditStateUnset
	case p.On():
		return fmt.Sprintf("on %d/%d", p.Rate, p.Burst)
	}
	return p.Mode
}

// GetFirewallSynflood reports the cluster's policy, always first (a host may
// be named "cluster" too), then each host's as this replica resolves it — its
// own row, else the cluster's (inherited), else off — sorted by host name.
func (s *Server) GetFirewallSynflood(ctx context.Context, _ *pb.GetFirewallSynfloodRequest) (*pb.GetFirewallSynfloodResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	cluster, err := s.synfloodPolicy(ctx, "")
	if err != nil {
		return nil, err
	}
	out := &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{cluster}}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list hosts: %v", err)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	for _, h := range hosts {
		p, err := s.synfloodPolicy(ctx, h.Name)
		if err != nil {
			return nil, err
		}
		out.Policies = append(out.Policies, p)
	}
	return out, nil
}

// synfloodPolicy is host's policy for the API, the cluster's own row for
// host "". A row this build cannot read shows as what is enforced for it: on
// at the defaults.
func (s *Server) synfloodPolicy(ctx context.Context, host string) (*pb.FirewallSynfloodPolicy, error) {
	out := &pb.FirewallSynfloodPolicy{Scope: host}
	if host == "" {
		out.Scope = corrosion.FirewallSynfloodScopeCluster
	}
	p, err := corrosion.ResolveFirewallSynflood(ctx, s.db, host)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableFirewallPolicy) {
		return nil, status.Errorf(codes.Unavailable, "read the SYN-flood policy of %s: %v", out.Scope, err)
	}
	out.Inherited = host != "" && p.Host != host
	out.Mode = corrosion.SynfloodOff
	if p.On() {
		out.Mode, out.Rate, out.Burst = corrosion.SynfloodOn, uint32(p.Rate), uint32(p.Burst)
	}
	if !out.Inherited {
		out.SetBy, out.UpdatedAt = p.SetBy, p.UpdatedAt
	}
	return out, nil
}

package grpcapi

// SYN-flood protection on guest NICs (docs/firewall.md, "SYN-flood
// protection"): the policy RPCs behind `lv firewall synflood`.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
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
	target := synfloodScope(host)
	if host != "" {
		h, err := corrosion.GetHost(ctx, s.db, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "look up host %s: %v", host, err)
		}
		if h == nil {
			return nil, status.Errorf(codes.NotFound,
				"no host named %q has joined, as this node sees it: --scope takes a host (lv host ls); leave it out for the cluster-wide policy", host)
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

// synfloodScope names a scope in the API and the audit log: "cluster" for the
// cluster's own policy, "host/<name>" for a host's, so a host named cluster
// is never read as the cluster.
func synfloodScope(host string) string {
	if host == "" {
		return corrosion.FirewallSynfloodScopeCluster
	}
	return synfloodHostScopePrefix + host
}

// synfloodHostScopePrefix prefixes a host's scope in the API and audit log.
const synfloodHostScopePrefix = "host/"

// synfloodFanoutTimeout bounds the whole status fan-out: every peer is asked
// at once under this one deadline.
var synfloodFanoutTimeout = 10 * time.Second

// GetFirewallSynflood reports the cluster's policy (scope "cluster"), then
// each host's (scope "host/<name>") as this replica resolves it — its own
// row, else the cluster's (inherited), else off — sorted by host name, with
// what the host itself has in force (in_force, from its last firewall pass)
// and its SYN-flood drops since its last reload: this host's read from its
// kernel, every other active host's asked of it (local_only), all at once
// under one deadline. A host that cannot be asked, or is not active, says why
// in error and carries no count. With local_only, only this host's entry; a
// failure to read its own policy or counters is reported in that entry's
// error, not as a failed call.
func (s *Server) GetFirewallSynflood(ctx context.Context, req *pb.GetFirewallSynfloodRequest) (*pb.GetFirewallSynfloodResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.GetLocalOnly() {
		p, err := s.synfloodPolicy(ctx, s.hostName)
		if err != nil {
			p = &pb.FirewallSynfloodPolicy{Scope: synfloodScope(s.hostName), Error: status.Convert(err).Message()}
		} else {
			s.localSynfloodDrops(ctx, p)
		}
		s.localSynfloodInForce(p)
		return &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{p}}, nil
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
	fctx, cancel := context.WithTimeout(ctx, synfloodFanoutTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, h := range hosts {
		p, err := s.synfloodPolicy(ctx, h.Name)
		if err != nil {
			return nil, err
		}
		switch {
		case h.Name == s.hostName:
			s.localSynfloodDrops(ctx, p)
			s.localSynfloodInForce(p)
		case h.State != "active":
			p.Error = fmt.Sprintf("not asked: the host is %s", h.State)
		default:
			wg.Add(1)
			go func(host string, p *pb.FirewallSynfloodPolicy) {
				defer wg.Done()
				s.peerSynfloodDrops(fctx, host, p)
			}(h.Name, p)
		}
		out.Policies = append(out.Policies, p)
	}
	wg.Wait()
	return out, nil
}

// localSynfloodDrops fills p with this host's drop counters, or why they
// could not be read.
func (s *Server) localSynfloodDrops(ctx context.Context, p *pb.FirewallSynfloodPolicy) {
	read := s.synFloodDrops
	if read == nil {
		read = firewall.SynFloodDrops
	}
	v4, v6, err := read(ctx)
	if err != nil {
		p.Error = err.Error()
		return
	}
	p.DropsV4, p.DropsV6 = v4, v6
}

// localSynfloodInForce fills p with what this host's last firewall pass put
// in force, or says in p's error that no pass has completed.
func (s *Server) localSynfloodInForce(p *pb.FirewallSynfloodPolicy) {
	if r, ok := s.fwRec().(appliedStater); ok {
		p.InForce = r.AppliedState().SynFloodInForce
	}
	if p.InForce == "" {
		why := "no firewall pass has completed on this host yet"
		if p.Error != "" {
			why = p.Error + "; " + why
		}
		p.Error = why
	}
}

// peerSynfloodDrops asks host for its own drop counters (local_only) and
// fills p with them, or with why not: the host's daemon predates the
// counters, the host reported its own failure to read them, or it could not
// be reached in time.
func (s *Server) peerSynfloodDrops(ctx context.Context, host string, p *pb.FirewallSynfloodPolicy) {
	client, closeFn, err := s.dialPeer(ctx, host)
	if err != nil {
		p.Error = "unreachable: " + err.Error()
		return
	}
	defer closeFn()
	r, err := client.GetFirewallSynflood(ctx, &pb.GetFirewallSynfloodRequest{LocalOnly: true})
	switch {
	case status.Code(err) == codes.Unimplemented:
		p.Error = "the host's daemon predates SYN-flood status; upgrade litevirtd there"
	case err != nil:
		p.Error = "unreachable: " + err.Error()
	case len(r.GetPolicies()) == 0:
		p.Error = "no answer"
	default:
		got := r.GetPolicies()[0]
		p.InForce = got.GetInForce() // "" from a build that predates it
		p.DropsV4, p.DropsV6 = got.GetDropsV4(), got.GetDropsV6()
		if got.GetError() != "" {
			p.DropsV4, p.DropsV6, p.Error = 0, 0, "reported by the host: "+got.GetError()
		}
	}
}

// synfloodPolicy is host's policy for the API, the cluster's own row for
// host "". A row this build cannot read shows as what is enforced for it: on
// at the defaults.
func (s *Server) synfloodPolicy(ctx context.Context, host string) (*pb.FirewallSynfloodPolicy, error) {
	out := &pb.FirewallSynfloodPolicy{Scope: synfloodScope(host)}
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

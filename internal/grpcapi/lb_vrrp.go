package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// The load balancers' VRRP transport (capabilities.VRRPUnicastV1).
//
// The transport is ONE value for the whole cluster, read by every host from
// its own replica (corrosion.GetVRRPTransport), so an LB's hosts render the
// same one whatever their own config says:
//
//   - the operator's choice (`lv cluster vrrp-transport`), when recorded;
//   - else unicast once any host's vrrp_unicast_v1 latch has become durable:
//     that host records it (the latch row), and every host renders unicast from
//     the moment the row reaches it;
//   - else unicast once this host's own latch is durable (before its row has
//     been written or replicated);
//   - else multicast, as every earlier build renders.
//
// enforcement.vrrp_unicast decides only whether this host advertises the
// token while it has not latched; it never decides what is rendered.

// LB health condition (evaluator "lb", subject this host).
const (
	LBEvaluator = "lb"
	// CondLBVRRPSplit: this host renders unicast VRRP for an LB one of whose
	// hosts does not advertise vrrp_unicast_v1 — an earlier build back in the
	// cluster after the latch, which renders multicast: both hold the VIP.
	CondLBVRRPSplit = "lb.vrrp.transport_split"
)

// vrrpUnicastActive reports whether this host renders its LBs' VRRP as
// unicast (see the package comment above). An error is a failed read of the
// policy; callers keep what is rendered.
func (s *Server) vrrpUnicastActive(ctx context.Context) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	p, err := corrosion.GetVRRPTransport(ctx, s.db)
	if err != nil {
		return false, err
	}
	if p.Unknown != "" {
		slog.Warn("lb: the recorded VRRP transport is unknown to this build; ignoring it", "value", p.Unknown)
	}
	g := s.gateV()
	own := g != nil && g.DurablyLatched(capabilities.VRRPUnicastV1)
	if own && !p.Latched && s.db.MayWriteClusterPolicy() {
		// The first host to latch tells every other one, so they switch with
		// replication rather than at their own latch.
		if err := corrosion.MarkVRRPUnicastLatched(ctx, s.db, s.hostName); err != nil {
			slog.Warn("lb: could not record the vrrp_unicast_v1 latch", "error", err)
		}
	}
	s.vrrpRowLatched.Store(p.Latched || own)
	switch p.Operator {
	case corrosion.VRRPTransportMulticast:
		return false, nil
	case corrosion.VRRPTransportUnicast:
		return true, nil
	}
	return p.Latched || own, nil
}

// lbVRRPTransport sets the VRRP transport of cfg, an LB this host runs with
// the other hosts in lbHosts. On the multicast transport it leaves cfg as it
// is. On unicast the adverts go from this host's recorded address, over the
// device that holds it, to each other LB host's recorded address.
//
// A host in lbHosts with no recorded IPv4 address — removed from the cluster,
// or never known — is left out of the peers: it cannot be a VRRP peer, and the
// hosts still serving must keep the VIP. With no peer left the LB renders the
// sole-host form and becomes master on its own. What it refuses: a failed
// read, and a host whose own recorded address no local device holds (its
// adverts would go out from an address nothing answers).
func (s *Server) lbVRRPTransport(ctx context.Context, cfg *lb.Config, lbHosts []string) error {
	unicast, err := s.vrrpUnicastActive(ctx)
	if err != nil {
		return fmt.Errorf("vrrp: read the VRRP transport: %w", err)
	}
	if !unicast {
		return nil
	}
	local, err := s.hostIPv4(ctx, s.hostName)
	if err != nil {
		return fmt.Errorf("vrrp: %w", err)
	}
	if local == "" {
		return fmt.Errorf("vrrp: host %s has no IPv4 address recorded to send VRRP from", s.hostName)
	}
	dev := s.lbIfaceForIP(local)
	if dev == "" {
		return fmt.Errorf("vrrp: no device on %s holds its recorded address %s, so VRRP sent from it would never be answered: correct advertise_address", s.hostName, local)
	}
	seen := map[string]bool{s.hostName: true}
	var peers, dropped []string
	for _, h := range lbHosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		ip, err := s.hostIPv4(ctx, h)
		if err != nil {
			return fmt.Errorf("vrrp: %w", err)
		}
		if ip == "" {
			dropped = append(dropped, h)
			continue
		}
		peers = append(peers, ip)
	}
	if len(dropped) > 0 {
		detail := fmt.Sprintf("load balancer %s lists %s, which has no recorded address (removed?): not a VRRP peer; correct its hosts with `lv lb update %s --host <host>` for each host it should run on",
			cfg.Name, strings.Join(dropped, ", "), cfg.Name)
		slog.Warn("lb: "+detail, "lb", cfg.Name)
		s.publish("lb.vrrp_peer_dropped", cfg.Name, detail)
	}
	cfg.VRRPUnicast = true
	cfg.VRRPInterface = dev
	cfg.UnicastSrc = local
	cfg.UnicastPeers = peers
	return nil
}

// lbIfaceForIP is the device holding ip, exactly ("" when none does).
func (s *Server) lbIfaceForIP(ip string) string {
	if s.lbIfaceForIPOverride != nil {
		return s.lbIfaceForIPOverride(ip)
	}
	return lb.InterfaceHoldingIP(ip)
}

// lbVRRPStale reports whether an LB's keepalived config on disk renders
// another transport from the one this host would render now: another mode,
// device, source or set of peers (the policy changed, a peer was added or
// removed, a host's address changed, an apply was missed). No readable config
// is not stale: there is nothing to switch.
func (s *Server) lbVRRPStale(ctx context.Context, rec corrosion.LBConfigRecord) bool {
	var have lb.Transport
	var ok bool
	if s.lbRenderedTransportOverride != nil {
		have, ok = s.lbRenderedTransportOverride(rec.Name)
	} else {
		have, ok = s.lbManager().KeepalivedTransport(rec.Name)
	}
	if !ok {
		return false
	}
	hosts, _ := parseHostsJSON(rec.Hosts)
	want := lb.Config{Name: rec.Name}
	if err := s.lbVRRPTransport(ctx, &want, hosts); err != nil {
		// The apply will refuse the same way and say so; re-apply only when
		// the mode itself is wrong, which is what the refusal must surface.
		unicast, rerr := s.vrrpUnicastActive(ctx)
		return rerr == nil && unicast != have.Unicast
	}
	return !have.Equal(lb.TransportOf(want))
}

// noteVRRPSplit raises CondLBVRRPSplit while this host renders unicast for an
// LB one of whose hosts answers a Ping without vrrp_unicast_v1 (an earlier
// build), and resolves it otherwise. An unreachable host is not counted: it is
// down, not on another transport.
func (s *Server) noteVRRPSplit(ctx context.Context, lbs []corrosion.LBConfigRecord) {
	unicast, err := s.vrrpUnicastActive(ctx)
	if err != nil {
		return
	}
	var split []string
	if unicast {
		lacks := map[string]bool{}
		asked := map[string]bool{}
		for _, rec := range lbs {
			hosts, _ := parseHostsJSON(rec.Hosts)
			for _, h := range hosts {
				if h == s.hostName {
					continue
				}
				if !asked[h] {
					asked[h] = true
					pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					var caps []string
					var perr error
					if s.vrrpPeerCapsOverride != nil {
						caps, perr = s.vrrpPeerCapsOverride(pctx, h)
					} else {
						caps, _, perr = s.PeerCapabilities(pctx, h)
					}
					cancel()
					lacks[h] = perr == nil && !capabilities.Has(caps, capabilities.VRRPUnicastV1)
				}
				if lacks[h] {
					split = append(split, fmt.Sprintf("%s (with %s)", rec.Name, h))
				}
			}
		}
	}
	sort.Strings(split)
	detail := ""
	if len(split) > 0 {
		detail = "load balancers whose VRRP is unicast here but multicast on a host on an earlier build, so both hold the VIP: " +
			strings.Join(split, ", ") + ". Upgrade those hosts, or run `lv cluster vrrp-transport multicast` until they are"
	}
	s.setHostCondition(ctx, LBEvaluator, CondLBVRRPSplit, len(split) > 0, corrosion.SeverityCritical, detail)
}

// GetVRRPTransport reports the transport this host renders and the policy.
func (s *Server) GetVRRPTransport(ctx context.Context, _ *emptypb.Empty) (*pb.VRRPTransportStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.vrrpTransportStatus(ctx)
}

// SetVRRPTransport records the cluster's VRRP transport, which every host
// then renders. Preconditions, each against a way the change could split an
// LB's hosts:
//
//   - failover_scope_v1 durably latched (cluster_policies is writable);
//   - "unicast" only once vrrp_unicast_v1 has latched: before that a host on
//     an earlier build may be an LB peer, and it renders multicast;
//   - every voter reachable, so the change does not reach one side of a
//     partition only.
func (s *Server) SetVRRPTransport(ctx context.Context, req *pb.SetVRRPTransportRequest) (*pb.VRRPTransportStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	t := req.GetTransport()
	if !corrosion.ValidVRRPTransport(t) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown VRRP transport %q (valid: %s, %s)",
			t, corrosion.VRRPTransportUnicast, corrosion.VRRPTransportMulticast)
	}
	if !s.failoverScopeSettable() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the VRRP transport cannot be set until %s has latched on every host", capabilities.FailoverScopeV1)
	}
	if t == corrosion.VRRPTransportUnicast {
		if _, err := s.vrrpUnicastActive(ctx); err != nil {
			return nil, status.Errorf(codes.Internal, "read the VRRP transport: %v", err)
		}
		if !s.vrrpRowLatched.Load() {
			return nil, status.Errorf(codes.FailedPrecondition,
				"the VRRP transport cannot be set to unicast until %s has latched: a host on an earlier build renders multicast",
				capabilities.VRRPUnicastV1)
		}
	}
	if missing, err := s.unreachableVoters(ctx); err != nil {
		return nil, status.Errorf(codes.Unavailable, "check voters are reachable: %v", err)
	} else if len(missing) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the VRRP transport can only be set while every voter is reachable, and %s cannot reach %s",
			s.hostName, strings.Join(missing, ", "))
	}
	if err := corrosion.SetVRRPTransport(ctx, s.db, t, callerUsername(ctx)); err != nil {
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "set VRRP transport: %v", err)
	}
	s.audit(ctx, "cluster.vrrp_transport", "vrrp_transport", "VRRP transport set to "+t, "ok")
	s.publish("cluster.vrrp_transport", t, "set by "+callerUsername(ctx))
	s.kickLBReconcile()
	return s.vrrpTransportStatus(ctx)
}

func (s *Server) vrrpTransportStatus(ctx context.Context) (*pb.VRRPTransportStatus, error) {
	p, err := corrosion.GetVRRPTransport(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the VRRP transport: %v", err)
	}
	unicast, err := s.vrrpUnicastActive(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the VRRP transport: %v", err)
	}
	out := &pb.VRRPTransportStatus{
		Transport: corrosion.VRRPTransportMulticast,
		Policy:    p.Operator, SetBy: p.SetBy, UpdatedAt: p.UpdatedAt,
		Latched:  s.vrrpRowLatched.Load(),
		Settable: s.failoverScopeSettable(),
	}
	if unicast {
		out.Transport = corrosion.VRRPTransportUnicast
	}
	if p.Unknown != "" {
		out.Policy = p.Unknown + " (unknown to this build: ignored)"
	}
	return out, nil
}

// KickLBReconcileForTests asks the LB reconciler for a pass now. Test-only.
func (s *Server) KickLBReconcileForTests() { s.kickLBReconcile() }

// kickLBReconcile asks the LB reconciler for a pass now (nil-safe, never
// blocks): the transport changed.
func (s *Server) kickLBReconcile() {
	select {
	case s.lbKick <- struct{}{}:
	default:
	}
}

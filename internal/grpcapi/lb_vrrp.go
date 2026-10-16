package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
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
// same one whatever their own config or latch schedule:
//
//   - the operator's choice (`lv cluster vrrp-transport`), when recorded;
//   - else unicast once the latch row is: the first host whose
//     vrrp_unicast_v1 latch is durable writes it (noteVRRPLatch), which needs
//     cluster_policies writable (failover_scope_v1 latched there too);
//   - else multicast, as every earlier build renders.
//
// A host's own latch never decides the render: until the row exists every
// host stays multicast, uniform rather than early. enforcement.vrrp_unicast
// decides only whether this host advertises the token before the latch.

// LB health conditions (evaluator "lb", subject this host).
const (
	LBEvaluator = "lb"
	// CondLBVRRPSplit: this host renders unicast VRRP for an LB one of whose
	// hosts is on an earlier build (it answers a Ping without
	// vrrp_unicast_v1, or reports WAL quarantine) and renders multicast: both
	// hold the VIP.
	CondLBVRRPSplit = "lb.vrrp.transport_split"
	// CondLBVRRPRefused: the cluster's transport is unicast and this host
	// cannot render it for an LB, so it has stopped that LB's keepalived
	// (when another LB host serves) rather than hold the VIP beside it.
	CondLBVRRPRefused = "lb.vrrp.transport_refused"
)

// vrrpPolicy reads the transport rows and refreshes vrrpRowLatched: the
// latch formed somewhere (the row) or durably here. It writes nothing.
func (s *Server) vrrpPolicy(ctx context.Context) (corrosion.VRRPTransportPolicy, error) {
	if s.db == nil {
		return corrosion.VRRPTransportPolicy{}, nil
	}
	p, err := corrosion.GetVRRPTransport(ctx, s.db)
	if err != nil {
		return p, err
	}
	g := s.gateV()
	own := g != nil && g.DurablyLatched(capabilities.VRRPUnicastV1)
	s.vrrpRowLatched.Store(p.Latched || own)
	return p, nil
}

// vrrpUnicastActive reports whether this host renders its LBs' VRRP as
// unicast: the cluster's rows only (see above). It writes nothing. An error
// is a failed read of the policy; callers keep what is rendered.
func (s *Server) vrrpUnicastActive(ctx context.Context) (bool, error) {
	p, err := s.vrrpPolicy(ctx)
	if err != nil {
		return false, err
	}
	switch p.Operator {
	case corrosion.VRRPTransportMulticast:
		return false, nil
	case corrosion.VRRPTransportUnicast:
		return true, nil
	}
	return p.Latched, nil
}

// noteVRRPLatch writes the latch row once this host's vrrp_unicast_v1 latch
// is durable and cluster_policies is writable here; until then nothing
// switches anywhere. Called from the LB reconciler's watch only.
func (s *Server) noteVRRPLatch(ctx context.Context) {
	if s.db == nil {
		return
	}
	p, err := s.vrrpPolicy(ctx)
	if err != nil || p.Latched {
		return
	}
	g := s.gateV()
	if g == nil || !g.DurablyLatched(capabilities.VRRPUnicastV1) || !s.db.MayWriteClusterPolicy() {
		return
	}
	if err := corrosion.MarkVRRPUnicastLatched(ctx, s.db, s.hostName); err != nil {
		slog.Warn("lb: could not record the vrrp_unicast_v1 latch", "error", err)
	}
}

// vrrpWant is the transport this host renders for one LB, and the LB hosts
// left out of its peers for want of a recorded address.
type vrrpWant struct {
	unicast bool
	dev     string
	src     string
	peers   []string
	dropped []string
}

// desiredVRRPTransport computes, without side effects, the VRRP transport of
// an LB this host runs with the other hosts in lbHosts. On unicast the
// adverts go from this host's recorded address, over the device that holds
// it, to each other LB host's recorded address.
//
// A host in lbHosts with no recorded IPv4 address — removed from the cluster,
// or never known — is left out of the peers: it cannot be a VRRP peer, and the
// hosts still serving must keep the VIP. With no peer left the LB renders the
// sole-host form and becomes master on its own. What it refuses: a failed
// read, and a host whose own recorded address no local, up, non-loopback
// device holds (its adverts would go out from an address nothing answers).
func (s *Server) desiredVRRPTransport(ctx context.Context, lbHosts []string) (vrrpWant, error) {
	unicast, err := s.vrrpUnicastActive(ctx)
	if err != nil {
		return vrrpWant{}, fmt.Errorf("vrrp: read the VRRP transport: %w", err)
	}
	if !unicast {
		return vrrpWant{}, nil
	}
	local, err := s.hostIPv4(ctx, s.hostName)
	if err != nil {
		return vrrpWant{}, fmt.Errorf("vrrp: %w", err)
	}
	if local == "" {
		return vrrpWant{}, fmt.Errorf("vrrp: host %s has no IPv4 address recorded to send VRRP from", s.hostName)
	}
	dev := s.lbIfaceForIP(local)
	if dev == "" {
		return vrrpWant{}, fmt.Errorf("vrrp: no up, non-loopback device on %s holds its recorded address %s, so VRRP sent from it would never be answered", s.hostName, local)
	}
	w := vrrpWant{unicast: true, dev: dev, src: local}
	seen := map[string]bool{s.hostName: true}
	for _, h := range lbHosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		ip, err := s.hostIPv4(ctx, h)
		if err != nil {
			return vrrpWant{}, fmt.Errorf("vrrp: %w", err)
		}
		if ip == "" {
			w.dropped = append(w.dropped, h)
			continue
		}
		w.peers = append(w.peers, ip)
	}
	return w, nil
}

// lbVRRPTransport sets the VRRP transport of cfg (desiredVRRPTransport), and
// says once per change which LB hosts it left out.
func (s *Server) lbVRRPTransport(ctx context.Context, cfg *lb.Config, lbHosts []string) error {
	w, err := s.desiredVRRPTransport(ctx, lbHosts)
	if err != nil {
		return err
	}
	if s.vrrpEventOnce(cfg.Name, "dropped", strings.Join(w.dropped, ",")) && len(w.dropped) > 0 {
		detail := fmt.Sprintf("load balancer %s lists %s, which has no recorded address (removed?): not a VRRP peer; correct its hosts with `lv lb update %s --host <host>` for each host it should run on",
			cfg.Name, strings.Join(w.dropped, ", "), cfg.Name)
		slog.Warn("lb: "+detail, "lb", cfg.Name)
		s.publish("lb.vrrp_peer_dropped", cfg.Name, detail)
	}
	if !w.unicast {
		return nil
	}
	cfg.VRRPUnicast = true
	cfg.VRRPInterface = w.dev
	cfg.UnicastSrc = w.src
	cfg.UnicastPeers = w.peers
	return nil
}

// vrrpEventOnce reports whether value is new for this LB's kind of event, and
// records it: each event is published when what it says changes, not on every
// apply.
func (s *Server) vrrpEventOnce(name, kind, value string) bool {
	s.vrrpMu.Lock()
	defer s.vrrpMu.Unlock()
	if s.vrrpLastEvent == nil {
		s.vrrpLastEvent = map[string]string{}
	}
	k := name + "\x00" + kind
	if prev, ok := s.vrrpLastEvent[k]; ok && prev == value {
		return false
	}
	s.vrrpLastEvent[k] = value
	return true
}

// vrrpRefused handles an apply whose VRRP transport cannot be rendered. The
// cluster's transport is one value, so the other LB hosts render it: this
// host's keepalived, still on the old transport, would hold the VIP beside
// them. When another LB host answers as one that renders it, this host stops
// its keepalived for the LB (that host is then the sole master); either way it
// raises the critical CondLBVRRPRefused naming the LB, the reason and the
// remedy. vrrpApplied resolves it.
func (s *Server) vrrpRefused(ctx context.Context, name string, lbHosts []string, cause error) error {
	detail := fmt.Sprintf("load balancer %q is not applied on %s: its VRRP transport cannot be rendered: %v. "+
		"Fix the host's recorded address (advertise_address) or the device holding it; where it cannot be on a local device (1:1 NAT), run `lv cluster vrrp-transport multicast`",
		name, s.hostName, cause)
	slog.Error("lb: "+detail, "lb", name)
	if s.vrrpEventOnce(name, "refused", cause.Error()) {
		s.publish("lb.vrrp_transport_refused", name, detail)
	}
	if s.otherLBHostRenders(ctx, lbHosts) {
		if err := s.lbDemote(name); err != nil {
			slog.Error("lb: could not stop the keepalived of a load balancer this host cannot render", "lb", name, "error", err)
		} else {
			detail += ". Its keepalived here is stopped; another LB host holds the VIP"
		}
	}
	s.setVRRPRefused(ctx, name, detail)
	return status.Error(codes.FailedPrecondition, detail)
}

// vrrpApplied resolves this LB's part of CondLBVRRPRefused.
func (s *Server) vrrpApplied(ctx context.Context, name string) {
	s.vrrpMu.Lock()
	_, had := s.vrrpRefusedLBs[name]
	s.vrrpMu.Unlock()
	if had {
		s.setVRRPRefused(ctx, name, "")
	}
	s.vrrpEventOnce(name, "refused", "")
}

// setVRRPRefused records (detail != "") or clears an LB's refusal and raises
// or resolves CondLBVRRPRefused over all of them.
func (s *Server) setVRRPRefused(ctx context.Context, name, detail string) {
	s.vrrpMu.Lock()
	if s.vrrpRefusedLBs == nil {
		s.vrrpRefusedLBs = map[string]string{}
	}
	if detail == "" {
		delete(s.vrrpRefusedLBs, name)
	} else {
		s.vrrpRefusedLBs[name] = detail
	}
	var all []string
	for _, d := range s.vrrpRefusedLBs {
		all = append(all, d)
	}
	s.vrrpMu.Unlock()
	sort.Strings(all)
	s.setHostCondition(ctx, LBEvaluator, CondLBVRRPRefused, len(all) > 0, corrosion.SeverityCritical, strings.Join(all, "; "))
}

// otherLBHostRenders reports whether some other host of the LB answers a
// Ping as a host that renders the cluster's transport: it advertises
// vrrp_unicast_v1 and is not WAL-quarantined. Asked in parallel, bounded.
func (s *Server) otherLBHostRenders(ctx context.Context, lbHosts []string) bool {
	ctx, cancel := context.WithTimeout(ctx, vrrpPeerAskTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := false
	for _, h := range lbHosts {
		if h == s.hostName {
			continue
		}
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if s.peerVRRPState(ctx, h) == peerRenders {
				mu.Lock()
				found = true
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return found
}

// lbDemote stops this host's keepalived for an LB and removes its VIP.
func (s *Server) lbDemote(name string) error {
	if s.lbDemoteOverride != nil {
		return s.lbDemoteOverride(name)
	}
	return s.lbManager().DemoteByName(name, 3*time.Second)
}

// What a peer's Ping says about its VRRP transport.
type peerVRRP int

const (
	peerUnknown peerVRRP = iota // unreachable, or answered with no capabilities (self-fenced)
	peerRenders                 // advertises vrrp_unicast_v1, not quarantined
	peerEarlier                 // an earlier build, or WAL-quarantined (rolled back): multicast
)

// vrrpPeerAskTimeout bounds one round of peer Pings.
const vrrpPeerAskTimeout = 3 * time.Second

func (s *Server) peerVRRPState(ctx context.Context, h string) peerVRRP {
	var caps []string
	var quarantined bool
	var err error
	if s.vrrpPeerCapsOverride != nil {
		caps, quarantined, err = s.vrrpPeerCapsOverride(ctx, h)
	} else {
		caps, _, err = s.PeerCapabilities(ctx, h)
		if err == nil {
			quarantined = s.peerWALQuarantinedNow(h)
		}
	}
	switch {
	case err != nil:
		return peerUnknown
	case quarantined:
		return peerEarlier
	case len(caps) == 0:
		// A self-fenced host answers with no capabilities; it is not an
		// earlier build.
		return peerUnknown
	case capabilities.Has(caps, capabilities.VRRPUnicastV1):
		return peerRenders
	}
	return peerEarlier
}

// peerWALQuarantinedNow is the last Ping answer's wal_quarantined for h.
func (s *Server) peerWALQuarantinedNow(h string) bool {
	s.peerWALQMu.Lock()
	defer s.peerWALQMu.Unlock()
	a, ok := s.peerWALQ[h]
	return ok && a.quarantined
}

// lbIfaceForIP is the up, non-loopback device holding ip, exactly ("" when
// none does).
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
// is not stale: there is nothing to switch. It has no side effects.
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
	w, err := s.desiredVRRPTransport(ctx, hosts)
	if err != nil {
		// The apply will refuse the same way and handle it (vrrpRefused);
		// re-apply only when the mode itself is wrong.
		unicast, rerr := s.vrrpUnicastActive(ctx)
		return rerr == nil && unicast != have.Unicast
	}
	want := lb.Transport{}
	if w.unicast {
		want = lb.Transport{Unicast: true, Iface: w.dev, Src: w.src, Peers: w.peers}
	}
	return !have.Equal(want)
}

// runVRRPSplitCheck runs checkVRRPSplit every interval until ctx ends.
func (s *Server) runVRRPSplitCheck(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkVRRPSplit(ctx)
		}
	}
}

// checkVRRPSplit runs noteVRRPSplit over the LBs this host runs.
func (s *Server) checkVRRPSplit(ctx context.Context) {
	configs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		return
	}
	var local []corrosion.LBConfigRecord
	for _, cfg := range configs {
		if cfg.Enabled && s.lbRunsOnHost(ctx, cfg) {
			local = append(local, cfg)
		}
	}
	s.noteVRRPSplit(ctx, local)
}

// noteVRRPSplit raises CondLBVRRPSplit while this host renders unicast for an
// LB one of whose hosts is on an earlier build (peerEarlier), and resolves it
// otherwise. An unreachable or self-fenced host is not counted. The peers are
// asked in parallel under one deadline.
func (s *Server) noteVRRPSplit(ctx context.Context, lbs []corrosion.LBConfigRecord) {
	unicast, err := s.vrrpUnicastActive(ctx)
	if err != nil {
		return
	}
	var split []string
	if unicast {
		peers := map[string]bool{}
		for _, rec := range lbs {
			hosts, _ := parseHostsJSON(rec.Hosts)
			for _, h := range hosts {
				if h != s.hostName {
					peers[h] = true
				}
			}
		}
		earlier := map[string]bool{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		actx, cancel := context.WithTimeout(ctx, vrrpPeerAskTimeout)
		for h := range peers {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				if s.peerVRRPState(actx, h) == peerEarlier {
					mu.Lock()
					earlier[h] = true
					mu.Unlock()
				}
			}(h)
		}
		wg.Wait()
		cancel()
		for _, rec := range lbs {
			hosts, _ := parseHostsJSON(rec.Hosts)
			for _, h := range hosts {
				if earlier[h] {
					split = append(split, fmt.Sprintf("%s (with %s)", rec.Name, h))
				}
			}
		}
	}
	sort.Strings(split)
	detail := ""
	if len(split) > 0 {
		detail = "load balancers whose VRRP is unicast here but multicast on a host on an earlier build (or rolled back), so both hold the VIP: " +
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

// SetLBIfaceForIPForTests replaces the lookup of the device holding this
// host's recorded address (the fleet's hosts share 127.0.0.1, on loopback).
// Test-only.
func (s *Server) SetLBIfaceForIPForTests(fn func(ip string) string) { s.lbIfaceForIPOverride = fn }

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

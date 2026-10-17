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
	err = corrosion.MarkVRRPUnicastLatched(ctx, s.db, s.hostName)
	// Said once per failure (WARN), repeated at DEBUG, and its end at INFO:
	// this runs every 2 s.
	s.vrrpMu.Lock()
	prev := s.vrrpLatchErr
	if err != nil {
		s.vrrpLatchErr = err.Error()
	} else {
		s.vrrpLatchErr = ""
	}
	s.vrrpMu.Unlock()
	switch {
	case err != nil && prev == "":
		slog.Warn("lb: could not record the vrrp_unicast_v1 latch; retrying", "error", err)
	case err != nil:
		slog.Debug("lb: could not record the vrrp_unicast_v1 latch", "error", err)
	case prev != "":
		slog.Info("lb: recorded the vrrp_unicast_v1 latch after earlier failures")
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
// sole-host form and becomes master on its own. It returns errVRRPUnrenderable
// when this host cannot render unicast at all — no recorded address, or no
// local, up, non-loopback device holding it (its adverts would go out from an
// address nothing answers) — and a plain error on a failed read, which callers
// treat as transient: what runs is kept and retried.
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
		return vrrpWant{}, fmt.Errorf("%w: host %s has no IPv4 address recorded to send VRRP from", errVRRPUnrenderable, s.hostName)
	}
	dev := s.lbIfaceForIP(local)
	if dev == "" {
		return vrrpWant{}, fmt.Errorf("%w: no up, non-loopback device on %s holds its recorded address %s, so VRRP sent from it would never be answered", errVRRPUnrenderable, s.hostName, local)
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

// errVRRPUnrenderable marks the two definitive refusals of the unicast
// transport (desiredVRRPTransport). Only these stop or re-render an LB.
var errVRRPUnrenderable = errors.New("vrrp: this host cannot render the cluster's unicast transport")

// vrrpRefused handles an apply whose unicast transport this host definitively
// cannot render; cfg is the LB's multicast render. The refusal is recorded
// first, so a peer asking at the same moment never sees this host as serving,
// and it raises the critical CondLBVRRPRefused naming the LB, the reason and
// the remedy. Then, by the last answer of the LB's other hosts
// (checkVRRPServing, off this path):
//
//   - one of them serves the LB on unicast: this host stops its keepalived
//     for the LB, so that host is the sole master;
//   - none does, or none has answered since this refusal: this host runs the
//     LB on multicast (availability first: it is then a holder, alone or with
//     another refused host, which elects one master with it), until a peer
//     serves it.
//
// vrrpApplied resolves it once the transport renders again.
//
// Known edge: a demoted host whose later reads fail (applyLBLocal returns
// Unavailable before it gets here) stays stopped until a read succeeds, even
// if the serving peer dies meanwhile. That needs a broken local DB, and
// keeping what runs on a failed read is the rule.
func (s *Server) vrrpRefused(ctx context.Context, cfg lb.Config, lbHosts []string, cause error) error {
	name := cfg.Name
	s.vrrpMu.Lock()
	if s.vrrpRefusedHosts == nil {
		s.vrrpRefusedHosts = map[string][]string{}
	}
	s.vrrpRefusedHosts[name] = append([]string(nil), lbHosts...)
	_, known := s.vrrpRefusedLBs[name]
	s.vrrpMu.Unlock()
	base := fmt.Sprintf("load balancer %q cannot run the cluster's unicast VRRP on %s: %v. "+
		"Fix the host's recorded address (advertise_address) or the device holding it; where it cannot be on a local device (1:1 NAT, an address routed to lo), run `lv cluster vrrp-transport multicast`",
		name, s.hostName, cause)
	if !known {
		// Once per refusal: a refused LB is re-applied on every pass.
		slog.Error("lb: "+base, "lb", name)
		s.setVRRPRefused(ctx, name, base)
		s.kickVRRPServing()
	} else {
		slog.Debug("lb: "+base, "lb", name)
	}
	if s.vrrpEventOnce(name, "refused", cause.Error()) {
		s.publish("lb.vrrp_transport_refused", name, base)
	}
	if s.vrrpPeerServing(name) {
		detail := base
		if err := s.lbDemote(name); err != nil {
			slog.Error("lb: could not stop the keepalived of a load balancer this host cannot render", "lb", name, "error", err)
			detail += ". Its keepalived here could not be confirmed stopped: " + err.Error()
		} else {
			detail += ". Its keepalived here is stopped; another LB host serves the VIP on unicast"
		}
		s.setVRRPRefused(ctx, name, detail)
		return status.Error(codes.FailedPrecondition, detail)
	}
	s.setVRRPRefused(ctx, name, base+". No other LB host reports serving it on unicast (refused, down, unreachable or on an earlier build), so it runs here on multicast meanwhile")
	return s.applyLBConfig(ctx, cfg)
}

// vrrpApplied resolves this LB's part of CondLBVRRPRefused.
func (s *Server) vrrpApplied(ctx context.Context, name string) {
	s.setVRRPRefused(ctx, name, "")
	s.vrrpEventOnce(name, "refused", "")
}

// setVRRPRefused records (detail != "") or clears an LB's refusal and raises
// or resolves CondLBVRRPRefused over all of them. A new refusal gets a new
// epoch; clearing one drops its peers' last answer, so a later refusal never
// acts on an answer asked for an earlier one.
func (s *Server) setVRRPRefused(ctx context.Context, name, detail string) {
	s.vrrpMu.Lock()
	if s.vrrpRefusedLBs == nil {
		s.vrrpRefusedLBs = map[string]string{}
	}
	if s.vrrpRefusedEpoch == nil {
		s.vrrpRefusedEpoch = map[string]uint64{}
	}
	if detail == "" {
		delete(s.vrrpRefusedLBs, name)
		delete(s.vrrpRefusedHosts, name)
		delete(s.vrrpRefusedEpoch, name)
		delete(s.vrrpServing, name)
	} else {
		if _, ok := s.vrrpRefusedLBs[name]; !ok {
			s.vrrpEpoch++
			s.vrrpRefusedEpoch[name] = s.vrrpEpoch
		}
		s.vrrpRefusedLBs[name] = detail
	}
	s.vrrpMu.Unlock()
	s.refreshVRRPRefusedCondition(ctx)
}

// refreshVRRPRefusedCondition raises or resolves CondLBVRRPRefused from the
// refusals recorded in this process (none after a restart, until a re-apply
// records them again).
func (s *Server) refreshVRRPRefusedCondition(ctx context.Context) {
	s.vrrpMu.Lock()
	var all []string
	for _, d := range s.vrrpRefusedLBs {
		all = append(all, d)
	}
	s.vrrpMu.Unlock()
	sort.Strings(all)
	s.setHostCondition(ctx, LBEvaluator, CondLBVRRPRefused, len(all) > 0, corrosion.SeverityCritical, strings.Join(all, "; "))
}

// pruneVRRPState forgets the refusals, served answers and event memory of
// LBs this host no longer runs (deleted, disabled, moved), and re-evaluates
// CondLBVRRPRefused: after a restart that resolves a condition no current
// refusal backs.
func (s *Server) pruneVRRPState(ctx context.Context, local map[string]bool) {
	s.vrrpMu.Lock()
	for name := range s.vrrpRefusedLBs {
		if !local[name] {
			delete(s.vrrpRefusedLBs, name)
		}
	}
	for name := range s.vrrpServing {
		if !local[name] {
			delete(s.vrrpServing, name)
		}
	}
	for name := range s.vrrpRefusedHosts {
		if !local[name] {
			delete(s.vrrpRefusedHosts, name)
		}
	}
	for name := range s.vrrpRefusedEpoch {
		if !local[name] {
			delete(s.vrrpRefusedEpoch, name)
		}
	}
	for k := range s.vrrpLastEvent {
		if !local[strings.SplitN(k, "\x00", 2)[0]] {
			delete(s.vrrpLastEvent, k)
		}
	}
	s.vrrpMu.Unlock()
	s.refreshVRRPRefusedCondition(ctx)
}

// vrrpRefusedHere reports whether this host has refused the LB's unicast
// transport.
func (s *Server) vrrpRefusedHere(name string) bool {
	s.vrrpMu.Lock()
	defer s.vrrpMu.Unlock()
	_, ok := s.vrrpRefusedLBs[name]
	return ok
}

// vrrpPeerServing is the last answer of checkVRRPServing for the LB's
// current refusal: another LB host reported serving it on unicast. No answer
// since this refusal is no.
func (s *Server) vrrpPeerServing(name string) bool {
	s.vrrpMu.Lock()
	defer s.vrrpMu.Unlock()
	return s.vrrpServing[name]
}

// kickVRRPServing asks checkVRRPServing for a pass now (never blocks).
func (s *Server) kickVRRPServing() {
	select {
	case s.vrrpAskKick <- struct{}{}:
	default:
	}
}

// vrrpUnicastServing reports whether this host serves the LB on unicast and
// can hold its VIP: keepalived running from a unicast config, not refused
// here, its source address still held by the device it sends from, and the
// VIP's device up with carrier (track_interface puts keepalived in FAULT
// otherwise: it keeps running but releases the VIP). It is what
// CheckLBPresent answers as vrrp_unicast_serving; a refused peer demotes only
// on it.
func (s *Server) vrrpUnicastServing(name string) bool {
	if s.vrrpRefusedHere(name) || !s.lbKeepalivedRunning(name) {
		return false
	}
	t, ok := s.lbRenderedTransport(name)
	if !ok || !t.Unicast || t.Src == "" || t.VIPDev == "" {
		return false
	}
	return s.lbIfaceForIP(t.Src) == t.Iface && s.lbIfaceRunning(t.VIPDev)
}

// lbRenderedTransport is the VRRP transport of the LB's keepalived config on
// disk; ok=false when there is none.
func (s *Server) lbRenderedTransport(name string) (lb.Transport, bool) {
	if s.lbRenderedTransportOverride != nil {
		return s.lbRenderedTransportOverride(name)
	}
	return s.lbManager().KeepalivedTransport(name)
}

// lbIfaceRunning reports whether dev is up and has carrier.
func (s *Server) lbIfaceRunning(dev string) bool {
	if s.lbIfaceRunningOverride != nil {
		return s.lbIfaceRunningOverride(dev)
	}
	return lb.InterfaceUpRunning(dev)
}

// checkVRRPServing asks, for each LB this host has refused, its other hosts
// whether one serves it on unicast (CheckLBPresent's vrrp_unicast_serving), in
// parallel under one deadline and one connection per host, off the
// reconciler's loop. An answer is kept only for the refusal it was asked for:
// one that arrives after the refusal cleared, or after a newer refusal began,
// is dropped. When an answer changes it asks the reconciler for a pass, which
// stops or restarts this host's keepalived for the LB (vrrpRefused). An
// unreachable host is not serving.
func (s *Server) checkVRRPServing(ctx context.Context) {
	s.vrrpMu.Lock()
	epochs := map[string]uint64{}
	asks := map[string][]string{} // host -> the refused LBs it runs
	for name := range s.vrrpRefusedLBs {
		epochs[name] = s.vrrpRefusedEpoch[name]
		seen := map[string]bool{s.hostName: true}
		for _, h := range s.vrrpRefusedHosts[name] {
			if !seen[h] {
				seen[h] = true
				asks[h] = append(asks[h], name)
			}
		}
	}
	s.vrrpMu.Unlock()
	if len(epochs) == 0 {
		return
	}
	actx, cancel := context.WithTimeout(ctx, vrrpPeerAskTimeout)
	defer cancel()
	answers := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for h, names := range asks {
		wg.Add(1)
		go func(h string, names []string) {
			defer wg.Done()
			served := s.peerServesLBs(actx, h, names)
			mu.Lock()
			for _, name := range served {
				answers[name] = true
			}
			mu.Unlock()
		}(h, names)
	}
	wg.Wait()
	changed := false
	s.vrrpMu.Lock()
	if s.vrrpServing == nil {
		s.vrrpServing = map[string]bool{}
	}
	for name, ep := range epochs {
		if cur, ok := s.vrrpRefusedEpoch[name]; !ok || cur != ep {
			continue // cleared, or refused anew, while asking
		}
		if s.vrrpServing[name] != answers[name] {
			changed = true
		}
		s.vrrpServing[name] = answers[name]
	}
	s.vrrpMu.Unlock()
	if changed {
		s.kickLBReconcile()
	}
}

// peerServesLBs asks host, over one connection, which of lbNames it serves
// on unicast.
func (s *Server) peerServesLBs(ctx context.Context, host string, lbNames []string) []string {
	var served []string
	if s.lbServingOverride != nil {
		for _, name := range lbNames {
			if s.lbServingOverride(ctx, host, name) {
				served = append(served, name)
			}
		}
		return served
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil
	}
	defer closeConn()
	for _, name := range lbNames {
		resp, err := c.CheckLBPresent(ctx, &pb.CheckLBPresentRequest{LbName: name})
		if err == nil && resp.GetVrrpUnicastServing() {
			served = append(served, name)
		}
	}
	return served
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
	have, ok := s.lbRenderedTransport(rec.Name)
	if !ok {
		return false
	}
	hosts, _ := parseHostsJSON(rec.Hosts)
	w, err := s.desiredVRRPTransport(ctx, hosts)
	if errors.Is(err, errVRRPUnrenderable) {
		// This host refuses now, whatever runs: the re-apply records the
		// refusal, raises the condition and follows the peers' answer
		// (vrrpRefused). A unicast config whose source this host no longer
		// holds would otherwise run on silently.
		return true
	}
	if err != nil {
		// A failed read: re-apply only when the mode itself is wrong.
		unicast, rerr := s.vrrpUnicastActive(ctx)
		return rerr == nil && unicast != have.Unicast
	}
	want := lb.Transport{}
	if w.unicast {
		want = lb.Transport{Unicast: true, Iface: w.dev, Src: w.src, Peers: w.peers}
	}
	return !have.Equal(want)
}

// runVRRPSplitCheck runs checkVRRPSplit every interval, and checkVRRPServing
// every vrrpWatchInterval (or interval, if shorter) and on a new refusal,
// until ctx ends. Both Ping peers, so neither runs in the reconciler's loop.
func (s *Server) runVRRPSplitCheck(ctx context.Context, interval time.Duration) {
	s.dbWorkerEvent(ctx, "vrrp", "entry")
	defer s.dbWorkerEvent(ctx, "vrrp", "exit")
	t := time.NewTicker(interval)
	defer t.Stop()
	serve := time.NewTicker(min(interval, vrrpWatchInterval))
	defer serve.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkVRRPSplit(ctx)
		case <-serve.C:
			s.checkVRRPServing(ctx)
		case <-s.vrrpAskKick:
			s.checkVRRPServing(ctx)
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

// SetLBIfaceRunningForTests replaces the check that an LB's VIP device is up
// with carrier (the fleet's VIP bridges do not exist). Test-only.
func (s *Server) SetLBIfaceRunningForTests(fn func(dev string) bool) { s.lbIfaceRunningOverride = fn }

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

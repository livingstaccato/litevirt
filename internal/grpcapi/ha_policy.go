package grpcapi

// `lv cluster ha` (docs/migration-failover.md, "Disarming HA for planned
// maintenance"): show, disarm or arm the cluster HA policy.
//
// A change is written on this node and then CONFIRMED: the handler waits until
// a majority of the voters (under region scope, a majority of every region
// that holds a voter) answer their health probe with exactly the written state
// and timestamp, and then waits a further health.PeerAnswerWindow. After that,
// any coordinator deciding a fence or a recovery either holds the row itself
// or reads, among the voters it counts live, one whose answer carries it — so
// a confirmed disarm holds for every coordinator, not only for this one.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// haConfirmTimeout bounds the wait for a change to be confirmed, haConfirmPoll
// is how often the answers are looked at, and haPeerWindow is the wait after
// confirmation. Vars so tests need not wait; haSleep and haNow are the
// handler's clock (a monotonic one).
var (
	haConfirmTimeout = 60 * time.Second
	haConfirmPoll    = 250 * time.Millisecond
	haPeerWindow     = health.PeerAnswerWindow
	haSleep          = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	haNow = time.Now
)

// HA voter statuses in `lv cluster ha`, the peer veto's own vocabulary.
const (
	haStatusConfirmed = "confirmed"
	haStatusStale     = "stale"
	haStatusUnknown   = "unknown"
	haStatusOlder     = "older row"
	haStatusNewer     = "newer row"
	haStatusNotLive   = "not counted live"
)

// GetHAPolicy reports the cluster HA policy as this host's replica holds it,
// with each voter's latest answer, each region's confirmation under region
// scope, whether the first use is paid, and, while disarmed, the hosts an arm
// would fence.
func (s *Server) GetHAPolicy(ctx context.Context, _ *emptypb.Empty) (*pb.HAPolicyStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return s.haPolicyStatus(ctx)
}

// SetHAPolicy disarms or arms the cluster HA policy and waits for it to be
// confirmed.
func (s *Server) SetHAPolicy(ctx context.Context, req *pb.SetHAPolicyRequest) (*pb.HAPolicyStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	state := req.GetState()
	if !corrosion.ValidHAState(state) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown HA state %q (valid: %s, %s)",
			state, corrosion.HAArmed, corrosion.HADisarmed)
	}
	if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureHADisarm); err != nil {
		return nil, err
	}
	if !s.failoverScopeSettable() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the HA policy cannot be changed until %s has latched on every host: "+
				"finish rolling every host (and every host in maintenance) to this release first",
			capabilities.FailoverScopeV1)
	}
	// Both directions need this node to hold the voter majority: a change
	// made from a minority would not reach the side that decides.
	gate := s.gateV()
	if gate == nil {
		return nil, status.Error(codes.FailedPrecondition, "this host cannot show it reaches a majority of the voters (no quorum view)")
	}
	if st, live, needed := gate.QuorumProof(ctx); st != health.QuorumYes {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s does not reach a majority of the voters (%d live, %d needed); change the HA policy from a host that does",
			s.hostName, live, needed)
	}
	if state == corrosion.HAArmed && !req.GetFenceDownHosts() {
		down, err := s.haDownHosts(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "list the hosts an arm would fence: %v", err)
		}
		if len(down) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"arming HA would fence these hosts, which a quorum reports down: %s. Bring them back, "+
					"or remove one that is never coming back with lv host rm --dead <host>, "+
					"or arm with --fence-down-hosts to fence them on the next cycle",
				strings.Join(down, ", "))
		}
	}
	after, from := s.haNewestSeen(ctx)
	if after != "" && corrosion.HATimestampSkewed(after, time.Now()) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the newest HA policy row seen (updated_at %s, from %s) is stamped implausibly far in the future, "+
				"so peers would quarantine any change ordered after it; correct %s's clock, then retry",
			after, from, from)
	}

	var written string
	err := s.WithReleaseFeature(ctx, capabilities.FeatureHADisarm, func(ctx context.Context, g capabilities.FeatureGrant) error {
		ts, err := corrosion.SetHAPolicy(ctx, s.db, g, state, req.GetReason(), callerUsername(ctx), after)
		switch {
		case errors.Is(err, corrosion.ErrClusterPolicyGateClosed), errors.Is(err, corrosion.ErrHAStampSkewed):
			return status.Error(codes.FailedPrecondition, err.Error())
		case err != nil:
			return status.Errorf(codes.Internal, "set HA policy: %v", err)
		}
		written = ts
		return nil
	})
	if err != nil {
		return nil, err
	}
	// This node's own answer follows its write at once.
	_ = s.RefreshHAPolicyCache(ctx)
	detail := fmt.Sprintf("HA %s (updated_at %s)", state, written)
	if r := req.GetReason(); r != "" {
		detail += ": " + r
	}
	if req.GetFenceDownHosts() {
		detail += " (--fence-down-hosts)"
	}
	s.audit(ctx, "cluster.ha", "ha", detail, "ok")
	s.publish("cluster.ha", state, "set by "+callerUsername(ctx)+": "+req.GetReason())

	if err := s.haConfirm(ctx, state, written); err != nil {
		return nil, err
	}
	return s.haPolicyStatus(ctx)
}

// haDownHosts lists the hosts the failover coordinator would fence now
// (its own candidate function, through the injected hook), less those in
// maintenance, which are never fenced.
func (s *Server) haDownHosts(ctx context.Context) ([]string, error) {
	if s.fenceCandidates == nil {
		return nil, errors.New("this host has no fence-candidate view")
	}
	cands, err := s.fenceCandidates(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, err
	}
	state := make(map[string]string, len(hosts))
	for _, h := range hosts {
		state[h.Name] = h.State
	}
	var out []string
	for _, h := range cands {
		if state[h] != "maintenance" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, nil
}

// haNewestSeen is the newest policy timestamp this node knows of — its own
// row and every peer's recorded answer — and where it came from.
func (s *Server) haNewestSeen(ctx context.Context) (at, from string) {
	if p, err := corrosion.GetHAPolicy(ctx, s.db); p.UpdatedAt != "" && (err == nil || errors.Is(err, corrosion.ErrUnreadableHAPolicy)) {
		at, from = p.UpdatedAt, s.hostName
	}
	if _, _, cached := s.haCache.snapshot(); cached != "" && (at == "" || corrosion.LWWNewer(cached, at)) {
		at, from = cached, s.hostName
	}
	s.peerHA.mu.Lock()
	defer s.peerHA.mu.Unlock()
	for host, a := range s.peerHA.m {
		if a.policyAt != "" && (at == "" || corrosion.LWWNewer(a.policyAt, at)) {
			at, from = a.policyAt, host
		}
	}
	return at, from
}

// haVoterView is one voter's latest answer, as the handler and the status
// read it.
type haVoterView struct {
	host                string
	asked               time.Time
	ok, known, disarmed bool
	policyAt            string
}

func (s *Server) haVoterAnswer(host string) haVoterView {
	if host == s.hostName {
		known, disarmed, at := s.haCache.snapshot()
		return haVoterView{host: host, asked: haNow(), ok: true, known: known, disarmed: disarmed, policyAt: at}
	}
	asked, known, disarmed, at, ok := s.PeerHAAnswer(host)
	return haVoterView{host: host, asked: asked, ok: ok, known: known, disarmed: disarmed, policyAt: at}
}

// matches reports whether the answer carries exactly the written row: its
// state AND its timestamp.
func (a haVoterView) matches(state, at string) bool {
	return a.ok && a.known && a.policyAt == at && a.disarmed == (state == corrosion.HADisarmed)
}

// haConfirmationState is how far a written change has got.
type haConfirmationState struct {
	confirmed       bool
	unconfirmed     []string // voters that have not answered with the row
	regionsShort    []string // regions without a confirming majority (region scope)
	supersededBy    *haVoterView
	regionConfirmed map[string]bool
}

// haConfirmation reads every voter's latest answer against the written row.
func (s *Server) haConfirmation(ctx context.Context, state, at string) (haConfirmationState, error) {
	vr, err := corrosion.VoterRegions(ctx, s.db)
	if err != nil {
		return haConfirmationState{}, err
	}
	scope, err := corrosion.GetFailoverScope(ctx, s.db)
	if err != nil {
		return haConfirmationState{}, err
	}
	out := haConfirmationState{regionConfirmed: map[string]bool{}}
	names := make([]string, 0, len(vr.Voters))
	for v := range vr.Voters {
		names = append(names, v)
	}
	sort.Strings(names)
	confirmed := map[string]bool{}
	for _, v := range names {
		a := s.haVoterAnswer(v)
		if a.ok && a.policyAt != "" && corrosion.LWWNewer(a.policyAt, at) && out.supersededBy == nil {
			out.supersededBy = &a
		}
		if a.matches(state, at) {
			confirmed[v] = true
		} else {
			out.unconfirmed = append(out.unconfirmed, v)
		}
	}
	// A newer row anywhere this node has heard of supersedes it too.
	if out.supersededBy == nil {
		s.peerHA.mu.Lock()
		for host, a := range s.peerHA.m {
			if a.policyAt != "" && corrosion.LWWNewer(a.policyAt, at) {
				v := haVoterView{host: host, ok: true, known: a.known, disarmed: a.disarmed, policyAt: a.policyAt}
				out.supersededBy = &v
				break
			}
		}
		s.peerHA.mu.Unlock()
	}
	majority := func(set map[string]bool) bool {
		n := 0
		for v := range set {
			if confirmed[v] {
				n++
			}
		}
		return n >= len(set)/2+1
	}
	if !scope.Region() {
		out.confirmed = majority(vr.Voters)
		return out, nil
	}
	out.confirmed = true
	for _, r := range vr.Regions() {
		in := vr.In(r)
		if len(in) == 0 {
			continue
		}
		ok := majority(in)
		out.regionConfirmed[r] = ok
		if !ok {
			out.confirmed = false
			out.regionsShort = append(out.regionsShort, r)
		}
	}
	return out, nil
}

// haConfirm waits until the written row is confirmed, then a further
// haPeerWindow, refusing with Aborted as soon as a newer row shows up.
func (s *Server) haConfirm(ctx context.Context, state, at string) error {
	superseded := func(c haConfirmationState) error {
		st := corrosion.HAArmed
		if c.supersededBy.disarmed {
			st = corrosion.HADisarmed
		}
		return status.Errorf(codes.Aborted, "another HA change superseded this one (state %s, set at %s, seen from %s)",
			st, c.supersededBy.policyAt, c.supersededBy.host)
	}
	stillTakes := "the change may still take effect as it replicates; check lv cluster ha"
	deadline := haNow().Add(haConfirmTimeout)
	for {
		c, err := s.haConfirmation(ctx, state, at)
		if err != nil {
			return status.Errorf(codes.Unavailable, "read the voters' confirmation: %v; %s", err, stillTakes)
		}
		if c.supersededBy != nil {
			return superseded(c)
		}
		if c.confirmed {
			break
		}
		if !haNow().Before(deadline) {
			msg := fmt.Sprintf("HA %s was written (updated_at %s) but not confirmed within %s", state, at, haConfirmTimeout)
			if len(c.unconfirmed) > 0 {
				msg += "; unconfirmed voters: " + strings.Join(c.unconfirmed, ", ")
			}
			if len(c.regionsShort) > 0 {
				msg += "; regions without a confirming majority: " + strings.Join(c.regionsShort, ", ")
			}
			return status.Error(codes.Unavailable, msg+"; "+stillTakes)
		}
		if err := haSleep(ctx, haConfirmPoll); err != nil {
			return status.Errorf(codes.Canceled, "%v; %s", err, stillTakes)
		}
	}
	// Every coordinator that may decide after this returns now reads the
	// row, or a live voter's answer carrying it, or vetoes as stale.
	end := haNow().Add(haPeerWindow)
	for haNow().Before(end) {
		if err := haSleep(ctx, haConfirmPoll); err != nil {
			return status.Errorf(codes.Canceled, "%v; %s", err, stillTakes)
		}
		c, err := s.haConfirmation(ctx, state, at)
		if err == nil && c.supersededBy != nil {
			return superseded(c)
		}
	}
	return nil
}

// haLiveVoters is the set of voters this node counts live, when its gate can
// say (health.Checker.LiveVoters), else itself and the peers it probed healthy.
func (s *Server) haLiveVoters(ctx context.Context, vr corrosion.VoterRegionSets) map[string]bool {
	g := s.gateV()
	if lv, ok := g.(interface {
		LiveVoters(voters, uncounted map[string]bool) map[string]bool
	}); ok {
		return lv.LiveVoters(vr.Voters, vr.Uncounted)
	}
	live := map[string]bool{s.hostName: vr.Voters[s.hostName]}
	if g != nil {
		for _, p := range g.HealthyPeers(ctx) {
			if vr.Voters[p] {
				live[p] = true
			}
		}
	}
	return live
}

func (s *Server) haPolicyStatus(ctx context.Context) (*pb.HAPolicyStatus, error) {
	p, err := corrosion.GetHAPolicy(ctx, s.db)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy) {
		return nil, status.Errorf(codes.Internal, "read HA policy: %v", err)
	}
	out := &pb.HAPolicyStatus{State: p.State, SetBy: p.SetBy, At: p.UpdatedAt, Reason: p.Reason}
	if p.Unreadable {
		out.State = corrosion.HADisarmed + " (unreadable on this host: nothing is fenced or recovered until it is set again)"
	}
	if info, ok := capabilities.LookupFeature(capabilities.FeatureHADisarm); ok {
		present, acked, ferr := corrosion.ReleaseFeatureState(ctx, s.db, info.Token, string(capabilities.FeatureHADisarm))
		out.FirstUsePaid = ferr == nil && present && acked
	}
	vr, err := corrosion.VoterRegions(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read voters: %v", err)
	}
	live := s.haLiveVoters(ctx, vr)
	names := make([]string, 0, len(vr.Voters))
	for v := range vr.Voters {
		names = append(names, v)
	}
	sort.Strings(names)
	state := p.State
	now := haNow()
	for _, v := range names {
		a := s.haVoterAnswer(v)
		ans := &pb.HAVoterAnswer{Host: v, HaKnown: a.known, HaDisarmed: a.disarmed, HaPolicyAt: a.policyAt}
		switch {
		case !live[v]:
			ans.Status = haStatusNotLive
		case !a.ok || now.Sub(a.asked) > haPeerWindow:
			ans.Status = haStatusStale
		case !a.known:
			ans.Status = haStatusUnknown
		case a.matches(state, p.UpdatedAt):
			ans.Status, ans.Confirmed = haStatusConfirmed, true
		case p.UpdatedAt != "" && (a.policyAt == "" || corrosion.LWWNewer(p.UpdatedAt, a.policyAt)):
			ans.Status = haStatusOlder
		default:
			ans.Status = haStatusNewer
		}
		out.Voters = append(out.Voters, ans)
	}
	if scope, serr := corrosion.GetFailoverScope(ctx, s.db); serr == nil && scope.Region() {
		if c, cerr := s.haConfirmation(ctx, state, p.UpdatedAt); cerr == nil {
			regions := make([]string, 0, len(c.regionConfirmed))
			for r := range c.regionConfirmed {
				regions = append(regions, r)
			}
			sort.Strings(regions)
			for _, r := range regions {
				out.Regions = append(out.Regions, &pb.HARegionConfirmation{Region: r, Confirmed: c.regionConfirmed[r]})
			}
		}
	}
	if p.Disarmed() {
		if down, derr := s.haDownHosts(ctx); derr == nil {
			out.WouldBeFenced = down
		}
	}
	return out, nil
}

package grpcapi

// Release features and `lv cluster upgrade-status` (capabilities.ReleaseToken,
// docs/upgrades.md "Rolling back after a release token latched").

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
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
)

// releaseFeatureGate opens a release feature: *health.Checker in production.
type releaseFeatureGate interface {
	WithFeature(ctx context.Context, feature capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error
	FeatureAvailable(feature capabilities.Feature) bool
}

// releaseFeatureRefuser is the optional entry-check side of a release gate:
// *health.Checker implements it (FeatureRefusal).
type releaseFeatureRefuser interface {
	FeatureRefusal(ctx context.Context, feature capabilities.Feature) error
}

// ReleaseFeatureRefusal is the entry-node fail-fast of a release feature: nil
// when its token has latched here (the latch is driven first, so a call made
// just after the last host upgraded does not wait for the HA monitor), else the
// release gate's refusal, naming the hosts that hold the release back and
// ending with the `lv cluster upgrade-status` pointer. It records no use and
// grants nothing: the node that writes the feature's data still goes through
// WithReleaseFeature. With no gate wired it refuses (fail closed).
func (s *Server) ReleaseFeatureRefusal(ctx context.Context, feature capabilities.Feature) error {
	if r, ok := s.releaseFeatures.(releaseFeatureRefuser); ok {
		return r.FeatureRefusal(ctx, feature)
	}
	if s.ReleaseFeatureAvailable(feature) {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)",
		feature, featureToken(feature))
}

// ReleaseFeatureAvailable reports, without asking any peer, whether feature's
// release token has durably latched here (health.Checker.FeatureAvailable). A
// HINT for a caller that falls back rather than fails — a default that picks
// the feature only when it can be used (backup_zstd) — so a mid-roll call does
// not pay WithFeature's refusal, which pings every lagging host to name it. It
// grants nothing: the write still goes through WithReleaseFeature, which can
// still refuse (a host rolled back after the latch). False with no gate wired.
func (s *Server) ReleaseFeatureAvailable(feature capabilities.Feature) bool {
	return s.releaseFeatures != nil && s.releaseFeatures.FeatureAvailable(feature)
}

// releaseTokenLatcher is the token side of a release gate. *health.Checker,
// the production gate, implements it (asserted at compile time in
// release_token_latcher_test.go); a production gate that wraps the checker
// must forward it, or ReleaseTokenLatched falls back to a feature's
// availability, the coupling it exists to remove.
type releaseTokenLatcher interface {
	DurablyLatched(token string) bool
}

// ReleaseTokenLatched reports, without asking any peer, whether the release
// token itself (capabilities.ReleaseToken) has durably latched here: every
// host this one replicates to runs this release's build or later. It is the
// readiness of a statement SHAPE this release introduced (the replication
// switch's compare-and-set, the placement mint), which a VM's switch emits as
// well as a container's; reading it through one feature's availability would
// tie VM behaviour to whichever token that feature belongs to. Like
// ReleaseFeatureAvailable it grants nothing and records no use. A gate that
// cannot name a token's latch (a test's) answers through a feature of the
// release token. False with no gate wired.
func (s *Server) ReleaseTokenLatched() bool {
	if g, ok := s.releaseFeatures.(releaseTokenLatcher); ok {
		return g.DurablyLatched(capabilities.ReleaseToken)
	}
	// Only a test's fake gate gets here; see releaseTokenLatcher.
	return s.ReleaseFeatureAvailable(capabilities.FeatureContainerReplication)
}

// SetReleaseFeatureGate injects the release-feature gate.
func (s *Server) SetReleaseFeatureGate(g releaseFeatureGate) { s.releaseFeatures = g }

// WithReleaseFeature runs write — the write a capabilities.Feature's data
// needs — through the release-feature gate on THIS node
// (health.Checker.WithFeature), handing it the FeatureGrant its writer checks.
// It refuses with FailedPrecondition until the feature's release token has
// latched; before a first use's write it records the use and waits for every
// replication recipient to hold the record. Return its error unchanged. Call
// it on the node that performs the write: a request forwarded to another node
// is gated there. With no gate wired it refuses everything: fail closed.
func (s *Server) WithReleaseFeature(ctx context.Context, feature capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
	if s.releaseFeatures == nil {
		return status.Errorf(codes.FailedPrecondition,
			"the cluster upgrade must finish first (%s needs %s): this host has no release-feature gate",
			feature, featureToken(feature))
	}
	return s.releaseFeatures.WithFeature(ctx, feature, write)
}

func featureToken(feature capabilities.Feature) string {
	if info, ok := capabilities.LookupFeature(feature); ok {
		return info.Token
	}
	return capabilities.ReleaseToken
}

// GetUpgradeStatus reports, as this host sees them, every capability token
// latched here, whether each would block a rollback, and every release
// feature with its used bit. Viewer.
func (s *Server) GetUpgradeStatus(ctx context.Context, _ *emptypb.Empty) (*pb.UpgradeStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	uses, err := corrosion.ListReleaseFeatureUses(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read release feature uses: %v", err)
	}
	usedBy := map[string]corrosion.ReleaseFeatureUse{}
	usedTokens := map[string]bool{}
	for _, u := range uses {
		usedBy[u.Token+"/"+u.Feature] = u
		usedTokens[u.Token] = true
	}

	out := &pb.UpgradeStatus{ReleaseToken: capabilities.ReleaseToken}
	gate := s.gateV()
	if gate != nil {
		for _, tok := range capabilities.All() {
			if !gate.Latched(tok) {
				continue
			}
			rule := capabilities.RollbackRule(tok)
			// What a rule-aware build would do, and what the build directly
			// below this token does: for the first release token that build
			// predates rules, so it quarantines on the marker, used or not (I4).
			ruleAware := rule != capabilities.RollbackSafeIfUnused || usedTokens[tok]
			out.Tokens = append(out.Tokens, &pb.UpgradeToken{
				Name:                    tok,
				Durable:                 gate.DurablyLatched(tok),
				Mandatory:               capabilities.Mandatory(tok),
				RollbackRule:            rule,
				BlocksRollback:          ruleAware || !capabilities.RuleHonouredBelow(tok),
				BlocksRollbackRuleAware: ruleAware,
			})
		}
	}
	sort.Slice(out.Tokens, func(i, j int) bool { return out.Tokens[i].GetName() < out.Tokens[j].GetName() })

	seen := map[string]bool{}
	for _, f := range capabilities.Features() {
		info, _ := capabilities.LookupFeature(f)
		key := info.Token + "/" + string(f)
		seen[key] = true
		row := &pb.ReleaseFeatureStatus{Token: info.Token, Name: string(f),
			Description: info.Description, Declared: true}
		if u, ok := usedBy[key]; ok {
			row.Used, row.RecordedBy, row.RecordedAt = true, u.RecordedBy, u.UpdatedAt
		}
		out.Features = append(out.Features, row)
	}
	// A use under a token or feature this build does not declare: a later
	// release's, which is what would quarantine this build.
	for _, u := range uses {
		if seen[u.Token+"/"+u.Feature] {
			continue
		}
		out.Features = append(out.Features, &pb.ReleaseFeatureStatus{Token: u.Token, Name: u.Feature,
			Used: true, RecordedBy: u.RecordedBy, RecordedAt: u.UpdatedAt})
	}
	sort.Slice(out.Features, func(i, j int) bool {
		a, b := out.Features[i], out.Features[j]
		if a.GetToken() != b.GetToken() {
			return a.GetToken() < b.GetToken()
		}
		return a.GetName() < b.GetName()
	})

	if s.walQuarantinedNow() {
		out.WalQuarantined = true
		if reason := s.db.QuarantineReason(); reason != "" {
			out.QuarantineReason = reason
		}
	}
	// Probation is not a quarantine, but every replicated write here is
	// refused while it lasts, so it is shown (m-R2-3).
	if s.db.InReleaseProbation() {
		out.ReleaseProbation, out.ProbationReason = true, s.db.QuarantineReason()
	}
	// The rollout summary the status opens with (UX 2).
	if gate != nil {
		total, on, lagging, err := s.releaseLagging(ctx)
		if err == nil {
			out.HostsTotal, out.HostsOnRelease, out.Lagging = int32(total), int32(on), lagging
		}
		if !gate.Latched(capabilities.ReleaseToken) {
			for _, f := range capabilities.Features() {
				if info, _ := capabilities.LookupFeature(f); info.Token == capabilities.ReleaseToken {
					out.FeaturesWaiting++
				}
			}
		}
	}
	out.RefusedPeers = s.RefusedReleasePeers()
	out.SelfUpgradeSkipped = s.selfUpgradeSkippedLines()
	return out, nil
}

// HoldsReleaseFeatureUse answers a peer's first use: does this replica hold
// its used record? Peer mTLS only.
func (s *Server) HoldsReleaseFeatureUse(ctx context.Context, q *pb.ReleaseFeatureUseQuery) (*pb.ReleaseFeatureUseHeld, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	present, _, err := corrosion.ReleaseFeatureState(ctx, s.db, q.GetToken(), q.GetFeature())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read release feature use: %v", err)
	}
	return &pb.ReleaseFeatureUseHeld{Held: present, InReleaseProbation: s.db.InReleaseProbation()}, nil
}

// PeerHoldsReleaseFeatureUse asks host whether its replica holds the used
// record: health.ReleaseUseConfirmer in production. A host that does not hold
// it and is in release probation — so applies nothing pushed to it until the
// probation lifts — answers an error wrapping corrosion.ErrReleaseProbation,
// so the refusal can say so rather than suggest removing a live voter (m1).
func (s *Server) PeerHoldsReleaseFeatureUse(ctx context.Context, host, token, feature string) (bool, error) {
	if host == s.hostName {
		present, _, err := corrosion.ReleaseFeatureState(ctx, s.db, token, feature)
		return present, err
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return false, err
	}
	defer closeConn()
	r, err := c.HoldsReleaseFeatureUse(ctx, &pb.ReleaseFeatureUseQuery{Token: token, Feature: feature})
	if err != nil {
		return false, err
	}
	if !r.GetHeld() && r.GetInReleaseProbation() {
		return false, fmt.Errorf("%s: %w", host, corrosion.ErrReleaseProbation)
	}
	return r.GetHeld(), nil
}

// haReleasePeerRefused: this node is refusing replication from a peer that
// cannot keep the data of a release feature in use (ReleasePeerAllowed).
const haReleasePeerRefused = "release_feature_peer_refused"

// releasePeerRefusedFor is how long a refusal keeps the HA condition raised.
const releasePeerRefusedFor = 2 * time.Minute

// releaseUsedCacheTTL bounds how often the push path re-reads which release
// tokens have a recorded use.
const releaseUsedCacheTTL = 5 * time.Second

// usedReleaseTokens lists the release tokens this build knows that have at
// least one recorded use, cached for releaseUsedCacheTTL. Whether the token has
// latched HERE does not matter (N5): a recorded use proves it latched somewhere,
// and a node that has not latched yet must refuse an old peer all the same, or
// it relays that peer's rows to the nodes that do.
func (s *Server) usedReleaseTokens(ctx context.Context) []string {
	s.releasePeerMu.Lock()
	if time.Since(s.releaseUsedAt) < releaseUsedCacheTTL {
		out := s.releaseUsed
		s.releasePeerMu.Unlock()
		return out
	}
	s.releasePeerMu.Unlock()
	var out []string
	if uses, err := corrosion.ListReleaseFeatureUses(ctx, s.db); err == nil {
		seen := map[string]bool{}
		for _, u := range uses {
			if !seen[u.Token] && capabilities.RollbackRule(u.Token) != "" {
				seen[u.Token] = true
				out = append(out, u.Token)
			}
		}
		sort.Strings(out)
	}
	s.releasePeerMu.Lock()
	s.releaseUsed, s.releaseUsedAt = out, time.Now()
	s.releasePeerMu.Unlock()
	return out
}

// peerCapsEntry is what this node knows of one peer's capability list: the
// last one it declared (a push) or answered (a Ping), when, and the state of
// the background refresh.
type peerCapsEntry struct {
	caps        []string
	known       bool
	nextRefresh time.Time
	backoff     time.Duration
	inFlight    bool
}

// releasePeerPositiveTTL is how long a peer's list is trusted before a
// background refresh; releasePeerBackoffMin/Max pace refreshes of a peer that
// lacks the token or does not answer.
const (
	releasePeerPositiveTTL = 30 * time.Second
	releasePeerBackoffMin  = 5 * time.Second
	releasePeerBackoffMax  = 5 * time.Minute
)

// notePeerCaps remembers the capability list a peer declared or answered
// (residual a), and schedules its next refresh: in 30s if it carries every
// used release token, else after a backoff that grows while it stays short.
func (s *Server) notePeerCaps(peer string, caps []string) {
	s.releasePeerMu.Lock()
	defer s.releasePeerMu.Unlock()
	if s.releasePeerLast == nil {
		s.releasePeerLast = map[string]*peerCapsEntry{}
	}
	e := s.releasePeerLast[peer]
	if e == nil {
		e = &peerCapsEntry{}
		s.releasePeerLast[peer] = e
	}
	e.caps, e.known = append([]string(nil), caps...), true
	ok := true
	for _, tok := range s.releaseUsed {
		if !capabilities.Has(caps, tok) {
			ok = false
		}
	}
	if ok {
		e.backoff = 0
		e.nextRefresh = time.Now().Add(releasePeerPositiveTTL)
		return
	}
	e.backoff = nextBackoff(e.backoff)
	e.nextRefresh = time.Now().Add(e.backoff)
}

func nextBackoff(b time.Duration) time.Duration {
	if b < releasePeerBackoffMin {
		return releasePeerBackoffMin
	}
	if b *= 2; b > releasePeerBackoffMax {
		return releasePeerBackoffMax
	}
	return b
}

// peerCapsFor returns what is known of peer and, when it is due, starts ONE
// background refresh (I-R2-1): the caller never waits on a dial.
func (s *Server) peerCapsFor(peer string) ([]string, bool) {
	s.releasePeerMu.Lock()
	if s.releasePeerLast == nil {
		s.releasePeerLast = map[string]*peerCapsEntry{}
	}
	e := s.releasePeerLast[peer]
	if e == nil {
		e = &peerCapsEntry{}
		s.releasePeerLast[peer] = e
	}
	caps, known := e.caps, e.known
	start := !e.inFlight && !time.Now().Before(e.nextRefresh)
	if start {
		e.inFlight = true
	}
	s.releasePeerMu.Unlock()
	if start {
		go s.refreshPeerCaps(peer)
	}
	return caps, known
}

// refreshPeerCaps asks peer for its list out of band. An unanswered ask keeps
// the last list and backs off.
//
// An EMPTY list from a peer whose Ping says it is not WAL-quarantined is no
// news (I-R3-2): that is a self-fenced node, which advertises nothing while it
// is fenced but runs a build that keeps the data, and whose own pushes still
// declare its release tokens (DeclaredCapabilities). It keeps its last list —
// positive or negative, or none — with no negative entry, no backoff growth and
// no release_feature_peer_refused alarm, and is asked again after the shortest
// backoff. A WAL-quarantined peer's empty list is an answer, and refused.
func (s *Server) refreshPeerCaps(peer string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	caps, quarantined, err := s.peerReleaseAnswer(ctx, peer)
	cancel()
	noNews := err == nil && len(caps) == 0 && !quarantined
	if err == nil && !noNews {
		s.notePeerCaps(peer, caps)
	}
	s.releasePeerMu.Lock()
	if e := s.releasePeerLast[peer]; e != nil {
		e.inFlight = false
		switch {
		case err != nil:
			e.backoff = nextBackoff(e.backoff)
			e.nextRefresh = time.Now().Add(e.backoff)
		case noNews:
			e.nextRefresh = time.Now().Add(releasePeerBackoffMin)
		}
	}
	s.releasePeerMu.Unlock()
}

// peerReleaseAnswer is peer's Ping as ReleasePeerAllowed reads it: its
// advertised capabilities and whether it reports itself WAL-quarantined.
func (s *Server) peerReleaseAnswer(ctx context.Context, peer string) ([]string, bool, error) {
	if peer == s.hostName {
		return s.advertisedCapabilities(), s.walQuarantinedNow(), nil
	}
	c, closeConn, err := s.dialPeer(ctx, peer)
	if err != nil {
		return nil, false, err
	}
	defer closeConn()
	resp, err := c.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return nil, false, err
	}
	s.notePeerWALQuarantined(peer, resp.GetWalQuarantined())
	return resp.GetCapabilities(), resp.GetWalQuarantined(), nil
}

// ReleaseSenderAllowed judges a push's SENDER by what it declared in the push
// (N4): no dial back, so an asymmetric link costs nothing, and the answer is the
// sender's state at the moment it pushed, not a cached one. Once a feature of a
// release token this build knows is in use, a sender whose declaration lacks
// that token — an older build sends no declaration at all — is refused with
// FailedPrecondition (back-pressure: retried, nothing dropped), raising
// release_feature_peer_refused naming it. With nothing used, everyone is
// accepted, as on main.
func (s *Server) ReleaseSenderAllowed(ctx context.Context, sender string, declared []string) error {
	s.notePeerCaps(sender, declared)
	for _, tok := range s.usedReleaseTokens(ctx) {
		if !capabilities.Has(declared, tok) {
			s.noteReleasePeerRefused(sender, tok)
			return status.Errorf(codes.FailedPrecondition,
				"replication from %s refused: a feature of %s is in use and %s does not declare it, so its "+
					"writes could drop that feature's data; upgrade it again or remove it", sender, tok, sender)
		}
	}
	return nil
}

// ReleasePeerAllowed judges a peer this node is about to take state FROM
// without a declaration — an anti-entropy pull source, or a relayed entry's
// origin — by the last list it declared or answered. It never dials (I-R2-1):
// a stale or missing list is refreshed in the background, one dial in flight
// per peer, positive answers trusted 30s, negative ones re-asked with backoff.
// A peer never heard from is not judged until its first answer: a dead host's
// relayed writes must not stall a stream, and a startup with no answers yet
// must not refuse everyone. A newly bad origin is therefore caught up to 30s
// late.
func (s *Server) ReleasePeerAllowed(ctx context.Context, peer string) error {
	toks := s.usedReleaseTokens(ctx)
	if len(toks) == 0 || peer == s.hostName {
		return nil
	}
	caps, known := s.peerCapsFor(peer)
	if !known {
		return nil
	}
	for _, tok := range toks {
		if !capabilities.Has(caps, tok) {
			s.noteReleasePeerRefused(peer, tok)
			return status.Errorf(codes.FailedPrecondition,
				"replication from %s refused: a feature of %s is in use and %s does not advertise it; "+
					"upgrade it again or remove it", peer, tok, peer)
		}
	}
	return nil
}

// ReleaseSourceAllowed judges a peer this node is about to take anti-entropy
// state FROM (corrosion.Client.SetReplicationSourceGate). It is
// ReleasePeerAllowed with one difference (m5): a peer this node has no list
// for is asked now — anti-entropy runs in the background, not on the push
// path — and one that answers with nothing while not WAL-quarantined (a
// self-fenced host, or an older build that is fenced) and was never heard
// from before is refused as a source until it declares what it keeps. That
// costs nothing: the pass pulls from another peer. No alarm is raised for it.
// An origin of relayed entries is still never refused for being unknown
// (releaseOriginsAllowed).
func (s *Server) ReleaseSourceAllowed(ctx context.Context, peer string) error {
	toks := s.usedReleaseTokens(ctx)
	if len(toks) == 0 || peer == s.hostName {
		return nil
	}
	if _, known := s.peerCapsFor(peer); !known {
		actx, cancel := context.WithTimeout(ctx, 2*time.Second)
		caps, quarantined, err := s.peerReleaseAnswer(actx, peer)
		cancel()
		switch {
		case err != nil:
			return status.Errorf(codes.FailedPrecondition,
				"anti-entropy from %s refused: a release feature is in use and %s has not said whether it keeps "+
					"its data (%v)", peer, peer, err)
		case len(caps) == 0 && !quarantined:
			return status.Errorf(codes.FailedPrecondition,
				"anti-entropy from %s refused: a release feature is in use and %s, never heard from before, "+
					"advertises nothing (self-fenced?); it is a source again once it declares what it keeps", peer, peer)
		}
		s.notePeerCaps(peer, caps)
	}
	return s.ReleasePeerAllowed(ctx, peer)
}

// releaseOriginsAllowed applies ReleasePeerAllowed to the origin of every
// relayed entry, so a relay that has not caught up cannot pass on what it
// should have refused. Only an origin KNOWN not to carry a used token refuses
// the push: one never heard from, or self-fenced (an empty advertisement that
// is not a WAL quarantine, refreshPeerCaps), is never judged on it, so one
// origin's unknown state never holds up the other origins on the stream.
//
// An origin KNOWN not to carry a used token refuses the WHOLE push (m7), so
// every other origin's entries behind it on that relay stream wait —
// back-pressure, nothing dropped, anti-entropy carrying them meanwhile — until
// that host is upgraded again or removed. That is intended: a push is
// acknowledged as a whole, so applying the rest while skipping one origin's
// entries would tell the relay they were delivered, and lose them. The
// operator sees release_feature_peer_refused naming the host.
func (s *Server) releaseOriginsAllowed(ctx context.Context, sender string, entries []*pb.MutationEntry) error {
	if len(s.usedReleaseTokens(ctx)) == 0 {
		return nil
	}
	seen := map[string]bool{sender: true, s.hostName: true}
	for _, e := range entries {
		o := e.GetOrigin()
		if o == "" || seen[o] {
			continue
		}
		seen[o] = true
		if err := s.ReleasePeerAllowed(ctx, o); err != nil {
			return status.Errorf(codes.FailedPrecondition, "replication relayed by %s refused: %v", sender,
				status.Convert(err).Message())
		}
	}
	return nil
}

// noteReleasePeerRefused records a refusal for the HA condition. It logs at
// Error each time a peer starts being refused — first ever, or after its last
// refusal aged out (N12).
func (s *Server) noteReleasePeerRefused(peer, tok string) {
	s.releasePeerMu.Lock()
	if s.releasePeerRefused == nil {
		s.releasePeerRefused = map[string]time.Time{}
	}
	last := s.releasePeerRefused[peer]
	s.releasePeerRefused[peer] = time.Now()
	s.releasePeerMu.Unlock()
	if last.IsZero() || time.Since(last) >= releasePeerRefusedFor {
		slog.Error("replication: refusing a peer that cannot keep the data of a release feature in use",
			"peer", peer, "token", tok,
			"fix", "upgrade "+peer+" to a build that advertises "+tok+", or remove it")
	}
}

// releasePeerRefusedNow lists, sorted, the peers refused within
// releasePeerRefusedFor.
func (s *Server) releasePeerRefusedNow() []string {
	s.releasePeerMu.Lock()
	defer s.releasePeerMu.Unlock()
	var out []string
	for p, at := range s.releasePeerRefused {
		if time.Since(at) < releasePeerRefusedFor {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// releasePeerRefusedGrew reports a peer refused now that was not before: news
// even while release_feature_peer_refused is already raised (N12).
func releasePeerRefusedGrew(prev, cur []string) bool {
	for _, p := range cur {
		if !slices.Contains(prev, p) {
			return true
		}
	}
	return false
}

// releasePeerRefusedDetail names the refused peers for the HA event.
func (s *Server) releasePeerRefusedDetail() string {
	peers := s.releasePeerRefusedNow()
	if len(peers) == 0 {
		return ""
	}
	return "refusing replication from " + strings.Join(peers, ", ") +
		": a release feature is in use and they do not advertise its token"
}

// Release rollout health condition (UX 3): informational, never degraded.
const (
	releaseRolloutEvaluator   = "release_rollout"
	condReleaseRolloutPending = "release_rollout_pending"
)

// DeclaredCapabilities is what this node's pushes declare
// (ReplicateRequest.sender_capabilities): its advertisement plus this build's
// release tokens, whatever the live advertisement says — a self-fenced node
// advertises nothing but its pending writes were made by a build that keeps
// the data (I-R2-2, m-R2-1). A WAL-quarantined node declares only its (empty)
// advertisement; it emits nothing anyway.
func (s *Server) DeclaredCapabilities() []string {
	adv := s.advertisedCapabilities()
	if s.walQuarantinedNow() {
		return adv
	}
	out := append([]string(nil), adv...)
	for _, t := range capabilities.ReleaseTokens() {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// RefusedReleasePeers lists the peers this node refused replication from in
// the last releasePeerRefusedFor.
func (s *Server) RefusedReleasePeers() []string { return s.releasePeerRefusedNow() }

// releaseRolloutTargets is the host set the release token's latch waits on
// (health.Checker.activationTargets for a replication-gated token): every
// voting-eligible host and every admitted member. A host parked in maintenance
// and out of membership is neither, and is not "not yet" (m2). This host is
// first, and counts as on the release.
func (s *Server) releaseRolloutTargets(ctx context.Context) ([]string, map[string]string, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, nil, err
	}
	version := map[string]string{}
	seen := map[string]bool{s.hostName: true}
	out := []string{s.hostName}
	for _, h := range hosts {
		version[h.Name] = h.Version
		if corrosion.VotingEligible(h.State) && !seen[h.Name] {
			seen[h.Name] = true
			out = append(out, h.Name)
		}
	}
	for _, p := range s.db.Members() {
		if p.Name != "" && !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out, version, nil
}

// releaseLagging lists the hosts of the latch's host set not yet advertising
// this build's release token, with their reported version, from a fresh Ping
// of each, in parallel (the status RPC an operator runs).
func (s *Server) releaseLagging(ctx context.Context) (total, on int, lagging []*pb.LaggingHost, err error) {
	targets, version, err := s.releaseRolloutTargets(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	tok := capabilities.ReleaseToken
	results := make([]bool, len(targets))
	var wg sync.WaitGroup
	for i, name := range targets {
		if name == s.hostName {
			results[i] = true
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			results[i] = s.gateV().PeerSupportsFresh(ctx, name, tok)
		}(i, name)
	}
	wg.Wait()
	for i, name := range targets {
		total++
		if results[i] {
			on++
			continue
		}
		lagging = append(lagging, &pb.LaggingHost{Name: name, Version: version[name],
			Reason: "not advertising " + tok + " (an older build, or unreachable)"})
	}
	sort.Slice(lagging, func(i, j int) bool { return lagging[i].GetName() < lagging[j].GetName() })
	return total, on, lagging, nil
}

// rolloutAnswer is the HA monitor's cached answer for one host: whether it
// advertised the release token, and when to ask it again.
type rolloutAnswer struct {
	on      bool
	next    time.Time
	backoff time.Duration
}

// releaseRolloutLagging is releaseLagging for the HA monitor (m2): from cached
// answers, asking at most ONE host per cycle — the one due longest, a host
// never asked first — so a cycle never fans out and an unreachable host costs
// one bounded Ping per backoff, not one per cycle. An answer that carries the
// token is trusted releasePeerPositiveTTL; one that does not, or no answer, is
// re-asked after a backoff (releasePeerBackoffMin doubling to Max).
//
// complete is false while some host of the latch's set has never been asked:
// this node's view is partial (m3) — every node writes the same row, and one
// that has just restarted, which during a roll is every node in turn, would
// otherwise resolve or rewrite it from a view of nobody.
func (s *Server) releaseRolloutLagging(ctx context.Context) (names []string, complete bool, err error) {
	targets, _, err := s.releaseRolloutTargets(ctx)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	s.releasePeerMu.Lock()
	if s.releaseRollout == nil {
		s.releaseRollout = map[string]*rolloutAnswer{}
	}
	due, dueAt := "", time.Time{}
	for _, name := range targets {
		if name == s.hostName {
			continue
		}
		a := s.releaseRollout[name]
		at := time.Time{}
		if a != nil {
			at = a.next
		}
		if now.Before(at) {
			continue
		}
		if due == "" || at.Before(dueAt) || at.Equal(dueAt) && name < due {
			due, dueAt = name, at
		}
	}
	s.releasePeerMu.Unlock()
	if due != "" {
		on := s.gateV().PeerSupportsFresh(ctx, due, capabilities.ReleaseToken)
		s.releasePeerMu.Lock()
		a := s.releaseRollout[due]
		if a == nil {
			a = &rolloutAnswer{}
			s.releaseRollout[due] = a
		}
		a.on = on
		if on {
			a.backoff, a.next = 0, time.Now().Add(releasePeerPositiveTTL)
		} else {
			a.backoff = nextBackoff(a.backoff)
			a.next = time.Now().Add(a.backoff)
		}
		s.releasePeerMu.Unlock()
	}
	complete = true
	s.releasePeerMu.Lock()
	for _, name := range targets {
		if name == s.hostName {
			continue
		}
		a := s.releaseRollout[name]
		if a == nil {
			complete = false
			continue
		}
		if !a.on {
			names = append(names, name)
		}
	}
	s.releasePeerMu.Unlock()
	sort.Strings(names)
	return names, complete, nil
}

// evaluateReleaseRollout keeps the informational release_rollout_pending
// condition (UX 3): open, naming the lagging hosts, while this build's release
// token has not latched here and some host does not advertise it; resolved
// once it latches or every host does. Written only on a change, and before the
// latch only from a complete view — every host of the latch's set asked at
// least once since this node started (m3). Severity info: an upgrade in
// progress is not a fault, and info does not degrade `lv health`.
func (s *Server) evaluateReleaseRollout(ctx context.Context) {
	gate := s.gateV()
	if gate == nil {
		return
	}
	tok := capabilities.ReleaseToken
	prev, open, err := corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", tok)
	if err != nil {
		return
	}
	open = open && prev.Lifecycle != corrosion.ConditionResolved
	var names []string
	if !gate.Latched(tok) {
		var complete bool
		if names, complete, err = s.releaseRolloutLagging(ctx); err != nil || !complete {
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row := corrosion.HealthCondition{Evaluator: releaseRolloutEvaluator, Code: condReleaseRolloutPending,
		SubjectKind: "cluster", SubjectID: tok, Severity: corrosion.SeverityInfo, Hosts: names,
		Reporter: s.hostName, LastSeen: now, FirstSeen: prev.FirstSeen, ConfirmedAt: prev.ConfirmedAt}
	if row.FirstSeen == "" {
		row.FirstSeen = now
	}
	switch {
	case len(names) > 0:
		if open && slices.Equal(prev.Hosts, names) {
			return
		}
		row.Lifecycle, row.ObserveCount = corrosion.ConditionConfirmed, 1
		if !open {
			// Reopened while the token is still unlatched (m5): keep when the
			// rollout was first seen pending, so a flapping row still shows how
			// long the roll has taken. A first opening starts now.
			row.ConfirmedAt = now
			if prev.FirstSeen == "" || prev.Lifecycle != corrosion.ConditionResolved {
				row.FirstSeen = now
			}
		}
		row.Evidence = fmt.Sprintf(`{"token":%q,"lagging":%d}`, tok, len(names))
	case open:
		row.Lifecycle, row.ResolvedAt, row.Hosts = corrosion.ConditionResolved, now, prev.Hosts
	default:
		return
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Debug("release rollout condition: write failed", "error", err)
	}
}

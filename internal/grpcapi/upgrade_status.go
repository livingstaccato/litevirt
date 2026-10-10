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
	if s.gate != nil {
		for _, tok := range capabilities.All() {
			if !s.gate.Latched(tok) {
				continue
			}
			rule := capabilities.RollbackRule(tok)
			// What a rule-aware build would do, and what the build directly
			// below this token does: for the first release token that build
			// predates rules, so it quarantines on the marker, used or not (I4).
			ruleAware := rule != capabilities.RollbackSafeIfUnused || usedTokens[tok]
			out.Tokens = append(out.Tokens, &pb.UpgradeToken{
				Name:                    tok,
				Durable:                 s.gate.DurablyLatched(tok),
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
	if s.gate != nil {
		total, on, lagging, err := s.releaseLagging(ctx, true)
		if err == nil {
			out.HostsTotal, out.HostsOnRelease, out.Lagging = int32(total), int32(on), lagging
		}
		if !s.gate.Latched(capabilities.ReleaseToken) {
			for _, f := range capabilities.Features() {
				if info, _ := capabilities.LookupFeature(f); info.Token == capabilities.ReleaseToken {
					out.FeaturesWaiting++
				}
			}
		}
	}
	out.RefusedPeers = s.RefusedReleasePeers()
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
	return &pb.ReleaseFeatureUseHeld{Held: present}, nil
}

// PeerHoldsReleaseFeatureUse asks host whether its replica holds the used
// record: health.ReleaseUseConfirmer in production.
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

// resetReleasePeerCache drops the cached used-token list (tests).
func (s *Server) resetReleasePeerCache() {
	s.releasePeerMu.Lock()
	s.releaseUsedAt = time.Time{}
	s.releasePeerMu.Unlock()
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
func (s *Server) refreshPeerCaps(peer string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	caps, _, err := s.PeerCapabilities(ctx, peer)
	cancel()
	if err == nil {
		s.notePeerCaps(peer, caps)
	}
	s.releasePeerMu.Lock()
	if e := s.releasePeerLast[peer]; e != nil {
		e.inFlight = false
		if err != nil {
			e.backoff = nextBackoff(e.backoff)
			e.nextRefresh = time.Now().Add(e.backoff)
		}
	}
	s.releasePeerMu.Unlock()
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

// releaseOriginsAllowed applies ReleasePeerAllowed to the origin of every
// relayed entry, so a relay that has not caught up cannot pass on what it
// should have refused.
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

// AdvertisedCapabilities is the capability list this node's Ping returns, which
// its pushes also declare (corrosion.Replicator.SetAdvertisedCapabilities).
func (s *Server) AdvertisedCapabilities() []string { return s.advertisedCapabilities() }

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

// releaseLagging lists the hosts not yet advertising this build's release
// token, with their reported version, this host excluded. fresh pings each
// (the status RPC); otherwise the checker's cached answer is used where the
// gate offers one (the HA monitor).
func (s *Server) releaseLagging(ctx context.Context, fresh bool) (total, on int, lagging []*pb.LaggingHost, err error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return 0, 0, nil, err
	}
	tok := capabilities.ReleaseToken
	cached, _ := s.gate.(interface {
		PeerSupports(ctx context.Context, peer, token string) bool
	})
	results := make([]bool, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		if h.Name == s.hostName {
			results[i] = true
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			if !fresh && cached != nil {
				results[i] = cached.PeerSupports(ctx, name, tok)
				return
			}
			results[i] = s.gate.PeerSupportsFresh(ctx, name, tok)
		}(i, h.Name)
	}
	wg.Wait()
	for i, h := range hosts {
		total++
		if results[i] {
			on++
			continue
		}
		lagging = append(lagging, &pb.LaggingHost{Name: h.Name, Version: h.Version,
			Reason: "not advertising " + tok + " (an older build, or unreachable)"})
	}
	sort.Slice(lagging, func(i, j int) bool { return lagging[i].GetName() < lagging[j].GetName() })
	return total, on, lagging, nil
}

// evaluateReleaseRollout keeps the informational release_rollout_pending
// condition (UX 3): open, naming the lagging hosts, while this build's release
// token has not latched here and some host does not advertise it; resolved
// once it latches or every host does. Written only on a change. Severity info:
// an upgrade in progress is not a fault, and info does not degrade `lv health`.
func (s *Server) evaluateReleaseRollout(ctx context.Context) {
	if s.gate == nil {
		return
	}
	tok := capabilities.ReleaseToken
	prev, open, err := corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", tok)
	if err != nil {
		return
	}
	open = open && prev.Lifecycle != corrosion.ConditionResolved
	var names []string
	if !s.gate.Latched(tok) {
		_, _, lagging, err := s.releaseLagging(ctx, false)
		if err != nil {
			return
		}
		for _, l := range lagging {
			names = append(names, l.GetName())
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
			row.FirstSeen, row.ConfirmedAt = now, now
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

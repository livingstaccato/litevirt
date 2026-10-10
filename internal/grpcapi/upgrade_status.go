package grpcapi

// Release features and `lv cluster upgrade-status` (capabilities.ReleaseToken,
// docs/upgrades.md "Rolling back after a release token latched").

import (
	"context"
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

// usedReleaseTokens lists the release tokens durably latched here with at
// least one recorded use, cached for releaseUsedCacheTTL.
func (s *Server) usedReleaseTokens(ctx context.Context) []string {
	s.releasePeerMu.Lock()
	if time.Since(s.releaseUsedAt) < releaseUsedCacheTTL {
		out := s.releaseUsed
		s.releasePeerMu.Unlock()
		return out
	}
	s.releasePeerMu.Unlock()
	var out []string
	if s.gate != nil {
		uses, err := corrosion.ListReleaseFeatureUses(ctx, s.db)
		if err == nil {
			seen := map[string]bool{}
			for _, u := range uses {
				if !seen[u.Token] && capabilities.RollbackRule(u.Token) != "" && s.gate.DurablyLatched(u.Token) {
					seen[u.Token] = true
					out = append(out, u.Token)
				}
			}
			sort.Strings(out)
		}
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
	s.releasePeerChecks = nil
	s.releasePeerMu.Unlock()
}

// ReleasePeerAllowed reports whether this node may take replicated state from
// peer (I6). Once a feature of a release token latched here is in use, a peer
// that does not advertise that token — rolled back, or back from a long
// absence on a build without it, where nothing on its own side can stop it —
// is refused: its writes may be rewrites that dropped the feature's data. The
// refusal back-pressures (the push is retried, nothing is dropped) and raises
// release_feature_peer_refused naming the peer. Advertisement is read by a fresh
// Ping reused for releasePeerCheckTTL, so a peer upgraded again is accepted
// within that. Nil gate, or nothing used: allowed, as on main.
func (s *Server) ReleasePeerAllowed(ctx context.Context, peer string) error {
	toks := s.usedReleaseTokens(ctx)
	if len(toks) == 0 || peer == s.hostName {
		return nil
	}
	for _, tok := range toks {
		if !s.releasePeerSupports(ctx, peer, tok) {
			s.noteReleasePeerRefused(peer, tok)
			return status.Errorf(codes.FailedPrecondition,
				"replication from %s refused: a feature of %s is in use and %s does not advertise it, so its "+
					"writes could drop that feature's data; upgrade it again or remove it", peer, tok, peer)
		}
	}
	return nil
}

// releasePeerCheckTTL bounds how long one fresh Ping's answer about a peer is
// reused by ReleasePeerAllowed. Deliberately much shorter than the checker's
// 30s capability cache: a peer that rolls back restarts, and an answer from
// before its restart must not admit its first pushes after it. A restart
// shorter than this is the residual window.
const releasePeerCheckTTL = 5 * time.Second

type releasePeerCheck struct {
	ok bool
	at time.Time
}

// releasePeerSupports reports whether peer advertises tok, from a fresh Ping
// reused for releasePeerCheckTTL.
func (s *Server) releasePeerSupports(ctx context.Context, peer, tok string) bool {
	key := peer + "\x00" + tok
	s.releasePeerMu.Lock()
	if e, ok := s.releasePeerChecks[key]; ok && time.Since(e.at) < releasePeerCheckTTL {
		s.releasePeerMu.Unlock()
		return e.ok
	}
	s.releasePeerMu.Unlock()
	ok := s.gate.PeerSupportsFresh(ctx, peer, tok)
	s.releasePeerMu.Lock()
	if s.releasePeerChecks == nil {
		s.releasePeerChecks = map[string]releasePeerCheck{}
	}
	s.releasePeerChecks[key] = releasePeerCheck{ok: ok, at: time.Now()}
	s.releasePeerMu.Unlock()
	return ok
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

// releasePeerRefusedDetail names the refused peers for the HA event.
func (s *Server) releasePeerRefusedDetail() string {
	peers := s.releasePeerRefusedNow()
	if len(peers) == 0 {
		return ""
	}
	return "refusing replication from " + strings.Join(peers, ", ") +
		": a release feature is in use and they do not advertise its token"
}

// releaseOriginsAllowed applies ReleasePeerAllowed to the origin of every
// relayed entry. An origin that cannot be asked right now (down, partitioned)
// is NOT refused: a relay forwarding a dead host's last writes must not stall
// every stream behind it. Only an origin that answers, and does not advertise
// the token, is refused. Its own pushes are refused outright, so a rolled-back
// origin's entries can only arrive relayed while it is unreachable from here —
// the residual this leaves.
func (s *Server) releaseOriginsAllowed(ctx context.Context, sender string, entries []*pb.MutationEntry) error {
	toks := s.usedReleaseTokens(ctx)
	if len(toks) == 0 {
		return nil
	}
	seen := map[string]bool{sender: true, s.hostName: true}
	for _, e := range entries {
		o := e.GetOrigin()
		if o == "" || seen[o] {
			continue
		}
		seen[o] = true
		for _, tok := range toks {
			if s.releaseOriginLacks(ctx, o, tok) {
				s.noteReleasePeerRefused(o, tok)
				return status.Errorf(codes.FailedPrecondition,
					"replication relayed by %s refused: entries from %s, which does not advertise %s while a "+
						"feature of it is in use; upgrade %s again or remove it", sender, o, tok, o)
			}
		}
	}
	return nil
}

// releaseOriginLacks reports whether origin ANSWERS a fresh Ping without tok
// (an unreachable origin is not judged), reusing an answer for
// releasePeerCheckTTL.
func (s *Server) releaseOriginLacks(ctx context.Context, origin, tok string) bool {
	key := "origin\x00" + origin + "\x00" + tok
	s.releasePeerMu.Lock()
	if e, ok := s.releasePeerChecks[key]; ok && time.Since(e.at) < releasePeerCheckTTL {
		s.releasePeerMu.Unlock()
		return !e.ok
	}
	s.releasePeerMu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	caps, _, err := s.PeerCapabilities(pctx, origin)
	cancel()
	ok := err != nil || capabilities.Has(caps, tok)
	s.releasePeerMu.Lock()
	if s.releasePeerChecks == nil {
		s.releasePeerChecks = map[string]releasePeerCheck{}
	}
	s.releasePeerChecks[key] = releasePeerCheck{ok: ok, at: time.Now()}
	s.releasePeerMu.Unlock()
	return !ok
}

// noteReleasePeerRefused records a refusal for the HA condition, logging the
// first one per peer.
func (s *Server) noteReleasePeerRefused(peer, tok string) {
	s.releasePeerMu.Lock()
	if s.releasePeerRefused == nil {
		s.releasePeerRefused = map[string]time.Time{}
	}
	first := s.releasePeerRefused[peer].IsZero()
	s.releasePeerRefused[peer] = time.Now()
	s.releasePeerMu.Unlock()
	if first {
		slog.Error("replication: refusing a peer that cannot keep the data of a release feature in use",
			"peer", peer, "token", tok,
			"fix", "upgrade "+peer+" to a build that advertises "+tok+", or remove it")
	}
}

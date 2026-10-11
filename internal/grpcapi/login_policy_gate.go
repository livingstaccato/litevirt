package grpcapi

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The login rules (account disable and expiry, the mandatory second factor,
// enrollment codes, directory identity bindings and the durable credential
// cut-offs) are the release feature capabilities.FeatureLoginPolicy. Every
// write of their data goes through the release-feature gate on the node that
// writes it, and its corrosion writer checks the grant.
//
// Two kinds of caller:
//
//   - an operator's change of a login rule (lv user disable/enable/expire,
//     lv 2fa policy, an enrollment code, lv user unbind, reset-admin's
//     --clear-2fa or re-enable) is NEW, and is refused with the gate's own
//     answer — "the cluster upgrade must finish first (login_policy needs
//     release_2026_11_v1)" — until the feature opens: withLoginPolicy.
//   - a login, a user create or delete, and the admin floor are what the
//     previous release does too. They are never refused for the feature's
//     sake: the login rules' data rides along when the gate passes, and they
//     run as before the release when it does not: LoginPolicyIfAvailable.

// loginPolicyGateWait bounds how long a best-effort caller waits on the gate.
// A first use waits for every replication recipient to acknowledge the used
// record (up to 30s); a login must not wait that long for data it can do
// without.
const loginPolicyGateWait = 3 * time.Second

// loginPolicyRefusalBackoff is how long a best-effort caller writes without
// the feature after the gate refused a FIRST use (no acknowledged record in
// this replica), so a recipient that cannot answer costs one bounded wait per
// interval — plus the callers already waiting on that attempt, each at most
// loginPolicyGateWait — not one per login. It never applies once this
// replica holds an acknowledged record: the gate's path is then local, with
// no peer wait, and a write that skipped it would lose data the feature
// already depends on (a presented factor, a delete's cut-offs).
const loginPolicyRefusalBackoff = time.Minute

// loginPolicyBackoff records when the gate last refused a best-effort write.
type loginPolicyBackoff struct {
	mu        sync.Mutex
	refusedAt time.Time
}

func (b *loginPolicyBackoff) backingOff(now time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.refusedAt.IsZero() && now.Sub(b.refusedAt) < loginPolicyRefusalBackoff
}

func (b *loginPolicyBackoff) refused(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.refusedAt = now
	b.mu.Unlock()
}

// withLoginPolicy runs write — an operator's change of a login rule — through
// the login_policy release feature's gate. The gate's refusal is returned as
// it is; write's own error too.
func (s *Server) withLoginPolicy(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error {
	return s.WithReleaseFeature(ctx, capabilities.FeatureLoginPolicy, write)
}

// withLoginPolicyIfAvailable is LoginPolicyIfAvailable on this server's gate,
// with the refusal backoff, which this replica's acknowledged record lifts.
func (s *Server) withLoginPolicyIfAvailable(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error {
	return loginPolicyIfAvailable(ctx, s.releaseFeatures, s.loginPolicyInUse, &s.loginPolicyBackoff, write)
}

// loginPolicyInUse reports whether this replica holds an ACKNOWLEDGED used
// record for login_policy, so the gate passes on its local path. A read that
// fails is "no".
func (s *Server) loginPolicyInUse(ctx context.Context) bool {
	return releaseFeatureAckedHere(ctx, s.db, capabilities.FeatureLoginPolicy)
}

// loginPolicyInUseOrUnknown is loginPolicyInUse for a caller that must fail
// closed: a read that fails is "in use" (re-review m6). An injected reader
// (tests) replaces the replica read.
func (s *Server) loginPolicyInUseOrUnknown(ctx context.Context) bool {
	if s.loginPolicyStateRead != nil {
		inUse, err := s.loginPolicyStateRead(ctx)
		return err != nil || inUse
	}
	info, ok := capabilities.LookupFeature(capabilities.FeatureLoginPolicy)
	if !ok || s.db == nil {
		return true
	}
	_, acked, err := corrosion.ReleaseFeatureState(ctx, s.db, info.Token, string(capabilities.FeatureLoginPolicy))
	return err != nil || acked
}

func releaseFeatureAckedHere(ctx context.Context, db *corrosion.Client, f capabilities.Feature) bool {
	info, ok := capabilities.LookupFeature(f)
	if !ok || db == nil {
		return false
	}
	_, acked, err := corrosion.ReleaseFeatureState(ctx, db, info.Token, string(f))
	return err == nil && acked
}

// LoginPolicyIfAvailable runs write — a write the previous release makes too
// (a login, a user create or delete, the admin floor's reinstatement) — with a
// grant for capabilities.FeatureLoginPolicy when the feature's gate passes on
// this node, and with the zero grant when it does not, so the write runs as it
// did before the release. It never refuses for the feature's sake: only
// write's own error is returned.
//
// The gate is asked only when the feature is available here (its release
// token durably latched; a local read, no Ping), and then for at most
// loginPolicyGateWait. A nil gate is the zero grant.
func LoginPolicyIfAvailable(ctx context.Context, gate releaseFeatureGate, write func(context.Context, capabilities.FeatureGrant) error) error {
	return loginPolicyIfAvailable(ctx, gate, nil, nil, write)
}

// loginPolicyIfAvailable is LoginPolicyIfAvailable with an optional backoff
// after a refused first use. inUse, when set, says this replica holds an
// acknowledged record; the backoff is then ignored (re-review I-1).
func loginPolicyIfAvailable(ctx context.Context, gate releaseFeatureGate, inUse func(context.Context) bool,
	backoff *loginPolicyBackoff, write func(context.Context, capabilities.FeatureGrant) error) error {
	const f = capabilities.FeatureLoginPolicy
	if gate != nil && gate.FeatureAvailable(f) &&
		(!backoff.backingOff(time.Now()) || (inUse != nil && inUse(ctx))) {
		gctx, cancel := context.WithTimeout(ctx, loginPolicyGateWait)
		ran := false
		err := gate.WithFeature(gctx, f, func(_ context.Context, g capabilities.FeatureGrant) error {
			ran = true
			// The write keeps the caller's context: the bound is on the gate.
			return write(ctx, g)
		})
		cancel()
		if ran {
			return err
		}
		backoff.refused(time.Now())
		slog.Warn("login rules: the release feature's gate did not pass; writing without the login rules' data, "+
			"as before the release", "feature", f, "error", err)
	}
	return write(ctx, capabilities.FeatureGrant{})
}

// voidEnrollmentCode tombstones user's outstanding first-enrollment code, if
// there is one, after an administrator enrolled a factor for the account. An
// account with no code has nothing to void, so enrolling a factor never opens
// the release feature by itself.
func (s *Server) voidEnrollmentCode(ctx context.Context, user string) error {
	live, err := corrosion.HasLiveEnrollmentCode(ctx, s.db, user)
	if err != nil || !live {
		return err
	}
	return s.withLoginPolicyIfAvailable(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return corrosion.InvalidateEnrollmentCode(ctx, s.db, g, user)
	})
}

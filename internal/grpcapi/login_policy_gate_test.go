package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// countingFeatureGate is a release-feature gate that counts what it is asked:
// available reports FeatureAvailable, refuse (when set) is WithFeature's
// refusal, and otherwise it hands the write a grant.
type countingFeatureGate struct {
	t         testing.TB
	available bool
	refuse    error
	asked     int
}

func (g *countingFeatureGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.asked++
	if g.refuse != nil {
		return g.refuse
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *countingFeatureGate) FeatureAvailable(capabilities.Feature) bool { return g.available }

// TestLoginPolicyIfAvailable_NeverRefusesWhatThePreviousReleaseDoes: a login,
// a create or a delete runs with the login rules' grant when the gate passes,
// and with the zero grant — as before the release, never refused — when the
// feature is not available or the gate refuses. After a refusal the gate is
// not asked again for a while; the write's own error is returned as it is.
func TestLoginPolicyIfAvailable_NeverRefusesWhatThePreviousReleaseDoes(t *testing.T) {
	ctx := context.Background()
	var got []bool
	write := func(_ context.Context, g capabilities.FeatureGrant) error {
		got = append(got, g.Check(capabilities.FeatureLoginPolicy) == nil)
		return nil
	}

	s := testServer(t)
	if err := s.withLoginPolicyIfAvailable(ctx, write); err != nil || len(got) != 1 || got[0] {
		t.Fatalf("no gate wired: err=%v granted=%v, want the write run without the grant", err, got)
	}

	g := &countingFeatureGate{t: t, available: false}
	s.SetReleaseFeatureGate(g)
	got = nil
	if err := s.withLoginPolicyIfAvailable(ctx, write); err != nil || len(got) != 1 || got[0] || g.asked != 0 {
		t.Fatalf("feature not available: err=%v granted=%v asked=%d, want the zero grant and the gate not asked", err, got, g.asked)
	}

	g.available = true
	g.refuse = status.Error(codes.Unavailable, "a recipient did not confirm the use")
	got = nil
	if err := s.withLoginPolicyIfAvailable(ctx, write); err != nil || len(got) != 1 || got[0] {
		t.Fatalf("gate refused: err=%v granted=%v, want the write run without the grant and no error", err, got)
	}
	if err := s.withLoginPolicyIfAvailable(ctx, write); err != nil || g.asked != 1 {
		t.Fatalf("right after a refusal: err=%v asked=%d, want the gate not asked again", err, g.asked)
	}

	g.refuse = nil
	s.loginPolicyBackoff = loginPolicyBackoff{} // the backoff has passed
	got = nil
	if err := s.withLoginPolicyIfAvailable(ctx, write); err != nil || len(got) != 1 || !got[0] {
		t.Fatalf("gate passes: err=%v granted=%v, want the write run with the grant", err, got)
	}
	boom := errors.New("disk full")
	if err := s.withLoginPolicyIfAvailable(ctx, func(context.Context, capabilities.FeatureGrant) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("a failing write: %v, want its own error", err)
	}
}

// TestResetAdmin_LoginRulesGoThroughTheGate: over the RPC, a plain password
// reset is what the previous release does and never asks the release
// feature's gate; --clear-2fa is a login rule, refused with the release
// refusal (as FailedPrecondition, never Unavailable, which the CLI would take
// for a daemon it cannot reach) until the feature opens.
func TestResetAdmin_LoginRulesGoThroughTheGate(t *testing.T) {
	s := resetAdminFixture(t)
	ctx, err := authedCtx(t, s, "test-host", tcpAddr("127.0.0.1"), "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	g := &countingFeatureGate{t: t, available: false,
		refuse: status.Error(codes.Unavailable, loginPolicyRefusal+": a recipient did not confirm the use")}
	s.SetReleaseFeatureGate(g)
	if _, err := s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: mustHash(t, "plain-pw-0123456789")}); err != nil {
		t.Fatalf("a plain reset before the feature opens: %v", err)
	}
	if g.asked != 0 {
		t.Fatalf("a plain reset asked the release feature's gate %d time(s)", g.asked)
	}
	if _, err := auth.EnrollTOTP(context.Background(), s.db, "admin", "phone"); err != nil {
		t.Fatal(err)
	}
	_, err = s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: mustHash(t, "clear-pw-0123456789"), ClearTwoFactor: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), loginPolicyRefusal) {
		t.Fatalf("--clear-2fa before the feature opens: %v, want FailedPrecondition %q", err, loginPolicyRefusal)
	}
	if f, _ := corrosion.ListUser2FA(context.Background(), s.db, "admin"); len(f) != 1 {
		t.Fatalf("a refused --clear-2fa changed the factors: %+v", f)
	}
}

// TestVoidEnrollmentCode_AsksTheGateOnlyForALiveCode: an admin enrolling a
// factor for an account with no enrollment code writes no login-rules data,
// so it never opens (and marks used) the release feature; with a code it
// voids it through the gate.
func TestVoidEnrollmentCode_AsksTheGateOnlyForALiveCode(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedUser(t, s, "bob", "viewer", "pw")
	g := &countingFeatureGate{t: t, available: true}
	s.SetReleaseFeatureGate(g)
	if err := s.voidEnrollmentCode(ctx, "bob"); err != nil || g.asked != 0 {
		t.Fatalf("no code: err=%v asked=%d, want the gate not asked", err, g.asked)
	}
	if _, _, err := corrosion.IssueEnrollmentCode(ctx, s.db, lpGrant(t), "bob", 0, "admin", s.hostName); err != nil {
		t.Fatal(err)
	}
	if err := s.voidEnrollmentCode(ctx, "bob"); err != nil || g.asked != 1 {
		t.Fatalf("a live code: err=%v asked=%d, want it voided through the gate", err, g.asked)
	}
	if live, err := corrosion.HasLiveEnrollmentCode(ctx, s.db, "bob"); err != nil || live {
		t.Fatalf("after voiding: live=%v err=%v", live, err)
	}
}

// TestLoginPolicyIfAvailable_BackoffLiftsOnceTheFeatureIsInUse is re-review
// I-1. A first use from this node is refused (a voter was down), and the
// node backs off. Another node then opens the feature, and its acknowledged
// record reaches this replica. Inside the backoff window, a login that
// presents a second factor still records it — or the policy would confine
// that session for life — and a delete still writes its cut-offs: with an
// acknowledged record the gate's path is local, so the backoff does not apply.
func TestLoginPolicyIfAvailable_BackoffLiftsOnceTheFeatureIsInUse(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	secrets := map[string]string{}
	for _, u := range []string{"ann", "uma"} {
		seedUser(t, s, u, "viewer", u+"-pw")
		res, err := auth.EnrollTOTP(ctx, s.db, u, "phone")
		if err != nil {
			t.Fatal(err)
		}
		secrets[u] = res.SecretBase32
	}
	seedUser(t, s, "carol", "viewer", "carol-pw")
	g := &countingFeatureGate{t: t, available: true,
		refuse: status.Error(codes.Unavailable, "voter y did not confirm the use")}
	s.SetReleaseFeatureGate(g)
	factorOf := func(token string) string {
		t.Helper()
		f, err := corrosion.SessionFactor(ctx, s.db, strings.TrimPrefix(token, SessionTokenPrefix))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	// 1. The first use is refused: the login works, without its factor row,
	// and this node backs off.
	r, err := s.Login(ctx, &pb.LoginRequest{Username: "ann", Password: "ann-pw", TotpCode: totpCode(t, secrets["ann"])})
	if err != nil {
		t.Fatalf("a factor login while the first use is refused: %v", err)
	}
	if f := factorOf(r.Token); f != "" || g.asked != 1 {
		t.Fatalf("refused first use: factor=%q asked=%d, want no factor row and one attempt", f, g.asked)
	}

	// 2. Another node opens the feature; its acknowledged record arrives.
	g.refuse = nil
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken,
		string(capabilities.FeatureLoginPolicy), "node-a", true); err != nil {
		t.Fatal(err)
	}

	// 3. Inside the backoff window: the factor is recorded.
	r, err = s.Login(ctx, &pb.LoginRequest{Username: "uma", Password: "uma-pw", TotpCode: totpCode(t, secrets["uma"])})
	if err != nil {
		t.Fatalf("a factor login in the backoff window: %v", err)
	}
	if f := factorOf(r.Token); f != "totp" {
		t.Fatalf("a factor login in the backoff window after the feature opened recorded factor %q, want totp", f)
	}
	// And a delete writes its durable cut-offs.
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "carol"}); err != nil {
		t.Fatal(err)
	}
	if l, err := corrosion.GetUserLifecycle(ctx, s.db, "carol"); err != nil || l.TokensNotBefore == "" {
		t.Fatalf("a delete in the backoff window wrote no cut-off: %+v %v", l, err)
	}
	// And a create of a name a peer left a disable on clears it rather than
	// refusing (switch-rereview-login m-A).
	writeLifecycle(t, s, "dave", corrosion.UserAttrDisabled, "true")
	if _, err := s.CreateUser(adminCtx(), &pb.CreateUserRequest{Username: "dave", Password: "dave-pw-0123456789"}); err != nil {
		t.Fatalf("a create over a peer's lifecycle row in the backoff window: %v", err)
	}
	if l, err := corrosion.GetUserLifecycle(ctx, s.db, "dave"); err != nil || l.Disabled || l.SessionsNotBefore == "" {
		t.Fatalf("a create in the backoff window did not reset the name's lifecycle: %+v %v", l, err)
	}
}

type ctxKeyLoginPolicyTest struct{}

// deadlineGate records the deadline of the context the gate is given.
type deadlineGate struct {
	t           testing.TB
	deadline    time.Time
	hasDeadline bool
}

func (g *deadlineGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.deadline, g.hasDeadline = ctx.Deadline()
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *deadlineGate) FeatureAvailable(capabilities.Feature) bool { return true }

// TestLoginPolicyIfAvailable_GateWaitIsBoundedTo3s (re-review m-2): a login,
// create or delete waits on the release feature's gate for at most 3 s (a
// first use's acknowledgements may take 30 s), and the write itself runs on
// the caller's context, not on that bound.
func TestLoginPolicyIfAvailable_GateWaitIsBoundedTo3s(t *testing.T) {
	g := &deadlineGate{t: t}
	caller := context.WithValue(context.Background(), ctxKeyLoginPolicyTest{}, "caller")
	start := time.Now()
	var writeCtx context.Context
	if err := loginPolicyIfAvailable(caller, g, nil, nil, func(ctx context.Context, _ capabilities.FeatureGrant) error {
		writeCtx = ctx
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !g.hasDeadline {
		t.Fatal("the gate was given no deadline")
	}
	// The deadline is set inside the call, so allow the call's own duration.
	if d := g.deadline.Sub(start); d <= 0 || d > 3*time.Second+time.Since(start) {
		t.Fatalf("the gate's deadline is %s after the call began, want at most 3s", d)
	}
	if writeCtx == nil || writeCtx.Value(ctxKeyLoginPolicyTest{}) != "caller" {
		t.Fatal("the write did not run on the caller's context")
	}
	if _, ok := writeCtx.Deadline(); ok {
		t.Fatal("the write runs under the gate's bound; it must keep the caller's context")
	}
}

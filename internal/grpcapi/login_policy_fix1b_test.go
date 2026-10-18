package grpcapi

// Fix round 1, the parts that needed new API: open streams (I1), enrollment
// codes and the self-enrollment window (I5), reset-admin --clear-2fa (I6),
// a failed revoke during enrollment (C1 d), realm warnings (m5) and the
// server-judged account status (m1).

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// blockingStream is a grpc.ServerStream whose context is the incoming one.
type blockingStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (b *blockingStream) Context() context.Context     { return b.ctx }
func (b *blockingStream) SetHeader(metadata.MD) error  { return nil }
func (b *blockingStream) SendHeader(metadata.MD) error { return nil }
func (b *blockingStream) SetTrailer(metadata.MD)       {}
func (b *blockingStream) SendMsg(any) error            { return nil }
func (b *blockingStream) RecvMsg(any) error            { return nil }

// openStream runs a stream whose handler holds it open until its context
// ends, the way a console does, and returns a channel that yields the
// stream's result.
func openStream(s *Server, token string) (<-chan error, <-chan struct{}) {
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		done <- s.StreamAuthInterceptor(nil, &blockingStream{ctx: bearerCtx(token)},
			&grpc.StreamServerInfo{FullMethod: "/litevirt.v1.LiteVirt/ConsoleVM"},
			func(_ any, ss grpc.ServerStream) error {
				close(started)
				<-ss.Context().Done()
				return ss.Context().Err()
			})
	}()
	return done, started
}

func wantStreamCut(t *testing.T, what string, done <-chan error, within time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("%s: stream ended with %v, want Unauthenticated", what, err)
		}
	case <-time.After(within):
		t.Fatalf("%s: the open stream was still running after %v", what, within)
	}
}

// I1: a disable made on this node cuts an open stream at once; one that
// arrives by replication cuts it within the recheck interval.
func TestI1_OpenStreamsAreCut(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  func(t *testing.T, s *Server, user, token string)
	}{
		{"disable on this node", func(t *testing.T, s *Server, user, _ string) { setDisabled(t, s, user, true) }},
		{"disable arriving by replication", func(t *testing.T, s *Server, user, _ string) {
			writeLifecycle(t, s, user, corrosion.UserAttrDisabled, "true")
		}},
		{"expiry passing", func(t *testing.T, s *Server, user, _ string) {
			writeLifecycle(t, s, user, corrosion.UserAttrExpiresAt, time.Now().Add(-time.Second).UTC().Format(time.RFC3339))
		}},
		{"session revoked", func(t *testing.T, s *Server, _, token string) {
			id := strings.TrimPrefix(token, SessionTokenPrefix)
			if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: id}); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy switched on", func(t *testing.T, s *Server, _, _ string) { setPolicy(t, s, "all") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loginPolicyServer(t)
			s.streamRecheckEvery = 50 * time.Millisecond
			seedAdmins(t, s)
			seedUser(t, s, "bob", "operator", "bob-pw")
			token := login(t, s, "bob", "bob-pw").Token
			done, started := openStream(s, token)
			<-started
			tc.act(t, s, "bob", token)
			wantStreamCut(t, tc.name, done, 2*time.Second)
		})
	}
	// An API token's stream is cut by its revoke too.
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	tok, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{Username: "bob", Name: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	done, started := openStream(s, tok.Token)
	<-started
	if _, err := s.RevokeToken(adminCtx(), &pb.RevokeTokenRequest{Id: tok.Id}); err != nil {
		t.Fatal(err)
	}
	wantStreamCut(t, "token revoked", done, 2*time.Second)
}

// I1: on the node where the change is made the cut is immediate, not left to
// the next tick: with a recheck interval of an hour, a local disable still
// ends the stream.
func TestI1_LocalChangeCutsAtOnce(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = time.Hour
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	setDisabled(t, s, "bob", true)
	wantStreamCut(t, "a local disable with an hour-long recheck interval", done, 2*time.Second)
}

// I1: a kick that arrives WHILE a recheck runs is not lost. The watcher used
// to take the channel it waits on after the recheck, so a kickStreams during
// the recheck closed a channel nobody held and the stream waited a full
// interval (an hour here) before looking again.
func TestI1_KickDuringRecheckIsNotLost(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = time.Hour
	seedUser(t, s, "bob", "operator", "bob-pw")
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	hook := func(context.Context) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	recheckHook.Store(&hook)
	t.Cleanup(func() { recheckHook.Store(nil) })
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	// Start the first recheck with a kick, repeated until it is running.
	for waiting := true; waiting; {
		s.kickStreams()
		select {
		case <-entered:
			waiting = false
		case <-time.After(10 * time.Millisecond):
		}
	}
	s.kickStreams() // during the recheck
	close(release)
	deadline := time.After(5 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("a kick during a recheck was lost: %d recheck(s) ran, want a second within 5s", calls.Load())
		case err := <-done:
			t.Fatalf("stream ended unexpectedly: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// I1: a stream with nothing wrong is not cut, across several rechecks.
//
// The test interval scales the fail-closed bound too (2.5 intervals), and a
// recheck's budget is what is left of it after the tick that started it
// fired. At a 20 ms interval that bound was 50 ms, so a loaded host whose
// timer fired late cut a healthy stream — correctly, at that bound. The
// interval here keeps the bound far above scheduler delay, and the test
// counts the rechecks that ran instead of sleeping a fixed time, so a slow
// host takes longer but still sees them.
func TestI1_HealthyStreamStaysOpen(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 250 * time.Millisecond
	seedUser(t, s, "bob", "operator", "bob-pw")
	var rechecks atomic.Int32
	hook := func(context.Context) error { rechecks.Add(1); return nil }
	recheckHook.Store(&hook)
	t.Cleanup(func() { recheckHook.Store(nil) })
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	const want = 4
	deadline := time.After(30 * time.Second)
	for rechecks.Load() <= want {
		select {
		case err := <-done:
			t.Fatalf("a healthy stream ended after %d rechecks: %v", rechecks.Load(), err)
		case <-deadline:
			t.Fatalf("only %d rechecks ran in 30s; want more than %d", rechecks.Load(), want)
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatalf("a healthy stream ended after %d rechecks: %v", rechecks.Load(), err)
	default:
	}
}

// I5: by default an enrollment-only session needs an admin-issued code, the
// code is single-use and short-lived, and the first enrollment is notified.
func TestI5_EnrollmentNeedsAnAdminIssuedCode(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setPolicy(t, s, "all")
	tok := login(t, s, "bob", "bob-pw").Token
	ctx, err := s.authenticate(bearerCtx(tok))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone"})
	wantCode(t, "enrollment without a code", err, codes.PermissionDenied)
	_, err = s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: "nope"})
	wantCode(t, "enrollment with a wrong code", err, codes.PermissionDenied)

	opCtx := userCtx("op", "operator")
	_, err = s.IssueEnrollmentCode(opCtx, &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	wantCode(t, "an operator issuing a code", err, codes.PermissionDenied)
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil || code.GetCode() == "" {
		t.Fatalf("IssueEnrollmentCode: %+v %v", code, err)
	}
	rows, _ := s.db.Query(context.Background(), `SELECT code_hash FROM user_enrollment_codes WHERE username = 'bob'`)
	if len(rows) != 1 || strings.Contains(rows[0].String("code_hash"), code.GetCode()) {
		t.Fatalf("the code is not stored hashed: %v", rows)
	}
	if _, err := s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()}); err != nil {
		t.Fatalf("enrollment with the code: %v", err)
	}
	audits, _ := s.db.Query(context.Background(), `SELECT 1 FROM audit_log WHERE action = 'auth.first_factor_enrolled' AND target = 'bob'`)
	if len(audits) != 1 {
		t.Errorf("first-factor enrollment recorded %d times, want once", len(audits))
	}
	// Single use: a second enrollment-only session (after removing the factor
	// so it may enroll again) cannot reuse it.
	if _, err := s.DisableTwoFactor(adminCtx(), &pb.DisableTwoFactorRequest{Username: "bob", Method: "totp", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	ctx2, _ := s.authenticate(bearerCtx(login(t, s, "bob", "bob-pw").Token))
	_, err = s.EnrollTOTP(ctx2, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()})
	wantCode(t, "reusing a code", err, codes.PermissionDenied)

	// Short-lived: an expired code is refused.
	code2, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob", TtlSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE user_enrollment_codes SET expires_at = '2000-01-01T00:00:00Z' WHERE username = 'bob'`); err != nil {
		t.Fatal(err)
	}
	_, err = s.EnrollTOTP(ctx2, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code2.GetCode()})
	wantCode(t, "an expired code", err, codes.PermissionDenied)
	_, err = s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob", TtlSeconds: 25 * 3600})
	wantCode(t, "a code living longer than a day", err, codes.InvalidArgument)
}

// I5: self-enrollment only through an explicit window, refused after it.
func TestI5_SelfEnrollmentWindow(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	_, err := s.SetLoginPolicy(adminCtx(), &pb.SetLoginPolicyRequest{Require_2Fa: "all", AllowSelfEnroll: true})
	wantCode(t, "self-enrollment without a deadline", err, codes.InvalidArgument)
	_, err = s.SetLoginPolicy(adminCtx(), &pb.SetLoginPolicyRequest{Require_2Fa: "all", AllowSelfEnroll: true,
		EnrollBy: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	wantCode(t, "a deadline in the past", err, codes.InvalidArgument)

	p := setPolicyFull(t, s, &pb.SetLoginPolicyRequest{Require_2Fa: "all", AllowSelfEnroll: true,
		EnrollBy: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if p.GetSelfEnrollBy() == "" {
		t.Fatalf("policy does not report the window: %+v", p)
	}
	ctx, _ := s.authenticate(bearerCtx(login(t, s, "bob", "bob-pw").Token))
	if _, err := s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone"}); err != nil {
		t.Fatalf("self-enrollment inside the window: %v", err)
	}
	// The window closes (as time would close it).
	seedUser(t, s, "carol", "operator", "carol-pw")
	if err := s.db.Execute(context.Background(), `UPDATE cluster_policies SET value = '2000-01-01T00:00:00Z' WHERE key = ?`,
		corrosion.LoginTwoFactorSelfEnrollKey); err != nil {
		t.Fatal(err)
	}
	cctx, _ := s.authenticate(bearerCtx(login(t, s, "carol", "carol-pw").Token))
	_, err = s.EnrollTOTP(cctx, &pb.EnrollTOTPRequest{Label: "phone"})
	wantCode(t, "self-enrollment after the deadline", err, codes.PermissionDenied)
	// Setting the policy again without the flag closes it.
	if p := setPolicy(t, s, "all"); p.GetSelfEnrollBy() != "" {
		t.Fatalf("re-setting without --allow-self-enroll kept the window: %+v", p)
	}
}

// C1(d): a revoke that fails during enrollment fails the enrollment, rather
// than leaving the session alive beside a fresh factor.
func TestC1_FailedRevokeFailsTheEnrollment(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setPolicy(t, s, "all")
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := s.authenticate(bearerCtx(login(t, s, "bob", "bob-pw").Token))
	orig := revokeSessionFn
	revokeSessionFn = func(context.Context, *corrosion.Client, string) error { return errors.New("disk full") }
	defer func() { revokeSessionFn = orig }()
	_, err = s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()})
	if err == nil {
		t.Fatal("enrollment succeeded although its session could not be ended")
	}
	if f, _ := corrosion.ListUser2FA(context.Background(), s.db, "bob"); len(f) != 0 {
		t.Fatalf("a factor was enrolled although the enrollment failed: %+v", f)
	}
}

// I6: the only admin, under `all`, with a lost factor, is recovered by
// reset-admin --clear-2fa and an enrollment code issued over local root.
func TestI6_OnlyAdminRecoversWithClearTwoFactor(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedUser(t, s, "admin", "admin", "old")
	if _, err := auth.EnrollTOTP(ctx, s.db, "admin", "lost-phone"); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")
	hash, _ := bcrypt.GenerateFromPassword([]byte("fresh-password-0123"), auth.BcryptCost)
	if err := corrosion.ResetAdminPassword(ctx, s.db, s.withLoginPolicy, string(hash), true); err != nil {
		t.Fatalf("ResetAdminPassword --clear-2fa: %v", err)
	}
	if f, _ := corrosion.ListUser2FA(ctx, s.db, "admin"); len(f) != 0 {
		t.Fatalf("factors left after --clear-2fa: %+v", f)
	}
	r := login(t, s, "admin", "fresh-password-0123")
	if !r.GetRequires_2FaEnrollment() {
		t.Fatalf("login after the reset: %+v, want enrollment-only", r)
	}
	localRoot := mtlsPeerCtx("test-host", tcpAddr("127.0.0.1"), "")
	lr, err := s.authenticate(localRoot)
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.IssueEnrollmentCode(lr, &pb.IssueEnrollmentCodeRequest{Username: "admin"})
	if err != nil {
		t.Fatalf("local root issuing the admin's enrollment code: %v", err)
	}
	actx, _ := s.authenticate(bearerCtx(r.Token))
	enr, err := s.EnrollTOTP(actx, &pb.EnrollTOTPRequest{Label: "new-phone", EnrollmentCode: code.GetCode()})
	if err != nil {
		t.Fatalf("enroll with the code: %v", err)
	}
	full, err := s.Login(ctx, &pb.LoginRequest{Username: "admin", Password: "fresh-password-0123", TotpCode: totpCode(t, enr.SecretBase32)})
	if err != nil || full.GetRequires_2FaEnrollment() || full.Role != "admin" {
		t.Fatalf("admin login with the new factor: %+v %v", full, err)
	}
	// Gated: with the latch closed, --clear-2fa refuses and changes nothing,
	// through the daemon's gate and with no gate at all (the daemon down).
	s.SetReleaseFeatureGate(nil)
	err = corrosion.ResetAdminPassword(ctx, s.db, s.withLoginPolicy, string(hash), true)
	if err == nil || !strings.Contains(err.Error(), loginPolicyRefusal) {
		t.Fatalf("--clear-2fa with the gate closed: %v, want %q", err, loginPolicyRefusal)
	}
	if err := corrosion.ResetAdminPassword(ctx, s.db, nil, string(hash), true); !errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
		t.Fatalf("--clear-2fa with no gate: %v, want ErrLoginPolicyGateClosed", err)
	}
	if f, _ := corrosion.ListUser2FA(ctx, s.db, "admin"); len(f) != 1 {
		t.Fatalf("--clear-2fa with the gate closed changed the factors: %+v", f)
	}
}

// m5: a covered realm this node does not have configured is warned about.
func TestM5_UnconfiguredRealmIsWarned(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "x"})
	p := setPolicy(t, s, "local,ldap:crop")
	if len(p.GetWarnings()) != 1 || !strings.Contains(p.GetWarnings()[0], "ldap:crop") {
		t.Fatalf("warnings = %v, want one naming ldap:crop", p.GetWarnings())
	}
}

// m1: ListUsers reports a status judged by the daemon's clock.
func TestM1_ListUsersStatusIsServerJudged(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	writeLifecycle(t, s, "bob", corrosion.UserAttrExpiresAt, "2000-01-01T00:00:00Z")
	resp, err := s.ListUsers(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range resp.Users {
		want := "active"
		if u.Username == "bob" {
			want = "expired"
		}
		if u.GetStatus() != want {
			t.Errorf("%s status = %q, want %q", u.Username, u.GetStatus(), want)
		}
	}
}

// I2: variant spellings share one brute-force bucket.
func TestLoginThrottleKey_Normalized(t *testing.T) {
	if loginThrottleKey("ALICE ", "10.0.0.1") != loginThrottleKey("alice", "10.0.0.1") {
		t.Fatal("ALICE and alice get separate login-throttle buckets")
	}
}

package grpcapi

// Fix round 2 of the login rules (t1-auth-rereview-1.md). The stream tests run
// the REAL ConsoleVM and ProxyVNC handlers through the real interceptor, over
// a stream whose RecvMsg is blind to every context but its own transport one —
// the way grpc-go's is — so a test passes only if the handler itself lets go
// of the console or VNC socket when the credential ends.

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// consoleVirt is libvirtfake with a real console path and VNC port.
type consoleVirt struct {
	*libvirtfake.Fake
	pty string
	vnc int
}

func (v consoleVirt) ConsolePTYPath(string) (string, error) { return v.pty, nil }
func (v consoleVirt) GetVMVNCPort(string) (int, error)      { return v.vnc, nil }

// StateReader and SecureStateReader are none: the console reads go to the
// overrides above, not to the embedded fake's own readers.
func (v consoleVirt) StateReader() *libvirt.StateReader       { return nil }
func (v consoleVirt) SecureStateReader() *libvirt.StateReader { return nil }

// transportStream is a server stream whose context is the caller's bearer
// context, and whose RecvMsg blocks until the TRANSPORT ends (transport
// closed) — never on any context derived from it, as grpc-go's does not.
type transportStream struct {
	ctx       context.Context
	transport chan struct{}
	mu        sync.Mutex
	sent      int
}

func (t *transportStream) Context() context.Context     { return t.ctx }
func (t *transportStream) SetHeader(metadata.MD) error  { return nil }
func (t *transportStream) SendHeader(metadata.MD) error { return nil }
func (t *transportStream) SetTrailer(metadata.MD)       {}
func (t *transportStream) SendMsg(any) error {
	t.mu.Lock()
	t.sent++
	t.mu.Unlock()
	return nil
}
func (t *transportStream) RecvMsg(any) error {
	<-t.transport
	return io.EOF
}

// runRealStream drives handler through the real stream interceptor and
// reports its result. The transport is ended only by the test's cleanup.
func runRealStream(t *testing.T, s *Server, token, method, vm string, handler func(grpc.ServerStream) error) (<-chan error, *transportStream) {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token, "x-vm-name", vm))
	ts := &transportStream{ctx: ctx, transport: make(chan struct{})}
	t.Cleanup(func() { close(ts.transport) })
	done := make(chan error, 1)
	go func() {
		done <- s.StreamAuthInterceptor(nil, ts, &grpc.StreamServerInfo{FullMethod: method},
			func(_ any, ss grpc.ServerStream) error { return handler(ss) })
	}()
	return done, ts
}

func consoleServer(t *testing.T) (*Server, consoleVirt) {
	t.Helper()
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	v := consoleVirt{Fake: libvirtfake.New()}
	s.virt = v
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web1", HostName: s.hostName, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return s, v
}

// N1: the real ConsoleVM, on the node that owns the VM, releases the console
// when its user is disabled — through the handler, not a context the
// interceptor alone watches.
func TestN1_RealConsoleIsCutOnDisable(t *testing.T) {
	s, v := consoleServer(t)
	fifo := filepath.Join(t.TempDir(), "console")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	v.pty = fifo
	s.virt = v
	// Keep a writer open so the console never reads EOF on its own.
	w, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	token := login(t, s, "bob", "bob-pw").Token
	handlerDone := make(chan struct{})
	done, _ := runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ConsoleVM", "web1", func(ss grpc.ServerStream) error {
		defer close(handlerDone)
		return s.ConsoleVM(&grpc.GenericServerStream[pb.ConsoleInput, pb.ConsoleOutput]{ServerStream: ss})
	})
	select {
	case err := <-done:
		t.Fatalf("the console ended before anything happened: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	setDisabled(t, s, "bob", true)
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("console ended with %v, want Unauthenticated", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the real console was still open 3s after the disable")
	}
	// The HANDLER let go of the console itself, inside the interceptor's
	// grace — not merely had its RPC ended around it.
	select {
	case <-handlerDone:
	case <-time.After(streamCutGrace / 2):
		t.Fatal("ConsoleVM was still holding the console after the cut")
	}
}

// N1: a handler blocked in the transport's RecvMsg, blind to every context,
// still has its RPC ended after the grace: the interceptor returns the cut.
func TestN1_BlindHandlerRPCIsEnded(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	token := login(t, s, "bob", "bob-pw").Token
	done, _ := runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ConsoleVM", "web1", func(ss grpc.ServerStream) error {
		var m pb.ConsoleInput
		return ss.RecvMsg(&m) // blocks until the transport ends
	})
	time.Sleep(100 * time.Millisecond)
	setDisabled(t, s, "bob", true)
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("blind handler's RPC ended with %v, want Unauthenticated", err)
		}
	case <-time.After(streamCutGrace + 2*time.Second):
		t.Fatal("a context-blind handler's RPC was never ended after the cut")
	}
}

// N1: a handler that loops on Send gets an error from the stream itself once
// the credential is cut, and returns well inside the grace.
func TestN1_SendAfterCutFails(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	token := login(t, s, "bob", "bob-pw").Token
	handlerDone := make(chan struct{})
	runRealStream(t, s, token, "/litevirt.v1.LiteVirt/StreamEvents", "", func(ss grpc.ServerStream) error {
		defer close(handlerDone)
		for {
			if err := ss.SendMsg(&pb.ClusterEvent{}); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	time.Sleep(100 * time.Millisecond)
	setDisabled(t, s, "bob", true)
	select {
	case <-handlerDone:
	case <-time.After(streamCutGrace / 2):
		t.Fatal("a Send loop kept sending after the cut")
	}
}

// N1: the real ProxyVNC releases the VNC socket when the session is revoked:
// the fake VNC server sees its connection closed.
func TestN1_RealVNCIsCutOnRevoke(t *testing.T) {
	s, v := consoleServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v.vnc = ln.Addr().(*net.TCPAddr).Port
	s.virt = v
	serverSide := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			serverSide <- c
		}
	}()
	token := login(t, s, "bob", "bob-pw").Token
	done, _ := runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ProxyVNC", "web1", func(ss grpc.ServerStream) error {
		return s.ProxyVNC(&grpc.GenericServerStream[pb.VNCData, pb.VNCData]{ServerStream: ss})
	})
	var conn net.Conn
	select {
	case conn = <-serverSide:
	case <-time.After(3 * time.Second):
		t.Fatal("ProxyVNC never connected to the VNC socket")
	}
	defer conn.Close()
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: strings.TrimPrefix(token, SessionTokenPrefix)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("VNC ended with %v, want Unauthenticated", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the real VNC proxy was still open 3s after the session was revoked")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the VNC socket was not closed by the proxy: read = %v, want EOF", err)
	}
}

// N2: deleting a user ends their open streams and revokes their sessions and
// API tokens.
// N2: a delete that arrives by replication — no local session sweep, just the
// tombstone — still ends the stream at the next recheck.
func TestN2_ReplicatedDeleteCutsStreams(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	if err := corrosion.DeleteUser(context.Background(), s.db, "bob"); err != nil {
		t.Fatal(err)
	}
	wantStreamCut(t, "a stream of a user deleted on a peer", done, 3*time.Second)
}

func TestN2_DeleteCutsStreamsAndRevokesCredentials(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = time.Hour // the delete's own kick must do it
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	token := login(t, s, "bob", "bob-pw").Token
	tok := mintAPIToken(t, s, "bob")
	done, started := openStream(s, token)
	<-started
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	wantStreamCut(t, "a deleted user's stream", done, 3*time.Second)
	ctx := context.Background()
	if rows, _ := s.db.Query(ctx, `SELECT 1 FROM sessions WHERE username = 'bob' AND revoked_at IS NULL`); len(rows) != 0 {
		t.Errorf("%d of bob's sessions are still live after the delete", len(rows))
	}
	if rows, _ := s.db.Query(ctx, `SELECT 1 FROM tokens WHERE username = 'bob' AND deleted_at IS NULL`); len(rows) != 0 {
		t.Errorf("%d of bob's API tokens are still live after the delete", len(rows))
	}
	_ = tok
}

// N3: an enrollment code is used only on the node that issued it, and the
// refusal names that node.
func TestN3_CodeIsBoundToTheIssuingNode(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setPolicy(t, s, "all")
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	// As if it had been issued on node-7 and replicated here.
	if err := s.db.Execute(context.Background(), `UPDATE user_enrollment_codes SET issued_on = 'node-7' WHERE username = 'bob'`); err != nil {
		t.Fatalf("mark the code as issued elsewhere: %v", err)
	}
	ctx, _ := s.authenticate(bearerCtx(login(t, s, "bob", "bob-pw").Token))
	_, err = s.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "node-7") {
		t.Fatalf("a code issued on node-7 used here: %v, want FailedPrecondition naming node-7", err)
	}
}

// N3: a disable, a delete or a re-create invalidates an outstanding code.
func TestN3_CodeInvalidatedByDisableDeleteRecreate(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  func(t *testing.T, s *Server)
	}{
		{"disable and re-enable", func(t *testing.T, s *Server) {
			setDisabled(t, s, "bob", true)
			setDisabled(t, s, "bob", false)
		}},
		{"delete", func(t *testing.T, s *Server) {
			if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "bob"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"re-create over a delete that left the code", func(t *testing.T, s *Server) {
			// A delete as an older build makes it: only the users row.
			if err := s.db.Execute(context.Background(), `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = 'bob'`,
				time.Now().UTC().Format(time.RFC3339), s.db.NowTS()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateUser(adminCtx(), &pb.CreateUserRequest{Username: "bob", Password: "bob-pw"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"an admin enrolls a factor for the user", func(t *testing.T, s *Server) {
			if _, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "bob", Label: "phone"}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loginPolicyServer(t)
			seedAdmins(t, s)
			seedUser(t, s, "bob", "operator", "bob-pw")
			setPolicy(t, s, "all")
			code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
			if err != nil {
				t.Fatal(err)
			}
			tc.act(t, s)
			if err := corrosion.CheckEnrollmentCode(context.Background(), s.db, "bob", code.GetCode(), s.hostName); err == nil {
				t.Fatalf("%s left the enrollment code valid", tc.name)
			}
		})
	}
}

// N3: WebAuthn Finish verifies the attestation BEFORE it spends the code or
// ends the session: a bad attestation leaves both.
func TestN3_WebAuthnBadAttestationSpendsNothing(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	svc, err := auth.NewWebAuthnService(s.db, auth.WebAuthnConfig{
		RPDisplayName: "t", RPID: "litevirt.test", RPOrigins: []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetWebAuthnService(svc)
	setPolicy(t, s, "all")
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	token := login(t, s, "bob", "bob-pw").Token
	ctx, _ := s.authenticate(bearerCtx(token))
	if _, err := s.BeginWebAuthnRegistration(ctx, &pb.BeginWebAuthnRegistrationRequest{EnrollmentCode: code.GetCode()}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	_, err = s.FinishWebAuthnRegistration(ctx, &pb.FinishWebAuthnRegistrationRequest{
		AttestationJson: []byte(`{"id":"x","rawId":"eA","type":"public-key","response":{}}`),
		EnrollmentCode:  code.GetCode(),
	})
	if err == nil {
		t.Fatal("a garbage attestation was accepted")
	}
	if _, err := s.authenticate(bearerCtx(token)); err != nil {
		t.Fatalf("the session was ended by a failed attestation: %v", err)
	}
	if err := corrosion.CheckEnrollmentCode(context.Background(), s.db, "bob", code.GetCode(), s.hostName); err != nil {
		t.Fatalf("the code was spent by a failed attestation: %v", err)
	}
}

// m-a: a session minted on a node whose clock runs ahead, before the disable
// in real time, stays dead after the re-enable (the skew margin).
func TestMA_SessionCutoffIsSkewTolerant(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setDisabled(t, s, "bob", true)
	now := time.Now().UTC()
	if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
		ID: "fast-clock", Username: "bob", Realm: "local", CreatedAt: now.Add(2 * time.Second).Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	// The re-enable's own cut-off is taken out of the picture (as if the
	// re-enable came from an older path), so only the disable's cut-off and
	// its margin can refuse the session.
	writeLifecycle(t, s, "bob", corrosion.UserAttrDisabled, "false")
	_, err := s.authenticate(bearerCtx(SessionTokenPrefix + "fast-clock"))
	wantCode(t, "a session minted 2s 'after' the disable by a clock running ahead", err, codes.Unauthenticated)
}

// m-a: the re-enable is itself a cut-off. A session minted after the disable
// instant — beyond its margin — on a node the disable had not reached (so the
// disabling node's sweep never saw it) does not revive with the re-enable.
func TestMA_ReEnableIsACutoff(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setDisabled(t, s, "bob", true)
	now := time.Now().UTC()
	// The disable happened 30s ago, as the replica holds it.
	writeLifecycle(t, s, "bob", corrosion.UserAttrSessionsNotBefore, now.Add(-30*time.Second).Format(time.RFC3339))
	if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
		ID: "lagging", Username: "bob", Realm: "local", CreatedAt: now.Add(-10 * time.Second).Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	setDisabled(t, s, "bob", false)
	_, err := s.authenticate(bearerCtx(SessionTokenPrefix + "lagging"))
	wantCode(t, "a session minted where the disable had not arrived, after the re-enable", err, codes.Unauthenticated)
}

// m-c: a delegated revoke leaves at most one sentinel per principal and path.
func TestMC_SentinelsAreDeduplicated(t *testing.T) {
	s := delegationServer(t)
	for i := 0; i < 3; i++ {
		r, err := s.GrantRole(patCtx(), &pb.GrantRoleRequest{Path: "/projects/acme/vms/web", Role: "VMOperator",
			Principal: "user:carol@local", Propagate: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: r.Binding.Id}); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.db.Query(context.Background(),
		`SELECT id FROM role_bindings WHERE principal = 'user:carol@local' AND role = 'NoAccess' AND deleted_at IS NULL`)
	if len(rows) != 1 {
		t.Fatalf("%d NoAccess sentinels after three grant/revoke cycles at one path, want 1", len(rows))
	}
}

// m-d: duplicate accounts have an exit: an exact-name delete.
func TestMD_ExactDeleteResolvesADuplicate(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "pw1")
	seedUser(t, s, "Bob", "viewer", "pw2")
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "Bob"}); err == nil {
		t.Fatal("a normalized delete chose one of two duplicates")
	}
	stored, err := corrosion.GetUserExact(context.Background(), s.db, "Bob")
	if err != nil || stored == nil {
		t.Fatalf("GetUserExact(Bob): %v %v", stored, err)
	}
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "Bob", Exact: true,
		ExactId: corrosion.VariantID(stored.Username, stored.CreatedAt)}); err != nil {
		t.Fatalf("exact delete of Bob: %v", err)
	}
	if r := login(t, s, "bob", "pw1"); r.Token == "" {
		t.Fatal("bob cannot log in after the duplicate was removed")
	}
	rows, _ := s.db.Query(context.Background(), `SELECT 1 FROM audit_log WHERE action = 'user.delete' AND target = 'Bob' AND detail LIKE '%exact%'`)
	if len(rows) != 1 {
		t.Errorf("the exact delete was audited %d times, want once, marked exact", len(rows))
	}
}

// m-d: an API token of one of two duplicate accounts is refused like every
// other lookup of them.
func TestMD_TokenOfADuplicateIsRefused(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "alice", "operator", "pw")
	tok := mintAPIToken(t, s, "alice")
	seedUser(t, s, "ALICE", "operator", "pw")
	_, err := s.authenticate(bearerCtx(tok))
	if err == nil {
		t.Fatal("an API token of a duplicated account authenticated")
	}
}

// m-d: a directory login after a legacy mixed-case shadow was disabled and
// deleted reactivates THAT row (and its disable), not a fresh one.
func TestMD_LegacyVariantTombstoneKeepsItsDisable(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "bob"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "Bob", "viewer", ""); err != nil { // legacy spelling
		t.Fatal(err)
	}
	writeLifecycle(t, s, "Bob", corrosion.UserAttrDisabled, "true")
	if err := corrosion.DeleteUser(ctx, s.db, "Bob"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "x", Realm: "ldap:corp"})
	wantCode(t, "directory login over a disabled, deleted legacy-spelled shadow", err, codes.Unauthenticated)
}

// m-e: a recheck that cannot complete within its timeout ends the stream —
// it does not wait forever on a stuck replica.
func TestME_StuckRecheckCutsTheStream(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedUser(t, s, "bob", "operator", "bob-pw")
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	// Stuck the way a query behind a held lock is: deaf to its context.
	release := make(chan struct{})
	defer close(release)
	hook := func(context.Context) error { <-release; return nil }
	recheckHook.Store(&hook)
	defer recheckHook.Store(nil)
	wantStreamCut(t, "a stream whose recheck hangs", done, 3*time.Second)
}

package grpcapi

// Fix round 3 of the login rules (t1-auth-rereview-2.md).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// idRealm authenticates any password as subject, carrying a directory id.
type idRealm struct {
	name, subject string
	id            *atomic.Value // string
}

func (r idRealm) Name() string { return r.name }
func (r idRealm) Authenticate(_ context.Context, c auth.Credentials) (*auth.Principal, error) {
	if c.Password == "" && c.OIDCCode == "" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Principal{Subject: r.subject, Realm: r.name, ExternalID: r.id.Load().(string)}, nil
}
func (idRealm) SyncGroups(context.Context) error { return nil }

func newIDRealm(name, subject, id string) idRealm {
	v := &atomic.Value{}
	v.Store(id)
	return idRealm{name: name, subject: subject, id: v}
}

// N5: the first login after the upgrade binds the account to the directory
// entry's immutable id; a later login through an entry with another id is
// refused with PermissionDenied and audited; and an id already bound to one
// account cannot log in as another.
func TestN5_AccountIsBoundToTheDirectoryEntry(t *testing.T) {
	r := newIDRealm("ldap:corp", "alice", "entryUUID:u-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	login := func() error {
		_, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"})
		return err
	}
	if err := login(); err != nil {
		t.Fatalf("first login: %v", err)
	}
	if err := login(); err != nil {
		t.Fatalf("second login through the same entry: %v", err)
	}
	r.id.Store("entryUUID:u-2") // a different entry now answers to "alice"
	err := login()
	wantCode(t, "a login through another directory entry", err, codes.PermissionDenied)
	rows, _ := s.db.Query(ctx, `SELECT 1 FROM audit_log WHERE action = 'auth.identity_mismatch' AND target = 'alice'`)
	if len(rows) == 0 {
		t.Error("the identity mismatch was not audited")
	}
	// An admin clears the binding (the entry was re-created); the next login
	// binds afresh.
	if _, err := s.ClearIdentityBinding(adminCtx(), &pb.ClearIdentityBindingRequest{Username: "alice", Realm: "ldap:corp"}); err != nil {
		t.Fatalf("ClearIdentityBinding: %v", err)
	}
	if err := login(); err != nil {
		t.Fatalf("login after the binding was cleared: %v", err)
	}
}

// N5: one directory entry cannot be two accounts.
func TestN5_OneEntryCannotBindTwoAccounts(t *testing.T) {
	r1 := newIDRealm("ldap:corp", "alice", "entryUUID:u-1")
	s := policyRealmServer(t, r1)
	seedAdmins(t, s)
	ctx := context.Background()
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"}); err != nil {
		t.Fatal(err)
	}
	// The same entry, now reached under another name (a second uid value).
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	reg.Register(newIDRealm("ldap:corp", "x2", "entryUUID:u-1"))
	s.realmRegistry = reg
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "x2", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "a second account for an entry already bound", err, codes.PermissionDenied)
	// Refused before the shadow: the refused login created no account.
	if u, _ := corrosion.GetUser(ctx, s.db, "x2"); u != nil {
		t.Fatalf("a refused login through a bound entry created the account %q", u.Username)
	}
}

// N5: OIDC binds (issuer, sub) the same way.
func TestN5_OIDCBindsIssuerAndSub(t *testing.T) {
	r := newIDRealm("oidc:okta", "olga", "https://issuer.example|sub-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	req := &pb.LoginRequest{Realm: "oidc:okta", OidcCode: "c", OidcState: "s"}
	if _, err := s.Login(ctx, req); err != nil {
		t.Fatal(err)
	}
	r.id.Store("https://issuer.example|sub-2")
	_, err := s.Login(ctx, req)
	wantCode(t, "an OIDC login with another sub for the same name", err, codes.PermissionDenied)
}

// N6: a session minted for a deleted spelling never authenticates as the
// account that survives under another spelling — on any path.
func TestN6_SessionOfADeletedSpellingIsRefused(t *testing.T) {
	s := loginPolicyServer(t)
	s.SetForwardedIdentity(true)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Sessions of the deleted spelling "Bob", minted on a node this one did
	// not hear the delete from, arriving now. One per path: the direct path
	// revokes what it refuses, which would hide the forwarded path's verdict.
	for _, id := range []string{"old-Bob-direct", "old-Bob-fwd"} {
		if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
			ID: id, Username: "Bob", Realm: "local", CreatedAt: now.Format(time.RFC3339),
			LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name string
		ctx  context.Context
	}{
		{"forwarded session", withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+SessionTokenPrefix+"old-Bob-fwd")},
		{"session", bearerCtx(SessionTokenPrefix + "old-Bob-direct")},
	} {
		got, err := s.authenticate(c.ctx)
		if err == nil {
			t.Fatalf("%s of the deleted spelling Bob authenticated as %q", c.name, callerUsername(got))
		}
	}
}

// N6: an open stream of a spelling that is then deleted ends, even though a
// normalized lookup now finds the surviving spelling.
func TestN6_StreamOfADeletedSpellingIsCut(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "Bob", "operator", "pw")
	done, started := openStream(s, login(t, s, "Bob", "pw").Token)
	<-started
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "bob", "operator", "x"); err != nil {
		t.Fatal(err)
	}
	// Bob is deleted without its sessions being revoked here.
	if err := s.db.Execute(ctx, `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = 'Bob'`,
		time.Now().UTC().Format(time.RFC3339), s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	wantStreamCut(t, "a stream of a deleted spelling", done, 3*time.Second)
}

// N6 / m-4: the delete's revocations are part of the delete's own batch, and
// it writes durable session and token cut-offs: a token whose revoke never
// reached a node does not come back when the name is re-created.
func TestM4_TokenOfADeletedNameDoesNotComeBack(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	tok := mintAPIToken(t, s, "bob")
	ctx := context.Background()
	// A delete as a node that never held the token row makes it: no token
	// revoke reaches this one.
	if err := s.db.Execute(ctx, `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = 'bob'`,
		time.Now().UTC().Format(time.RFC3339), s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := s.CreateUser(adminCtx(), &pb.CreateUserRequest{Username: "bob", Password: "pw2"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "an old token after the name was re-created", err, codes.Unauthenticated)
}

// m-3: reset-admin's re-enable is a session cut-off like any other.
func TestM3_ResetAdminReEnableIsACutoff(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "admin", "admin", "old")
	writeLifecycle(t, s, "admin", corrosion.UserAttrDisabled, "true")
	now := time.Now().UTC()
	writeLifecycle(t, s, "admin", corrosion.UserAttrSessionsNotBefore, now.Add(-30*time.Second).Format(time.RFC3339))
	if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
		ID: "lagging-admin", Username: "admin", Realm: "local", CreatedAt: now.Add(-10 * time.Second).Format(time.RFC3339),
		LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ResetAdminPassword(context.Background(), s.db, s.withLoginPolicy, mustHash(t, "fresh-pw-0123456789"), false); err != nil {
		t.Fatal(err)
	}
	_, err := s.authenticate(bearerCtx(SessionTokenPrefix + "lagging-admin"))
	wantCode(t, "a session from before reset-admin's re-enable", err, codes.Unauthenticated)
}

// m-3: a login inside the cut-off margin is refused BEFORE the second factor
// is checked, so it does not use up the TOTP step.
func TestM3_MarginRefusalSpendsNoTOTPStep(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	enr, err := auth.EnrollTOTP(context.Background(), s.db, "bob", "phone")
	if err != nil {
		t.Fatal(err)
	}
	setDisabled(t, s, "bob", false) // a change: the margin starts now
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw", TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "a login inside the margin", err, codes.Unavailable)
	f, _ := corrosion.ListUser2FA(context.Background(), s.db, "bob")
	if len(f) != 1 || f[0].LastStep != 0 {
		t.Fatalf("the refused login used up a TOTP step: %+v", f)
	}
}

// m-5: an issued code says which node it is bound to.
func TestM5_IssuedCodeNamesItsNode(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	r, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil || r.GetIssuedOn() != s.hostName {
		t.Fatalf("IssueEnrollmentCode: issued_on=%q err=%v, want %q", r.GetIssuedOn(), err, s.hostName)
	}
}

// m-6: an admin registering a security key for a user voids the user's
// outstanding enrollment code, as an admin enrolling TOTP does. The
// attestation is a real (format "none") one, so the real verification runs.
func TestM6_AdminWebAuthnRegistrationVoidsTheCode(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	svc, err := auth.NewWebAuthnService(s.db, auth.WebAuthnConfig{
		RPDisplayName: "t", RPID: "litevirt.test", RPOrigins: []string{"https://litevirt.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetWebAuthnService(svc)
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	begin, err := s.BeginWebAuthnRegistration(adminCtx(), &pb.BeginWebAuthnRegistrationRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	att := noneAttestation(t, begin.OptionsJson, "litevirt.test", "https://litevirt.test")
	if _, err := s.FinishWebAuthnRegistration(adminCtx(), &pb.FinishWebAuthnRegistrationRequest{Username: "bob", AttestationJson: att}); err != nil {
		t.Fatalf("admin registration of bob's key: %v", err)
	}
	if err := corrosion.CheckEnrollmentCode(context.Background(), s.db, "bob", code.GetCode(), s.hostName); err == nil {
		t.Fatal("an admin registering a security key left the user's enrollment code valid")
	}
}

// noneAttestation builds a real WebAuthn registration response, attestation
// format "none", over a fresh P-256 key, for the challenge in optionsJSON.
func noneAttestation(t *testing.T, optionsJSON []byte, rpID, origin string) []byte {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		t.Fatalf("options: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	bstr := func(b []byte) []byte {
		switch {
		case len(b) < 24:
			return append([]byte{0x40 | byte(len(b))}, b...)
		case len(b) < 256:
			return append([]byte{0x58, byte(len(b))}, b...)
		default:
			return append([]byte{0x59, byte(len(b) >> 8), byte(len(b))}, b...)
		}
	}
	text := func(s string) []byte { return append([]byte{0x60 | byte(len(s))}, s...) }
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01}
	cose = append(cose, 0x21)
	cose = append(cose, bstr(pad(key.X.Bytes()))...)
	cose = append(cose, 0x22)
	cose = append(cose, bstr(pad(key.Y.Bytes()))...)
	credID := make([]byte, 16)
	_, _ = rand.Read(credID)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45) // UP | UV | AT
	authData = append(authData, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(credID)))
	authData = append(authData, l...)
	authData = append(authData, credID...)
	authData = append(authData, cose...)
	attObj := []byte{0xa3}
	attObj = append(attObj, text("fmt")...)
	attObj = append(attObj, text("none")...)
	attObj = append(attObj, text("attStmt")...)
	attObj = append(attObj, 0xa0)
	attObj = append(attObj, text("authData")...)
	attObj = append(attObj, bstr(authData)...)
	clientData, _ := json.Marshal(map[string]string{
		"type": "webauthn.create", "challenge": opts.PublicKey.Challenge, "origin": origin,
	})
	b64 := base64.RawURLEncoding.EncodeToString
	out, _ := json.Marshal(map[string]any{
		"id": b64(credID), "rawId": b64(credID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(clientData), "attestationObject": b64(attObj)},
	})
	return out
}

// m-7: an exact delete shows the operator both accounts and acts only on the
// one chosen by id.
func TestM7_ExactDeleteChoosesByID(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "pw1")
	seedUser(t, s, "Bob", "operator", "pw2")
	v, err := s.ListUserVariants(adminCtx(), &pb.ListUserVariantsRequest{Username: "bob"})
	if err != nil || len(v.Variants) != 2 {
		t.Fatalf("ListUserVariants: %+v %v, want both spellings", v, err)
	}
	var target *pb.UserVariant
	for _, x := range v.Variants {
		if x.Username == "Bob" {
			target = x
		}
		if x.Id == "" || x.CreatedAt == "" || x.Role == "" {
			t.Errorf("variant %+v lacks what an operator chooses by", x)
		}
	}
	_, err = s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "Bob", Exact: true})
	wantCode(t, "an exact delete without the chosen id", err, codes.InvalidArgument)
	_, err = s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "Bob", Exact: true, ExactId: "deadbeefdead"})
	wantCode(t, "an exact delete with the wrong id", err, codes.FailedPrecondition)
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "Bob", Exact: true, ExactId: target.Id}); err != nil {
		t.Fatalf("exact delete by id: %v", err)
	}
}

// m-7: an admin that is one of an ambiguous pair cannot log in, so it does not
// count as the admin that remains.
func TestM7_AmbiguousAdminIsNotTheOneThatRemains(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "alice", "admin", "pw")
	seedUser(t, s, "root2", "admin", "pw")
	seedUser(t, s, "ROOT2", "admin", "pw")
	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
	wantCode(t, "deleting the only unambiguous admin", err, codes.FailedPrecondition)
}

// m-1: one recheck that fails does not end the stream; a credential that
// stays unknown past the bound does.
func TestM1_OneFailedRecheckIsRetried(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	// The fail-closed bound is measured on a clock that stands still here:
	// what is pinned is that one failure is retried, not how late this host
	// fires the retry's timer. On the wall clock a loaded host used up the
	// 125 ms bound before the retry ran, and cut the stream.
	frozen := time.Now()
	s.streamClock = func() time.Time { return frozen }
	seedUser(t, s, "bob", "operator", "bob-pw")
	done, started := openStream(s, login(t, s, "bob", "bob-pw").Token)
	<-started
	var calls atomic.Int32
	hook := func(context.Context) error {
		if calls.Add(1) == 1 {
			return errors.New("transient")
		}
		return nil
	}
	recheckHook.Store(&hook)
	defer recheckHook.Store(nil)
	deadline := time.After(30 * time.Second)
	for calls.Load() < 3 {
		select {
		case err := <-done:
			t.Fatalf("one failed recheck ended the stream: %v", err)
		case <-deadline:
			t.Fatalf("only %d rechecks ran in 30 s", calls.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatalf("one failed recheck ended the stream: %v", err)
	default:
	}
}

// m-2: every streaming RPC of the service is in the reviewed audit of what it
// holds open, so a new one cannot be added without saying how a cut releases it.
func TestM2_EveryStreamingRPCIsAudited(t *testing.T) {
	for _, problem := range streamAuditProblems(streamHandlerAudit) {
		t.Error(problem)
	}
}

func streamAuditProblems(audit map[string]string) []string {
	desc := pb.LiteVirt_ServiceDesc
	var problems []string
	for _, sd := range desc.Streams {
		full := "/" + desc.ServiceName + "/" + sd.StreamName
		if strings.TrimSpace(audit[full]) == "" {
			problems = append(problems, "streaming RPC "+sd.StreamName+" is not in streamHandlerAudit")
		}
	}
	for name := range audit {
		found := false
		for _, sd := range desc.Streams {
			if "/"+desc.ServiceName+"/"+sd.StreamName == name {
				found = true
			}
		}
		if !found {
			problems = append(problems, "streamHandlerAudit lists "+name+", which is not a streaming RPC")
		}
	}
	return problems
}

func TestM2_StreamAuditRejectsMissingAndUnknownMethods(t *testing.T) {
	const export = "/litevirt.v1.LiteVirt/ExportAutomationSource"
	for _, mode := range []string{"missing-export", "blank-export", "unknown-stream"} {
		t.Run(mode, func(t *testing.T) {
			audit := make(map[string]string, len(streamHandlerAudit))
			for k, v := range streamHandlerAudit {
				audit[k] = v
			}
			want := "streaming RPC ExportAutomationSource is not in streamHandlerAudit"
			switch mode {
			case "missing-export":
				delete(audit, export)
			case "blank-export":
				audit[export] = " \t"
			case "unknown-stream":
				audit["/litevirt.v1.LiteVirt/UnreviewedStream"] = "not a real descriptor"
				want = "streamHandlerAudit lists /litevirt.v1.LiteVirt/UnreviewedStream, which is not a streaming RPC"
			}
			got := streamAuditProblems(audit)
			if len(got) != 1 || got[0] != want {
				t.Fatalf("audit failed to classify %s: %v, want %q", mode, got, want)
			}
		})
	}
}

// m-2: a closer a handler registers runs at the cut, before the grace — the
// device is released even by a handler that ignores its context.
func TestM2_RegisteredCloserRunsAtTheCut(t *testing.T) {
	s := loginPolicyServer(t)
	s.streamRecheckEvery = 50 * time.Millisecond
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	closed := make(chan struct{})
	token := login(t, s, "bob", "bob-pw").Token
	runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ConsoleVM", "", func(ss grpc.ServerStream) error {
		registerStreamCloser(ss.Context(), func() { close(closed) })
		var m pb.ConsoleInput
		return ss.RecvMsg(&m) // blind: never looks at its context
	})
	time.Sleep(100 * time.Millisecond)
	setDisabled(t, s, "bob", true)
	select {
	case <-closed:
	case <-time.After(streamCutGrace / 2):
		t.Fatal("the registered closer did not run at the cut")
	}
}

var _ = status.Code

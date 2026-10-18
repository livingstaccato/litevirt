package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Consumer fixture only: hand-signed retained history, with an explicit generic
// authority/adoption seed. No fresh business Accept or projection insertion.
func automationLoginServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	c, err := corrosion.NewLocalClient(t.TempDir(), "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	s.db, s.hostName = c, "a"
	seedUser(t, s, "alice", "viewer", "correct-password")
	evidence, err := corrosion.AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	members := []corrosion.VoterMember{{Name: "a", Incarnation: inc}, {Name: "b", Incarnation: "b-inc"}, {Name: "c", Incarnation: "c-inc"}}
	var signers []*corrosion.ClaimSigner
	for _, name := range []string{"a", "b"} {
		vd := filepath.Join(dir, name)
		if err := os.Mkdir(vd, 0700); err != nil {
			t.Fatal(err)
		}
		ca, err := os.ReadFile(caCert)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vd, "ca.crt"), ca, 0600); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(vd, "host.crt"), filepath.Join(vd, "host.key"), name, net.ParseIP("127.0.0.1")); err != nil {
			t.Fatal(err)
		}
		signer, err := corrosion.LoadClaimSigner(vd, name)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	verifier, err := corrosion.LoadClaimVerifier(dir)
	if err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	if err := corrosion.WriteVoterConfig(ctx, c, corrosion.VoterConfigValue{Generation: 1, Members: members, Change: corrosion.VoterChangeGenesis, CreatedBy: "fixture", CreatedAt: "fixture"}, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, c, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO local_automation_authority(id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES(1,1,?,?, 'fixture','initialize','test-only:login-consumer')`, corrosion.MembersHash(members), inc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	apply := func(d contract.Decision) string {
		t.Helper()
		encoded, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: encoded}}
		key, err := corrosion.AutomationClaimKey(d.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		ballot := corrosion.Ballot{Round: 2, Coordinator: "a", Nonce: []byte{1}}
		r := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
		for i, signer := range signers {
			signed, err := signer.Sign(key, 1, ballot, value.MustDigest(), members[i].Incarnation)
			if err != nil {
				t.Fatal(err)
			}
			r.Certificate.Accepts = append(r.Certificate.Accepts, signed)
		}
		if err := verifier.Verify(r.Certificate, corrosion.CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: members, Quorum: 2}); err != nil {
			t.Fatal(err)
		}
		if receipt, err := c.AutomationApply(ctx, r, verifier, contract.Reduce); err != nil || receipt.Code != "" {
			t.Fatalf("certified history: %+v %v", receipt, err)
		}
		return value.MustDigest()
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "initialize-op", RecordedAt: "2026-10-17T00:00:00Z"})
	parent := apply(contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", PrincipalID: "fixture", RequestID: "initialize", Body: []byte(`{"version":1}`)}, Assignment: assignment})
	body, _ := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: "principal", Alias: "alice", Witness: evidence.Witness, EvidenceID: "closed-cutover"})
	assignment, _ = json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "principal-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "principal-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "closed-cutover", ClusterUID: "established-cluster", Kind: "principal", Alias: "alice", Witness: evidence.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	apply(contract.Decision{Sequence: 2, ParentDigest: parent, Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: "principal-request", Body: body}, Assignment: assignment})
	head, err := c.AutomationHead(ctx)
	if err != nil || head.Sequence != 2 {
		t.Fatalf("retained head: %+v %v", head, err)
	}
	rows, err := c.Query(ctx, `SELECT uid,cluster_uid,witness FROM local_automation_identities WHERE stage='' AND kind='principal' AND alias='alice' AND retired=0`)
	if err != nil || len(rows) != 1 || rows[0].String("uid") != "principal-uid" || rows[0].String("witness") != evidence.Witness {
		t.Fatalf("certified projection: %+v %v", rows, err)
	}
	return s
}

// Removing Login's composite issuance must lose the committed provenance.
func TestAutomationIdentityLoginSessionCarriesCertifiedPrincipal(t *testing.T) {
	s := automationLoginServer(t)
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password"})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := corrosion.AutomationSessionPrincipal(context.Background(), s.db, strings.TrimPrefix(resp.Token, SessionTokenPrefix))
	if err != nil {
		t.Fatalf("real Login returned an unstamped session: %v", err)
	}
	if principal.UID != "principal-uid" || principal.ClusterUID != "established-cluster" {
		t.Fatalf("wrong certified identity: %+v", principal)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+resp.Token))
	ctx, err = s.authenticate(ctx)
	if err != nil || callerUsername(ctx) != "alice" {
		t.Fatalf("real bearer: %v", err)
	}
	if p, ok := callerAutomationPrincipal(ctx); !ok || p.principalUID != "principal-uid" || p.clusterUID != "established-cluster" {
		t.Fatalf("private certified principal: %+v %v", p, ok)
	}
	if err := s.RequirePerm(ctx, "/vms/blocked", "vm.create", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("certification bypassed permissions: %v", err)
	}
	seedUser(t, s, "ordinary", "viewer", "password")
	ordinary, err := s.Login(context.Background(), &pb.LoginRequest{Username: "ordinary", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = s.authenticate(bearerCtx(ordinary.Token))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := callerAutomationPrincipal(ctx); ok {
		t.Fatal("ordinary birth gained certified authority")
	}
}

func automationLoginSQL(t *testing.T, s *Server, query string, args ...interface{}) {
	t.Helper()
	// Negative storage/trigger setup uses the existing test DB handle. Positive
	// certified history above still uses ExecuteLocal and AutomationApply.
	if _, err := s.db.DB().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func automationLogin(t *testing.T, s *Server) *pb.LoginResponse {
	t.Helper()
	r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAutomationIdentityLoginSessionClassifiesMalformedRetainedProof(t *testing.T) {
	for _, mode := range []string{"semantic-head", "anchor-digest", "retained-outer", "retained-inner", "retained-digest", "semantic-storage", "retained-storage", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s := automationLoginServer(t)
			old := automationLogin(t, s)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			corrupt := true
			switch mode {
			case "semantic-head":
				automationLoginSQL(t, s, `UPDATE local_automation_semantic_heads SET digest='' WHERE stage=''`)
			case "anchor-digest":
				automationLoginSQL(t, s, `UPDATE local_automation_anchors SET digest=? WHERE sequence=2`, strings.Repeat("f", 64))
			case "retained-outer":
				automationLoginSQL(t, s, `UPDATE local_automation_history SET value_json='{' WHERE sequence=2`)
			case "retained-inner":
				raw, err := json.Marshal(corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: []byte(`{}`)}})
				if err != nil {
					t.Fatal(err)
				}
				automationLoginSQL(t, s, `UPDATE local_automation_history SET value_json=? WHERE sequence=2`, string(raw))
			case "retained-digest":
				automationLoginSQL(t, s, `UPDATE local_automation_history SET digest=? WHERE sequence=2`, strings.Repeat("f", 64))
				automationLoginSQL(t, s, `UPDATE local_automation_anchors SET digest=? WHERE sequence=2`, strings.Repeat("f", 64))
			case "semantic-storage":
				corrupt = false
				automationLoginSQL(t, s, `DROP TABLE local_automation_semantic_heads`)
			case "retained-storage":
				corrupt = false
				automationLoginSQL(t, s, `DROP TABLE local_automation_anchors`)
			case "canceled":
				corrupt = false
				cancel()
			}
			a, d, err := corrosion.PrepareAutomationLocalSession(ctx, s.db, "alice", "correct-password")
			if a != nil || d != corrosion.AutomationCredentialUnknown || err == nil {
				t.Fatalf("failed proof became eligible/absent: %v %v %v", a, d, err)
			}
			var failure *corrosion.AutomationCredentialError
			typed := errors.As(err, &failure)
			if typed != corrupt || typed && failure.Kind != corrosion.AutomationCredentialProofInvalid {
				t.Errorf("preparation corruption=%v classification=%T %v", corrupt, err, err)
			}
			if mode == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("preparation lost cancellation: %v", err)
				}
				_, err = corrosion.AutomationSessionPrincipal(ctx, s.db, strings.TrimPrefix(old.Token, SessionTokenPrefix))
				if !errors.Is(err, context.Canceled) || errors.As(err, &failure) || status.Code(automationCredentialUnavailable(err)) != codes.Canceled {
					t.Errorf("provenance lost real cancellation: %T %v", err, err)
				}
				return
			}
			response, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"})
			if response != nil || status.Code(err) != codes.Unavailable {
				t.Errorf("invalid proof Login: %v %v", response, err)
			}
			want := codes.Unavailable
			if corrupt {
				want = codes.Unauthenticated
			}
			authenticated, err := s.authenticate(bearerCtx(old.Token))
			if status.Code(err) != want {
				t.Errorf("existing bearer status=%v want=%v", status.Code(err), want)
			}
			if _, ok := callerAutomationPrincipal(authenticated); ok {
				t.Error("invalid proof retained private authority")
			}
		})
	}
}

// Interpose only after the real LocalRealm verified the supplied credentials;
// never substitute a successful authentication result or production hook.
type automationAfterPasswordRealm struct {
	auth.Realm
	after func()
}

func (r automationAfterPasswordRealm) Authenticate(ctx context.Context, creds auth.Credentials) (*auth.Principal, error) {
	p, err := r.Realm.Authenticate(ctx, creds)
	if err == nil {
		r.after()
	}
	return p, err
}

func TestAutomationIdentityLoginSessionRejectsUnenrolledOrRecreatedPrincipal(t *testing.T) {
	for _, mode := range []string{"no-lifetime", "stale-witness", "recreated", "uid-mismatch", "invalid-stamp", "replica-no-stamp", "malformed-projection", "storage-failure"} {
		t.Run(mode, func(t *testing.T) {
			s := automationLoginServer(t)
			old := automationLogin(t, s)
			switch mode {
			case "no-lifetime":
				automationLoginSQL(t, s, `DELETE FROM local_automation_lifetimes WHERE name='alice'`)
			case "stale-witness":
				automationLoginSQL(t, s, `UPDATE local_automation_identities SET witness='stale' WHERE uid='principal-uid'`)
			case "recreated":
				if err := corrosion.DeleteUser(context.Background(), s.db, "alice"); err != nil {
					t.Fatal(err)
				}
				seedUser(t, s, "alice", "viewer", "correct-password")
			case "uid-mismatch":
				automationLoginSQL(t, s, `UPDATE local_automation_aliases SET uid='other-uid' WHERE alias='alice'`)
			case "invalid-stamp":
				automationLoginSQL(t, s, `UPDATE local_automation_credential_issuance SET valid=0`)
			case "replica-no-stamp":
				automationLoginSQL(t, s, `DELETE FROM local_automation_credential_issuance`)
			case "malformed-projection":
				automationLoginSQL(t, s, `UPDATE local_automation_semantic_heads SET digest='corrupt' WHERE stage=''`)
			case "storage-failure":
				automationLoginSQL(t, s, `DROP TABLE local_automation_credential_issuance`)
			}
			ctx, err := s.authenticate(bearerCtx(old.Token))
			if mode == "replica-no-stamp" {
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := callerAutomationPrincipal(ctx); ok {
					t.Fatal("replica invented provenance")
				}
			} else if mode == "storage-failure" {
				if status.Code(err) != codes.Unavailable {
					t.Fatalf("storage error became legacy/no-proof: %v", err)
				}
			} else if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("stale bearer not refused: %v", err)
			}
			if mode == "invalid-stamp" || mode == "replica-no-stamp" || mode == "storage-failure" {
				return
			}
			r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password"})
			if mode == "no-lifetime" {
				if err != nil {
					t.Fatal(err)
				}
				ctx, err := s.authenticate(bearerCtx(r.Token))
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := callerAutomationPrincipal(ctx); ok {
					t.Fatal("missing local lifetime invented authority")
				}
			} else if status.Code(err) != codes.Unavailable || r != nil {
				t.Fatalf("invalid present proof fell back to Login: %+v %v", r, err)
			}
		})
	}
}

func TestAutomationIdentityLoginSessionRechecksIssuanceTransaction(t *testing.T) {
	for _, mode := range []string{"common-mint-disappeared", "common-mint-ambiguous", "common-mint-unreadable", "common-mint-canceled"} {
		t.Run(mode, func(t *testing.T) {
			s := automationLoginServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, d, err := corrosion.PrepareAutomationLocalSession(ctx, s.db, "alice", "correct-password")
			if err != nil || d != corrosion.AutomationCredentialEligible {
				t.Fatalf("prepare actual account: %v %v", d, err)
			}
			want := codes.Unavailable
			switch mode {
			case "common-mint-disappeared":
				if err := corrosion.DeleteUser(ctx, s.db, "alice"); err != nil {
					t.Fatal(err)
				}
			case "common-mint-ambiguous":
				seedUser(t, s, "ALICE", "viewer", "correct-password")
			case "common-mint-unreadable":
				automationLoginSQL(t, s, `DROP TABLE user_credentials`)
			case "common-mint-canceled":
				cancel()
				want = codes.Canceled
			}
			token, _, _, err := s.mintSessionWithAuthentication(ctx, "alice", "local", "", "", "", nil, a)
			if token != "" || status.Code(err) != want {
				t.Fatalf("eligible common mint: token=%q status=%v want=%v", token, status.Code(err), want)
			}
			rows, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM sessions`)
			if err != nil || rows[0].Int64("n") != 0 {
				t.Fatalf("common mint change stored credential: %v %v", rows, err)
			}
		})
	}
	for _, mode := range []string{"ambiguous-after-auth", "unreadable-after-auth", "canceled-after-auth", "disappeared-after-auth"} {
		t.Run(mode, func(t *testing.T) {
			s := automationLoginServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := codes.Unavailable
			if mode == "canceled-after-auth" {
				want = codes.Canceled
			}
			s.realmRegistry = auth.NewRegistry()
			s.realmRegistry.Register(automationAfterPasswordRealm{Realm: auth.NewLocalRealm(s.db), after: func() {
				switch mode {
				case "ambiguous-after-auth":
					seedUser(t, s, "ALICE", "viewer", "correct-password")
				case "unreadable-after-auth":
					automationLoginSQL(t, s, `DROP TABLE user_credentials`)
				case "canceled-after-auth":
					cancel()
				case "disappeared-after-auth":
					if err := corrosion.DeleteUser(context.Background(), s.db, "alice"); err != nil {
						t.Fatal(err)
					}
				}
			}})
			r, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"})
			if r != nil || status.Code(err) != want {
				t.Fatalf("post-auth account change: response=%v status=%v want=%v", r, status.Code(err), want)
			}
			rows, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM sessions`)
			if err != nil || rows[0].Int64("n") != 0 {
				t.Fatalf("post-auth change minted credential: %v %v", rows, err)
			}
		})
	}
	for name, change := range map[string]string{
		"parent":     `UPDATE users SET updated_at='changed' WHERE username=NEW.username;`,
		"uid":        `UPDATE local_automation_identities SET uid='other' WHERE alias=NEW.username; UPDATE local_automation_aliases SET uid='other' WHERE alias=NEW.username;`,
		"projection": `UPDATE local_automation_semantic_heads SET digest='corrupt';`,
		"factor":     `INSERT INTO user_2fa_sets(username,active_epoch,updated_at) VALUES(NEW.username,'new','fixture'); INSERT INTO user_2fa(username,method,secret,enrolled_at,updated_at,epoch) VALUES(NEW.username,'totp','secret','fixture','fixture','new');`,
		"policy":     `INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES('login_2fa_required','all','fixture','fixture');`,
		"cutoff":     `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES(NEW.username,'sessions_not_before','2099-01-01T00:00:00Z','fixture','fixture');`,
	} {
		t.Run(name, func(t *testing.T) {
			s := automationLoginServer(t)
			before, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM mutation_log`)
			if err != nil {
				t.Fatal(err)
			}
			automationLoginSQL(t, s, `CREATE TRIGGER change_during_login AFTER INSERT ON sessions BEGIN `+change+` END`)
			r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password"})
			if status.Code(err) != codes.Unavailable || r != nil {
				t.Fatalf("post-insert %s escaped: %+v %v", name, r, err)
			}
			for _, table := range []string{"sessions", "session_factors", "session_groups", "local_automation_credential_issuance"} {
				rows, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM `+table)
				if err != nil || rows[0].Int64("n") != 0 {
					t.Fatalf("rollback left %s: %+v %v", table, rows, err)
				}
			}
			after, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM mutation_log`)
			if err != nil || after[0].Int64("n") != before[0].Int64("n") {
				t.Fatalf("rollback logged credential mutation: %+v %v", after, err)
			}
		})
	}
}

func TestAutomationIdentityLoginSessionPreservesPolicyAndScope(t *testing.T) {
	for _, mode := range []string{"other-realm", "inactive-factor", "revoked", "expired", "idle", "cutoff", "malformed-expiry", "unreadable-policy", "unhydrated"} {
		t.Run(mode, func(t *testing.T) {
			s := automationLoginServer(t)
			if mode == "other-realm" {
				automationLoginSQL(t, s, `INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?, 'oidc:corp','fixture','fixture')`, corrosion.LoginTwoFactorPolicyKey)
			}
			if mode == "inactive-factor" {
				automationLoginSQL(t, s, `INSERT INTO user_2fa(username,method,secret,enrolled_at,updated_at,epoch) VALUES('alice','totp','old','fixture','fixture','old')`)
			}
			if mode == "malformed-expiry" {
				automationLoginSQL(t, s, `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','expires_at','bad','fixture','fixture')`)
			}
			if mode == "unreadable-policy" {
				automationLoginSQL(t, s, `DROP TABLE cluster_policies`)
			}
			if mode == "unhydrated" {
				s.db.MarkCredentialsUnhydrated()
			}
			r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password"})
			if mode == "malformed-expiry" || mode == "unreadable-policy" || mode == "unhydrated" {
				if err == nil || r != nil {
					t.Fatal("invalid policy/account minted a bearer")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "revoked":
				if err := corrosion.RevokeSession(context.Background(), s.db, strings.TrimPrefix(r.Token, SessionTokenPrefix)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				automationLoginSQL(t, s, `UPDATE sessions SET expires_at='2000-01-01T00:00:00Z'`)
			case "idle":
				automationLoginSQL(t, s, `UPDATE sessions SET last_used_at='2000-01-01T00:00:00Z'`)
			case "cutoff":
				automationLoginSQL(t, s, `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','sessions_not_before','2099-01-01T00:00:00Z','fixture','fixture')`)
			}
			ctx, err := s.authenticate(bearerCtx(r.Token))
			if mode == "other-realm" || mode == "inactive-factor" {
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := callerAutomationPrincipal(ctx); !ok {
					t.Fatal("supported local flow lost certification")
				}
				if err := s.RequirePerm(ctx, "/vms/blocked", "vm.create", "operator"); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("RBAC widened: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid session authenticated")
			}
		})
	}
}

func TestAutomationIdentityLoginSessionDoesNotPromoteUnsupportedFlow(t *testing.T) {
	t.Run("forwarded-and-ordinary-context-clear", func(t *testing.T) {
		s := automationLoginServer(t)
		r := automationLogin(t, s)
		stale := context.WithValue(context.Background(), automationPrincipalContextKey{}, verifiedAutomationPrincipal{clusterUID: "foreign", principalUID: "foreign"})
		ctx, err := s.authenticateForwardedBearer(stale, "Bearer "+r.Token)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := callerAutomationPrincipal(ctx); ok {
			t.Fatal("forwarded context retained authority")
		}
		token, _, _, err := s.mintSession(context.Background(), "alice", "local", "", "webauthn", "webauthn")
		if err != nil {
			t.Fatal(err)
		}
		ctx, err = s.authenticate(metadata.NewIncomingContext(stale, metadata.Pairs("authorization", "Bearer "+token)))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := callerAutomationPrincipal(ctx); ok {
			t.Fatal("WebAuthn mint/ordinary entry retained authority")
		}
	})
	t.Run("mfa-pending-completed", func(t *testing.T) {
		s := automationLoginServer(t)
		enroll, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		pending := automationLogin(t, s)
		if !pending.Requires_2Fa || pending.Token != "" {
			t.Fatal("missing actual MFA challenge")
		}
		code, err := totp.GenerateCode(enroll.SecretBase32, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: "correct-password", TotpCode: code})
		if err != nil || r.Token == "" {
			t.Fatalf("completed MFA: %+v %v", r, err)
		}
		ctx, err := s.authenticate(bearerCtx(r.Token))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := callerAutomationPrincipal(ctx); ok {
			t.Fatal("completed MFA gained unsupported authority")
		}
	})
	for _, policy := range []string{"all", "local", "unknown-policy"} {
		t.Run("enrollment-only-"+policy, func(t *testing.T) {
			s := automationLoginServer(t)
			automationLoginSQL(t, s, `INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?,?,'fixture','fixture')`, corrosion.LoginTwoFactorPolicyKey, policy)
			r := automationLogin(t, s)
			if !r.Requires_2FaEnrollment {
				t.Fatal("policy did not confine login")
			}
			ctx, err := s.authenticate(bearerCtx(r.Token))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := callerAutomationPrincipal(ctx); ok {
				t.Fatal("enrollment-only gained authority")
			}
		})
	}
	t.Run("actual-external-login", func(t *testing.T) {
		s, idp := groupServer(t, "ops")
		_, ctx := oidcSession(t, s, idp)
		if _, ok := callerAutomationPrincipal(ctx); ok {
			t.Fatal("external session gained authority")
		}
	})
}

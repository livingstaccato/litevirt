package corrosion

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
	"time"
)

// Removing the real birth transaction's evidence write makes this fail, even
// though the legacy account still exists and can authenticate.
func TestAutomationLifecycleBirthRetirementAndRecreation(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "password-hash"); err != nil {
		t.Fatal(err)
	}
	first, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || first.Witness == "" || first.Origin != "birth" {
		t.Fatalf("actual account birth has no positive witness: %+v, %v", first, err)
	}
	old, err := GetUser(ctx, c, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, c, "alice", "rotated-hash"); err != nil {
		t.Fatal(err)
	}
	rotated, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || rotated.Witness != first.Witness {
		t.Fatalf("password rotation changed lifetime: %+v, %v", rotated, err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
		t.Fatal("retired account retained current proof")
	}
	if err := InsertUser(ctx, c, "alice", "operator", "password-hash"); err != nil {
		t.Fatal(err)
	}
	next, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || next.Witness == "" || next.Witness == first.Witness {
		t.Fatalf("same-name recreation reused lifetime: %+v, %v", next, err)
	}
	current, err := GetUser(ctx, c, "alice")
	if err != nil || current.CreatedAt != old.CreatedAt {
		t.Fatalf("legacy created_at compatibility changed: %+v, %v", current, err)
	}
	rows, err := c.Query(ctx, `SELECT retired FROM local_automation_lifetimes WHERE witness=?`, first.Witness)
	if err != nil || len(rows) != 1 || rows[0].Int("retired") != 1 {
		t.Fatalf("retirement evidence lost: %+v, %v", rows, err)
	}
}

func TestAutomationLifecycleProjectBirthAndRetirement(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	first, err := AutomationLifetime(ctx, c, "project", "acme")
	if err != nil || first.Witness == "" {
		t.Fatalf("project birth missing proof: %+v, %v", first, err)
	}
	if err := DeleteProject(ctx, c, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationLifetime(ctx, c, "project", "acme"); err == nil {
		t.Fatal("deleted project retained proof")
	}
	// The legacy project API retains tombstones. Physical retention cleanup is
	// not a birth; the next actual InsertProject must capture a new witness.
	if _, err := c.db.ExecContext(ctx, `DELETE FROM projects WHERE name='acme'`); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	next, err := AutomationLifetime(ctx, c, "project", "acme")
	if err != nil || next.Witness == first.Witness {
		t.Fatalf("project recreation reused proof: %+v, %v", next, err)
	}
	if _, err := AutomationLifetime(ctx, c, "project", DefaultProject); err == nil {
		t.Fatal("implicit project fabricated birth")
	}
}

func TestAutomationLifecycleEqualPayloadRewriteInvalidates(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "same-hash"); err != nil {
		t.Fatal(err)
	}
	before, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Bypass the originating adapter exactly as a remote apply does. All visible
	// parent values, including updated_at, remain byte-identical.
	if _, err := c.db.ExecContext(ctx, `UPDATE users SET password_hash=password_hash, updated_at=updated_at WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if after, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
		t.Fatalf("equal-payload rewrite retained stale proof: before=%+v after=%+v", before, after)
	}
	if err := UpdateUserPassword(ctx, c, "alice", "new-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
		t.Fatal("rotation silently repaired missing lineage")
	}
}

func TestAutomationLifecycleAuthenticatedEnrollment(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// This is a historical row, deliberately entering through the old builder
	// without claiming that we observed its birth.
	if err := c.Execute(ctx, usersInsertSQL, "legacy", "operator", string(hash), nowRFC3339(), c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationLifetime(ctx, c, "principal", "legacy"); err == nil {
		t.Fatal("legacy row acquired fabricated birth")
	}
	if _, err := EnrollAutomationLocalAccount(ctx, c, "legacy", "wrong-password"); err == nil {
		t.Fatal("unauthenticated enrollment succeeded")
	}
	e, err := EnrollAutomationLocalAccount(ctx, c, "legacy", "correct-password")
	if err != nil || e.Origin != "enrollment" || e.Witness == "" {
		t.Fatalf("authenticated existing account cannot enroll: %+v %v", e, err)
	}
	again, err := EnrollAutomationLocalAccount(ctx, c, "legacy", "correct-password")
	if err != nil || again.Witness != e.Witness {
		t.Fatalf("repeated authenticated enrollment changed lifetime: %+v %v", again, err)
	}
	if _, err := AuthenticateAutomationLocalAccount(ctx, c, "legacy", "correct-password"); err != nil {
		t.Fatalf("enrolled account authentication: %v", err)
	}
	if _, err := AuthenticateAutomationLocalAccount(ctx, c, "legacy", "wrong-password"); err == nil {
		t.Fatal("wrong password obtained issuance proof")
	}
}

func TestAutomationLifecycleReplicationAndRestart(t *testing.T) {
	for _, mode := range []string{"crr", "anti_entropy", "replace"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			c, err := NewLocalClient(dir, "source")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { c.Close() }()
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := InsertUser(ctx, c, "alice", "operator", "same-hash"); err != nil {
				t.Fatal(err)
			}
			first, err := AutomationLifetime(ctx, c, "principal", "alice")
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.Query(ctx, `SELECT created_at,updated_at FROM users WHERE username='alice'`)
			if err != nil {
				t.Fatal(err)
			}
			created, stamp := rows[0].String("created_at"), rows[0].String("updated_at")
			switch mode {
			case "crr":
				newer := c.NowTS()
				data, err := json.Marshal([]Statement{{SQL: usersReactivateSQL, Params: []interface{}{"operator", "same-hash", newer, "alice"}}})
				if err != nil {
					t.Fatal(err)
				}
				r := NewReplicator(c, "", RelayConfig{})
				if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: "2000000000000-0000-peer", Origin: "peer", Stmts: string(data)}}); err != nil {
					t.Fatal(err)
				}
			case "anti_entropy":
				data, err := json.Marshal(syncPayload{Tables: []syncTable{{Name: "users", Columns: []string{"username", "role", "password_hash", "created_at", "updated_at"}, Rows: [][]interface{}{{"alice", "operator", "same-hash", created, c.NowTS()}}}}})
				if err != nil {
					t.Fatal(err)
				}
				var compressed bytes.Buffer
				writer := gzip.NewWriter(&compressed)
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := c.MergeStateBytesLWW(compressed.Bytes()); err != nil {
					t.Fatal(err)
				}
			case "replace":
				// SQLite REPLACE can omit DELETE triggers with recursive_triggers off;
				// the INSERT invalidator must still catch identical payload/timestamp ABA.
				if _, err := c.db.ExecContext(ctx, `INSERT OR REPLACE INTO users(username,role,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)`, "alice", "operator", "same-hash", created, stamp); err != nil {
					t.Fatal(err)
				}
			}
			if e, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
				t.Fatalf("%s retained source proof %+v after actual incoming write", mode, e)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			c, err = NewLocalClient(dir, "source")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
				t.Fatal("reopen revived invalid proof")
			}
			records, err := c.Query(ctx, `SELECT valid FROM local_automation_lifetimes WHERE witness=?`, first.Witness)
			if err != nil || len(records) != 1 || records[0].Int("valid") != 0 {
				t.Fatalf("durable invalidation absent: %+v %v", records, err)
			}
		})
	}
}

func TestAutomationLifecycleRollbackParentAndProof(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "old"); err != nil {
		t.Fatal(err)
	}
	before, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// The parent's real invalidation trigger aborts after its evidence update;
	// both parent and evidence must be rolled back by the production writer.
	if _, err := c.db.ExecContext(ctx, `CREATE TRIGGER fail_lifecycle_update AFTER UPDATE ON users BEGIN SELECT RAISE(ABORT,'injected rollback'); END`); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, c, "alice", "new"); err == nil {
		t.Fatal("injected failure succeeded")
	}
	after, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || after != before {
		t.Fatalf("failed transaction changed proof: %+v %v", after, err)
	}
	user, err := GetUser(ctx, c, "alice")
	if err != nil || user.PasswordHash != "old" {
		t.Fatal("failed transaction changed credential")
	}
}

// This fixture applies real signed certified history through the sole reducer.
// It does not establish a fresh production closed-cut permit.
func lifecycleCertifiedAccount(t *testing.T) (*Client, *AutomationAccountAuthentication) {
	return lifecycleCertifiedAccountWithGates(t, false, false)
}

func lifecycleCertifiedAccountWithGates(t *testing.T, split, clear bool) (*Client, *AutomationAccountAuthentication) {
	t.Helper()
	ca, original, b, other := threeVoters(t)
	file, err := NewLocalClient(t.TempDir(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	file.SetVoterConfigGate(func() bool { return true })
	inc, err := file.VoterIncarnation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := &claimTestVoter{name: "a", c: file, signer: original.signer, pki: original.pki, inc: inc}
	adoptHandBuilt(t, 1, membersOf(a, b, other), a)
	t.Cleanup(func() { file.Close() })
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "lifecycle-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if split {
		a.c.SetCredentialsSplitGate(func() bool { return true })
		a.c.SetCredentialsClearGate(func() bool { return clear })
		if _, err := a.c.SplitCredentials(ctx); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a.c, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	evidence, err := AutomationLifetime(ctx, a.c, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	initial := sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", a, b)
	if _, err := applySharedAutomation(t, a.c, initial, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	body := contract.IdentityEnrollment{Version: 1, Kind: "principal", Alias: "alice", Witness: evidence.Witness, EvidenceID: "closed-cutover"}
	bodyJSON, _ := json.Marshal(body)
	assignmentJSON, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "principal-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "principal-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: "established-cluster", Kind: "principal", Alias: "alice", Witness: evidence.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	decision := contract.Decision{Sequence: 2, ParentDigest: initial.Value.MustDigest(), Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: "principal-request", Body: bodyJSON}, Assignment: assignmentJSON}
	encoded, err := contract.EncodeDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	key, _ := AutomationClaimKey(2)
	ballot := testBallot(2, "a")
	record := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
	for _, v := range []*claimTestVoter{a, b} {
		signed, err := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
		if err != nil {
			t.Fatal(err)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, signed)
	}
	if err := verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(a, b, other), Quorum: 2}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" {
		t.Fatalf("certified principal: %+v %v", receipt, err)
	}
	authenticated, err := AuthenticateAutomationLocalAccount(ctx, a.c, "alice", "correct-password")
	if err != nil {
		t.Fatal(err)
	}
	return a.c, authenticated
}

func TestAutomationLifecycleCredentialIssuance(t *testing.T) {
	ctx := context.Background()
	c, authenticated := lifecycleCertifiedAccount(t)
	raw := strings.Repeat("a", 64)
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "first", Username: "alice", Name: "first", TokenHash: string(hash)}); err != nil {
		t.Fatalf("real token issuance did not stamp certified account: %v", err)
	}
	identity, err := AutomationTokenPrincipal(ctx, c, raw)
	if err != nil || identity == nil || identity.UID != "principal-uid" {
		t.Fatalf("issued credential not bound to certified principal: %+v %v", identity, err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "legacy", Username: "alice", TokenHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	// Legacy acceptance remains independent of automation provenance.
	if user, err := ValidateToken(ctx, c, raw); err != nil || user == nil {
		t.Fatal("legacy authentication regressed")
	}
	session := SessionRecord{ID: "session-first", Username: "alice", Realm: "local", CreatedAt: nowRFC3339(), LastUsedAt: nowRFC3339(), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := InsertAutomationSession(ctx, c, authenticated, session); err != nil {
		t.Fatalf("session issuance: %v", err)
	}
	if principal, err := AutomationSessionPrincipal(ctx, c, session.ID); err != nil || principal.UID != identity.UID {
		t.Fatalf("session principal: %+v %v", principal, err)
	}
	if err := UpdateUserPassword(ctx, c, "alice", string(hash)); err != nil {
		t.Fatal(err)
	}
	if principal, err := AutomationSessionPrincipal(ctx, c, session.ID); err != nil || principal.UID != identity.UID {
		t.Fatalf("password rotation changed principal: %+v %v", principal, err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	// Restore an old credential as a late legacy replica may do. Its bearer
	// remains valid under legacy username semantics, but cannot regain automation.
	if _, err := c.db.ExecContext(ctx, `UPDATE tokens SET deleted_at=NULL WHERE id='first'`); err != nil {
		t.Fatal(err)
	}
	if legacy, err := ValidateToken(ctx, c, raw); err != nil || legacy == nil {
		t.Fatal("late old credential did not exercise legacy acceptance")
	}
	if _, err := AutomationTokenPrincipal(ctx, c, raw); err == nil {
		t.Fatal("old token gained recreated account")
	}
	if _, err := AutomationSessionPrincipal(ctx, c, session.ID); err == nil {
		t.Fatal("old session gained recreated account")
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "stale", Username: "alice", TokenHash: string(hash)}); err == nil {
		t.Fatal("stale authenticated handle issued token for new lifetime")
	}
	rows, err := c.Query(ctx, `SELECT id FROM tokens WHERE id='stale'`)
	if err != nil || len(rows) != 0 {
		t.Fatal("refused issuance left credential row")
	}
}

func TestAutomationLifecycleIssuanceRechecksAfterWrites(t *testing.T) {
	ctx := context.Background()
	c, a := lifecycleCertifiedAccount(t)
	s := SessionRecord{ID: "rollback-session", Username: "alice", Realm: "local", CreatedAt: nowRFC3339(), LastUsedAt: nowRFC3339(), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	// A write after the credential creation invalidates its exact account proof.
	// The whole real credential batch must roll back, including the session.
	err := c.executeCredentialBatch(ctx, a, "session", s.ID, s.Username, []Statement{sessionInsertStatement(s), {SQL: usersUpdatePasswordSQL, Params: []interface{}{"changed", c.NowTS(), "alice"}}})
	if err == nil {
		t.Fatal("issuance callback accepted account altered inside its write transaction")
	}
	got, err := GetSession(ctx, c, s.ID)
	if err != nil || got != nil {
		t.Fatal("refused issuance left session row")
	}
	if _, err := AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password"); err != nil {
		t.Fatal("rollback failed to restore parent and proof")
	}
}

func TestAutomationLifecycleAdminReinstatementAndReset(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertUser(ctx, c, "admin", "admin", "initial"); err != nil {
		t.Fatal(err)
	}
	first, err := AutomationLifetime(ctx, c, "principal", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := ResetAdminPassword(ctx, c, nil, "rotated", false); err != nil {
		t.Fatal(err)
	}
	rotated, err := AutomationLifetime(ctx, c, "principal", "admin")
	if err != nil || rotated.Witness != first.Witness {
		t.Fatalf("admin password reset lost lifetime: %+v %v", rotated, err)
	}
	if err := DeleteUser(ctx, c, "admin"); err != nil {
		t.Fatal(err)
	}
	name, err := ReinstateAdminIfNoneRemain(ctx, c, nil)
	if err != nil || name != "admin" {
		t.Fatalf("legacy admin floor failed: %q %v", name, err)
	}
	next, err := AutomationLifetime(ctx, c, "principal", "admin")
	if err != nil || next.Witness == first.Witness || next.Origin != "birth" {
		t.Fatalf("admin floor did not record new lifetime: %+v %v", next, err)
	}
}

func TestAutomationLifecycleCredentialRefusalsAndReopen(t *testing.T) {
	ctx := context.Background()
	c, authenticated := lifecycleCertifiedAccount(t)
	raw := strings.Repeat("b", 64)
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "bound", Username: "alice", TokenHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	dir := c.dataDir
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	identity, err := AutomationTokenPrincipal(ctx, c, raw)
	if err != nil || identity.UID != "principal-uid" {
		t.Fatalf("reopen lost enrolled principal: %+v %v", identity, err)
	}
	authenticated, err = AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password")
	if err != nil {
		t.Fatal(err)
	}
	// A second issued credential is rotation within the same account lifetime.
	raw2 := strings.Repeat("c", 64)
	hash2, err := bcrypt.GenerateFromPassword([]byte(raw2), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "rotated", Username: "alice", TokenHash: string(hash2)}); err != nil {
		t.Fatal(err)
	}
	if next, err := AutomationTokenPrincipal(ctx, c, raw2); err != nil || next.UID != identity.UID {
		t.Fatalf("token rotation changed principal: %+v %v", next, err)
	}
	if err := RevokeToken(ctx, c, "bound"); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationTokenPrincipal(ctx, c, raw); err == nil {
		t.Fatal("revoked token retained automation")
	}
	// An equal-payload underlying credential rewrite cannot reuse its issuance.
	if _, err := c.db.ExecContext(ctx, `UPDATE tokens SET token_hash=token_hash,updated_at=updated_at WHERE id='rotated'`); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationTokenPrincipal(ctx, c, raw2); err == nil {
		t.Fatal("altered credential retained stamp")
	}
	if legacy, err := ValidateToken(ctx, c, raw2); err != nil || legacy == nil {
		t.Fatal("unstamped token stopped working for legacy authentication")
	}
	raw3 := strings.Repeat("d", 64)
	hash3, err := bcrypt.GenerateFromPassword([]byte(raw3), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "unstamped", Username: "alice", TokenHash: string(hash3)}); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationTokenPrincipal(ctx, c, raw3); err == nil {
		t.Fatal("legacy unstamped token gained automation identity")
	}
	if _, err := c.db.ExecContext(ctx, `DELETE FROM local_automation_lifetimes WHERE name='alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password"); err == nil {
		t.Fatal("lost lifetime silently repaired")
	}
}

func TestAutomationLifecycleEnrollmentDoesNotBypassAuthenticationPolicy(t *testing.T) {
	for _, mode := range []string{"disabled", "second_factor", "unhydrated", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c := lifecycleDB(t)
			hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertUser(ctx, c, "alice", "operator", string(hash)); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "disabled":
				yes := true
				if err := SetUserLifecycle(ctx, c, lpGrant(t), "alice", &yes, nil, "test"); err != nil {
					t.Fatal(err)
				}
			case "second_factor":
				if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa_sets(username,active_epoch,updated_at) VALUES('alice','','fixture')`); err != nil {
					t.Fatal(err)
				}
				if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa(username,method,label,secret,enrolled_at,updated_at) VALUES('alice','totp','factor','secret',?,?)`, nowRFC3339(), c.NowTS()); err != nil {
					t.Fatal(err)
				}
			case "unhydrated":
				c.MarkCredentialsUnhydrated()
			case "ambiguous":
				if err := InsertUser(ctx, c, "ALICE", "operator", string(hash)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := EnrollAutomationLocalAccount(ctx, c, "alice", "password"); err == nil {
				t.Fatal("enrollment bypassed authentication policy")
			}
		})
	}
}

// The actual stale revive must miss its guarded transaction without retiring
// the concurrently born winner's positive source observation.
func TestAutomationLifecycleProjectGuardMissPreservesWinner(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "acme"); err != nil {
		t.Fatal(err)
	}
	var winner AutomationLifetimeEvidence
	var logs int
	projectLifecycleInterleaveHook = func() {
		projectLifecycleInterleaveHook = nil
		if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
			t.Fatal(err)
		}
		var err error
		winner, err = AutomationLifetime(ctx, c, "project", "acme")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&logs); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { projectLifecycleInterleaveHook = nil })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err == nil {
		t.Fatal("stale revival unexpectedly applied")
	}
	after, err := AutomationLifetime(ctx, c, "project", "acme")
	if err != nil || winner.Witness == "" || after != winner {
		t.Fatalf("loser changed winner evidence: before=%+v after=%+v err=%v", winner, after, err)
	}
	var afterLogs int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&afterLogs); err != nil || afterLogs != logs {
		t.Fatalf("guard miss changed log: %d -> %d, %v", logs, afterLogs, err)
	}
}

func TestAutomationLifecycleProjectGuardedBirthPaths(t *testing.T) {
	for _, nextName := range []string{"acme", "/acme"} {
		t.Run(nextName, func(t *testing.T) {
			ctx := context.Background()
			c := lifecycleDB(t)
			if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
				t.Fatal(err)
			}
			first, err := AutomationLifetime(ctx, c, "project", "acme")
			if err != nil {
				t.Fatal(err)
			}
			if err := DeleteProject(ctx, c, "acme"); err != nil {
				t.Fatal(err)
			}
			if _, err := AutomationLifetime(ctx, c, "project", "acme"); err == nil {
				t.Fatal("guarded delete left current evidence")
			}
			if err := InsertProject(ctx, c, ProjectRecord{Name: nextName}); err != nil {
				t.Fatal(err)
			}
			next, err := AutomationLifetime(ctx, c, "project", nextName)
			if err != nil || next.Witness == "" || next.Witness == first.Witness || next.Origin != "birth" {
				t.Fatalf("guarded birth lacks fresh coupled evidence: %+v, %v", next, err)
			}
		})
	}
}

func TestAutomationLifecycleProjectGuardedCallbackRollback(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "acme"); err != nil {
		t.Fatal(err)
	}
	before, err := c.Query(ctx, `SELECT * FROM local_automation_lifetimes WHERE kind='project' AND name='acme'`)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var logs int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	// after() has run the parent and mutation-log writes when its new positive
	// observation fails; their common transaction must roll everything back.
	if _, err := c.db.ExecContext(ctx, `CREATE TRIGGER fail_project_birth BEFORE INSERT ON local_automation_lifetimes WHEN NEW.kind='project' BEGIN SELECT RAISE(ABORT,'injected proof failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err == nil || !strings.Contains(err.Error(), "injected proof failure") {
		t.Fatalf("expected injected proof failure, got %v", err)
	}
	if live, err := GetProject(ctx, c, "acme"); err != nil || live != nil {
		t.Fatalf("callback failure revived parent: %+v %v", live, err)
	}
	after, err := c.Query(ctx, `SELECT * FROM local_automation_lifetimes WHERE kind='project' AND name='acme'`)
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("callback failure changed prior proof: %s -> %s, %v", beforeJSON, afterJSON, err)
	}
	var afterLogs int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&afterLogs); err != nil || afterLogs != logs {
		t.Fatalf("callback failure changed log: %d -> %d, %v", logs, afterLogs, err)
	}
}

// The automation password entry has its own transaction-local policy check;
// a held set must not turn into password-only access when its active join is empty.
func TestAutomationLifecycleHeldFactorPasswordRefusal(t *testing.T) {
	for _, mode := range []string{"none", "active", "held", "held_and_active"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c := lifecycleDB(t)
			hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertUser(ctx, c, "alice", "operator", string(hash)); err != nil {
				t.Fatal(err)
			}
			if mode != "none" {
				epoch := "factor-set"
				if mode == "held" || mode == "held_and_active" {
					epoch += userEpochHeldSuffix
				}
				if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa_sets(username,active_epoch,updated_at) VALUES(?,?,?)`, "alice", epoch, c.NowTS()); err != nil {
					t.Fatal(err)
				}
				if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa(username,method,label,secret,enrolled_at,updated_at,epoch) VALUES(?,?,?,?,?,?,?)`, "alice", "totp", "factor", "secret", nowRFC3339(), c.NowTS(), "factor-set"); err != nil {
					t.Fatal(err)
				}
				if mode == "held_and_active" {
					if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa(username,method,label,secret,enrolled_at,updated_at,epoch) VALUES(?,?,?,?,?,?,?)`, "alice", "totp", "active", "secret", nowRFC3339(), c.NowTS(), epoch); err != nil {
						t.Fatal(err)
					}
				}
			}
			held, err := ListHeldUser2FA(ctx, c, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if (len(held) != 0) != (mode == "held" || mode == "held_and_active") {
				t.Fatal("fixture did not establish actual held-factor representation")
			}
			active, err := ListUser2FA(ctx, c, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if (len(active) != 0) != (mode == "active" || mode == "held_and_active") {
				t.Fatal("fixture active-factor join differs from intended state")
			}
			_, enrollErr := EnrollAutomationLocalAccount(ctx, c, "alice", "password")
			_, authErr := AuthenticateAutomationLocalAccount(ctx, c, "alice", "password")
			if mode == "none" {
				if enrollErr != nil || authErr != nil {
					t.Fatalf("no-factor positive refused: enroll=%v auth=%v", enrollErr, authErr)
				}
			} else if enrollErr == nil || authErr == nil {
				t.Fatalf("factor policy bypass: enroll=%v auth=%v", enrollErr, authErr)
			}
		})
	}
}

func TestAutomationLifecycleUserIncarnationGuardedRevive(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "alice", "operator", "old-hash"); err != nil {
		t.Fatal(err)
	}
	first, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	old, err := GetUser(ctx, c, "alice")
	if err != nil || old == nil {
		t.Fatal("old account missing", err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationLifetime(ctx, c, "principal", "alice"); err == nil {
		t.Fatal("delete retained live witness")
	}
	if err := InsertUser(ctx, c, "alice", "operator", "new-hash"); err != nil {
		t.Fatal(err)
	}
	next, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || next.Witness == "" || next.Witness == first.Witness || next.Origin != "birth" {
		t.Fatalf("revive lacks fresh coupled witness: %+v %v", next, err)
	}
	current, err := GetUser(ctx, c, "alice")
	if err != nil || current == nil || current.CreatedAt == old.CreatedAt {
		t.Fatal("revive did not advance actual user incarnation", err)
	}
	rows, err := c.Query(ctx, `SELECT password_hash FROM user_credentials WHERE username='alice' AND deleted_at IS NULL`)
	if err != nil || len(rows) != 1 || rows[0].String("password_hash") != "new-hash" {
		t.Fatal("revive lost coupled credential", err)
	}
}

func TestAutomationLifecycleUserGuardMissPreservesWinner(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "alice", "operator", "old-hash"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	var winner AutomationLifetimeEvidence
	var logs int
	userWriteInterleaveHook = func(string) {
		userWriteInterleaveHook = nil
		if err := InsertUser(ctx, c, "alice", "operator", "winner-hash"); err != nil {
			t.Fatal(err)
		}
		var err error
		winner, err = AutomationLifetime(ctx, c, "principal", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&logs); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { userWriteInterleaveHook = nil })
	if err := InsertUser(ctx, c, "alice", "operator", "loser-hash"); err != ErrUserAccountChanged {
		t.Fatalf("stale revive = %v, want account-changed", err)
	}
	after, err := AutomationLifetime(ctx, c, "principal", "alice")
	if err != nil || winner.Witness == "" || after != winner {
		t.Fatalf("guard loser changed winner witness: %+v -> %+v, %v", winner, after, err)
	}
	var afterLogs int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&afterLogs); err != nil || afterLogs != logs {
		t.Fatalf("guard miss changed log: %d -> %d, %v", logs, afterLogs, err)
	}
}

func TestAutomationLifecycleUserGuardedCallbackRollback(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "alice", "operator", "old-hash"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	capture := func() []byte {
		t.Helper()
		var state []interface{}
		for _, query := range []string{`SELECT * FROM users WHERE username='alice'`, `SELECT * FROM user_credentials WHERE username='alice'`, `SELECT * FROM local_automation_lifetimes WHERE kind='principal' AND name='alice'`, `SELECT * FROM mutation_log ORDER BY seq`} {
			rows, err := c.Query(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			state = append(state, rows)
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := capture()
	if _, err := c.db.ExecContext(ctx, `CREATE TRIGGER fail_user_birth BEFORE INSERT ON local_automation_lifetimes WHEN NEW.kind='principal' BEGIN SELECT RAISE(ABORT,'injected user proof failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "alice", "operator", "new-hash"); err == nil || !strings.Contains(err.Error(), "injected user proof failure") {
		t.Fatalf("revive did not reach proof failure: %v", err)
	}
	if after := capture(); !bytes.Equal(before, after) {
		t.Fatalf("proof failure changed parent/credential/witness/log: %s -> %s", before, after)
	}
}

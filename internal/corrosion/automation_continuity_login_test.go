package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"golang.org/x/crypto/bcrypt"
	"modernc.org/sqlite"
	"path/filepath"
	"strings"
	"testing"
)

// Historical enrollment/certified storage premise only. Daemon coverage owns
// actual native continuity certification and second-entry public Login.
func continuityLoginAccount(t *testing.T) (*Client, *AutomationAccountAuthentication) {
	t.Helper()
	a, b, c, session := continuityNativeFixture(t)
	ctx := context.Background()
	p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "principal", "principal-uid", "login-continuity")
	if err != nil {
		t.Fatal(err)
	}
	key, value := continuityTestValue(t, a, p)
	ballot := testBallot(4, "a")
	record := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
	for _, v := range []*claimTestVoter{a, b} {
		vote, err := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
		if err != nil {
			t.Fatal(err)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, vote)
	}
	verifier := (*a.c.claimCertVerifier.Load())()
	if err := verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(a, b, c), Quorum: 2}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" {
		t.Fatal(receipt, err)
	}
	auth, d, err := PrepareAutomationLocalSession(ctx, a.c, "alice", "correct-password")
	if err != nil || d != AutomationCredentialEligible {
		t.Fatalf("continuity preparation %v %v", d, err)
	}
	return a.c, auth
}
func loginProofSQL(t *testing.T, c *Client, q string, args ...any) {
	t.Helper()
	if _, err := c.db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}
func loginProofFailure(t *testing.T, err error) {
	t.Helper()
	var proof *AutomationCredentialError
	if !errors.As(err, &proof) || proof.Kind != AutomationCredentialProofInvalid || errors.Is(err, ErrAutomationCredentialUnstamped) {
		t.Fatalf("present invalid proof misclassified: %T %v", err, err)
	}
}
func TestAutomationContinuityLoginSelection(t *testing.T) {
	for _, origin := range []string{"matching", "missing", "different", "invalid", "retired", "empty"} {
		for _, continuity := range []string{"valid", "absent", "malformed"} {
			t.Run(origin+"/"+continuity, func(t *testing.T) {
				c, _ := continuityLoginAccount(t)
				switch origin {
				case "missing":
					loginProofSQL(t, c, `DELETE FROM local_automation_lifetimes`)
				case "different":
					loginProofSQL(t, c, `UPDATE local_automation_lifetimes SET witness='another-origin'`)
				case "invalid":
					loginProofSQL(t, c, `UPDATE local_automation_lifetimes SET valid=0`)
				case "retired":
					loginProofSQL(t, c, `UPDATE local_automation_lifetimes SET retired=1`)
				case "empty":
					loginProofSQL(t, c, `UPDATE local_automation_lifetimes SET witness=''`)
				}
				switch continuity {
				case "absent":
					loginProofSQL(t, c, `DELETE FROM local_automation_identity_continuity`)
				case "malformed":
					loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET parent_kind='vm'`)
				}
				a, d, err := PrepareAutomationLocalSession(context.Background(), c, "alice", "correct-password")
				if continuity == "valid" || continuity == "absent" && origin == "matching" {
					if err != nil || a == nil || d != AutomationCredentialEligible {
						t.Fatalf("valid selected proof refused: %v %v", d, err)
					}
					return
				}
				if continuity == "absent" && origin == "missing" {
					if err != nil || a != nil || d != AutomationCredentialNoLocalProof {
						t.Fatal(a, d, err)
					}
					return
				}
				if a != nil || d != AutomationCredentialUnknown {
					t.Fatal(a, d, err)
				}
				loginProofFailure(t, err)
			})
		}
	}
}
func TestAutomationContinuityLoginTransaction(t *testing.T) {
	for _, proof := range []string{"origin", "continuity"} {
		for _, change := range []string{"parent-before", "parent-after", "projection-after", "attachment-after", "origin-after", "later-error"} {
			t.Run(proof+"/"+change, func(t *testing.T) {
				c, a := continuityLoginAccount(t)
				if proof == "origin" {
					loginProofSQL(t, c, `DELETE FROM local_automation_identity_continuity`)
					var d AutomationCredentialDisposition
					var err error
					a, d, err = PrepareAutomationLocalSession(context.Background(), c, "alice", "correct-password")
					if err != nil || d != AutomationCredentialEligible {
						t.Fatal(d, err)
					}
				}
				s := automationTestSession("atomic-login")
				if change == "parent-before" {
					loginProofSQL(t, c, `UPDATE users SET updated_at='changed' WHERE username='alice'`)
				} else {
					q := `UPDATE users SET updated_at='changed' WHERE username=NEW.username;`
					switch change {
					case "projection-after":
						q = `UPDATE local_automation_semantic_heads SET digest='corrupt';`
					case "attachment-after":
						q = `UPDATE local_automation_identity_continuity SET parent_birth='other';`
						if proof == "origin" {
							q = `UPDATE local_automation_lifetimes SET witness='changed';`
						}
					case "origin-after":
						if proof == "origin" {
							q = `UPDATE local_automation_lifetimes SET origin='enrollment';`
						} else {
							q = `UPDATE local_automation_identity_continuity SET parent_realm='other';`
						}
					case "later-error":
						q = `SELECT RAISE(ABORT,'injected later statement failure');`
					}
					loginProofSQL(t, c, `CREATE TRIGGER change_during_continuity_login AFTER INSERT ON sessions BEGIN `+q+` END`)
				}
				if err := InsertAutomationSessionWithLoginData(context.Background(), c, lpGrant(t), a, s, "", nil); err == nil {
					t.Fatal("changed issuance committed")
				}
				for _, table := range []string{"sessions", "local_automation_credential_issuance"} {
					var n int
					if err := c.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE `+map[string]string{"sessions": "id", "local_automation_credential_issuance": "credential_id"}[table]+`=?`, s.ID).Scan(&n); err != nil || n != 0 {
						t.Fatal("failed insert retained credential", table, n, err)
					}
				}
			})
		}
	}
}
func TestAutomationContinuityLoginDurableMode(t *testing.T) {
	for _, mode := range []string{"continuity", "origin-pinned", "wrong-mode", "invalid-flag", "mixed-witness", "wrong-generation", "wrong-original", "wrong-parent", "blob-mode", "foreign-db", "token-handle"} {
		t.Run(mode, func(t *testing.T) {
			c, a := continuityLoginAccount(t)
			ctx := context.Background()
			if mode == "origin-pinned" {
				a, _ = AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password")
			}
			if mode == "foreign-db" {
				file := filepath.Join(t.TempDir(), "state.db")
				if _, err := c.db.Exec(`VACUUM INTO ?`, file); err != nil {
					t.Fatal(err)
				}
				other, err := NewLocalClient(filepath.Dir(file), "a")
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if err := InsertAutomationSession(ctx, other, a, automationTestSession("foreign")); err == nil {
					t.Fatal("other Client accepted opaque authentication")
				}
				return
			}
			if mode == "token-handle" {
				if err := InsertAutomationToken(ctx, c, a, TokenRecord{ID: "token", Username: "alice", TokenHash: "unused"}); err == nil {
					t.Fatal("continuity session handle issued token")
				}
				return
			}
			s := automationTestSession("durable-login")
			if err := InsertAutomationSession(ctx, c, a, s); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "origin-pinned":
				loginProofSQL(t, c, `UPDATE local_automation_lifetimes SET valid=0`)
			case "wrong-mode":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET proof_mode='unknown' WHERE credential_id=?`, s.ID)
			case "invalid-flag":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET valid=0 WHERE credential_id=?`, s.ID)
			case "mixed-witness":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET witness='not-origin' WHERE credential_id=?`, s.ID)
			case "wrong-generation":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET identity_generation=2 WHERE credential_id=?`, s.ID)
			case "wrong-original":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET original_witness='other' WHERE credential_id=?`, s.ID)
			case "wrong-parent":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET parent_birth='other' WHERE credential_id=?`, s.ID)
			case "blob-mode":
				loginProofSQL(t, c, `UPDATE local_automation_credential_issuance SET proof_mode=CAST(proof_mode AS BLOB) WHERE credential_id=?`, s.ID)
			}
			if mode != "continuity" {
				_, err := AutomationSessionPrincipal(ctx, c, s.ID)
				loginProofFailure(t, err)
				return
			}
			dir := c.dataDir
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewLocalClient(dir, "a")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			reopened.SetUserIncarnationGate(func() bool { return true })
			i, err := AutomationSessionPrincipal(ctx, reopened, s.ID)
			if err != nil || i == nil || i.UID != "principal-uid" {
				t.Fatal("durable continuity issuance lost", i, err)
			}
		})
	}
}
func TestAutomationContinuityLoginStorageCause(t *testing.T) {
	for _, mode := range []string{"continuity-storage", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := continuityLoginAccount(t)
			ctx := context.Background()
			if mode == "continuity-storage" {
				loginProofSQL(t, c, `DROP TABLE local_automation_identity_continuity`)
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password")
			var proof *AutomationCredentialError
			if err == nil || a != nil || d != AutomationCredentialUnknown || errors.As(err, &proof) {
				t.Fatal("storage became missing or typed proof", a, d, err)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if mode == "continuity-storage" {
				var cause *sqlite.Error
				if !errors.As(err, &cause) {
					t.Fatalf("lost actual sqlite cause %T %v", err, err)
				}
			}
		})
	}
}
func TestAutomationContinuityLoginRotationAndRebirth(t *testing.T) {
	c, a := continuityLoginAccount(t)
	ctx := context.Background()
	loginProofSQL(t, c, `DELETE FROM local_automation_lifetimes`)
	s := automationTestSession("rotation-login")
	if err := InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), a, s, "", nil); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("rotated-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, c, "alice", string(hash)); err != nil {
		t.Fatal(err)
	}
	if i, err := AutomationSessionPrincipal(ctx, c, s.ID); err != nil || i == nil || i.UID != "principal-uid" {
		t.Fatal("rotation lost stable UID session", i, err)
	}
	if a, _, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password"); err == nil || a != nil {
		t.Fatal("old password freshly authenticated")
	}
	if a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "rotated-password"); err != nil || a == nil || d != AutomationCredentialEligible {
		t.Fatal("new password lost original UID", a, d, err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	if _, err := AutomationSessionPrincipal(ctx, c, s.ID); err == nil {
		t.Fatal("rebirth inherited session")
	}
	a, _, err = PrepareAutomationLocalSession(ctx, c, "alice", "rotated-password")
	if a != nil {
		t.Fatal("rebirth inherited original certified UID")
	}
	loginProofFailure(t, err)
}

func TestAutomationContinuityLoginPolicyAndCurrentness(t *testing.T) {
	for _, mode := range []string{"disabled", "account-expiry", "cutoff", "session-expiry", "factor-policy", "active-factor", "held-factor", "held-newer", "retired-identity", "missing-alias", "wrong-cluster", "wrong-generation", "malformed-generation", "oversized-parent", "blob-original"} {
		t.Run(mode, func(t *testing.T) {
			c, a := continuityLoginAccount(t)
			ctx := context.Background()
			s := automationTestSession("policy-login")
			if err := InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), a, s, "", nil); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "disabled":
				loginProofSQL(t, c, `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','disabled','true','fixture','fixture')`)
			case "account-expiry":
				loginProofSQL(t, c, `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','expires_at','2000-01-01T00:00:00Z','fixture','fixture')`)
			case "cutoff":
				loginProofSQL(t, c, `INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','sessions_not_before','2099-01-01T00:00:00Z','fixture','fixture')`)
			case "session-expiry":
				loginProofSQL(t, c, `UPDATE sessions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, s.ID)
			case "factor-policy":
				loginProofSQL(t, c, `INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES('login_2fa_required','local','fixture','fixture')`)
			case "active-factor", "held-factor":
				epoch := "current"
				active := epoch
				if mode == "held-factor" {
					active = epoch + userEpochHeldSuffix
				}
				loginProofSQL(t, c, `INSERT INTO user_2fa_sets(username,active_epoch,updated_at) VALUES('alice',?,'fixture')`, active)
				loginProofSQL(t, c, `INSERT INTO user_2fa(username,method,secret,enrolled_at,updated_at,epoch) VALUES('alice','totp','test-secret','fixture','fixture',?)`, epoch)
			case "held-newer":
				u, err := GetUser(ctx, c, "alice")
				if err != nil {
					t.Fatal(err)
				}
				stmts, err := json.Marshal([]Statement{{SQL: sessionsInsertSQL, Params: []interface{}{"future-session", "alice", "local", "", "", nowRFC3339(), nowRFC3339(), nowRFC3339()}, Guard: &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "alice", Incarnation: nextIncarnation(u.CreatedAt)}}})
				if err != nil {
					t.Fatal(err)
				}
				receiver := NewReplicator(c, "", RelayConfig{})
				if _, err := receiver.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: c.NowTS(), Origin: "peer", Stmts: string(stmts)}}); err != nil {
					t.Fatal(err)
				}
				if c.UserHolds() == 0 {
					t.Fatal("actual newer lifetime not held")
				}
			case "retired-identity":
				loginProofSQL(t, c, `UPDATE local_automation_identities SET retired=1 WHERE uid='principal-uid'`)
			case "missing-alias":
				loginProofSQL(t, c, `DELETE FROM local_automation_aliases`)
			case "wrong-cluster":
				loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET cluster_uid='other'`)
			case "wrong-generation":
				loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET generation=2`)
			case "malformed-generation":
				loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET generation='bad'`)
			case "oversized-parent":
				loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET parent_birth=?`, strings.Repeat("x", contract.MaxStringBytes+1))
			case "blob-original":
				loginProofSQL(t, c, `UPDATE local_automation_identity_continuity SET original_witness=CAST(original_witness AS BLOB)`)
			}
			if _, err := AutomationSessionPrincipal(ctx, c, s.ID); err == nil || errors.Is(err, ErrAutomationCredentialUnstamped) {
				t.Fatal("invalid current proof retained authority", err)
			}
			if mode == "factor-policy" || mode == "active-factor" || mode == "held-factor" {
				a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password")
				if err != nil || a != nil || d != AutomationCredentialUnsupportedFlow {
					t.Fatal("unsupported flow promoted", a, d, err)
				}
			}
		})
	}
}

// Changing the selected identity generation while retaining its original UID,
// witness, alias and account must not cross the authentication/INSERT boundary.
func TestAutomationLoginIdentityTuplePin(t *testing.T) {
	for _, mode := range []string{"origin", "continuity"} {
		for _, when := range []string{"before", "after"} {
			t.Run(mode+"/"+when, func(t *testing.T) {
				c, _ := continuityLoginAccount(t)
				ctx := context.Background()
				if mode == "origin" {
					loginProofSQL(t, c, `DELETE FROM local_automation_identity_continuity`)
				}
				a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password")
				if err != nil || d != AutomationCredentialEligible {
					t.Fatal(d, err)
				}
				change := `UPDATE local_automation_identities SET generation=2 WHERE uid='principal-uid'; UPDATE local_automation_aliases SET generation=2 WHERE uid='principal-uid'; UPDATE local_automation_identity_continuity SET generation=2 WHERE uid='principal-uid';`
				if when == "before" {
					loginProofSQL(t, c, change)
				} else {
					loginProofSQL(t, c, `CREATE TRIGGER change_identity_generation AFTER INSERT ON sessions BEGIN `+change+` END`)
				}
				s := automationTestSession("identity-tuple-boundary")
				err = InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), a, s, "", nil)
				if err == nil {
					var sessions, stamps int
					_ = c.db.QueryRow(`SELECT count(*) FROM sessions WHERE id=?`, s.ID).Scan(&sessions)
					_ = c.db.QueryRow(`SELECT count(*) FROM local_automation_credential_issuance WHERE credential_id=?`, s.ID).Scan(&stamps)
					t.Fatalf("%s %s generation drift committed session=%d stamp=%d; expected refusal/rollback", mode, when, sessions, stamps)
				}
				loginProofFailure(t, err)
				var n int
				if err := c.db.QueryRow(`SELECT count(*) FROM sessions WHERE id=?`, s.ID).Scan(&n); err != nil || n != 0 {
					t.Fatal("generation refusal retained session", n, err)
				}
				if err := c.db.QueryRow(`SELECT count(*) FROM local_automation_credential_issuance WHERE credential_id=?`, s.ID).Scan(&n); err != nil || n != 0 {
					t.Fatal("generation refusal retained stamp", n, err)
				}
				if when == "after" {
					if err := c.db.QueryRow(`SELECT generation FROM local_automation_identities WHERE stage='' AND uid='principal-uid'`).Scan(&n); err != nil || n != 1 {
						t.Fatal("generation trigger escaped rollback", n, err)
					}
				}
			})
		}
	}
	t.Run("legacy-origin/after", func(t *testing.T) {
		c, a := lifecycleCertifiedAccount(t)
		ctx := context.Background()
		loginProofSQL(t, c, `CREATE TRIGGER change_legacy_identity_generation AFTER INSERT ON sessions BEGIN UPDATE local_automation_identities SET generation=2 WHERE uid='principal-uid'; UPDATE local_automation_aliases SET generation=2 WHERE uid='principal-uid'; END`)
		s := automationTestSession("legacy-identity-tuple")
		err := InsertAutomationSession(ctx, c, a, s)
		if err == nil {
			t.Fatal("legacy origin INSERT changed first selected identity tuple and committed")
		}
		loginProofFailure(t, err)
		var n int
		if err := c.db.QueryRow(`SELECT count(*) FROM sessions WHERE id=?`, s.ID).Scan(&n); err != nil || n != 0 {
			t.Fatal("legacy tuple refusal retained session", n, err)
		}
		if err := c.db.QueryRow(`SELECT count(*) FROM local_automation_credential_issuance WHERE credential_id=?`, s.ID).Scan(&n); err != nil || n != 0 {
			t.Fatal("legacy tuple refusal retained stamp", n, err)
		}
	})
}

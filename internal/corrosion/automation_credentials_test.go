package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
	"golang.org/x/crypto/bcrypt"
)

// Counting retired factor epochs or treating another realm's policy as local
// must fail these positive password authentication controls.
func TestAutomationLocalSessionPolicyUsesActiveRealmAndFactorEpoch(t *testing.T) {
	for _, mode := range []string{"other-realm", "inactive-factor"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := lifecycleCertifiedAccount(t)
			ctx := context.Background()
			if mode == "other-realm" {
				c.SetClusterPolicyGate(func() bool { return true })
				p, err := ParseTwoFactorPolicy("oidc:corp")
				if err != nil {
					t.Fatal(err)
				}
				if err := SetTwoFactorPolicy(ctx, c, lpGrant(t), p, "fixture"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := c.db.ExecContext(ctx, `INSERT INTO user_2fa(username,method,secret,enrolled_at,updated_at,epoch) VALUES('alice','totp','old-secret','2026-10-17T00:00:00Z','fixture','old-epoch')`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password"); err != nil {
				t.Fatalf("supported local password flow refused: %v", err)
			}
		})
	}
}

func TestAutomationLocalSessionPreparationClassifiesEvidence(t *testing.T) {
	for _, mode := range []string{"eligible", "missing-lifetime", "invalid-lifetime", "retired-lifetime", "uncertified-birth", "missing-alias", "stale-witness", "corrupt-head", "malformed-identity", "ambiguous-account", "required", "unknown-policy", "policy-read-error", "factor-read-error", "canceled", "wrong-password", "malformed-expiry"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := lifecycleCertifiedAccount(t)
			ctx := context.Background()
			password := "correct-password"
			exec := func(q string, args ...interface{}) {
				t.Helper()
				if _, err := c.db.ExecContext(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			want := AutomationCredentialUnknown
			var failure AutomationCredentialFailure
			switch mode {
			case "eligible":
				want = AutomationCredentialEligible
			case "missing-lifetime":
				exec(`DELETE FROM local_automation_lifetimes`)
				want = AutomationCredentialNoLocalProof
			case "invalid-lifetime":
				exec(`UPDATE local_automation_lifetimes SET valid=0`)
				failure = AutomationCredentialProofInvalid
			case "retired-lifetime":
				exec(`UPDATE local_automation_lifetimes SET retired=1`)
				failure = AutomationCredentialProofInvalid
			case "uncertified-birth":
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				if err := InsertUser(ctx, c, "bob", "viewer", string(hash)); err != nil {
					t.Fatal(err)
				}
				a, d, err := PrepareAutomationLocalSession(ctx, c, "bob", password)
				if err != nil || a != nil || d != AutomationCredentialNoLocalProof {
					t.Fatalf("unbound birth: %v %v %v", a, d, err)
				}
				return
			case "missing-alias":
				exec(`DELETE FROM local_automation_aliases`)
				failure = AutomationCredentialProofInvalid
			case "stale-witness":
				exec(`UPDATE local_automation_identities SET witness='stale'`)
				failure = AutomationCredentialProofInvalid
			case "corrupt-head":
				exec(`UPDATE local_automation_semantic_heads SET digest='bad'`)
				failure = AutomationCredentialProofInvalid
			case "malformed-identity":
				exec(`UPDATE local_automation_identities SET uid=?`, strings.Repeat("x", 6*contract.MaxStringBytes+1))
				exec(`UPDATE local_automation_aliases SET uid=?`, strings.Repeat("x", 6*contract.MaxStringBytes+1))
				failure = AutomationCredentialProofInvalid
			case "ambiguous-account":
				u, err := GetUser(ctx, c, "alice")
				if err != nil {
					t.Fatal(err)
				}
				if err := InsertUser(ctx, c, "ALICE", "viewer", u.PasswordHash); err != nil {
					t.Fatal(err)
				}
				failure = AutomationCredentialAuthenticationChanged
			case "required", "unknown-policy":
				value := "local"
				if mode == "unknown-policy" {
					value = "unknown"
				}
				exec(`INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?,?,'fixture','fixture')`, LoginTwoFactorPolicyKey, value)
				want = AutomationCredentialUnsupportedFlow
			case "policy-read-error":
				exec(`DROP TABLE cluster_policies`)
			case "factor-read-error":
				exec(`DROP TABLE user_2fa_sets`)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-password":
				password = "wrong"
				failure = AutomationCredentialAuthenticationChanged
			case "malformed-expiry":
				exec(`INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','expires_at','bad','fixture','fixture')`)
				failure = AutomationCredentialAuthenticationChanged
			}
			a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", password)
			if d != want || (a != nil) != (want == AutomationCredentialEligible) {
				t.Fatalf("disposition=%v auth=%v error=%v want=%v", d, a, err, want)
			}
			if want != AutomationCredentialUnknown {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("failure became successful negative eligibility")
			}
			var typed *AutomationCredentialError
			if failure != 0 && (!errors.As(err, &typed) || typed.Kind != failure) {
				t.Fatalf("wrong failure classification: %T %v", err, err)
			}
			if failure == 0 && errors.As(err, &typed) {
				t.Fatalf("storage/cancel was relabeled: %v", err)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation cause: %v", err)
			}
		})
	}
}

func automationTestSession(id string) SessionRecord {
	now := time.Now().UTC()
	return SessionRecord{ID: id, Username: "alice", Realm: "local", CreatedAt: now.Format(time.RFC3339), LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
}

func TestAutomationCredentialCompositeIssuersAndSplitModes(t *testing.T) {
	for _, mode := range []string{"legacy", "split", "split-clear"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c, _ := lifecycleCertifiedAccountWithGates(t, mode != "legacy", mode == "split-clear")
			a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password")
			if err != nil || d != AutomationCredentialEligible {
				t.Fatalf("prepare %v %v", d, err)
			}
			for _, issuer := range []string{"composite", "basic", "factor", "groups", "no-grant"} {
				s := automationTestSession(issuer)
				s.automationAuthentication = a
				switch issuer {
				case "composite":
					err = InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), a, s, "", nil)
				case "basic":
					err = InsertSession(ctx, c, s)
				case "factor":
					err = InsertSessionWithFactor(ctx, c, lpGrant(t), s, "totp")
				case "groups":
					err = InsertSessionWithLoginData(ctx, c, lpGrant(t), s, "totp", []string{"ops"})
				case "no-grant":
					err = InsertSessionWithLoginData(ctx, c, capabilities.FeatureGrant{}, s, "totp", []string{"ops"})
				}
				if err != nil {
					t.Fatalf("%s issuer: %v", issuer, err)
				}
				p, err := AutomationSessionPrincipal(ctx, c, issuer)
				if err != nil || p.UID != "principal-uid" {
					t.Fatalf("%s provenance: %v %v", issuer, p, err)
				}
				rows, err := c.Query(ctx, `SELECT method FROM session_factors WHERE session_id=?`, issuer)
				if err != nil || (len(rows) != 0) != (issuer == "factor" || issuer == "groups") {
					t.Fatalf("factor carrier/grant %s: %v %v", issuer, rows, err)
				}
				groups, err := SessionGroups(ctx, c, issuer, "local")
				if err != nil || (len(groups) != 0) != (issuer == "groups") {
					t.Fatalf("groups carrier/grant %s: %v %v", issuer, groups, err)
				}
			}
			for _, flow := range []string{"factor", "groups", "realm", "unpinned"} {
				s := automationTestSession("refused-" + flow)
				factor := ""
				var groups []string
				handle := a
				switch flow {
				case "factor":
					factor = "totp"
				case "groups":
					groups = []string{"ops"}
				case "realm":
					s.Realm = "oidc:corp"
				case "unpinned":
					handle, err = AuthenticateAutomationLocalAccount(ctx, c, "alice", "correct-password")
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), handle, s, factor, groups); err == nil {
					t.Fatalf("public wrapper supported %s", flow)
				}
			}
			if err := RevokeSession(ctx, c, "basic"); err != nil {
				t.Fatal(err)
			}
			if _, err := AutomationSessionPrincipal(ctx, c, "basic"); err == nil {
				t.Fatal("revoked session retained proof")
			}
			if _, err := c.db.ExecContext(ctx, `UPDATE sessions SET user_agent='changed' WHERE id='composite'`); err != nil {
				t.Fatal(err)
			}
			if _, err := AutomationSessionPrincipal(ctx, c, "composite"); err == nil || errors.Is(err, ErrAutomationCredentialUnstamped) {
				t.Fatal("invalid present stamp became absent")
			}
			raw := strings.Repeat("a", 64)
			hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertAutomationToken(ctx, c, a, TokenRecord{ID: "token", Username: "alice", TokenHash: string(hash)}); err != nil {
				t.Fatal(err)
			}
			if p, err := AutomationTokenPrincipal(ctx, c, raw); err != nil || p.UID != "principal-uid" {
				t.Fatalf("token provenance: %v %v", p, err)
			}
			q := `UPDATE tokens SET token_hash=token_hash WHERE id='token'`
			if mode != "legacy" {
				q = `UPDATE token_credentials SET token_hash=token_hash WHERE token_id='token'`
			}
			if _, err := c.db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
			if _, err := AutomationTokenPrincipal(ctx, c, raw); err == nil {
				t.Fatal("immutable token mutation retained proof")
			}
		})
	}
}

func TestAutomationCredentialCompositeIssuanceRollsBackChanges(t *testing.T) {
	for _, mode := range []string{"parent", "witness", "uid-pin", "cluster-pin", "policy", "active-factor", "cutoff", "hydration", "composite-after-write"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := lifecycleCertifiedAccount(t)
			ctx := context.Background()
			a, d, err := PrepareAutomationLocalSession(ctx, c, "alice", "correct-password")
			if err != nil || d != AutomationCredentialEligible {
				t.Fatal(d, err)
			}
			exec := func(q string, args ...interface{}) {
				t.Helper()
				if _, err := c.db.ExecContext(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "parent":
				exec(`UPDATE users SET updated_at='changed' WHERE username='alice'`)
			case "witness":
				exec(`DELETE FROM local_automation_lifetimes`)
			case "uid-pin":
				exec(`UPDATE local_automation_identities SET uid='other' WHERE uid='principal-uid'`)
				exec(`UPDATE local_automation_aliases SET uid='other' WHERE uid='principal-uid'`)
			case "cluster-pin":
				a.clusterUID = "other"
			case "policy":
				exec(`INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?,'local','fixture','fixture')`, LoginTwoFactorPolicyKey)
			case "active-factor":
				exec(`INSERT INTO user_2fa_sets(username,active_epoch,updated_at) VALUES('alice','new','fixture')`)
				exec(`INSERT INTO user_2fa(username,method,secret,enrolled_at,updated_at,epoch) VALUES('alice','totp','secret','fixture','fixture','new')`)
			case "cutoff":
				exec(`INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice','sessions_not_before','2099-01-01T00:00:00Z','fixture','fixture')`)
			case "hydration":
				c.MarkCredentialsUnhydrated()
			case "composite-after-write":
				exec(`CREATE TRIGGER corrupt_composite AFTER INSERT ON session_groups BEGIN UPDATE local_automation_aliases SET uid='other'; END`)
			}
			before := localTestMutationLogCount(t, c)
			s := automationTestSession("refused")
			if mode == "composite-after-write" {
				s.automationAuthentication = a
				err = InsertSessionWithLoginData(ctx, c, lpGrant(t), s, "totp", []string{"ops"})
			} else {
				err = InsertAutomationSessionWithLoginData(ctx, c, lpGrant(t), a, s, "", nil)
			}
			if err == nil {
				t.Fatal("changed authentication issued a credential")
			}
			for _, table := range []string{"sessions", "session_factors", "session_groups", "local_automation_credential_issuance"} {
				rows, err := c.Query(ctx, `SELECT count(*) AS n FROM `+table)
				if err != nil || rows[0].Int64("n") != 0 {
					t.Fatalf("rollback left %s: %v %v", table, rows, err)
				}
			}
			if localTestMutationLogCount(t, c) != before {
				t.Fatal("rollback left replication log")
			}
		})
	}
}

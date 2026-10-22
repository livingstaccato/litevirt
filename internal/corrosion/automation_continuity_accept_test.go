package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
	"golang.org/x/crypto/bcrypt"
)

// The identity certificate is a historical prerequisite, not a claim that the
// fresh enrollment provider exists. All origin/session rows use real issuers.
func continuityNativeAccount(t *testing.T) (*claimTestVoter, *AutomationOwnerSession) {
	t.Helper()
	a, _, _, session := continuityNativeFixture(t)
	return a, session
}

func continuityNativeFixture(t *testing.T) (*claimTestVoter, *claimTestVoter, *claimTestVoter, *AutomationOwnerSession) {
	t.Helper()
	ctx := context.Background()
	ca, old, b, c := threeVoters(t)
	db, err := NewLocalClient(t.TempDir(), "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetVoterConfigGate(func() bool { return true })
	db.SetUserIncarnationGate(func() bool { return true })
	inc, err := db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := &claimTestVoter{name: "a", c: db, signer: old.signer, pki: old.pki, inc: inc}
	adoptHandBuilt(t, 1, membersOf(a, b, c), a)
	// Existing custody prerequisite only; this unit does not implement Task5.
	genesisKey, _ := AutomationClaimKey(1)
	installAutomationEvidence(t, db, genesisKey, "", 1)
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "continuity-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetClaimCertificateVerifier(func() *ClaimVerifier { return verifier })
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err = InsertUser(ctx, db, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	origin, err := AutomationLifetime(ctx, db, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	initial := sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", a, b)
	if _, err = applySharedAutomation(t, db, initial, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	body := contract.IdentityEnrollment{Version: 1, Kind: "principal", Alias: "alice", Witness: origin.Witness, EvidenceID: "closed-cutover"}
	raw, _ := json.Marshal(body)
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "principal-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "principal-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: "established-cluster", Kind: "principal", Alias: "alice", Witness: origin.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	d := contract.Decision{Sequence: 2, ParentDigest: initial.Value.MustDigest(), Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: "principal-request", Body: raw}, Assignment: assignment}
	encoded, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	key, _ := AutomationClaimKey(2)
	ballot := testBallot(2, "a")
	record := AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
	for _, v := range []*claimTestVoter{a, b} {
		vote, err := v.signer.Sign(key, 1, ballot, value.MustDigest(), v.inc)
		if err != nil {
			t.Fatal(err)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, vote)
	}
	if err = verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(a, b, c), Quorum: 2}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := applySharedAutomation(t, db, record, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" {
		t.Fatalf("historical prerequisite: %+v %v", receipt, err)
	}
	if cfg, err := db.AutomationMembership(ctx); err != nil || cfg.Generation != 1 {
		t.Fatalf("current authority prerequisite: %+v %v", cfg, err)
	}
	auth, disposition, err := PrepareAutomationLocalSession(ctx, db, "alice", "correct-password")
	if err != nil || disposition != AutomationCredentialEligible {
		t.Fatalf("real password login: %v %v", disposition, err)
	}
	if err = InsertAutomationSessionWithLoginData(ctx, db, lpGrant(t), auth, automationTestSession("continuity-session"), "", nil); err != nil {
		t.Fatal(err)
	}
	identity, session, err := AuthenticateAutomationOwnerSession(ctx, db, "continuity-session", time.Hour)
	if err != nil || identity.UID != "principal-uid" {
		t.Fatalf("real local session: %+v %v", identity, err)
	}
	return a, b, c, session
}

func TestContinuityNativePreparationFromGenuineSession(t *testing.T) {
	a, session := continuityNativeAccount(t)
	prepared, err := PrepareAutomationIdentityContinuity(context.Background(), a.c, session, "principal", "principal-uid", "retained-request")
	if err != nil || prepared == nil {
		t.Fatalf("genuine native continuity preparation unavailable: %v", err)
	}
}

func continuityTestValue(t *testing.T, a *claimTestVoter, p *AutomationIdentityContinuity) (ClaimKey, ClaimValue) {
	t.Helper()
	h, err := a.c.AutomationHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	facts := p.Facts()
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: facts.ClusterUID, OperationID: "continuity-op", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Continuity: &facts})
	d := contract.Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: p.Command(), Assignment: assignment}
	encoded, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := AutomationClaimKey(d.Sequence)
	return key, ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
}

func TestContinuityNativeFULLAccept(t *testing.T) {
	a, session := continuityNativeAccount(t)
	ctx := context.Background()
	p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "principal", "principal-uid", "retained-request")
	if err != nil {
		t.Fatal(err)
	}
	// Unit prerequisite only. Real checker/daemon tests own barrier causality.
	a.c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
		return write(ctx, capabilities.GrantForTest(t, f))
	})
	key, value := continuityTestValue(t, a, p)
	result, err := a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(4, "a"), value, 1, a.signer, p)
	if err != nil || !result.Accepted || result.Accept == nil {
		t.Fatalf("genuine native FULL Accept unavailable: %+v %v", result, err)
	}
	state, found, err := a.c.ClaimState(ctx, key)
	if err != nil || !found || state.Accept == nil || state.ValueDigest != value.MustDigest() {
		t.Fatalf("success before durable exact signed row: %+v %v", state, err)
	}
}

func TestContinuityNativeRechecksGenuineCurrentAuthority(t *testing.T) {
	for _, mode := range []string{"rotation", "revoked", "expired", "idle", "cutoff", "factor-policy", "missing-origin", "wrong-witness", "wrong-alias", "held-newer", "wrong-generation", "wrong-principal", "wrong-realm", "parent-recreated", "gate-missing", "zero-grant", "foreign-grant", "wrong-selected", "before-commit"} {
		t.Run(mode, func(t *testing.T) {
			a, session := continuityNativeAccount(t)
			ctx := context.Background()
			p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "principal", "principal-uid", "retained-request")
			if err != nil {
				t.Fatal(err)
			}
			key, value := continuityTestValue(t, a, p)
			a.c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
				g := capabilities.GrantForTest(t, f)
				if mode == "zero-grant" {
					g = capabilities.FeatureGrant{}
				}
				if mode == "foreign-grant" {
					g = capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
				}
				return write(ctx, g)
			})
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := a.c.db.ExecContext(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "rotation":
				if err = UpdateUserPassword(ctx, a.c, "alice", "rotated-hash"); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				exec(`UPDATE sessions SET revoked_at='revoked' WHERE id='continuity-session'`)
			case "expired":
				exec(`UPDATE sessions SET expires_at='2020-01-01T00:00:00Z' WHERE id='continuity-session'`)
			case "idle":
				exec(`UPDATE sessions SET last_used_at='2020-01-01T00:00:00Z' WHERE id='continuity-session'`)
			case "cutoff":
				exec(`INSERT INTO user_lifecycle(username,attribute,value,set_by,updated_at) VALUES('alice',?,'2099-01-01T00:00:00Z','test','test')`, UserAttrSessionsNotBefore)
			case "factor-policy":
				exec(`INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?,'local','test','test')`, LoginTwoFactorPolicyKey)
			case "missing-origin":
				exec(`DELETE FROM local_automation_lifetimes`)
			case "wrong-alias":
				exec(`UPDATE local_automation_identities SET alias='another'`)
			case "held-newer":
				stmts, e := json.Marshal([]Statement{{SQL: sessionsInsertSQL, Params: []interface{}{"future-session", "alice", "local", "", "", nowRFC3339(), nowRFC3339(), nowRFC3339()}, Guard: &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "alice", Incarnation: nextIncarnation(p.facts.Parent.Birth)}}})
				if e != nil {
					t.Fatal(e)
				}
				receiver := NewReplicator(a.c, "", RelayConfig{})
				if _, e = receiver.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: a.c.NowTS(), Origin: "peer", Stmts: string(stmts)}}); e != nil {
					t.Fatal(e)
				}
				if a.c.UserHolds() == 0 {
					t.Fatal("actual newer incarnation was not held")
				}
			case "wrong-witness":
				exec(`UPDATE local_automation_identities SET witness='another'`)
			case "wrong-generation":
				exec(`UPDATE local_automation_identities SET generation=2`)
			case "wrong-principal":
				exec(`UPDATE local_automation_credential_issuance SET principal_uid='another'`)
			case "wrong-realm":
				exec(`UPDATE users SET realm='remote' WHERE username='alice'`)
			case "parent-recreated":
				if err = DeleteUser(ctx, a.c, "alice"); err != nil {
					t.Fatal(err)
				}
				if err = InsertUser(ctx, a.c, "alice", "operator", "new-hash"); err != nil {
					t.Fatal(err)
				}
			case "gate-missing":
				a.c.SetReleaseFeatureGate(nil)
			case "wrong-selected":
				d, err := automationDecision(value)
				if err != nil {
					t.Fatal(err)
				}
				d.Command.RequestID = "another-request"
				raw, err := contract.EncodeDecision(d)
				if err != nil {
					t.Fatal(err)
				}
				value.Automation.Envelope = raw
			case "before-commit":
				a.c.automationSeams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { return context.Canceled }}
			}
			result, err := a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(4, "a"), value, 1, a.signer, p)
			if mode == "rotation" {
				if err != nil || !result.Accepted {
					t.Fatalf("same-account rotation denied: %+v %v", result, err)
				}
				return
			}
			if err == nil && result.Accepted {
				t.Fatalf("stale/missing native authority signed: %+v", result)
			}
			a.c.automationSeams = nil
			state, found, err := a.c.ClaimState(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			if found && (state.Accept != nil || state.Value != nil) {
				t.Fatalf("refusal left acceptance: %+v", state)
			}
		})
	}
}

func TestContinuityNativeLostReplyReopensExactAcceptedBytes(t *testing.T) {
	a, session := continuityNativeAccount(t)
	ctx := context.Background()
	p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "principal", "principal-uid", "retained-request")
	if err != nil {
		t.Fatal(err)
	}
	key, value := continuityTestValue(t, a, p)
	a.c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
		return write(ctx, capabilities.GrantForTest(t, f))
	})
	lost := new(int)
	a.c.automationSeams = &localCommitSeams{beforeReply: func() { panic(lost) }}
	func() {
		defer func() {
			if recover() != lost {
				t.Fatal("lost-reply seam not reached")
			}
		}()
		_, _ = a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(9, "a"), value, 1, a.signer, p)
	}()
	dir := a.c.dataDir
	a.c.automationSeams = nil
	a.c.Close()
	reopened, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	row, found, err := reopened.ClaimState(ctx, key)
	if err != nil || !found || row.Value == nil || row.ValueDigest != value.MustDigest() || row.Value.MustDigest() != value.MustDigest() || row.Accept == nil || !row.Accepted.Equal(testBallot(9, "a")) {
		t.Fatalf("durable accepted bytes lost: %+v %v", row, err)
	}
}

func TestContinuityReleaseProofInvocationAndCurrentBinding(t *testing.T) {
	for _, mode := range []string{"live", "released", "copied", "foreign-client", "factory-change", "incarnation-change", "authority-change", "unsigned-own-row"} {
		t.Run(mode, func(t *testing.T) {
			a, session := continuityNativeAccount(t)
			ctx := context.Background()
			n, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "principal", "principal-uid", "retained-request")
			if err != nil {
				t.Fatal(err)
			}
			key, value := continuityTestValue(t, a, n)
			a.c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
				return write(ctx, capabilities.GrantForTest(t, f))
			})
			accepted, err := a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(5, "a"), value, 1, a.signer, n)
			if err != nil || !accepted.Accepted {
				t.Fatal("native prerequisite", err)
			}
			proof, release, err := a.c.prepareContinuityProof(ctx, continuityLocal, key, value, 1, ClaimCertificate{}, a.signer)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			exec := func(q string) {
				t.Helper()
				if _, e := a.c.db.ExecContext(ctx, q); e != nil {
					t.Fatal(e)
				}
			}
			target := a.c
			switch mode {
			case "released":
				release()
			case "copied":
				duplicate := new(AutomationContinuityReleaseEvidence)
				reflect.ValueOf(duplicate).Elem().Set(reflect.ValueOf(proof).Elem())
				proof = duplicate
			case "foreign-client":
				other, e := NewLocalClient(t.TempDir(), "other")
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				target = other
			case "factory-change":
				factory := a.c.claimCertVerifier.Load()
				a.c.SetClaimCertificateVerifier(*factory)
			case "incarnation-change":
				exec(`UPDATE local_voter_incarnation SET incarnation='changed'`)
			case "authority-change":
				exec(`UPDATE local_automation_authority SET members_hash='changed'`)
			case "unsigned-own-row":
				if e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					r, _, e := loadClaimRowTx(ctx, tx, key)
					if e != nil {
						return e
					}
					r.Accept = nil
					return saveClaimRowTx(ctx, tx, r)
				}); e != nil {
					t.Fatal(e)
				}
			}
			err = target.ValidateAutomationContinuityReleaseEvidence(ctx, proof)
			if mode == "live" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("stale, foreign or unsigned evidence restored authority")
			}
		})
	}
}

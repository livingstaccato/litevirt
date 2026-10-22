package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth/policy"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// Certified identity history is a prerequisite, not fresh enrollment. Project
// parent/origin and authenticated session come from their real local writers.
func continuityNativeProject(t *testing.T, legacy bool) (*claimTestVoter, *AutomationOwnerSession) {
	t.Helper()
	ctx := context.Background()
	a, b, _, session := continuityNativeFixture(t)
	a.c.SetProjectIncarnationGate(func() bool { return !legacy })
	if err := InsertProject(ctx, a.c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	origin, err := AutomationLifetime(ctx, a.c, "project", "/acme")
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		a.c.SetProjectIncarnationGate(func() bool { return true })
		if ok, e := AdoptProjectIncarnation(ctx, a.c, adoptGrant(t), "/acme"); e != nil || !ok {
			t.Fatalf("real project adoption: %v %v", ok, e)
		}
	}
	h, err := a.c.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: "project", Alias: "/acme", Witness: origin.Witness, EvidenceID: "closed-project-cutover"})
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: h.ClusterUID, OperationID: "project-op", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Identity: &contract.IdentityAssignment{UID: "project-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "closed-project-cutover", ClusterUID: h.ClusterUID, Kind: "project", Alias: "/acme", Witness: origin.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	d := contract.Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: contract.Command{Kind: "assign_identity", ClusterUID: h.ClusterUID, PrincipalID: "host", RequestID: "project-request", Body: body}, Assignment: assignment}
	raw, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	v := ClaimValue{Automation: &AutomationClaimValue{Envelope: raw}}
	key, _ := AutomationClaimKey(d.Sequence)
	ballot := testBallot(3, "a")
	record := AutomationRecord{Value: v, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: v.MustDigest()}}
	for _, voter := range []*claimTestVoter{a, b} {
		vote, e := voter.signer.Sign(key, 1, ballot, v.MustDigest(), voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, vote)
	}
	if receipt, e := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); e != nil || receipt.Code != "" {
		t.Fatalf("certified project prerequisite: %+v %v", receipt, e)
	}
	a.c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
		return write(ctx, capabilities.GrantForTest(t, f))
	})
	return a, session
}

func TestAutomationProjectNativeFULLAccept(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "birth"
		if legacy {
			name = "adopted"
		}
		t.Run(name, func(t *testing.T) {
			a, session := continuityNativeProject(t, legacy)
			ctx := context.Background()
			if e := InsertRole(ctx, a.c, RoleRecord{Name: "ProjectOwner", Verbs: []string{policy.OwnerManage}}); e != nil {
				t.Fatal(e)
			}
			id, e := ProjectBindingID(ctx, a.c, "/projects/acme", "genuine-owner")
			if e != nil {
				t.Fatal(e)
			}
			if e = InsertRoleBinding(ctx, a.c, RoleBindingRecord{ID: id, Path: "/projects/acme", Role: "ProjectOwner", Principal: "user:alice@local", Propagate: true}); e != nil {
				t.Fatal(e)
			}
			p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "project", "project-uid", "project-retained-request")
			if err != nil || p == nil {
				t.Fatalf("genuine project preparation: %v", err)
			}
			if p.Command().ProjectUID != "project-uid" || p.Command().PrincipalID != "principal-uid" || p.Facts().Parent.Kind != "project" || p.Facts().Parent.Alias != "/acme" {
				t.Fatalf("project/principal scope confused: %+v %+v", p.Command(), p.Facts())
			}
			key, value := continuityTestValue(t, a, p)
			accepted, err := a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(5, "a"), value, 1, a.signer, p)
			if err != nil || !accepted.Accepted || accepted.Accept == nil {
				t.Fatalf("project native FULL refused: %+v %v", accepted, err)
			}
			state, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || state.Accept == nil || state.ValueDigest != value.MustDigest() {
				t.Fatalf("missing durable exact signed project row: %+v %v", state, err)
			}
		})
	}
}

func TestAutomationProjectNativeRechecksScopeAndParent(t *testing.T) {
	for _, mode := range []string{"denied", "held-binding", "unrelated-binding", "permission-change", "revoked", "missing-origin", "invalid-origin", "unadopted", "ambiguity", "rebirth", "wrong-generation", "wrong-witness", "held-newer-principal", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			a, session := continuityNativeProject(t, false)
			p, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "project", "project-uid", "project-retained-request")
			if err != nil {
				t.Fatal(err)
			}
			key, value := continuityTestValue(t, a, p)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, e := a.c.db.ExecContext(ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "denied", "held-binding", "unrelated-binding", "permission-change":
				role, id, path := SentinelRole, "deny", "/projects/acme"
				if mode == "held-binding" || mode == "permission-change" {
					role = "Owner"
					if e := InsertRole(ctx, a.c, RoleRecord{Name: role, Verbs: []string{policy.OwnerManage}}); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "held-binding" {
					id = "held~p:r0123456789abcdef0123456789abcdef"
				}
				if mode == "unrelated-binding" {
					path = "/projects/elsewhere"
				}
				if mode == "held-binding" {
					// Use the project owner's older-grant fixture: ordinary replicated
					// insertion models a late prior-incarnation binding, without bypassing
					// the modern tagged originating writer's refusal.
					if e := a.c.Execute(ctx, roleBindingInsertSQL, id, path, role, "user:alice@local", 1, a.c.NowTS()); e != nil {
						t.Fatal(e)
					}
				} else if e := InsertRoleBinding(ctx, a.c, RoleBindingRecord{ID: id, Path: path, Role: role, Principal: "user:alice@local", Propagate: true}); e != nil {
					t.Fatal(e)
				}
				if mode == "permission-change" {
					if e := DeleteRoleBinding(ctx, a.c, id); e != nil {
						t.Fatal(e)
					}
					tagged, e := ProjectBindingID(ctx, a.c, path, "current-owner")
					if e != nil {
						t.Fatal(e)
					}
					if e = InsertRoleBinding(ctx, a.c, RoleBindingRecord{ID: tagged, Path: path, Role: role, Principal: "user:alice@local", Propagate: true}); e != nil {
						t.Fatal(e)
					}
					if e = p.Authorize(ctx); e != nil {
						t.Fatalf("current scoped owner prerequisite: %v", e)
					}
					if e = InsertRole(ctx, a.c, RoleRecord{Name: role, Verbs: []string{"vm.read"}}); e != nil {
						t.Fatal(e)
					}
				}
			case "revoked":
				exec(`UPDATE sessions SET revoked_at='revoked' WHERE id='continuity-session'`)
			case "missing-origin":
				exec(`DELETE FROM local_automation_lifetimes WHERE kind='project'`)
			case "invalid-origin":
				exec(`UPDATE local_automation_lifetimes SET valid=0 WHERE kind='project'`)
			case "unadopted":
				exec(`UPDATE projects SET incarnation='' WHERE name='/acme'`)
			case "ambiguity":
				a.c.SetProjectIncarnationGate(nil)
				if e := InsertProject(ctx, a.c, ProjectRecord{Name: "acme"}); e != nil {
					t.Fatal(e)
				}
			case "rebirth":
				if e := DeleteProject(ctx, a.c, "/acme"); e != nil {
					t.Fatal(e)
				}
				if e := InsertProject(ctx, a.c, ProjectRecord{Name: "/acme"}); e != nil {
					t.Fatal(e)
				}
			case "wrong-generation":
				exec(`UPDATE local_automation_identities SET generation=2 WHERE uid='project-uid'`)
			case "wrong-witness":
				exec(`UPDATE local_automation_identities SET witness='another' WHERE uid='project-uid'`)
			case "held-newer-principal":
				user, e := GetUser(ctx, a.c, "alice")
				if e != nil {
					t.Fatal(e)
				}
				raw, e := json.Marshal([]Statement{{SQL: sessionsInsertSQL, Params: []interface{}{"future-project-session", "alice", "local", "", "", nowRFC3339(), nowRFC3339(), nowRFC3339()}, Guard: &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "alice", Incarnation: nextIncarnation(user.CreatedAt)}}})
				if e != nil {
					t.Fatal(e)
				}
				if _, e = NewReplicator(a.c, "", RelayConfig{}).ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: a.c.NowTS(), Origin: "held-principal", Stmts: string(raw)}}); e != nil {
					t.Fatal(e)
				}
				if a.c.UserHolds() == 0 {
					t.Fatal("actual newer principal not held")
				}
			case "rollback":
				a.c.automationSeams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { return context.Canceled }}
			}
			accepted, e := a.c.ClaimAcceptContinuityNative(ctx, key, testBallot(5, "a"), value, 1, a.signer, p)
			if e == nil && accepted.Accepted {
				t.Fatalf("changed authority accepted: %+v", accepted)
			}
			state, found, e := a.c.ClaimState(ctx, key)
			if e != nil || found && state.Accept != nil {
				t.Fatalf("refusal left durable vote: %+v %v", state, e)
			}
		})
	}
}

func TestAutomationProjectNativeRequiresCurrentScopedPermissionAtPrepare(t *testing.T) {
	a, session := continuityNativeProject(t, false)
	ctx := context.Background()
	if err := InsertRoleBinding(ctx, a.c, RoleBindingRecord{ID: "deny", Path: "/projects/acme", Role: SentinelRole, Principal: "user:alice@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareAutomationIdentityContinuity(ctx, a.c, session, "project", "project-uid", "denied-request"); !errors.Is(err, ErrAutomationOwnerPermission) {
		t.Fatalf("preparation lost explicit scoped denial: %v", err)
	}
}

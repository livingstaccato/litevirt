package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"modernc.org/sqlite"
)

func continuityLoginDeliver(t *testing.T, from, to *continuityNode) {
	t.Helper()
	ctx := context.Background()
	// Account/project/policy delivery is ordinary replication. Login's private
	// session must be issued independently at the destination.
	rows, err := from.d.db.Query(ctx, `SELECT seq,hlc,origin,stmts FROM mutation_log WHERE stmts NOT LIKE '%sessions%' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var entries []*pb.MutationEntry
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{Seq: r.Int64("seq"), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts")})
	}
	rep := corrosion.NewReplicator(to.d.db, to.d.cfg.PKIDir, corrosion.RelayConfig{})
	if _, err := rep.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatal(err)
	}
}
func continuityLoginSQL(t *testing.T, n *continuityNode, q string, args ...any) {
	t.Helper()
	if _, err := n.d.db.DB().ExecContext(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}
func continuityLoginCount(t *testing.T, n *continuityNode, table string) int64 {
	t.Helper()
	rows, err := n.d.db.Query(context.Background(), `SELECT count(*) AS n FROM `+table)
	if err != nil {
		t.Fatal(err)
	}
	return rows[0].Int64("n")
}
func continuityLoginSecondEntry(t *testing.T, project bool) (*continuityNode, *continuityNode) {
	t.Helper()
	nodes := continuityDaemonCluster(t)
	a, b := nodes[0], nodes[1]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine, err := a.s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	if project {
		p := continuityDaemonProject(t, nodes)
		if _, err := continuityDaemonCertifyRetained(t, ctx, engine, p); err != nil {
			t.Fatal(err)
		}
	}
	p := continuityDaemonRequest(t, a, "principal", "principal-uid", "independent-login-continuity")
	if _, err := continuityDaemonCertifyRetained(t, ctx, engine, p); err != nil {
		t.Fatal(err)
	}
	continuityLoginDeliver(t, a, b)
	if project {
		b.d.db.SetProjectIncarnationGate(func() bool { return true })
	}
	for _, table := range []string{"local_automation_lifetimes", "local_automation_credential_issuance", "sessions"} {
		if n := continuityLoginCount(t, b, table); n != 0 {
			t.Fatalf("second entry imported private authority %s: %d", table, n)
		}
	}
	return a, b
}
func continuityLoginPublic(t *testing.T, n *continuityNode, password string) *pb.LoginResponse {
	t.Helper()
	r, err := n.s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: password, Realm: "local"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func continuityLoginPrincipal(t *testing.T, n *continuityNode, r *pb.LoginResponse) {
	t.Helper()
	i, err := corrosion.AutomationSessionPrincipal(context.Background(), n.d.db, strings.TrimPrefix(r.GetToken(), "lvs_"))
	if err != nil || i == nil || i.UID != "principal-uid" {
		t.Fatalf("independent genuine Login has no certified provenance: %+v %v", i, err)
	}
}

// Existing enrollment/custody is explicit fixture input. Continuity certification,
// ordinary account delivery and public second-entry Login use production owners.
// This does not claim fresh enrollment, two-copy readiness or HA activation.
func TestAutomationContinuityLogin(t *testing.T) {
	for _, mode := range []string{"independent_session", "no_private_row_copy", "missing_clean_proof", "invalid_present_proof", "storage_cause", "session_insert_parent_change", "session_insert_rollback", "rotation_keeps_uid_access", "rebirth_refuses", "lost_stamp_requires_login", "explicit_scope_denial"} {
		t.Run(mode, func(t *testing.T) {
			a, b := continuityLoginSecondEntry(t, mode == "explicit_scope_denial")
			ctx := context.Background()
			switch mode {
			case "missing_clean_proof":
				continuityLoginSQL(t, b, `DELETE FROM local_automation_identity_continuity`)
				a, d, err := corrosion.PrepareAutomationLocalSession(ctx, b.d.db, "alice", "correct-password")
				if err != nil || a != nil || d != corrosion.AutomationCredentialNoLocalProof {
					t.Fatal(a, d, err)
				}
				r := continuityLoginPublic(t, b, "correct-password")
				if _, err := corrosion.AutomationSessionPrincipal(ctx, b.d.db, strings.TrimPrefix(r.Token, "lvs_")); !errors.Is(err, corrosion.ErrAutomationCredentialUnstamped) {
					t.Fatal("missing clean proof promoted", err)
				}
				return
			case "invalid_present_proof":
				continuityLoginSQL(t, b, `UPDATE local_automation_identity_continuity SET parent_kind='vm'`)
				a, d, err := corrosion.PrepareAutomationLocalSession(ctx, b.d.db, "alice", "correct-password")
				var proof *corrosion.AutomationCredentialError
				if a != nil || d != corrosion.AutomationCredentialUnknown || !errors.As(err, &proof) || proof.Kind != corrosion.AutomationCredentialProofInvalid {
					t.Fatal("invalid selected proof became absent", a, d, err)
				}
				if r, err := b.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"}); r != nil || status.Code(err) != codes.Unavailable {
					t.Fatal("invalid proof fell through public Login", r, err)
				}
				return
			case "storage_cause":
				continuityLoginSQL(t, b, `DROP TABLE local_automation_identity_continuity`)
				a, d, err := corrosion.PrepareAutomationLocalSession(ctx, b.d.db, "alice", "correct-password")
				var cause *sqlite.Error
				var proof *corrosion.AutomationCredentialError
				if a != nil || d != corrosion.AutomationCredentialUnknown || !errors.As(err, &cause) || errors.As(err, &proof) {
					t.Fatal("storage lost driver cause", a, d, err)
				}
				if r, err := b.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"}); r != nil || status.Code(err) != codes.Unavailable {
					t.Fatal(r, err)
				}
				return
			case "session_insert_parent_change", "session_insert_rollback":
				before := continuityLoginCount(t, b, "mutation_log")
				change := `UPDATE users SET updated_at='changed' WHERE username=NEW.username;`
				if mode == "session_insert_rollback" {
					change = `SELECT RAISE(ABORT,'injected later insert failure');`
				}
				continuityLoginSQL(t, b, `CREATE TRIGGER independent_login_change AFTER INSERT ON sessions BEGIN `+change+` END`)
				if r, err := b.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"}); r != nil || status.Code(err) != codes.Unavailable {
					t.Fatal("composite issuance escaped change", r, err)
				}
				for _, table := range []string{"sessions", "session_factors", "session_groups", "local_automation_credential_issuance"} {
					if n := continuityLoginCount(t, b, table); n != 0 {
						t.Fatal("rollback retained rows", table, n)
					}
				}
				if continuityLoginCount(t, b, "mutation_log") != before {
					t.Fatal("rollback logged credential")
				}
				return
			}
			r := continuityLoginPublic(t, b, "correct-password")
			continuityLoginPrincipal(t, b, r)
			switch mode {
			case "rotation_keeps_uid_access":
				hash, err := bcrypt.GenerateFromPassword([]byte("rotated-password"), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				if err := corrosion.UpdateUserPassword(ctx, b.d.db, "alice", string(hash)); err != nil {
					t.Fatal(err)
				}
				continuityLoginPrincipal(t, b, r)
				if old, err := b.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"}); old != nil || status.Code(err) != codes.Unauthenticated {
					t.Fatal("old password freshly authenticated", old, err)
				}
				continuityLoginPrincipal(t, b, continuityLoginPublic(t, b, "rotated-password"))
			case "rebirth_refuses":
				if err := corrosion.DeleteUser(ctx, b.d.db, "alice"); err != nil {
					t.Fatal(err)
				}
				hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				if err := corrosion.InsertUser(ctx, b.d.db, "alice", "operator", string(hash)); err != nil {
					t.Fatal(err)
				}
				if _, err := corrosion.AutomationSessionPrincipal(ctx, b.d.db, strings.TrimPrefix(r.Token, "lvs_")); err == nil {
					t.Fatal("rebirth inherited session")
				}
				if next, err := b.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password"}); next != nil || status.Code(err) != codes.Unavailable {
					t.Fatal("rebirth inherited certified UID", next, err)
				}
				return
			case "lost_stamp_requires_login":
				continuityLoginSQL(t, b, `DELETE FROM local_automation_credential_issuance`)
				if _, err := corrosion.AutomationSessionPrincipal(ctx, b.d.db, strings.TrimPrefix(r.Token, "lvs_")); !errors.Is(err, corrosion.ErrAutomationCredentialUnstamped) {
					t.Fatal("lost stamp retained authority", err)
				}
				continuityLoginPrincipal(t, b, continuityLoginPublic(t, b, "correct-password"))
			case "explicit_scope_denial":
				_, session, err := corrosion.AuthenticateAutomationOwnerSession(ctx, b.d.db, strings.TrimPrefix(r.Token, "lvs_"), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				command := contract.Command{Kind: "ensure_owner", ClusterUID: "continuity-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "independent-owner", RequestID: "independent-owner-request", Body: []byte(`{"version":1}`)}
				submission, err := corrosion.NewAutomationOwnerSubmission(ctx, session, command, "")
				if err != nil {
					t.Fatal("current scoped OwnerManage with project continuity", err)
				}
				if err := corrosion.InsertRole(ctx, b.d.db, corrosion.RoleRecord{Name: "ProjectOwner", Verbs: []string{"vm.read"}}); err != nil {
					t.Fatal(err)
				}
				if err := submission.Authorize(ctx); !errors.Is(err, corrosion.ErrAutomationOwnerPermission) {
					t.Fatal("explicit scope denial fell back to operator", err)
				}
				if err := corrosion.InsertRole(ctx, b.d.db, corrosion.RoleRecord{Name: "ProjectOwner", Verbs: []string{"automation.owner.manage"}}); err != nil {
					t.Fatal(err)
				}
				if err := submission.Authorize(ctx); err != nil {
					t.Fatal("current scoped grant did not restore access", err)
				}
				// Principal continuity cannot replace absent or invalid project provenance.
				continuityLoginSQL(t, b, `UPDATE local_automation_identity_continuity SET parent_kind='vm' WHERE uid='project-uid'`)
				var proof *corrosion.AutomationCredentialError
				if err := submission.Authorize(ctx); !errors.As(err, &proof) || proof.Kind != corrosion.AutomationCredentialProofInvalid {
					t.Fatal("malformed selected project proof fell back", err)
				}
				continuityLoginSQL(t, b, `DELETE FROM local_automation_identity_continuity WHERE uid='project-uid'`)
				if err := submission.Authorize(ctx); !errors.As(err, &proof) {
					t.Fatal("principal Login bypassed missing project provenance", err)
				}
				// The origin owner supplies its own genuine project observation. Selected
				// malformed continuity must refuse even with that matching valid origin.
				ar := continuityLoginPublic(t, a, "correct-password")
				_, as, err := corrosion.AuthenticateAutomationOwnerSession(ctx, a.d.db, strings.TrimPrefix(ar.Token, "lvs_"), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				originSubmission, err := corrosion.NewAutomationOwnerSubmission(ctx, as, command, "")
				if err != nil {
					t.Fatal("genuine origin project owner", err)
				}
				continuityLoginSQL(t, a, `UPDATE local_automation_identity_continuity SET parent_birth='wrong-parent' WHERE uid='project-uid'`)
				if err := originSubmission.Authorize(ctx); !errors.As(err, &proof) || proof.Kind != corrosion.AutomationCredentialProofInvalid {
					t.Fatal("invalid selected project continuity fell back to valid origin", err)
				}

			}
			if mode != "rebirth_refuses" && continuityLoginCount(t, b, "local_automation_lifetimes") != 0 {
				t.Fatal("Login minted private origin")
			}
		})
	}
}

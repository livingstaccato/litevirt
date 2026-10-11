package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The last-admin guard fails CLOSED on a replica that holds a reinstated
// admin's users row but not yet its credential row. Once credentials_clear_v1
// has latched, the reinstatement writes "" in the old column and the
// ReinstatedAdminPasswordHash sentinel only in the credential row, which
// replicates separately: until it arrives, the account resolves to "" here and
// cannot be told from a usable admin. The guard does not count it — the
// change is refused with a retry message — so the only admin who can log in
// is never deleted, disabled or expired on the strength of an account that
// cannot. Once the row arrives, the ordinary last-admin refusal applies.
//
// Mutation: count an account whose credential this node cannot judge (as
// before) — every case goes red, and the delete removes alice.
func TestLastAdminGuard_FailsClosedWhileAReinstatedCredentialIsInFlight(t *testing.T) {
	s := loginPolicyServer(t)
	s.db.SetCredentialsSplitGate(func() bool { return true })
	s.db.SetCredentialsClearGate(func() bool { return true })
	ctx := context.Background()
	seedUser(t, s, "alice", "admin", "alice-pw")
	seedUser(t, s, "oldops", "admin", "old-pw")
	rawDelete(t, s, "oldops")
	writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "true")
	if who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db, s.withLoginPolicyIfAvailable); err != nil || who != "oldops" {
		t.Fatalf("floor reinstated %q, %v; want oldops", who, err)
	}
	writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "false")
	// This replica: the reinstated users row, not yet its credential row.
	if err := s.db.Execute(ctx, `DELETE FROM user_credentials WHERE username = 'oldops'`); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.db.Query(ctx, `SELECT password_hash FROM users WHERE username = 'oldops'`); len(rows) != 1 || rows[0].String("password_hash") != "" {
		t.Fatalf("setup: oldops's old column = %v; want the cleared \"\"", rows)
	}

	yes := true
	never := "2099-01-01T00:00:00Z"
	calls := map[string]func() error{
		"delete": func() error {
			_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
			return err
		},
		"disable": func() error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes})
			return err
		},
		"expire": func() error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", ExpiresAt: &never})
			return err
		},
	}
	for what, call := range calls {
		err := call()
		wantCode(t, what+" of the only admin who can log in, beside an admin whose credential is in flight", err, codes.Unavailable)
		wantMessage(t, what+" refusal", err, `"oldops"`, "Retry in a moment")
	}
	if u, _ := corrosion.GetUser(ctx, s.db, "alice"); u == nil {
		t.Fatal("alice was deleted")
	}
	if l, _ := corrosion.GetUserLifecycle(ctx, s.db, "alice"); !l.Unrestricted() {
		t.Fatalf("alice was restricted: %+v", l)
	}

	// The credential row arrives: the sentinel, so the ordinary refusal.
	if err := s.db.Execute(ctx, `INSERT INTO user_credentials (username, password_hash, updated_at, deleted_at) VALUES ('oldops', ?, ?, NULL)`,
		corrosion.ReinstatedAdminPasswordHash, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	for what, call := range calls {
		err := call()
		wantCode(t, what+" once the sentinel arrived", err, codes.FailedPrecondition)
		wantMessage(t, what+" refusal", err, "lv user reset-admin --user oldops")
	}
}

// Before credentials_clear_v1 has latched (and nothing in this database shows
// a clear), an empty old column can only be a directory admin's: only a clear
// empties a local one. So an admin this node holds no evidence for — bob, a
// directory admin first seen on another node mid-rolling-upgrade — counts, and
// deleting, disabling or expiring the other admin goes through, as on main.
//
// Mutation: fail closed on an unjudgeable admin whatever the clear latch (as
// before this fix) — every case is refused with Unavailable.
func TestLastAdminGuard_BeforeTheClearADirectoryAdminCounts(t *testing.T) {
	yes := true
	never := "2099-01-01T00:00:00Z"
	for what, call := range map[string]func(s *Server) error{
		"disable": func(s *Server) error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes})
			return err
		},
		"expire": func(s *Server) error {
			_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", ExpiresAt: &never})
			return err
		},
		"delete": func(s *Server) error {
			_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
			return err
		},
	} {
		for _, split := range []bool{false, true} {
			s := loginPolicyServer(t)
			s.db.SetCredentialsSplitGate(func() bool { return split })
			ctx := context.Background()
			seedUser(t, s, "alice", "admin", "alice-pw")
			// bob: a directory admin's row, with no credential row and no
			// evidence on this node (materialised on another node).
			if err := corrosion.InsertUser(ctx, s.db, "bob", "admin", ""); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(ctx, `DELETE FROM user_credentials WHERE username = 'bob'`); err != nil {
				t.Fatal(err)
			}
			if err := call(s); err != nil {
				t.Errorf("%s of alice beside directory admin bob (split gate %v, clear not latched): %v; want allowed, as on main",
					what, split, err)
			}
		}
	}
}

// A peer may latch credentials_clear_v1 first: its cleared rows replicate here
// before this node's own latch. Such a row (an empty old column beside a live
// credential) shows a clear has happened, so an admin this node cannot judge
// is in doubt again and the guard fails closed.
//
// Mutation: consult only this node's clear latch — the change goes through.
func TestLastAdminGuard_APeersClearSeenHereFailsClosed(t *testing.T) {
	s := loginPolicyServer(t)
	s.db.SetCredentialsSplitGate(func() bool { return true })
	ctx := context.Background()
	seedUser(t, s, "alice", "admin", "alice-pw")
	seedUser(t, s, "carol", "operator", "carol-pw")
	// carol's row as a peer that cleared it wrote it.
	if err := s.db.Execute(ctx, `UPDATE users SET password_hash = '' WHERE username = 'carol'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, s.db, "bob", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `DELETE FROM user_credentials WHERE username = 'bob'`); err != nil {
		t.Fatal(err)
	}
	yes := true
	_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes})
	wantCode(t, "disable of alice beside an unjudgeable bob, a peer's clear seen here", err, codes.Unavailable)
	wantMessage(t, "the refusal", err, `"bob"`, "lv user mark-external bob")
}

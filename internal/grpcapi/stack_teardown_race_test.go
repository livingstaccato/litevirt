package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// afriend c-0003. A synchronous down whose firewall or backup-repo cleanup
// fails reports the failure and keeps the stack "deleting" for the stack
// reconciler, instead of tombstoning it with the rows left behind.
//
// Mutation: log the cleanup error and tombstone the stack anyway — the stack
// record is gone and no error is streamed.
func TestDeleteStack_CleanupFailureKeepsTheStackDeleting(t *testing.T) {
	for _, tc := range []struct{ what, table string }{
		{"firewall rows", "security_groups"},
		{"backup repos", "backup_repos"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s := testServer(t)
			ctx := adminCtx()
			putStack(t, ctx, s, "app", "name: app\n")
			if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg1", Name: "web", StackName: "app"}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "app"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.DB().ExecContext(ctx, `CREATE TRIGGER cr8_fail BEFORE UPDATE ON `+tc.table+`
				BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END`); err != nil {
				t.Fatal(err)
			}
			stream := &mockDeleteStream{ctx: ctx}
			if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "app"}, stream); err != nil {
				t.Fatalf("DeleteStack: %v", err)
			}
			st, err := corrosion.GetStack(ctx, s.db, "app")
			if err != nil {
				t.Fatal(err)
			}
			if st == nil || st.State != "deleting" {
				t.Errorf("stack after a down whose %s cleanup failed = %+v, want kept in deleting", tc.what, st)
			}
			said := false
			for _, p := range stream.sent {
				if p.Status == "error" && strings.Contains(p.Error, tc.what) {
					said = true
				}
			}
			if !said {
				t.Errorf("no error progress named the failed %s cleanup", tc.what)
			}
		})
	}
}

// afriend c-0006. Stacks A (owns the deny) and B (asks for it) go down at
// the same time. A reads B as live and hands B the deny, while B's teardown,
// which saw A owning the row, removes nothing and tombstones its record. A
// must not leave the deny with a gone owner: it passes B over and removes
// the row.
//
// Mutation: hand the row over without re-reading the heir — the deny stays,
// owned by the gone B.
func TestDeleteStackFirewallDefaults_TwoTeardownsLeaveNoOrphan(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", denyFile("a"))
	putStack(t, ctx, s, "b", denyFile("b"))
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	bDown := false
	read := func(y string) (bool, map[string]bool, error) {
		if !bDown && strings.Contains(y, "name: b") {
			bDown = true
			// B's whole teardown runs here, after A read B as live.
			if err := corrosion.SetStackState(ctx, s.db, "b", "deleting"); err != nil {
				t.Error(err)
			}
			if err := corrosion.DeleteStackFirewallDefaults(ctx, s.db, "b", compose.StoredStackWants); err != nil {
				t.Error(err)
			}
			if err := corrosion.DeleteStackRecord(ctx, s.db, "b"); err != nil {
				t.Error(err)
			}
		}
		return compose.StoredStackWants(y)
	}
	if err := corrosion.SetStackState(ctx, s.db, "a", "deleting"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteStackFirewallDefaults(ctx, s.db, "a", read); err != nil {
		t.Fatal(err)
	}
	if !bDown {
		t.Fatal("fixture: b's teardown never ran mid-handoff")
	}
	if d := clusterDefault(t, ctx, s); d != nil && d.DefaultDeny {
		t.Errorf("cluster default after both stacks went down = %+v, want none", d)
	}
}

// The same race for a backup repo.
//
// Mutation: as above — the repo stays registered to the gone B.
func TestDeleteStackBackupRepos_TwoTeardownsLeaveNoOrphan(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", nightlyOwnerYAML)
	putStack(t, ctx, s, "b", "name: b\nbackup-repos:\n  nightly: {path: /srv/nightly}\n")
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "a"}); err != nil {
		t.Fatal(err)
	}
	bDown := false
	read := func(y string) (bool, map[string]bool, error) {
		if !bDown && strings.Contains(y, "name: b") {
			bDown = true
			if err := corrosion.SetStackState(ctx, s.db, "b", "deleting"); err != nil {
				t.Error(err)
			}
			if err := corrosion.DeleteStackBackupRepos(ctx, s.db, "b", compose.StoredStackWants); err != nil {
				t.Error(err)
			}
			if err := corrosion.DeleteStackRecord(ctx, s.db, "b"); err != nil {
				t.Error(err)
			}
		}
		return compose.StoredStackWants(y)
	}
	if err := corrosion.DeleteStackBackupRepos(ctx, s.db, "a", read); err != nil {
		t.Fatal(err)
	}
	if !bDown {
		t.Fatal("fixture: b's teardown never ran mid-handoff")
	}
	if _, owner, ok := repoOwner(t, ctx, s, "nightly"); ok {
		t.Errorf("repo nightly after both stacks went down is registered to %q, want unregistered", owner)
	}
}

// afriend c-0006, the sweep. A row a torn-down stack still owns goes to a
// live stack that asks for it, or goes. An operator's row, a row owned by a
// stack never recorded (a first deploy in flight or failed), and a row
// written after the owner's tombstone (a new deploy of the name) stay.
//
// Mutations: sweep nothing (the orphan repo stays); remove an orphan deny
// no stack asks for (the cluster opens); ignore the tombstone time (the new
// deploy's row goes); sweep never-recorded owners (the first deploy's row
// goes); ignore backup schedules (a scheduled repo goes).
func TestSweepOrphanStackRows(t *testing.T) {
	ctx := context.Background()
	sweep := func(t *testing.T, s *Server) string {
		t.Helper()
		orphan, err := corrosion.SweepOrphanStackRows(ctx, s.db, compose.StoredStackWants)
		if err != nil {
			t.Fatal(err)
		}
		return orphan
	}
	tornDown := func(t *testing.T, s *Server, name string) {
		t.Helper()
		putStack(t, ctx, s, name, denyFile(name))
		if err := corrosion.DeleteStackRecord(ctx, s.db, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("orphan deny is kept and reported, orphan repo goes", func(t *testing.T) {
		s := testServer(t)
		putStack(t, ctx, s, "b", denyFile("b"))
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "b"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "b"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, "b"); err != nil {
			t.Fatal(err)
		}
		// cr8 round 1, I1: the unattended sweep never opens the cluster.
		for i := 0; i < 3; i++ {
			if orphan := sweep(t, s); orphan != "b" {
				t.Errorf("sweep %d reported orphaned deny owner %q, want b", i, orphan)
			}
		}
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "b" {
			t.Errorf("deny owned by torn-down b after three sweeps = %+v, want kept", d)
		}
		if _, _, ok := repoOwner(t, ctx, s, "nightly"); ok {
			t.Error("repo owned by torn-down b is still registered after a sweep")
		}
		// A stack asking for it later takes it over.
		putStack(t, ctx, s, "c", denyFile("c"))
		if orphan := sweep(t, s); orphan != "" {
			t.Errorf("sweep reported orphan %q after c asked for the deny", orphan)
		}
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "c" {
			t.Errorf("deny after c asked = %+v, want handed to c", d)
		}
	})
	t.Run("repo a backup schedule names is kept", func(t *testing.T) {
		s := testServer(t)
		putStack(t, ctx, s, "b", nightlyOwnerYAML)
		if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "b"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{VMName: "vm1", Repo: "nightly", Cron: "0 2 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, "b"); err != nil {
			t.Fatal(err)
		}
		sweep(t, s)
		if _, _, ok := repoOwner(t, ctx, s, "nightly"); !ok {
			t.Error("repo a live backup schedule names was unregistered")
		}
	})
	t.Run("orphan deny goes to a live stack asking", func(t *testing.T) {
		s := testServer(t)
		putStack(t, ctx, s, "b", denyFile("b"))
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "b"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, "b"); err != nil {
			t.Fatal(err)
		}
		putStack(t, ctx, s, "c", denyFile("c"))
		sweep(t, s)
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "c" {
			t.Errorf("deny after a sweep = %+v, want handed to c", d)
		}
	})
	t.Run("new deploy of a torn-down name keeps its row", func(t *testing.T) {
		s := testServer(t)
		tornDown(t, s, "b")
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "b"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "b"}); err != nil {
			t.Fatal(err)
		}
		sweep(t, s)
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "b" {
			t.Errorf("deny of b's new deploy after a sweep = %+v, want kept", d)
		}
		if _, _, ok := repoOwner(t, ctx, s, "nightly"); !ok {
			t.Error("repo of b's new deploy was unregistered by a sweep")
		}
	})
	t.Run("never-recorded owner keeps its row", func(t *testing.T) {
		s := testServer(t)
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "first"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "first"}); err != nil {
			t.Fatal(err)
		}
		sweep(t, s)
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny {
			t.Errorf("deny of a stack with no record yet after a sweep = %+v, want kept", d)
		}
		if _, _, ok := repoOwner(t, ctx, s, "nightly"); !ok {
			t.Error("repo of a stack with no record yet was unregistered by a sweep")
		}
	})
	t.Run("operator row stays", func(t *testing.T) {
		s := testServer(t)
		tornDown(t, s, "b")
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, ""); err != nil {
			t.Fatal(err)
		}
		sweep(t, s)
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "" {
			t.Errorf("operator deny after a sweep = %+v, want kept", d)
		}
	})
}

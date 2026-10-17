package grpcapi

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
)

// scheduledDeleteServer is a VM vm1 this host owns with a backup and a
// replication schedule of its own, plus a schedule of another VM and a
// cluster-scoped one.
func scheduledDeleteServer(t *testing.T) *Server {
	t.Helper()
	s := hotplugDiskServer(t)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	seedForceVM(t, s, "vm1")
	insertTestVMWithSpec(t, adminCtx(), s.db, "vm2", "other-host", "running", "{}")
	ctx := context.Background()
	for _, r := range []corrosion.BackupScheduleRecord{
		{VMName: "vm1", Repo: "main", Cron: "0 4 * * *", Enabled: true},
		{VMName: "vm1", Repo: "pool-b", Cron: "0 5 * * *", Enabled: true, Type: "replication", TargetPool: "pool-b"},
		{VMName: "vm2", Repo: "main", Cron: "0 4 * * *", Enabled: true},
		{VMName: "@cluster", Scope: "cluster", Repo: "main", Cron: "0 3 * * *", Enabled: true},
	} {
		if err := corrosion.UpsertBackupSchedule(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// liveSchedules is every live schedule in s's replica as vm_name/repo, sorted.
func liveSchedules(t *testing.T, s *Server) string {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.VMName+"/"+r.Repo)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// A plain delete (lv rm, compose down, the stack reconciler) tombstones the
// VM's own schedules, backup and replication, and nothing else: no schedule
// is left firing for a VM that is gone, nor holding a stack's backup repo
// registered (lab 2, e2e-brepo-59201-1).
//
// Mutation: drop the schedule drop from DeleteVM — red.
func TestDeleteVM_APlainDeleteTombstonesTheVMsSchedules(t *testing.T) {
	s := scheduledDeleteServer(t)
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if got, want := liveSchedules(t, s), "@cluster/main,vm2/main"; got != want {
		t.Fatalf("live schedules after deleting vm1 = %q, want %q", got, want)
	}
}

// A rebuild's or re-create's delete keeps the schedules: the VM of the name
// comes back, and the operator's schedule with it. So does the owner of a
// delete a peer forwarded — with the entry's marker, or from an entry on an
// older build that sends none (a rolling re-create through such an entry
// must not lose the schedule on a newer owner): the entry decides.
//
// A blue-green cutover's delete of the blue keeps them too, as main did.
//
// Mutations: drop hasDeletedVMSink from the predicate — the sink cases go
// red; drop isRemotePeer — the older-entry case goes red; drop
// schedulesKept — the blue-green case goes red.
func TestDeleteVM_ARecreatesOrAForwardedDeleteKeepsTheSchedules(t *testing.T) {
	peer := func(t *testing.T, s *Server) context.Context {
		ctx := context.WithValue(peerCtxFor(t, s, "entry-host"), ctxKeyUsername, "admin")
		return context.WithValue(ctx, ctxKeyRole, "admin")
	}
	for what, mk := range map[string]func(t *testing.T, s *Server) context.Context{
		"recreate sink": func(t *testing.T, s *Server) context.Context {
			ctx, _ := withDeletedVMSink(adminCtx(), "vm1", mustGetVM(t, s, "vm1").CreatedAt)
			return ctx
		},
		"inline report": func(t *testing.T, s *Server) context.Context {
			ctx, _ := withDeletedVMReport(adminCtx(), "vm1", mustGetVM(t, s, "vm1").CreatedAt)
			return ctx
		},
		"forwarded by the entry": func(t *testing.T, s *Server) context.Context {
			return metadata.NewIncomingContext(peer(t, s), metadata.Pairs(entryClearsFirewallTagsMD, "1"))
		},
		"forwarded by an older entry": peer,
		"blue-green cutover": func(t *testing.T, s *Server) context.Context {
			return withSchedulesKept(adminCtx())
		},
	} {
		t.Run(what, func(t *testing.T) {
			s := scheduledDeleteServer(t)
			if _, err := s.DeleteVM(mk(t, s), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			if vm, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); vm != nil {
				t.Fatal("premise: the delete did not happen")
			}
			if got, want := liveSchedules(t, s), "@cluster/main,vm1/main,vm1/pool-b,vm2/main"; got != want {
				t.Fatalf("the %s delete changed the schedules: %q, want %q", what, got, want)
			}
		})
	}
}

// The orphan sweep: on the failover lease holder only, it tombstones a
// schedule of a deleted VM once the tombstone is past the grace, and never a
// schedule of a VM with no row (it may be one replicating ahead of its VM).
//
// Mutations: sweep without the grace — red; sweep on a non-holder — red.
func TestSweepVMScheduleOrphans(t *testing.T) {
	setup := func(t *testing.T, holder string) *Server {
		s, _, _, _ := sweepServer(t, holder)
		s.SetReleaseFeatureGate(&relGate{t: t, open: true})
		ctx := context.Background()
		insertTestVMWithSpec(t, ctx, s.db, "gone", "h", "stopped", "{}")
		for _, vm := range []string{"gone", "unborn"} {
			if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{VMName: vm, Repo: "main", Cron: "0 4 * * *", Enabled: true}); err != nil {
				t.Fatal(err)
			}
		}
		if err := corrosion.DeleteVM(ctx, s.db, "gone"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx := context.Background()

	s := setup(t, "")
	s.sweepVMScheduleOrphans(ctx, time.Now().Add(time.Hour))
	if got := liveSchedules(t, s); got != "gone/main,unborn/main" {
		t.Fatalf("swept inside the grace: %q", got)
	}
	other := setup(t, "someone-else")
	other.sweepVMScheduleOrphans(ctx, time.Now().Add(48*time.Hour))
	if got := liveSchedules(t, other); got != "gone/main,unborn/main" {
		t.Fatalf("a host that does not hold the failover lease swept: %q", got)
	}
	s.sweepVMScheduleOrphans(ctx, time.Now().Add(48*time.Hour))
	if got := liveSchedules(t, s); got != "unborn/main" {
		t.Fatalf("after the sweep past the grace: %q, want unborn/main", got)
	}
}

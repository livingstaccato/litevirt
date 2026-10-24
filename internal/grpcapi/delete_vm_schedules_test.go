package grpcapi

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
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
		// CreateBackupSchedule stores a vm-scoped request's pool_name too.
		{VMName: "vm1", Scope: "vm", PoolName: "fast", Repo: "nightly", Cron: "0 6 * * *", Enabled: true},
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
// Mutations: drop the schedule drop from DeleteVM — red; skip a vm-scoped
// row that carries a pool_name — red (vm1/nightly is left).
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
			if got, want := liveSchedules(t, s), "@cluster/main,vm1/main,vm1/nightly,vm1/pool-b,vm2/main"; got != want {
				t.Fatalf("the %s delete changed the schedules: %q, want %q", what, got, want)
			}
		})
	}
}

// The orphan sweep: on the failover lease holder only, it tombstones a
// schedule of a torn-down stack's deleted VM once the tombstone is past the
// grace. A schedule of a deleted VM that was no stack's (a failed rebuild
// leaves exactly this: rebuild tombstones through DeleteVMReporting) stays
// dormant, as does one of a VM with no row.
//
// Mutations: sweep without the grace — red; sweep on a non-holder — red;
// drop the torn-down-stack clause — red ("plain" swept); skip a vm-scoped
// schedule that carries a pool_name — red (gone/nightly is left).
func TestSweepScheduleOrphans(t *testing.T) {
	setup := func(t *testing.T, holder string) *Server {
		s, _, _, _ := sweepServer(t, holder)
		s.SetReleaseFeatureGate(&relGate{t: t, open: true})
		ctx := context.Background()
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "down", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "gone", StackName: "down", HostName: "h", Spec: "{}", State: "stopped"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		insertTestVMWithSpec(t, ctx, s.db, "plain", "h", "stopped", "{}")
		for _, vm := range []string{"gone", "plain", "unborn"} {
			if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{VMName: vm, Repo: "main", Cron: "0 4 * * *", Enabled: true}); err != nil {
				t.Fatal(err)
			}
		}
		// A vm-scoped schedule with a pool_name is still gone's.
		if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{VMName: "gone", Scope: "vm", PoolName: "fast", Repo: "nightly", Cron: "0 4 * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteVM(ctx, s.db, "gone"); err != nil {
			t.Fatal(err)
		}
		if _, err := corrosion.DeleteVMReporting(ctx, s.db, "plain"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, "down"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx := context.Background()
	all := "gone/main,gone/nightly,plain/main,unborn/main"

	s := setup(t, "")
	s.sweepScheduleOrphans(ctx, time.Now().Add(time.Hour))
	if got := liveSchedules(t, s); got != all {
		t.Fatalf("swept inside the grace: %q", got)
	}
	other := setup(t, "someone-else")
	other.sweepScheduleOrphans(ctx, time.Now().Add(48*time.Hour))
	if got := liveSchedules(t, other); got != all {
		t.Fatalf("a host that does not hold the failover lease swept: %q", got)
	}
	s.sweepScheduleOrphans(ctx, time.Now().Add(48*time.Hour))
	if got := liveSchedules(t, s); got != "plain/main,unborn/main" {
		t.Fatalf("after the sweep past the grace: %q, want plain/main,unborn/main", got)
	}
}

// scheduledContainerServer is a container ct this host holds with a
// replication schedule, plus another container's schedule.
func scheduledContainerServer(t *testing.T) *Server {
	t.Helper()
	s, _ := tagsServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	for _, name := range []string{"ct", "other"} {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: s.hostName, Name: name, State: "stopped"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertContainerReplicationSchedule(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureContainerReplication),
			corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("", name), Scope: "container", Type: "replication",
				Repo: "dr", TargetPool: "dr", Cron: "0 * * * *", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// A plain container delete tombstones that container's schedules and no
// other's; a re-create's delete (withSchedulesKept), the owner of a
// forwarded delete, and a delete of one of two containers holding the name
// (a move's stale copy) keep them.
//
// Mutations: drop the drop call from DeleteContainer — the plain case goes
// red; drop schedulesKept or isRemotePeer from its predicate — those cases go
// red; drop the live-holder check in deleteContainerSchedules — the stale-copy
// case goes red.
func TestDeleteContainer_SchedulesEndWithAPlainDeleteOnly(t *testing.T) {
	const both = "@ct:_default/ct/dr,@ct:_default/other/dr"
	t.Run("plain", func(t *testing.T) {
		s := scheduledContainerServer(t)
		if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct", HostName: s.hostName, Force: true}); err != nil {
			t.Fatalf("DeleteContainer: %v", err)
		}
		if got := liveSchedules(t, s); got != "@ct:_default/other/dr" {
			t.Fatalf("live schedules after deleting ct = %q", got)
		}
	})
	for what, mk := range map[string]func(t *testing.T, s *Server) context.Context{
		"re-create": func(t *testing.T, s *Server) context.Context { return withSchedulesKept(adminCtx()) },
		"forwarded by an older entry": func(t *testing.T, s *Server) context.Context {
			ctx := context.WithValue(peerCtxFor(t, s, "entry-host"), ctxKeyUsername, "admin")
			return context.WithValue(ctx, ctxKeyRole, "admin")
		},
	} {
		t.Run(what, func(t *testing.T) {
			s := scheduledContainerServer(t)
			if _, err := s.DeleteContainer(mk(t, s), &pb.DeleteContainerRequest{Name: "ct", HostName: s.hostName, Force: true}); err != nil {
				t.Fatalf("DeleteContainer: %v", err)
			}
			if ct, _ := corrosion.GetContainer(context.Background(), s.db, s.hostName, "ct"); ct != nil {
				t.Fatal("premise: the delete did not happen")
			}
			if got := liveSchedules(t, s); got != both {
				t.Fatalf("the %s delete changed the schedules: %q", what, got)
			}
		})
	}
	t.Run("stale copy", func(t *testing.T) {
		s := scheduledContainerServer(t)
		if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{HostName: "other-host", Name: "ct", State: "running"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct", HostName: s.hostName, Force: true}); err != nil {
			t.Fatalf("DeleteContainer: %v", err)
		}
		if got := liveSchedules(t, s); got != both {
			t.Fatalf("deleting the stale copy dropped the live container's schedule: %q", got)
		}
	})
}

// The deleted container's own row is not another holder: a forwarded delete
// whose tombstone has not reached the entry's replica yet still drops the
// schedules. Another host's live row of the name keeps them.
//
// Mutation: count the deleted container's own (host, name) row as a holder — red.
func TestDeleteContainerSchedules_TheDeletedRowIsNoHolder(t *testing.T) {
	s := scheduledContainerServer(t)
	ctx := context.Background()
	// ct is still live here, as on an entry whose replica lags the owner.
	s.deleteContainerSchedules(ctx, s.hostName, "_default", "ct")
	if got := liveSchedules(t, s); got != "@ct:_default/other/dr" {
		t.Fatalf("schedules after the drop for ct on %s = %q, want only other's", s.hostName, got)
	}
	s2 := scheduledContainerServer(t)
	if err := corrosion.UpsertContainer(ctx, s2.db, corrosion.ContainerRecord{HostName: "other-host", Name: "ct", State: "running"}); err != nil {
		t.Fatal(err)
	}
	s2.deleteContainerSchedules(ctx, s2.hostName, "_default", "ct")
	if got := liveSchedules(t, s2); got != "@ct:_default/ct/dr,@ct:_default/other/dr" {
		t.Fatalf("another host's live ct did not keep the schedules: %q", got)
	}
}

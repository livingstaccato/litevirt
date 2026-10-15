package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A limit is refused before the schedule is written while the
// cluster-policy table it is stored in is not writable, as FailedPrecondition:
// no unlimited schedule is left behind under an Internal error. A clear that
// meets the same closed table is FailedPrecondition too.
//
// Mutations: drop the MayWriteClusterPolicy check from the precheck — the
// create leaves a row; drop the error mapping — the clear is Internal.
func TestReplicationRate_ClusterPolicyGateClosedIsFailedPrecondition(t *testing.T) {
	s := rateServer(t, &rateGate{})
	ctx := adminCtx()
	s.db.SetClusterPolicyGate(func() bool { return false })
	_, err := s.CreateReplicationSchedule(ctx, vmRateReq("0 * * * *", i64(8<<20)))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("create with a rate on a closed table: %v, want FailedPrecondition", err)
	}
	if rows := scheduleRows(t, s); len(rows) != 0 {
		t.Fatalf("a refused rate left a schedule: %+v", rows)
	}

	s.db.SetClusterPolicyGate(func() bool { return true })
	if _, err := s.CreateReplicationSchedule(ctx, vmRateReq("0 * * * *", i64(8<<20))); err != nil {
		t.Fatal(err)
	}
	s.db.SetClusterPolicyGate(func() bool { return false })
	_, err = s.CreateReplicationSchedule(ctx, vmRateReq("0 * * * *", i64(0)))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not cleared") {
		t.Fatalf("clear on a closed table: %v, want FailedPrecondition saying it was not cleared", err)
	}
}

// A limit left behind by a deleted schedule (its clear failed, or the delete
// ran on a node the limit had not reached yet) is not inherited by a new
// schedule of the same name, for a VM and for a container: a schedule added
// without --bwlimit where none existed starts unlimited. A re-add of a live
// schedule still keeps its limit (TestReplicationRate_OptionalSemantics).
//
// Mutation: skip the clear of a stale limit on a new schedule — both cases
// answer 4MiB.
func TestReplicationRate_NewScheduleDoesNotInheritAStaleLimit(t *testing.T) {
	stale := func(t *testing.T, s *Server, schedule, repo string) {
		t.Helper()
		if err := corrosion.SetReplicationRate(context.Background(), s.db,
			capabilities.GrantForTest(t, capabilities.FeatureReplicationRate), schedule, repo, 4<<20, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("vm", func(t *testing.T) {
		s := rateServer(t, &rateGate{})
		stale(t, s, "web1", "dr")
		got, err := s.CreateReplicationSchedule(adminCtx(), vmRateReq("0 * * * *", nil))
		if err != nil || got.GetBwlimitBytesPerSec() != 0 {
			t.Fatalf("new schedule: %v, answer rate %d, want unlimited", err, got.GetBwlimitBytesPerSec())
		}
		if v, _ := storedRate(t, s, "web1", "dr"); v != "" {
			t.Fatalf("the stale limit is still stored: %q", v)
		}
	})
	t.Run("container", func(t *testing.T) {
		s := rateServer(t, &rateGate{})
		seedActiveHost(t, s, "host-b", true)
		seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return &replicaPeer{}, func() {}, nil
		}
		key := corrosion.ContainerScheduleKey("_default", "web")
		stale(t, s, key, "dr")
		got, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr"))
		if err != nil || got.GetBwlimitBytesPerSec() != 0 {
			t.Fatalf("new container schedule: %v, answer rate %d, want unlimited", err, got.GetBwlimitBytesPerSec())
		}
	})
	// The clear of a stale limit is best effort: a gate that cannot take it
	// never refuses the schedule, and the answer shows the limit it kept.
	t.Run("clear refused", func(t *testing.T) {
		g := &rateGate{}
		s := rateServer(t, g)
		stale(t, s, "web1", "dr")
		g.writeFails = map[capabilities.Feature]error{
			capabilities.FeatureReplicationRate: status.Error(codes.Unavailable, "could not confirm"),
		}
		got, err := s.CreateReplicationSchedule(adminCtx(), vmRateReq("0 * * * *", nil))
		if err != nil || got.GetBwlimitBytesPerSec() != 4<<20 {
			t.Fatalf("new schedule over a stale limit the gate will not clear: %v, answer rate %d", err, got.GetBwlimitBytesPerSec())
		}
	})
}

// A container schedule whose limit could not be cleared on delete cannot be
// deleted again (it is gone), so the error names the retry that works:
// adding the schedule again.
//
// Mutation: restore "delete it again to retry".
func TestReplicationRate_FailedClearOnDeleteNamesARetryThatWorks(t *testing.T) {
	g := &rateGate{}
	s := rateServer(t, g)
	key := corrosion.ContainerScheduleKey("_default", "web")
	putCTSchedule(t, s, corrosion.BackupScheduleRecord{
		VMName: key, ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b",
	})
	if err := corrosion.SetReplicationRate(context.Background(), s.db,
		capabilities.GrantForTest(t, capabilities.FeatureReplicationRate), key, "dr", 4<<20, "alice"); err != nil {
		t.Fatal(err)
	}
	g.writeFails = map[capabilities.Feature]error{
		capabilities.FeatureReplicationRate: status.Error(codes.Unavailable, "could not confirm"),
	}
	_, err := s.DeleteReplicationSchedule(adminCtx(), &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr"})
	if err == nil || strings.Contains(err.Error(), "delete it again") || !strings.Contains(err.Error(), "adding the schedule again clears it") {
		t.Fatalf("err = %v, want it to name adding the schedule again", err)
	}
}

// A listing never fails over the limits: when they cannot be read, the
// schedules are listed without them.
//
// Mutation: return the rates error — the listing fails.
func TestReplicationRate_ListSurvivesUnreadableRates(t *testing.T) {
	s := rateServer(t, &rateGate{})
	ctx := adminCtx()
	if _, err := s.CreateReplicationSchedule(ctx, vmRateReq("0 * * * *", i64(8<<20))); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `DROP TABLE cluster_policies`); err != nil {
		t.Fatalf("DROP TABLE cluster_policies: %v", err)
	}
	list, err := s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
	if err != nil || len(list.GetSchedules()) != 1 {
		t.Fatalf("list with unreadable rates: %v %+v, want the schedule", err, list)
	}
}

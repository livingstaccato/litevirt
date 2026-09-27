package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lxc"
)

// sweepStoppedContainer runs one container-checker sweep on s's host with name
// present in the runtime and stopped, and returns how many times it was started.
func sweepStoppedContainer(t *testing.T, s *Server, name string) int {
	t.Helper()
	rt := newRaceLXC()
	rt.states[name] = lxc.StateStopped
	ck := health.NewContainerChecker(s.hostName, s.db, rt)
	ck.SetContainerLock(s.TryLockContainer)
	ck.SweepOnce(context.Background())
	_, starts := rt.snapshot(name)
	return starts
}

// A clone made without --start has never run: it has not stopped, so the
// restart policy it copies from its source does not start it. The checker
// started it on its next sweep, because the clone's row said stopped with no
// detail — exactly what an out-of-band stop looks like.
func TestCloneContainer_UnstartedCloneIsNotStartedByItsRestartPolicy(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "base", State: "stopped", Image: "alpine:3.19",
		Project: "acme", IsTemplate: true, RestartPolicy: `{"condition":"always"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "base", Target: "web1", HostName: "host-a"}); err != nil {
		t.Fatalf("CloneContainer: %v", err)
	}
	if n := sweepStoppedContainer(t, s, "web1"); n != 0 {
		t.Fatalf("the checker started a clone nobody had started (%d starts)", n)
	}
	row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "web1")
	if row == nil || row.State != "stopped" || row.StateDetail != corrosion.ContainerCreatedDetail {
		t.Fatalf("unstarted clone row = %+v, want stopped/%s", row, corrosion.ContainerCreatedDetail)
	}
}

// A restore without --start of a backup that carries no stop intent (the
// source was running when it was backed up) has not run here either: the
// restart policy restored with it does not start it.
func TestRestoreContainer_UnstartedRestoreIsNotStartedByItsRestartPolicy(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running",
		Image: "alpine:3.19", Project: "acme", RestartPolicy: `{"condition":"always"}`,
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-29T10:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-29T10:00:00Z", Start: false,
	}, rs); err != nil {
		t.Fatalf("RestoreContainer(start=false): %v", err)
	}
	if n := sweepStoppedContainer(t, s, "ct1"); n != 0 {
		t.Fatalf("the checker started a restored container nobody had started (%d starts)", n)
	}
	row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if row == nil || row.State != "stopped" || row.StateDetail != corrosion.ContainerCreatedDetail {
		t.Fatalf("unstarted restore row = %+v, want stopped/%s", row, corrosion.ContainerCreatedDetail)
	}
}

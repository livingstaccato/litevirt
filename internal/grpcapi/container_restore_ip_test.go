package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// restoreIPServer creates container web (project acme) with ip=10.9.0.5/24 on
// a shared managed network and backs it up, returning the repo.
func restoreIPServer(t *testing.T) (*Server, *fakeCTRuntime, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	mkManagedNetwork(t, s, "shared", "br-shared", "10.9.0.0/24")
	for _, p := range []string{"acme", "beta"} {
		if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.19", Project: "acme",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "shared", Ip: "10.9.0.5/24"}},
	}); err != nil {
		t.Fatalf("create web: %v", err)
	}
	repo := ctTestRepo(t)
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("backup web: %v", err)
	}
	rt.startCalls = nil
	return s, rt, repo
}

// R1, flow 1: a copy of web restored on host-b while the original runs on
// host-a must not start on the original's live address.
func TestRestoreContainer_CopyBesideOriginalDoesNotTakeItsAddress(t *testing.T) {
	s, rt, repo := restoreIPServer(t)
	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "web", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z", Start: true,
	}, rs)
	assertIPUnavailable(t, err)
	if len(rt.startCalls) != 0 {
		t.Fatalf("the copy was started on the original's address: start calls %v", rt.startCalls)
	}
	if al, _ := network.GetAllocationFor(context.Background(), s.db, "shared", "ct", "host-b", "web"); al != nil {
		t.Fatalf("the copy holds a lease on the original's address: %+v", al)
	}
}

// R1, flow 2: web is deleted, its address goes to another project's
// container, and web is restored: it must not take that address back.
func TestRestoreContainer_DeletedThenReallocatedAcrossProjectsRefused(t *testing.T) {
	s, rt, repo := restoreIPServer(t)
	ctx := adminCtx()
	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "web", HostName: "host-a"}); err != nil {
		t.Fatalf("delete web: %v", err)
	}
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "y", Template: "download", Distro: "alpine", Release: "3.19", Project: "beta",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "shared", Ip: "10.9.0.5"}},
	}); err != nil {
		t.Fatalf("create y on the released address: %v", err)
	}
	rt.startCalls = nil
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "web", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z", Start: true,
	}, rs)
	assertIPUnavailable(t, err)
	if len(rt.startCalls) != 0 {
		t.Fatalf("web was started on y's address: start calls %v", rt.startCalls)
	}
	if al, _ := network.GetAllocationFor(context.Background(), s.db, "shared", "ct", "host-a", "web"); al != nil {
		t.Fatalf("web holds a lease on y's address: %+v", al)
	}
	if al, _ := network.GetAllocationFor(context.Background(), s.db, "shared", "ct", "host-a", "y"); al == nil {
		t.Fatal("y lost its lease")
	}
}

// m4 end to end: beta's same-named container's backups are recorded under
// beta and do not count toward acme's backup_gib, so they cannot block an
// acme create; acme's own backup is recorded under acme.
func TestBackupContainer_IndexKeyedByManifestProject(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	for _, c := range []corrosion.ContainerRecord{
		{HostName: "host-a", Name: "web", State: "stopped", Project: "acme"},
		{HostName: "host-b", Name: "web", State: "stopped", Project: "beta"},
	} {
		if err := corrosion.UpsertContainer(ctx, s.db, c); err != nil {
			t.Fatal(err)
		}
	}
	repo := ctTestRepo(t)
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z",
	}, bk); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.db.Query(ctx, `SELECT 1 AS ok FROM container_backups WHERE ct_name = ? AND repo = ?`,
		corrosion.ContainerBackupKey("acme", "web"), repo)
	if len(rows) != 1 {
		t.Fatal("acme's backup is not indexed under acme")
	}
	u, err := corrosion.SumProjectUsage(ctx, s.db, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if u.BackupGiBUsed != 0 {
		t.Fatalf("beta charged for acme's backup: %d GiB", u.BackupGiBUsed)
	}
}

// assertIPUnavailable pins that a restore was refused for its IP and nothing
// else, so the no-start assertions after it cannot pass because the restore
// failed early for an unrelated reason.
func assertIPUnavailable(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "unavailable IPs") {
		t.Fatalf("restore error = %v, want FailedPrecondition with \"unavailable IPs\"", err)
	}
}

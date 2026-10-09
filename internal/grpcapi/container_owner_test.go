package grpcapi

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Container files are chosen by their recorded owner, never by name alone.
// Names are per host and reusable: a container deleted in one project and
// created again under the same name in another must not inherit the first
// one's snapshots, backups or on-disk directory.

// reuseName deletes ct1 (project acme) and records a new ct1 in project beta.
func reuseName(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", Project: "beta",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestContainerSnapshot_AnEarlierProjectsSnapshotIsNotTheNewContainers(t *testing.T) {
	s, rt := snapTestServer(t, "stopped") // ct1 in project acme
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatal(err)
	}
	reuseName(t, s)

	_, err := s.RevertContainerSnapshot(ctOperatorCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revert onto beta's ct1 from acme's snapshot: got %v, want PermissionDenied", err)
	}
	if len(rt.reverted) != 0 {
		t.Fatal("the runtime reverted to another project's snapshot")
	}
	if _, err := s.DeleteContainerSnapshot(ctOperatorCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("delete of acme's snapshot by beta: got %v, want PermissionDenied", err)
	}
	resp, err := s.ListContainerSnapshots(ctOperatorCtx(), &pb.ListContainerSnapshotsRequest{Name: "ct1", HostName: "host-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Snapshots) != 0 {
		t.Fatalf("beta's ct1 lists acme's snapshots: %+v", resp.Snapshots)
	}
	// Admin keeps the escape hatch: it sees and may act on it.
	resp, _ = s.ListContainerSnapshots(adminCtx(), &pb.ListContainerSnapshotsRequest{Name: "ct1", HostName: "host-a"})
	if len(resp.GetSnapshots()) != 1 {
		t.Fatalf("admin list = %+v", resp.GetSnapshots())
	}
}

// A snapshot with no owner record (an earlier build's) behaves as today.
func TestContainerSnapshot_NoOwnerRecordIsToday(t *testing.T) {
	s, rt := snapTestServer(t, "stopped")
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatal(err)
	}
	removeSnapshotOwner(s.dataDir, "ct1", "s1")
	reuseName(t, s)
	if _, err := s.RevertContainerSnapshot(ctOperatorCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("revert without an owner record: %v", err)
	}
	if len(rt.reverted) != 1 {
		t.Fatal("not reverted")
	}
}

// Failover restores the relocating container's own latest backup: a newer
// backup of another project's container of the same name is not it.
func TestRestoreContainerFromBackup_ChoosesTheOwnersBackup(t *testing.T) {
	for _, o := range []struct{ project, ownerID string }{
		{"beta", "other-1"}, // another project's container
		{"beta", ""},        // another project's, from before owner ids
		{"acme", "other-1"}, // the same project, another lineage of the name
	} {
		t.Run(o.project+"/"+o.ownerID, func(t *testing.T) { chooseOwnersBackup(t, o.project, o.ownerID) })
	}
}

func chooseOwnersBackup(t *testing.T, otherProject, otherOwnerID string) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repoPath := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	s.SetBackupRepos(map[string]string{"main": repoPath})
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	own := &corrosion.ContainerRecord{HostName: "host-a", Name: "ct1", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", OwnerID: "own-1"})}
	other := &corrosion.ContainerRecord{HostName: "host-c", Name: "ct1", Project: otherProject,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", OwnerID: otherOwnerID})}
	if _, err := s.archiveContainer(ctx, repo, own, "2026-06-27T12:00:00Z", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.archiveContainer(ctx, repo, other, "2026-06-28T12:00:00Z", nil); err != nil {
		t.Fatal(err)
	}
	own.State, own.StateDetail = "relocating", corrosion.RelocateRestoreDetail("host-b", "tok-x")
	if err := corrosion.UpsertContainer(ctx, s.db, *own); err != nil {
		t.Fatal(err)
	}
	var gotTs string
	s.migrateRestoreOverride = func(_ context.Context, target, repoPath, name, ts string, start bool) (corrosion.RestoreOutcome, error) {
		gotTs = ts
		return corrosion.RestoreLanded, nil
	}
	if _, err := s.RestoreContainerFromBackup(ctx, "ct1", "host-b", "tok-x"); err != nil {
		t.Fatal(err)
	}
	if gotTs != "2026-06-27T12:00:00Z" {
		t.Fatalf("restored the backup at %q, want the relocating container's own (2026-06-27T12:00:00Z)", gotTs)
	}
}

// removeSnapshotOwner deletes a snapshot's owner record, as if an earlier build
// had taken it.
func removeSnapshotOwner(dataDir, ct, snap string) {
	_ = os.Remove(ctSnapshotPath(dataDir, ct, snap) + ".owner")
}

// A non-admin's call forwarded to the owning host arrives as the peer; the
// entry node marks it so the owner rules still bind there.
func TestContainerSnapshot_OwnerRulesSurviveAForward(t *testing.T) {
	s := newPeerAuthServer(t) // hostName "self", knows peer "peer-1"
	if s.ownerStrict(mtlsAdminCtx("peer-1")) {
		t.Fatal("a peer's own call is bound by the owner rules")
	}
	marked := metadata.NewIncomingContext(mtlsAdminCtx("peer-1"), metadata.Pairs(ownerStrictMDKey, "1"))
	if !s.ownerStrict(marked) {
		t.Fatal("a peer forwarding for a non-admin is not bound")
	}
	out, _ := metadata.FromOutgoingContext(s.ownerStrictOutgoing(ctOperatorCtx()))
	if v := out.Get(ownerStrictMDKey); len(v) != 1 || v[0] != "1" {
		t.Fatalf("operator forward carries %v", v)
	}
	out, _ = metadata.FromOutgoingContext(s.ownerStrictOutgoing(adminCtx()))
	if v := out.Get(ownerStrictMDKey); len(v) != 0 {
		t.Fatalf("admin forward carries %v", v)
	}
}

func ownerIDOf(t *testing.T, s *Server, host, name string) (string, string) {
	t.Helper()
	row, err := corrosion.GetContainer(context.Background(), s.db, host, name)
	if err != nil || row == nil {
		t.Fatalf("row %s/%s: %v", host, name, err)
	}
	return row.Project, corrosion.DecodeCreateSpec(row.CreateSpec).OwnerID
}

// A create mints the owner record into the spec and stamps it on disk; a clone
// is a new lineage with its own; a restore stamps the lineage it restores.
func TestContainerOwner_MintedAndStamped(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "c1", Template: "download", Distro: "alpine", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	proj, id := ownerIDOf(t, s, "host-a", "c1")
	if id == "" {
		t.Fatal("create recorded no owner_id")
	}
	if got := rt.owners["c1"]; got.Project != proj || got.OwnerID != id {
		t.Fatalf("on-disk owner = %+v, want {%s %s}", got, proj, id)
	}

	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "c1", Target: "c2", HostName: "host-a"}); err != nil {
		t.Fatal(err)
	}
	_, cid := ownerIDOf(t, s, "host-a", "c2")
	if cid == "" || cid == id {
		t.Fatalf("clone owner_id = %q (source %q), want a new one", cid, id)
	}
	if got := rt.owners["c2"]; got.OwnerID != cid || got.Project != "acme" {
		t.Fatalf("clone on-disk owner = %+v", got)
	}

	repo := ctTestRepo(t)
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "c1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, bk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "c1", HostName: "host-a"}); err != nil {
		t.Fatal(err)
	}
	delete(rt.owners, "c1")
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "c1", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, rs); err != nil {
		t.Fatal(err)
	}
	if _, rid := ownerIDOf(t, s, "host-a", "c1"); rid != id {
		t.Fatalf("restored owner_id = %q, want the backed-up lineage %q", rid, id)
	}
	if got := rt.owners["c1"]; got.OwnerID != id || got.Project != "acme" {
		t.Fatalf("restored on-disk owner = %+v", got)
	}
}

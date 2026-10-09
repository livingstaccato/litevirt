package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Which backup is a container's is decided one way everywhere: by project AND
// lineage (owner_id), the rule failover restores by (manifestOwnedBy). Inspect
// must not call a backup "available" that failover would never use, and an
// operator's copy restored beside a live original must not take over the
// original's lineage, or failover could rebuild the original from the copy.

// putCTManifestOwned writes a container backup manifest of name in project,
// of the lineage ownerID, into the repo at dir.
func putCTManifestOwned(t *testing.T, dir, name, project, ownerID, ts string) {
	t.Helper()
	repo, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(containerBackupSpec{Name: name, Project: project,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: ownerID})})
	if _, err := pbsstore.PushDisk(context.Background(), repo, strings.NewReader("rootfs-tar-"+name+project+ownerID), pbsstore.PushOptions{
		VMName: name, DiskName: containerBackupDisk, Timestamp: ts, ContainerSpecJSON: string(spec),
	}); err != nil {
		t.Fatal(err)
	}
}

// setOwnerID records ownerID as the lineage of the container row host/name.
func setOwnerID(t *testing.T, s *Server, host, name, ownerID string) {
	t.Helper()
	ctx := context.Background()
	row, err := corrosion.GetContainer(ctx, s.db, host, name)
	if err != nil || row == nil {
		t.Fatalf("row %s/%s: %v", host, name, err)
	}
	cs := corrosion.DecodeCreateSpec(row.CreateSpec)
	cs.OwnerID = ownerID
	row.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, s.db, *row); err != nil {
		t.Fatal(err)
	}
}

// The probe attributes a manifest only when it is of this project AND this
// lineage; a same-project manifest of another lineage is reported as such. A
// request with no owner_id (an older peer asking) matches by project, as
// before, and a manifest from before owner ids matches any lineage.
func TestProbeContainerBackups_JudgesByLineage(t *testing.T) {
	s := newPeerAuthServer(t)
	repo, legacy := ctTestRepo(t), ctTestRepo(t)
	putCTManifestOwned(t, repo, "ct1", "acme", "own-1", "2026-10-08T10:00:00Z")
	putCTManifestOwned(t, repo, "ct1", "acme", "old-1", "2026-10-08T11:00:00Z")
	putCTManifest(t, legacy, "ct1", "acme", "2026-10-08T09:00:00Z")
	probe := func(ownerID, r string) *pb.ContainerBackupProbe {
		t.Helper()
		resp, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), &pb.ProbeContainerBackupsRequest{
			Name: "ct1", Project: "acme", OwnerId: ownerID, Repos: []string{r}})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetResults()[0]
	}
	if p := probe("own-1", repo); !p.GetAttributed() || !p.GetOtherLineage() || p.GetForeign() || p.GetLatestTimestamp() != "2026-10-08T10:00:00Z" {
		t.Fatalf("own-1: probe = %+v, want its own 10:00 backup attributed and old-1's reported as another lineage", p)
	}
	if p := probe("new-2", repo); p.GetAttributed() || !p.GetOtherLineage() || p.GetForeign() {
		t.Fatalf("new-2: probe = %+v, want nothing attributed: both backups are of other lineages", p)
	}
	if p := probe("", repo); !p.GetAttributed() || p.GetOtherLineage() || p.GetLatestTimestamp() != "2026-10-08T11:00:00Z" {
		t.Fatalf("no owner_id (older peer): probe = %+v, want project-only matching, newest 11:00", p)
	}
	if p := probe("own-1", legacy); !p.GetAttributed() || p.GetOtherLineage() {
		t.Fatalf("legacy manifest: probe = %+v, want it attributed (no owner record matches by name)", p)
	}
}

// A deleted predecessor's backups in the same project are not this
// container's: failover will not restore them, so inspect does not call them
// available — on this host, or on the peer that holds the repo (which must be
// told the lineage). Only an admin sees them, as another container's.
func TestInspectContainer_AnotherLineagesBackupIsNotAvailable(t *testing.T) {
	check := func(t *testing.T, owner *Server, repo string) {
		t.Helper()
		d, err := owner.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
		if err != nil {
			t.Fatalf("InspectContainer: %v", err)
		}
		if len(d.GetBackups()) != 1 {
			t.Fatalf("backups = %+v", d.GetBackups())
		}
		if b := d.GetBackups()[0]; b.GetRepo() != repo || b.GetAvailable() || b.GetStatus() != backupOtherLineage || b.GetUnavailableReason() == "" {
			t.Fatalf("predecessor's backup = %+v, want %s with a reason, not available", b, backupOtherLineage)
		}
		viewer := grantUser(t, owner, "carol", "/projects/acme", "Viewer")
		d, err = owner.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ct1"})
		if err != nil {
			t.Fatalf("viewer InspectContainer: %v", err)
		}
		if len(d.GetBackups()) != 0 {
			t.Fatalf("viewer was told the predecessor's backup protects this container: %+v", d.GetBackups())
		}
	}

	t.Run("local", func(t *testing.T) {
		s := inspectTestServer(t, "")
		setOwnerID(t, s, "host-a", "ct1", "own-2")
		repo := ctTestRepo(t)
		putCTManifestOwned(t, repo, "ct1", "acme", "own-1", "2026-10-08T10:00:00Z")
		if err := corrosion.UpsertContainerBackup(context.Background(), s.db, "acme", "ct1", repo, 4096); err != nil {
			t.Fatal(err)
		}
		check(t, s, repo)
	})

	t.Run("peer", func(t *testing.T) {
		owner := inspectTestServer(t, "")
		setOwnerID(t, owner, "host-a", "ct1", "own-2")
		sink := newPeerAuthServer(t)
		sink.hostName = "sink-host"
		sinkDir := ctTestRepo(t)
		sink.SetBackupRepos(map[string]string{"r1": sinkDir})
		putCTManifestOwned(t, sinkDir, "ct1", "acme", "own-1", "2026-10-08T10:00:00Z")
		addHost(t, sink, "host-a")
		addHost(t, owner, "sink-host")
		if err := corrosion.UpsertContainerBackup(context.Background(), owner.db, "acme", "ct1", "r1", 7000); err != nil {
			t.Fatal(err)
		}
		owner.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
			if host != "sink-host" {
				return nil, nil, status.Error(codes.Unavailable, "no such peer")
			}
			return &probePeer{srv: sink, callAs: "host-a"}, func() {}, nil
		}
		check(t, owner, "r1")
	})
}

// I2 with M4: an operator restores web's backup on host-b while web still
// runs on host-a. The copy is a new container: a fresh id range, no claim on
// the original's address, and a lineage of its own — so when the copy is
// backed up later and host-a dies, failover rebuilds the original from the
// original's backup, not from the copy's newer one.
func TestRestoreContainer_CopyBesideALiveOriginalIsANewContainer(t *testing.T) {
	s, rt, repo := restoreIPServer(t)
	ctx := context.Background()
	orig := specOf(t, s, "host-a", "web")
	if orig.OwnerID == "" || orig.IDMapBase == 0 {
		t.Fatalf("original created as %+v, want an owner_id and an id range", orig)
	}

	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	assertIPUnavailable(t, s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "web", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z", Start: true,
	}, rs))
	cp := specOf(t, s, "host-b", "web")
	if cp.OwnerID == "" || cp.OwnerID == orig.OwnerID {
		t.Fatalf("copy owner_id = %q, original's %q: want a lineage of its own", cp.OwnerID, orig.OwnerID)
	}
	if got := rt.owners["web"]; got.OwnerID != cp.OwnerID || got.Project != "acme" {
		t.Fatalf("copy's on-disk owner record = %+v, want {acme %s}", got, cp.OwnerID)
	}
	if cp.IDMapBase == 0 || cp.IDMapBase == orig.IDMapBase {
		t.Fatalf("copy id range = %d, original's %d: want a fresh one", cp.IDMapBase, orig.IDMapBase)
	}
	if got := specOf(t, s, "host-a", "web").OwnerID; got != orig.OwnerID {
		t.Fatalf("the original's owner_id changed to %q", got)
	}

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "web", HostName: "host-b", RepoPath: repo, Timestamp: "2026-10-09T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("backup the copy: %v", err)
	}
	row, err := corrosion.GetContainer(ctx, s.db, "host-a", "web")
	if err != nil || row == nil {
		t.Fatalf("original row: %v", err)
	}
	row.State, row.StateDetail = "relocating", corrosion.RelocateRestoreDetail("host-c", "tok-x")
	if err := corrosion.UpsertContainer(ctx, s.db, *row); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"main": repo})
	var gotTs string
	s.migrateRestoreOverride = func(_ context.Context, target, repoPath, name, ts string, start bool) (corrosion.RestoreOutcome, error) {
		gotTs = ts
		return corrosion.RestoreLanded, nil
	}
	if _, err := s.RestoreContainerFromBackup(ctx, "web", "host-c", "tok-x"); err != nil {
		t.Fatal(err)
	}
	if gotTs != "2026-10-08T12:00:00Z" {
		t.Fatalf("failover restored the backup at %q, want the original's own (2026-10-08T12:00:00Z), not the copy's", gotTs)
	}
}

// M5, as ruled: a relocating row that cannot be read must not cost the
// container its data. Failover still restores the backup, picked by name as
// before the owner rule existed, rather than falling back to an image
// recreate.
func TestRestoreContainerFromBackup_UnreadableRelocatingRowStillRestores(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	s.SetBackupRepos(map[string]string{"main": repo})
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: "main", Timestamp: "2026-06-27T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	if err := s.db.Execute(ctx, `DROP TABLE containers`); err != nil {
		t.Fatal(err)
	}
	var gotTs string
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, ts string, _ bool) (corrosion.RestoreOutcome, error) {
		gotTs = ts
		return corrosion.RestoreLanded, nil
	}
	outcome, err := s.RestoreContainerFromBackup(ctx, "ct1", "host-b", "tok-x")
	if err != nil || outcome != corrosion.RestoreLanded || gotTs != "2026-06-27T12:00:00Z" {
		t.Fatalf("got (%v, %v) restoring %q; want the backup at 2026-06-27T12:00:00Z restored (RestoreLanded)", outcome, err, gotTs)
	}
}

// putCTManifestNoProject writes a container backup manifest whose embedded
// spec records no project, as a build from before projects did.
func putCTManifestNoProject(t *testing.T, dir, name, ts string) {
	t.Helper()
	repo, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(containerBackupSpec{Name: name})
	if _, err := pbsstore.PushDisk(context.Background(), repo, strings.NewReader("rootfs-tar-noproject-"+name), pbsstore.PushOptions{
		VMName: name, DiskName: containerBackupDisk, Timestamp: ts, ContainerSpecJSON: string(spec),
	}); err != nil {
		t.Fatal(err)
	}
}

// Inspect reads a manifest that records no project as the default
// project's, as it did before the lineage rule: available to a _default
// container, another project's (admin-only) to any other.
func TestProbeContainerBackups_NoProjectManifestIsTheDefaultProjects(t *testing.T) {
	s := newPeerAuthServer(t)
	repo := ctTestRepo(t)
	putCTManifestNoProject(t, repo, "ct1", "2026-10-08T09:00:00Z")
	for _, c := range []struct {
		project             string
		attributed, foreign bool
	}{
		{"", true, false},
		{"_default", true, false},
		{"acme", false, true},
	} {
		resp, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), &pb.ProbeContainerBackupsRequest{
			Name: "ct1", Project: c.project, OwnerId: "own-1", Repos: []string{repo}})
		if err != nil {
			t.Fatal(err)
		}
		p := resp.GetResults()[0]
		if p.GetAttributed() != c.attributed || p.GetForeign() != c.foreign || p.GetOtherLineage() {
			t.Fatalf("project %q: probe = %+v, want attributed=%v foreign=%v", c.project, p, c.attributed, c.foreign)
		}
	}
}

// A host-loss relocation is the same container moving: the restore on the
// survivor keeps the backed-up owner_id even though the relocating row on
// the dead host still records it (an operator restore beside it would not).
func TestRestoreContainer_PeerRelocationKeepsTheLineage(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	spec := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", OwnerID: "own-1"})
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme", CreateSpec: spec,
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T13:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	// The container lived on dead-host, which the coordinator has marked for a
	// restore-relocation here; host-a holds no row of it.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "dead-host", Name: "ct1", State: "relocating", Image: "alpine:3.19", Project: "acme", CreateSpec: spec,
		StateDetail: corrosion.RelocateRestoreDetail("host-a", "tok-xyz"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.7", State: "active"}); err != nil {
		t.Fatal(err)
	}
	rctx := metadata.NewIncomingContext(mtlsAdminCtx("peer-1"), metadata.Pairs(relocateTokenMDKey, "tok-xyz"))
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: rctx}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-27T13:00:00Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}
	if got := specOf(t, s, "host-a", "ct1").OwnerID; got != "own-1" {
		t.Fatalf("relocated owner_id = %q, want the container's own own-1", got)
	}
	if got := rt.owners["ct1"]; got.OwnerID != "own-1" {
		t.Fatalf("relocated on-disk owner record = %+v, want own-1", got)
	}
}

// I-1, scenario A: the operator's manual host-loss recovery. web's host-a
// died and its row stays (fenced, not relocated); the operator restores last
// night's backup on host-b. The row on host-a makes the restore a copy with a
// lineage of its own, but it keeps the backup it came from: when host-b dies
// before the first new backup, failover rebuilds it from that backup rather
// than from the image.
func TestRestoreContainer_RecoveryBesideADeadHostsRowKeepsItsBackup(t *testing.T) {
	s, _ := secServer(t)
	ctx := context.Background()
	repo := ctTestRepo(t)
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "db", State: "running", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: "own-1"}),
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "db", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("backup: %v", err)
	}

	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "db", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z",
	}, rs); err != nil {
		t.Fatalf("recover on host-b: %v", err)
	}
	cp := specOf(t, s, "host-b", "db")
	if cp.OwnerID == "" || cp.OwnerID == "own-1" || cp.RestoredFromOwnerID != "own-1" || cp.RestoredFromTS != "2026-10-08T12:00:00Z" {
		t.Fatalf("recovered spec = %+v, want a new owner_id restored from own-1 at 2026-10-08T12:00:00Z", cp)
	}

	if got := failOverRestoreTs(t, s, repo, "host-b", "db"); got != "2026-10-08T12:00:00Z" {
		t.Fatalf("failover restored %q, want the backup it was recovered from (2026-10-08T12:00:00Z)", got)
	}
}

// I-1, scenario B: a copy restored beside a live original fails over to the
// backup it was restored from — and never to a backup the original took
// after the restore, which is the original's data, not the copy's.
func TestRestoreContainer_CopyFailsOverToItsOwnStartingPoint(t *testing.T) {
	s, _, repo := restoreIPServer(t)
	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	assertIPUnavailable(t, s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "web", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z", Start: true,
	}, rs))
	// The original runs on and is backed up after the restore.
	s.hostName = "host-a"
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-09T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("backup the original: %v", err)
	}
	if got := failOverRestoreTs(t, s, repo, "host-b", "web"); got != "2026-10-08T12:00:00Z" {
		t.Fatalf("the copy failed over to %q, want its own starting point 2026-10-08T12:00:00Z (not the original's 10-09)", got)
	}
}

// failOverRestoreTs marks host/name for a restore-relocation to host-z, with
// repo as the configured backup repo, and returns the backup timestamp
// failover drives (failing when none is chosen).
func failOverRestoreTs(t *testing.T, s *Server, repo, host, name string) string {
	t.Helper()
	ctx := context.Background()
	row, err := corrosion.GetContainer(ctx, s.db, host, name)
	if err != nil || row == nil {
		t.Fatalf("row %s/%s: %v", host, name, err)
	}
	row.State, row.StateDetail = "relocating", corrosion.RelocateRestoreDetail("host-z", "tok-fo")
	if err := corrosion.UpsertContainer(ctx, s.db, *row); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"main": repo})
	var gotTs string
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, ts string, _ bool) (corrosion.RestoreOutcome, error) {
		gotTs = ts
		return corrosion.RestoreLanded, nil
	}
	if _, err := s.RestoreContainerFromBackup(ctx, name, "host-z", "tok-fo"); err != nil {
		t.Fatalf("failover of %s/%s chose no backup: %v", host, name, err)
	}
	return gotTs
}

// I-1 (d): inspect shows a restored copy the backup it came from as
// available — on this host and on the peer that holds the repo — and its
// size and time are that backup's, not the parent's later one.
func TestInspectContainer_ARestoredCopyShowsTheBackupItCameFrom(t *testing.T) {
	restoredFrom := func(t *testing.T, s *Server) {
		t.Helper()
		ctx := context.Background()
		row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
		cs := corrosion.DecodeCreateSpec(row.CreateSpec)
		cs.OwnerID, cs.RestoredFromOwnerID, cs.RestoredFromTS = "own-2", "own-1", "2026-10-08T10:00:00Z"
		row.CreateSpec = corrosion.EncodeCreateSpec(cs)
		if err := corrosion.UpsertContainer(ctx, s.db, *row); err != nil {
			t.Fatal(err)
		}
	}
	check := func(t *testing.T, s *Server) {
		t.Helper()
		d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.GetBackups()) != 1 {
			t.Fatalf("backups = %+v", d.GetBackups())
		}
		if b := d.GetBackups()[0]; b.GetStatus() != backupAvailable || b.GetLatestTimestamp() != "2026-10-08T10:00:00Z" {
			t.Fatalf("backup = %+v, want available at the restored-from 10:00 (not the parent's 11:00)", b)
		}
	}
	t.Run("local", func(t *testing.T) {
		s := inspectTestServer(t, "")
		restoredFrom(t, s)
		repo := ctTestRepo(t)
		putCTManifestOwned(t, repo, "ct1", "acme", "own-1", "2026-10-08T10:00:00Z")
		putCTManifestOwned(t, repo, "ct1", "acme", "own-1", "2026-10-08T11:00:00Z")
		if err := corrosion.UpsertContainerBackup(context.Background(), s.db, "acme", "ct1", repo, 4096); err != nil {
			t.Fatal(err)
		}
		check(t, s)
	})
	t.Run("peer", func(t *testing.T) {
		owner := inspectTestServer(t, "")
		restoredFrom(t, owner)
		sink := newPeerAuthServer(t)
		sink.hostName = "sink-host"
		sinkDir := ctTestRepo(t)
		sink.SetBackupRepos(map[string]string{"r1": sinkDir})
		putCTManifestOwned(t, sinkDir, "ct1", "acme", "own-1", "2026-10-08T10:00:00Z")
		putCTManifestOwned(t, sinkDir, "ct1", "acme", "own-1", "2026-10-08T11:00:00Z")
		addHost(t, sink, "host-a")
		addHost(t, owner, "sink-host")
		if err := corrosion.UpsertContainerBackup(context.Background(), owner.db, "acme", "ct1", "r1", 7000); err != nil {
			t.Fatal(err)
		}
		owner.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
			if host != "sink-host" {
				return nil, nil, status.Error(codes.Unavailable, "no such peer")
			}
			return &probePeer{srv: sink, callAs: "host-a"}, func() {}, nil
		}
		check(t, owner)
	})
}

// m2: a restore after the original was deleted on ANOTHER host keeps the
// lineage: the tombstoned row is not a live holder.
func TestRestoreContainer_AfterDeleteOnAnotherHostKeepsTheLineage(t *testing.T) {
	s, _ := secServer(t)
	ctx := context.Background()
	repo := ctTestRepo(t)
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "c1", State: "stopped", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: "own-1"}),
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "c1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z",
	}, bk); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, s.db, "host-a", "c1"); err != nil {
		t.Fatal(err)
	}
	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "c1", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z"}, rs); err != nil {
		t.Fatal(err)
	}
	if cs := specOf(t, s, "host-b", "c1"); cs.OwnerID != "own-1" || cs.RestoredFromOwnerID != "" {
		t.Fatalf("restored spec = %+v, want the lineage own-1 kept, with no parent", cs)
	}
}

// R-I1: a copy (own-2, restored from own-1's 10-08 backup) whose host dies is
// rebuilt from that very backup — end to end, the target-side restore runs
// for real. The relocated container stays the copy: own-2 with its parent,
// on the row and on disk. Its next failover still cannot take the original's
// later backup, and the original's failover never takes the copy's.
func TestRestoreContainer_ACopyRelocatedFromItsParentsBackupStaysTheCopy(t *testing.T) {
	s, rt := secServer(t)
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetBackupRepos(map[string]string{"main": repo})
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.7", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "db", State: "running", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: "own-1"}),
	}); err != nil {
		t.Fatal(err)
	}
	backup := func(host, ts string) {
		t.Helper()
		s.hostName = host
		bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
		if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "db", HostName: host, RepoPath: repo, Timestamp: ts}, bk); err != nil {
			t.Fatalf("backup %s at %s: %v", host, ts, err)
		}
	}
	backup("host-a", "2026-10-08T12:00:00Z")

	// The copy, restored on host-b beside the live original.
	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "db", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z"}, rs); err != nil {
		t.Fatalf("restore the copy: %v", err)
	}
	cp := specOf(t, s, "host-b", "db")
	if cp.OwnerID == "own-1" || cp.RestoredFromOwnerID != "own-1" {
		t.Fatalf("copy spec = %+v", cp)
	}
	backup("host-a", "2026-10-09T12:00:00Z") // the original's, after the restore

	// host-b dies: fail the copy over to host-z through the real target restore.
	row, _ := corrosion.GetContainer(ctx, s.db, "host-b", "db")
	row.State, row.StateDetail = "relocating", corrosion.RelocateRestoreDetail("host-z", "tok-r")
	if err := corrosion.UpsertContainer(ctx, s.db, *row); err != nil {
		t.Fatal(err)
	}
	var gotTs string
	s.migrateRestoreOverride = func(_ context.Context, target, repoPath, name, ts string, start bool) (corrosion.RestoreOutcome, error) {
		gotTs = ts
		s.hostName = target
		rctx := metadata.NewIncomingContext(mtlsAdminCtx("peer-1"), metadata.Pairs(relocateTokenMDKey, "tok-r"))
		trs := &progressStream[pb.RestoreContainerProgress]{ctx: rctx}
		if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: name, RepoPath: repoPath, Timestamp: ts, Start: start}, trs); err != nil {
			return corrosion.RestoreFailedBeforeRow, err
		}
		return corrosion.RestoreLanded, nil
	}
	if outcome, err := s.RestoreContainerFromBackup(ctx, "db", "host-z", "tok-r"); err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("relocate the copy: (%v, %v)", outcome, err)
	}
	if gotTs != "2026-10-08T12:00:00Z" {
		t.Fatalf("the copy was rebuilt from %q, want its starting point 2026-10-08T12:00:00Z", gotTs)
	}
	moved := specOf(t, s, "host-z", "db")
	if moved.OwnerID != cp.OwnerID || moved.RestoredFromOwnerID != "own-1" || moved.RestoredFromTS != "2026-10-08T12:00:00Z" {
		t.Fatalf("relocated spec = %+v, want the copy's %q with parent own-1@2026-10-08T12:00:00Z", moved, cp.OwnerID)
	}
	if got := rt.owners["db"]; got.OwnerID != cp.OwnerID {
		t.Fatalf("relocated on-disk owner record = %+v, want the copy's %q", got, cp.OwnerID)
	}
	s.migrateRestoreOverride = nil

	// Its next failover still keeps to its starting point, not the original's 10-09.
	if got := failOverRestoreTs(t, s, repo, "host-z", "db"); got != "2026-10-08T12:00:00Z" {
		t.Fatalf("the relocated copy's next failover picked %q, want 2026-10-08T12:00:00Z", got)
	}
	// The copy (now on host-z) is backed up; the original's failover never takes it.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-z", "db")
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-z", Name: "db", State: "running", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(moved),
	}); err != nil {
		t.Fatal(err)
	}
	backup("host-z", "2026-10-10T12:00:00Z")
	if got := failOverRestoreTs(t, s, repo, "host-a", "db"); got != "2026-10-09T12:00:00Z" {
		t.Fatalf("the original's failover picked %q, want its own 2026-10-09T12:00:00Z", got)
	}
}

// R-m1: the restored-from bound compares times, not strings: an offset or a
// fractional second must not sort a later backup of the parent below it, nor
// an earlier one above it.
func TestManifestOwnedBy_ParentBoundComparesTimes(t *testing.T) {
	rec := &corrosion.ContainerRecord{Project: "acme", CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
		OwnerID: "own-2", RestoredFromOwnerID: "own-1", RestoredFromTS: "2026-10-08T12:00:00Z"})}
	spec, _ := json.Marshal(containerBackupSpec{Name: "db", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{OwnerID: "own-1"})})
	for _, c := range []struct {
		ts   string
		want bool
	}{
		{"2026-10-08T12:00:00Z", true},
		{"2026-10-08T11:59:59Z", true},
		{"2026-10-08T11:00:00-05:00", false}, // 16:00Z, after
		{"2026-10-08T12:00:00.5Z", false},    // half a second after
		{"2026-10-08T13:00:00+02:00", true},  // 11:00Z, before
		{"2026-10-08T12:00:01Z", false},
	} {
		m := &pbsstore.Manifest{ContainerSpecJSON: string(spec), Timestamp: c.ts}
		if got := manifestOwnedBy(m, rec); got != c.want {
			t.Errorf("parent manifest at %s: owned = %v, want %v", c.ts, got, c.want)
		}
	}
}

// Round 4: the lineage fields of a restore request are the failover
// coordinator's alone. An operator restore that sends them, and a restore over
// a peer cert that is not a relocation, has them ignored: the restore lays
// down the lineage it would have without them, so no request can claim
// another container's lineage.
func TestRestoreContainer_AnOperatorCannotSetTheLineage(t *testing.T) {
	const ts = "2026-10-08T12:00:00Z"
	forged := func(r *pb.RestoreContainerRequest) *pb.RestoreContainerRequest {
		r.OwnerId, r.RestoredFromOwnerId, r.RestoredFromTs = "own-victim", "own-victim", "2030-01-01T00:00:00Z"
		return r
	}
	setup := func(t *testing.T) (*Server, *fakeCTRuntime, string) {
		t.Helper()
		s, rt := secServer(t)
		ctx := context.Background()
		repo := ctTestRepo(t)
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: "host-a", Name: "db", State: "running", Image: "alpine:3.19", Project: "acme",
			CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: "own-1"}),
		}); err != nil {
			t.Fatal(err)
		}
		bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
		if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "db", HostName: "host-a", RepoPath: repo, Timestamp: ts}, bk); err != nil {
			t.Fatal(err)
		}
		return s, rt, repo
	}
	for _, c := range []struct {
		name string
		ctx  func() context.Context
	}{
		{"operator", adminCtx},
		{"peer cert, no relocation", func() context.Context { return mtlsAdminCtx("peer-1") }},
	} {
		t.Run(c.name+"/after a delete", func(t *testing.T) {
			s, rt, repo := setup(t)
			if err := corrosion.DeleteContainer(context.Background(), s.db, "host-a", "db"); err != nil {
				t.Fatal(err)
			}
			rs := &progressStream[pb.RestoreContainerProgress]{ctx: c.ctx()}
			if err := s.RestoreContainer(forged(&pb.RestoreContainerRequest{Name: "db", RepoPath: repo, Timestamp: ts}), rs); err != nil {
				t.Fatal(err)
			}
			if cs := specOf(t, s, "host-a", "db"); cs.OwnerID != "own-1" || cs.RestoredFromOwnerID != "" || cs.RestoredFromTS != "" {
				t.Fatalf("restored spec = %+v, want own-1 with no parent: the request's lineage was honoured", cs)
			}
			if got := rt.owners["db"]; got.OwnerID != "own-1" {
				t.Fatalf("on-disk owner record = %+v, want own-1", got)
			}
		})
		t.Run(c.name+"/beside the live original", func(t *testing.T) {
			s, rt, repo := setup(t)
			s.hostName = "host-b"
			rs := &progressStream[pb.RestoreContainerProgress]{ctx: c.ctx()}
			if err := s.RestoreContainer(forged(&pb.RestoreContainerRequest{Name: "db", RepoPath: repo, Timestamp: ts}), rs); err != nil {
				t.Fatal(err)
			}
			cs := specOf(t, s, "host-b", "db")
			if cs.OwnerID == "" || cs.OwnerID == "own-1" || cs.OwnerID == "own-victim" ||
				cs.RestoredFromOwnerID != "own-1" || cs.RestoredFromTS != ts {
				t.Fatalf("copy spec = %+v, want a new owner_id restored from own-1@%s", cs, ts)
			}
			if got := rt.owners["db"]; got.OwnerID != cs.OwnerID {
				t.Fatalf("on-disk owner record = %+v, want %s", got, cs.OwnerID)
			}
		})
	}
}

// A clone is a new lineage that was restored from nothing: cloning a restored
// copy must not carry the copy's parent record, or the clone would own the
// parent's backups up to the copy's starting point.
func TestCloneContainer_ClearsTheRestoredFromParent(t *testing.T) {
	s, _ := secServer(t)
	ctx := context.Background()
	repo := ctTestRepo(t)
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "db", State: "running", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", OwnerID: "own-1"}),
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "db", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z"}, bk); err != nil {
		t.Fatal(err)
	}
	s.hostName = "host-b"
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "db", RepoPath: repo, Timestamp: "2026-10-08T12:00:00Z"}, rs); err != nil {
		t.Fatal(err)
	}
	cp := specOf(t, s, "host-b", "db")
	if cp.RestoredFromOwnerID != "own-1" {
		t.Fatalf("copy spec = %+v: it records no parent, so the clone would prove nothing", cp)
	}
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "db", Target: "db2", HostName: "host-b"}); err != nil {
		t.Fatal(err)
	}
	cl := specOf(t, s, "host-b", "db2")
	if cl.OwnerID == "" || cl.OwnerID == cp.OwnerID || cl.OwnerID == "own-1" {
		t.Fatalf("clone owner_id = %q, want a new lineage", cl.OwnerID)
	}
	if cl.RestoredFromOwnerID != "" || cl.RestoredFromTS != "" {
		t.Fatalf("clone spec = %+v, want no restored-from parent", cl)
	}
}

package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
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

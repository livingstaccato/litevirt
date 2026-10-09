package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// insertLegacyCTBackupRow writes a container_backups row the way every
// release before project-qualified keys did: keyed on the bare name.
func insertLegacyCTBackupRow(t *testing.T, s *Server, name, repo string, bytes int64, updated string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO container_backups (ct_name, repo, total_bytes, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(ct_name, repo) DO UPDATE SET total_bytes = excluded.total_bytes, updated_at = excluded.updated_at`,
		name, repo, bytes, updated); err != nil {
		t.Fatal(err)
	}
}

func manifestSize(t *testing.T, dir, name, ts string) int64 {
	t.Helper()
	r, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.GetManifest(name, ts, containerBackupDisk)
	if err != nil {
		t.Fatal(err)
	}
	return m.TotalSize
}

// R2: one shared repo holds backups of "ct1" from acme AND beta. The index
// row is shared and was last written by beta. acme's viewer must see acme's
// own size and time (from acme's manifest), never beta's.
func TestInspectContainer_SharedRepoTwoProjectsShowsOwnSizeAndTime(t *testing.T) {
	s := inspectTestServer(t, "")
	shared := ctTestRepo(t)
	putCTManifest(t, shared, "ct1", "acme", "2026-10-08T10:00:00Z")
	putCTManifest(t, shared, "ct1", "beta", "2026-10-08T11:00:00Z")
	insertLegacyCTBackupRow(t, s, "ct1", shared, 999_999, "2026-10-08T11:00:00Z")
	want := manifestSize(t, shared, "ct1", "2026-10-08T10:00:00Z")

	viewer := grantUser(t, s, "carol", "/projects/acme", "Viewer")
	d, err := s.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.GetBackups()) != 1 {
		t.Fatalf("backups = %+v", d.GetBackups())
	}
	b := d.GetBackups()[0]
	if b.GetTotalBytes() != want || b.GetUpdatedAt() != "2026-10-08T10:00:00Z" {
		t.Fatalf("acme's entry shows size %d at %q, want acme's own %d at 2026-10-08T10:00:00Z (beta's row says 999999 at 11:00)",
			b.GetTotalBytes(), b.GetUpdatedAt(), want)
	}
}

// R2: the probe keeps Foreign alongside Attributed.
func TestProbeContainerBackups_KeepsForeignWithAttributed(t *testing.T) {
	s := newPeerAuthServer(t)
	shared := ctTestRepo(t)
	putCTManifest(t, shared, "ct1", "acme", "2026-10-08T10:00:00Z")
	putCTManifest(t, shared, "ct1", "beta", "2026-10-08T11:00:00Z")
	resp, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), &pb.ProbeContainerBackupsRequest{Name: "ct1", Project: "acme", Repos: []string{shared}})
	if err != nil {
		t.Fatal(err)
	}
	p := resp.GetResults()[0]
	if !p.GetAttributed() || !p.GetForeign() || p.GetLatestTimestamp() != "2026-10-08T10:00:00Z" || p.GetLatestTotalBytes() <= 0 {
		t.Fatalf("probe = %+v, want attributed+foreign with acme's latest", p)
	}
}

// m2: a repo that opened but whose manifests of this name cannot be read
// is not evidence of absence: the entry is unknown, not not_found.
func TestInspectContainer_UnreadableRepoIsUnknown(t *testing.T) {
	s := inspectTestServer(t, "")
	repo := ctTestRepo(t)
	dir := filepath.Join(repo, "snapshots", "ct1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "2026-10-08T10:00:00Z-rootfs.manifest.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertLegacyCTBackupRow(t, s, "ct1", repo, 10, "2026-10-08T10:00:00Z")
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatal(err)
	}
	if b := d.GetBackups()[0]; b.GetStatus() != "unknown" {
		t.Fatalf("unreadable repo = %+v, want unknown", b)
	}
}

// m1: the probe honours the caller's deadline, waiting for a slot included.
func TestProbeContainerBackups_HonoursDeadlineAndCapsConcurrency(t *testing.T) {
	s := newPeerAuthServer(t)
	repo := ctTestRepo(t)
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T10:00:00Z")
	// Occupy every probe slot: a new probe must give up at its deadline.
	for i := 0; i < cap(s.backupProbeSlots()); i++ {
		s.backupProbeSlots() <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(mtlsAdminCtx("peer-1"), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, err := s.ProbeContainerBackups(ctx, &pb.ProbeContainerBackupsRequest{Name: "ct1", Project: "acme", Repos: []string{repo}})
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe ignored the deadline while waiting for a slot")
	}
	if err != nil {
		t.Fatalf("probe without a slot: %v", err)
	}
	if p := resp.GetResults()[0]; p.GetAttributed() || !p.GetUnreadable() {
		t.Fatalf("probe without a slot = %+v, want unreadable", p)
	}
	for i := 0; i < cap(s.backupProbeSlots()); i++ {
		<-s.backupProbeSlots()
	}
	// A cancelled context is not walked either. (Called below the RPC gate,
	// whose own lookups would also fail on a cancelled context.)
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	for i := 0; i < 20; i++ {
		if p := s.probeContainerBackupRepo(cctx, "ct1", "acme", repo); p.GetAttributed() || !p.GetUnreadable() {
			t.Fatalf("probe with a cancelled context = %+v, want unreadable", p)
		}
	}
}

// m1: parsed manifests are cached per repo and name for a short TTL, so a
// repeated probe does not walk the repo again.
func TestProbeContainerBackups_CachesManifests(t *testing.T) {
	s := newPeerAuthServer(t)
	repo := ctTestRepo(t)
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T10:00:00Z")
	req := &pb.ProbeContainerBackupsRequest{Name: "ct1", Project: "acme", Repos: []string{repo}}
	if _, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), req); err != nil {
		t.Fatal(err)
	}
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T12:00:00Z")
	resp, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetResults()[0].GetLatestTimestamp(); got != "2026-10-08T10:00:00Z" {
		t.Fatalf("second probe inside the TTL re-walked the repo (saw %s)", got)
	}
}

// m3: a viewer without the admin role gets no host paths: no rootfs path and
// no absolute repo path.
func TestInspectContainer_NoHostPathsForViewer(t *testing.T) {
	s := inspectTestServer(t, "")
	repo := ctTestRepo(t)
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T10:00:00Z")
	insertLegacyCTBackupRow(t, s, "ct1", repo, 10, "2026-10-08T10:00:00Z")
	viewer := grantUser(t, s, "carol", "/projects/acme", "Viewer")
	d, err := s.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.GetRootfsPath() != "" {
		t.Errorf("viewer sees rootfs path %q", d.GetRootfsPath())
	}
	for _, b := range d.GetBackups() {
		if strings.HasPrefix(b.GetRepo(), "/") {
			t.Errorf("viewer sees absolute repo path %q", b.GetRepo())
		}
	}
	if len(d.GetBackups()) != 1 {
		t.Fatalf("viewer lost the available entry: %+v", d.GetBackups())
	}
}

type fwdInspectPeer struct {
	pb.LiteVirtClient
	detail *pb.ContainerDetail
}

func (f *fwdInspectPeer) InspectContainer(context.Context, *pb.InspectContainerRequest, ...grpc.CallOption) (*pb.ContainerDetail, error) {
	return f.detail, nil
}

// The filter also runs on the node a viewer reached when the call is
// forwarded: the owner answers a peer, so it returns everything.
func TestInspectContainer_ForwardedCallFilteredForViewer(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ctb", State: "running", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &fwdInspectPeer{detail: &pb.ContainerDetail{
			Container:  &pb.Container{Name: "ctb", HostName: "host-b", Project: "acme"},
			RootfsPath: "/var/lib/lxc/ctb/rootfs", HostDetail: true,
			Backups: []*pb.ContainerBackupRef{
				{Repo: "r1", Status: "available", Available: true, Location: "host-b"},
				{Repo: "/srv/beta-only", Status: "foreign", UnavailableReason: "repo /srv/beta-only ..."},
				{Repo: "/srv/gone", Status: "not_found", UnavailableReason: "repo /srv/gone is not present on host-b"},
			},
		}}, func() {}, nil
	}
	viewer := grantUser(t, s, "carol", "/projects/acme", "Viewer")
	d, err := s.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ctb"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.GetBackups()) != 1 || d.GetBackups()[0].GetRepo() != "r1" || d.GetRootfsPath() != "" {
		t.Fatalf("forwarded detail reached the viewer unfiltered: rootfs=%q backups=%+v", d.GetRootfsPath(), d.GetBackups())
	}
}

// When every backup entry resolves on the answering host, no peer is asked.
func TestInspectContainer_NoPeerDialWhenResolvedLocally(t *testing.T) {
	s := inspectTestServer(t, "")
	repo := ctTestRepo(t)
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T10:00:00Z")
	if err := corrosion.UpsertContainerBackup(context.Background(), s.db, "acme", "ct1", repo, 10); err != nil {
		t.Fatal(err)
	}
	addHost(t, s, "host-z")
	dialed := false
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		dialed = true
		return &probePeer{canned: &pb.ProbeContainerBackupsResponse{}}, func() {}, nil
	}
	if _, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"}); err != nil {
		t.Fatal(err)
	}
	if dialed {
		t.Fatal("a peer was asked although every entry resolved locally")
	}
}

// n3: the local probe has its own deadline, so an inspect from a caller with
// no deadline (the CLI) cannot hang on a hung repo walk or a full set of
// probe slots: the entry comes back unknown.
func TestInspectContainer_LocalProbeHasADeadline(t *testing.T) {
	s := inspectTestServer(t, "")
	repo := ctTestRepo(t)
	putCTManifest(t, repo, "ct1", "acme", "2026-10-08T10:00:00Z")
	if err := corrosion.UpsertContainerBackup(context.Background(), s.db, "acme", "ct1", repo, 10); err != nil {
		t.Fatal(err)
	}
	prev := backupProbeTimeout
	backupProbeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { backupProbeTimeout = prev })
	slots := s.backupProbeSlots()
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	})
	done := make(chan *pb.ContainerDetail, 1)
	go func() {
		d, _ := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
		done <- d
	}()
	select {
	case d := <-done:
		if d == nil || len(d.GetBackups()) != 1 || d.GetBackups()[0].GetStatus() != "unknown" {
			t.Fatalf("inspect with a stuck local probe = %+v, want the entry unknown", d.GetBackups())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inspect without a caller deadline hung on the local probe")
	}
}

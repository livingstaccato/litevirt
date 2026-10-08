package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// inspectTestServer seeds host-a with container ct1 whose on-disk dir holds an
// LXC config (with extraConfig appended) and a 1000-byte rootfs file.
func inspectTestServer(t *testing.T, extraConfig string) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()

	ctDir := filepath.Join(t.TempDir(), "ct1")
	rootfs := filepath.Join(ctDir, "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "blob"), make([]byte, 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "lxc.uts.name = ct1\nlxc.rootfs.path = dir:" + rootfs + "\n" + extraConfig
	if err := os.WriteFile(filepath.Join(ctDir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	s.SetContainerRuntime(&fakeCTRuntime{rootfs: rootfs})

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19",
		CPULimit: 2, MemMiB: 256, Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
			Networks: []corrosion.ContainerNetwork{
				{Name: "eth0", NetworkName: "lxtnet", IP: "172.16.77.50/24", MAC: "aa:bb:cc:00:00:01"},
				{Name: "eth1", Bridge: "lxcbr0"},
			},
		}),
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct1", NetworkName: "lxtnet", Ordinal: 0,
		MAC: "aa:bb:cc:00:00:01", IP: "172.16.77.50/24", VethDevice: "lvc1a2b3c0", SecurityGroups: []string{"web"},
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}
	if err := corrosion.InsertContainerSnapshot(ctx, s.db, corrosion.ContainerSnapshotRecord{
		CtName: "ct1", HostName: "host-a", Name: "s1", State: "ok", Type: "tar", SizeBytes: 4096,
	}); err != nil {
		t.Fatalf("InsertContainerSnapshot: %v", err)
	}
	return s
}

// Inspect reports the row, the create spec, the NICs, the rootfs and its
// size, snapshots, backups, and the privilege mode read from the LXC config.
func TestInspectContainer_ReportsTheContainer(t *testing.T) {
	s := inspectTestServer(t, "")
	ctx := context.Background()
	live := ctTestRepo(t)
	putCTManifest(t, live, "ct1", "acme", "2026-10-08T12:48:39Z")
	if err := corrosion.UpsertContainerBackup(ctx, s.db, "ct1", live, 1<<20); err != nil {
		t.Fatal(err)
	}

	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1", MeasureRootfs: true})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	c := d.GetContainer()
	if c.GetHostName() != "host-a" || c.GetState() != "running" || c.GetImage() != "alpine:3.19" ||
		c.GetProject() != "acme" || c.GetCpuLimit() != 2 || c.GetMemoryMib() != 256 || c.GetCreatedAt() == "" {
		t.Errorf("container = %+v", c)
	}
	if !d.GetHostDetail() {
		t.Error("host_detail false on the container's own host")
	}
	if d.GetPrivilege() != "privileged" {
		t.Errorf("privilege = %q, want privileged (no lxc.idmap in the config)", d.GetPrivilege())
	}
	if d.GetTemplate() != "download" || d.GetDistro() != "alpine" || d.GetRelease() != "3.19" || d.GetArch() != "amd64" {
		t.Errorf("create spec = %q/%q/%q/%q", d.GetTemplate(), d.GetDistro(), d.GetRelease(), d.GetArch())
	}
	if len(d.GetInterfaces()) != 2 {
		t.Fatalf("interfaces = %+v, want 2", d.GetInterfaces())
	}
	if n := d.GetInterfaces()[0]; n.GetName() != "eth0" || n.GetNetworkName() != "lxtnet" || n.GetIp() != "172.16.77.50/24" ||
		n.GetVeth() != "lvc1a2b3c0" || len(n.GetSecurityGroups()) != 1 {
		t.Errorf("eth0 = %+v", n)
	}
	if n := d.GetInterfaces()[1]; n.GetName() != "eth1" || n.GetBridge() != "lxcbr0" {
		t.Errorf("eth1 = %+v", n)
	}
	if !strings.HasSuffix(d.GetRootfsPath(), "/ct1/rootfs") || d.GetRootfsBytes() < 1000 {
		t.Errorf("rootfs = %q (%d bytes), want the rootfs and >= 1000 bytes", d.GetRootfsPath(), d.GetRootfsBytes())
	}
	if len(d.GetSnapshots()) != 1 || d.GetSnapshots()[0].GetName() != "s1" {
		t.Errorf("snapshots = %+v", d.GetSnapshots())
	}
	if len(d.GetBackups()) != 1 || !d.GetBackups()[0].GetAvailable() || d.GetBackups()[0].GetTotalBytes() != 1<<20 ||
		d.GetBackups()[0].GetStatus() != "available" || d.GetBackups()[0].GetLocation() != "host-a" ||
		d.GetBackups()[0].GetLatestTimestamp() != "2026-10-08T12:48:39Z" {
		t.Errorf("backups = %+v, want the live repo available on host-a", d.GetBackups())
	}
}

// An lxc.idmap in the config makes the container unprivileged; inspect reads
// the real config, so it stays right once containers are created that way.
func TestInspectContainer_UnprivilegedFromIdmap(t *testing.T) {
	s := inspectTestServer(t, "lxc.idmap = u 0 100000 65536\nlxc.idmap = g 0 100000 65536\n")
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1", HostName: "host-a"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if d.GetPrivilege() != "unprivileged" {
		t.Fatalf("privilege = %q, want unprivileged", d.GetPrivilege())
	}
}

// A backup index row whose repo was deleted (lab: /srv/lxtbk) is reported to
// an admin as not_found once every host has answered, and never removed. A
// viewer without the admin role is not shown it (it cannot be attributed to
// this container any more), so no host path reaches them.
func TestInspectContainer_BackupInVanishedRepo(t *testing.T) {
	s := inspectTestServer(t, "")
	ctx := context.Background()
	gone := filepath.Join(t.TempDir(), "lxtbk")
	if err := corrosion.UpsertContainerBackup(ctx, s.db, "ct1", gone, 5000); err != nil {
		t.Fatal(err)
	}
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if len(d.GetBackups()) != 1 {
		t.Fatalf("backups = %+v, want the stale row reported to an admin", d.GetBackups())
	}
	b := d.GetBackups()[0]
	if b.GetRepo() != gone || b.GetAvailable() || b.GetStatus() != "not_found" || b.GetUnavailableReason() == "" || b.GetTotalBytes() != 5000 {
		t.Fatalf("stale backup = %+v, want not_found with a reason", b)
	}
	rows, _ := s.db.Query(ctx, `SELECT 1 AS ok FROM container_backups WHERE ct_name = 'ct1' AND repo = ?`, gone)
	if len(rows) != 1 {
		t.Fatal("inspect removed the backup index row")
	}

	viewer := grantUser(t, s, "carol", "/projects/acme", "Viewer")
	d, err = s.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("viewer InspectContainer: %v", err)
	}
	if len(d.GetBackups()) != 0 {
		t.Fatalf("viewer was shown an unattributable backup row: %+v", d.GetBackups())
	}
}

// I1: container_backups has no host or project column, so a same-named
// container in another project shares index rows with this one. Inspect
// shows a viewer only the repos whose manifests carry THIS container's
// name and project; the other project's repo is shown only to an admin, as
// foreign.
func TestInspectContainer_SameNameOtherProjectBackupsNotShown(t *testing.T) {
	s := inspectTestServer(t, "")
	ctx := context.Background()
	ours, theirs := ctTestRepo(t), ctTestRepo(t)
	putCTManifest(t, ours, "ct1", "acme", "2026-10-08T10:00:00Z")
	putCTManifest(t, theirs, "ct1", "beta", "2026-10-08T11:00:00Z")
	for _, r := range []string{ours, theirs} {
		if err := corrosion.UpsertContainerBackup(ctx, s.db, "ct1", r, 4096); err != nil {
			t.Fatal(err)
		}
	}

	viewer := grantUser(t, s, "carol", "/projects/acme", "Viewer")
	d, err := s.InspectContainer(viewer, &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("viewer InspectContainer: %v", err)
	}
	if len(d.GetBackups()) != 1 || d.GetBackups()[0].GetRepo() != ours {
		t.Fatalf("viewer backups = %+v, want only acme's repo %s", d.GetBackups(), ours)
	}

	d, err = s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("admin InspectContainer: %v", err)
	}
	st := map[string]string{}
	for _, b := range d.GetBackups() {
		st[b.GetRepo()] = b.GetStatus()
	}
	if st[ours] != "available" || st[theirs] != "foreign" {
		t.Fatalf("admin statuses = %v, want ours available and theirs foreign", st)
	}
}

// putCTManifest writes a container backup manifest of name in project into
// the repo at dir, as BackupContainer would.
func putCTManifest(t *testing.T, dir, name, project, ts string) {
	t.Helper()
	repo, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(containerBackupSpec{Name: name, Project: project})
	if _, err := pbsstore.PushDisk(context.Background(), repo, strings.NewReader("rootfs-tar-"+name+project), pbsstore.PushOptions{
		VMName: name, DiskName: containerBackupDisk, Timestamp: ts, ContainerSpecJSON: string(spec),
	}); err != nil {
		t.Fatal(err)
	}
}

// probePeer answers ProbeContainerBackups by delegating to a real server as a
// peer, or with a canned result, or fails to be reached.
type probePeer struct {
	pb.LiteVirtClient
	srv    *Server
	callAs string
	canned *pb.ProbeContainerBackupsResponse
	err    error
}

func (p *probePeer) ProbeContainerBackups(_ context.Context, in *pb.ProbeContainerBackupsRequest, _ ...grpc.CallOption) (*pb.ProbeContainerBackupsResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.canned != nil {
		return p.canned, nil
	}
	return p.srv.ProbeContainerBackups(mtlsAdminCtx(p.callAs), in)
}

func addHost(t *testing.T, s *Server, name string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: name, Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
}

// I2, remote sink: a backup taken through a sink lands in the SINK's repo,
// named by a logical repo the owner may not even have. The owner asks the
// other hosts, and the sink, which holds it, makes it available there.
func TestInspectContainer_SinkBackupIsAvailableOnTheSink(t *testing.T) {
	owner := inspectTestServer(t, "")
	sink := newPeerAuthServer(t)
	sink.hostName = "sink-host"
	sinkDir := ctTestRepo(t)
	sink.SetBackupRepos(map[string]string{"r1": sinkDir})
	putCTManifest(t, sinkDir, "ct1", "acme", "2026-10-08T12:00:00Z")
	addHost(t, sink, "host-a")
	addHost(t, owner, "sink-host")
	if err := corrosion.UpsertContainerBackup(context.Background(), owner.db, "ct1", "r1", 7000); err != nil {
		t.Fatal(err)
	}
	owner.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "sink-host" {
			return nil, nil, status.Error(codes.Unavailable, "no such peer")
		}
		return &probePeer{srv: sink, callAs: "host-a"}, func() {}, nil
	}

	d, err := owner.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if len(d.GetBackups()) != 1 {
		t.Fatalf("backups = %+v", d.GetBackups())
	}
	if b := d.GetBackups()[0]; b.GetStatus() != "available" || !b.GetAvailable() || b.GetLocation() != "sink-host" {
		t.Fatalf("sink backup = %+v, want available on sink-host", b)
	}
}

// I2, migrated container: backed up to host-a's local repo, then migrated to
// host-b. Inspect on host-b finds it on host-a rather than calling it gone.
func TestInspectContainer_MigratedContainerBackupFoundOnFormerHost(t *testing.T) {
	s := inspectTestServer(t, "")
	s.hostName = "host-b"
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "mig", State: "running", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	repoOnA := "/srv/only-on-host-a"
	if err := corrosion.UpsertContainerBackup(ctx, s.db, "mig", repoOnA, 9000); err != nil {
		t.Fatal(err)
	}
	addHost(t, s, "host-a")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &probePeer{canned: &pb.ProbeContainerBackupsResponse{Results: []*pb.ContainerBackupProbe{
			{Repo: repoOnA, Opened: true, Attributed: true, LatestTimestamp: "2026-10-07T09:00:00Z"},
		}}}, func() {}, nil
	}
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "mig"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if len(d.GetBackups()) != 1 || d.GetBackups()[0].GetStatus() != "available" || d.GetBackups()[0].GetLocation() != "host-a" {
		t.Fatalf("migrated backup = %+v, want available on host-a", d.GetBackups())
	}
}

// I2: when a host that might hold the repo cannot be asked, the status is
// unknown, never "does not exist".
func TestInspectContainer_UnaskableHostMakesBackupUnknown(t *testing.T) {
	s := inspectTestServer(t, "")
	ctx := context.Background()
	if err := corrosion.UpsertContainerBackup(ctx, s.db, "ct1", "/srv/somewhere", 100); err != nil {
		t.Fatal(err)
	}
	addHost(t, s, "host-c")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &probePeer{err: status.Error(codes.Unavailable, "host-c down")}, func() {}, nil
	}
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	b := d.GetBackups()[0]
	if b.GetStatus() != "unknown" || b.GetAvailable() || strings.Contains(b.GetUnavailableReason(), "does not exist") {
		t.Fatalf("backup with an unaskable host = %+v, want unknown", b)
	}
}

// The probe is peer-only.
func TestProbeContainerBackups_PeerOnly(t *testing.T) {
	s := newPeerAuthServer(t)
	if _, err := s.ProbeContainerBackups(adminCtx(), &pb.ProbeContainerBackupsRequest{Name: "ct1", Project: "acme", Repos: []string{"/x"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator call: %v, want PermissionDenied", err)
	}
	if _, err := s.ProbeContainerBackups(mtlsAdminCtx("peer-1"), &pb.ProbeContainerBackupsRequest{Name: "ct1", Project: "acme", Repos: []string{"/x"}}); err != nil {
		t.Fatalf("peer call: %v", err)
	}
}

// The rootfs is walked only when asked, and a recent size is reused, so a
// viewer cannot make the owner walk the tree on every inspect.
func TestInspectContainer_RootfsSizeOnRequestAndCached(t *testing.T) {
	s := inspectTestServer(t, "")
	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.GetRootfsBytes() != -1 || d.GetRootfsPath() == "" {
		t.Fatalf("unrequested size: path=%q bytes=%d, want the path and -1", d.GetRootfsPath(), d.GetRootfsBytes())
	}
	first, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1", MeasureRootfs: true})
	if err != nil || first.GetRootfsBytes() < 1000 {
		t.Fatalf("measured: %v %d", err, first.GetRootfsBytes())
	}
	if err := os.WriteFile(filepath.Join(first.GetRootfsPath(), "grown"), make([]byte, 50000), 0o644); err != nil {
		t.Fatal(err)
	}
	again, _ := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1", MeasureRootfs: true})
	if again.GetRootfsBytes() != first.GetRootfsBytes() {
		t.Fatalf("second measure inside the TTL walked again: %d then %d", first.GetRootfsBytes(), again.GetRootfsBytes())
	}
}

// A viewer scoped to another project gets the same PermissionDenied for an
// existing container as for a missing one; an in-project viewer reads it.
func TestInspectContainer_RBAC(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedContainers(t, holder)
	lacker := testServer(t)

	acme := grantUser(t, holder, "carol", "/projects/acme", "Viewer")
	if _, err := holder.InspectContainer(acme, &pb.InspectContainerRequest{Name: "ca1"}); err != nil {
		t.Fatalf("in-project inspect: %v", err)
	}
	_, present := holder.InspectContainer(acme, &pb.InspectContainerRequest{Name: "cb1"})
	_, absent := lacker.InspectContainer(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.InspectContainerRequest{Name: "cb1"})
	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("out-of-project inspect: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
	if _, err := holder.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("admin inspect of a missing container: %v, want NotFound", err)
	}
}

type fakeInspectPeer struct {
	pb.LiteVirtClient
	got *pb.InspectContainerRequest
	err error
}

func (f *fakeInspectPeer) InspectContainer(_ context.Context, in *pb.InspectContainerRequest, _ ...grpc.CallOption) (*pb.ContainerDetail, error) {
	f.got = in
	if f.err != nil {
		return nil, f.err
	}
	return &pb.ContainerDetail{Container: &pb.Container{Name: in.Name, HostName: in.HostName}, Privilege: "unprivileged", HostDetail: true}, nil
}

// A container on another host is inspected there (host-local fields come
// from its own host); with that host down the cluster view is still returned
// with the host-local fields marked unknown.
func TestInspectContainer_ForwardsToTheOwningHost(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ctb", State: "stopped", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	peer := &fakeInspectPeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }

	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ctb"})
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if peer.got == nil || peer.got.GetHostName() != "host-b" || d.GetPrivilege() != "unprivileged" {
		t.Fatalf("not forwarded to host-b: got=%+v detail=%+v", peer.got, d)
	}

	peer.err = status.Error(codes.Unavailable, "host-b down")
	d, err = s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ctb"})
	if err != nil {
		t.Fatalf("InspectContainer with the owner down: %v", err)
	}
	if d.GetHostDetail() || d.GetPrivilege() != "unknown" || d.GetContainer().GetState() != "stopped" || d.GetRootfsBytes() != -1 {
		t.Fatalf("owner-down view = %+v, want the cluster row with host fields unknown", d)
	}
}

package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	if err := corrosion.UpsertContainerBackup(ctx, s.db, "ct1", live, 1<<20); err != nil {
		t.Fatal(err)
	}

	d, err := s.InspectContainer(adminCtx(), &pb.InspectContainerRequest{Name: "ct1"})
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
	if len(d.GetBackups()) != 1 || !d.GetBackups()[0].GetAvailable() || d.GetBackups()[0].GetTotalBytes() != 1<<20 {
		t.Errorf("backups = %+v, want the live repo available", d.GetBackups())
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

// A backup index row whose repo was deleted (lab: /srv/lxtbk) is reported as
// unavailable with the reason, not hidden and never removed.
func TestInspectContainer_BackupInVanishedRepoIsUnavailable(t *testing.T) {
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
		t.Fatalf("backups = %+v, want the stale row reported", d.GetBackups())
	}
	b := d.GetBackups()[0]
	if b.GetRepo() != gone || b.GetAvailable() || b.GetUnavailableReason() == "" || b.GetTotalBytes() != 5000 {
		t.Fatalf("stale backup = %+v, want unavailable with a reason", b)
	}
	rows, _ := s.db.Query(ctx, `SELECT 1 AS ok FROM container_backups WHERE ct_name = 'ct1' AND repo = ?`, gone)
	if len(rows) != 1 {
		t.Fatal("inspect removed the backup index row")
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

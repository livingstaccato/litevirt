package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The filter a deleting owner applies to a live VM's soft-deleted disk rows:
// only this incarnation's host-local, delete-with-VM detaches on OTHER hosts.
//
// Mutations: drop the self check — the "self" row is planned; drop the storage
// check — the "nfs" row is; drop delete_with_vm — "adopted" is; drop the
// incarnation check — "previous VM" is. Each makes the result differ.
func TestDepartedDetachedDisks_OnlyThisIncarnationsLocalDetachesElsewhere(t *testing.T) {
	created := "2026-10-05T10:00:00.700000000Z"
	row := func(disk, host, typ string, withVM bool, deletedAt string) corrosion.SoftDeletedDisk {
		return corrosion.SoftDeletedDisk{
			DiskRecord: corrosion.DiskRecord{
				VMName: "os1", DiskName: disk, HostName: host, Path: "/d/os1-" + disk + ".qcow2",
				StorageType: typ, DeleteWithVM: withVM,
			},
			DeletedAt: deletedAt,
		}
	}
	rows := []corrosion.SoftDeletedDisk{
		row("post1", "node-3", "local", true, "2026-10-05T11:00:00Z"),
		// Same second as the create: deleted_at has second precision.
		row("post2", "node-3", "dir", true, "2026-10-05T10:00:00Z"),
		row("self", "node-1", "local", true, "2026-10-05T11:00:00Z"),
		row("nfs", "node-3", "nfs", true, "2026-10-05T11:00:00Z"),
		row("adopted", "node-3", "local", false, "2026-10-05T11:00:00Z"),
		row("previous VM", "node-2", "local", true, "2026-10-04T09:00:00Z"),
		row("garbled", "node-2", "local", true, "yesterday"),
		row("nohost", "", "local", true, "2026-10-05T11:00:00Z"),
	}
	got := departedDetachedDisks("node-1", created, rows)
	want := map[string][]string{"node-3": {"/d/os1-post1.qcow2", "/d/os1-post2.qcow2"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("planned %v, want %v", got, want)
	}
	if got := departedDetachedDisks("node-1", "not a time", rows); len(got) != 0 {
		t.Fatalf("an unparseable created_at must plan nothing, planned %v", got)
	}
}

// leftoverHost is a host the VM "os1" left: its replica holds the VM's rows
// (owned by owner-host), a detached disk row naming this host, the file, and
// the owner-epoch marker the migration left here.
type leftoverHost struct {
	s      *Server
	fake   *libvirtfake.Fake
	disk   string
	marker string
}

func newLeftoverHost(t *testing.T) *leftoverHost {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	disk := filepath.Join(s.dataDir, "disks", "os1-post1.qcow2")
	if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(disk, 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "os1", HostName: "owner-host", State: "running",
	}, nil, []corrosion.DiskRecord{{
		VMName: "os1", DiskName: "post1", HostName: s.hostName, Path: disk,
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vdb",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.SoftDeleteDisk(ctx, s.db, "os1", "post1"); err != nil {
		t.Fatalf("SoftDeleteDisk: %v", err)
	}
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "os1", 3); err != nil {
		t.Fatalf("WriteVMOwnerEpochMarker: %v", err)
	}
	return &leftoverHost{s: s, fake: fake, disk: disk,
		marker: filepath.Join(s.dataDir, "vms", "os1", "owner_epoch")}
}

func (h *leftoverHost) tombstone(t *testing.T) {
	t.Helper()
	if err := corrosion.DeleteVM(adminCtx(), h.s.db, "os1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
}

func (h *leftoverHost) cleanup(paths ...string) error {
	_, err := h.s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "os1", DiskPaths: paths, VmDeleted: true,
	})
	return err
}

// A deleted VM's detached disk and owner-epoch marker on a host it left are
// removed once that host's replica has the tombstone — the vms/<name> dir too.
//
// Mutation: drop the vm_deleted branch from CleanupMigrationArtifacts — the
// stub rule keeps the disk and nothing touches the marker; red.
func TestCleanupMigrationArtifacts_VMDeletedRemovesItsLeftoversHere(t *testing.T) {
	h := newLeftoverHost(t)
	h.tombstone(t)
	if err := h.cleanup(h.disk); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if fileExists(h.disk) {
		t.Fatal("the deleted VM's detached disk is still on the host it left")
	}
	if fileExists(h.marker) {
		t.Fatal("the deleted VM's owner-epoch marker is still on the host it left")
	}
	if fileExists(filepath.Dir(h.marker)) {
		t.Fatal("the deleted VM's vms/<name> directory is still on the host it left")
	}
}

// Everything a deleted-VM cleanup must keep. Each case is one reason the file
// (and, where noted, the marker) is not provably a dead VM's leftover.
//
// Mutations, each turning exactly its case red: drop the live-row refusal
// ("tombstone not here yet"); drop the domain refusal ("domain defined here");
// drop the recorded-here check ("not recorded here"); drop pathStillReferenced
// ("another VM's backing image"); drop localDomainUsesPath ("in a local
// domain's backing chain"); drop the snapshot check ("snapshot record"); drop
// withinDiskArtifactRoot ("outside the disk root").
func TestCleanupMigrationArtifacts_VMDeletedKeepsWhatItCannotProve(t *testing.T) {
	type outcome struct {
		code       codes.Code
		keepMarker bool
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, h *leftoverHost) []string // returns the paths to send
		want  outcome
	}{
		{"tombstone not here yet", func(t *testing.T, h *leftoverHost) []string {
			return []string{h.disk}
		}, outcome{codes.Aborted, true}},
		{"domain defined here", func(t *testing.T, h *leftoverHost) []string {
			h.tombstone(t)
			h.fake.SetState("os1", libvirtfake.StateRunning)
			return []string{h.disk}
		}, outcome{codes.FailedPrecondition, true}},
		{"not recorded here", func(t *testing.T, h *leftoverHost) []string {
			// The row names another host: the same path there is a different file.
			if _, err := h.s.db.ExecuteRows(adminCtx(), `UPDATE vm_disks SET host_name = 'node-9' WHERE vm_name = 'os1'`); err != nil {
				t.Fatal(err)
			}
			h.tombstone(t)
			return []string{h.disk}
		}, outcome{codes.OK, false}},
		{"another VM's backing image", func(t *testing.T, h *leftoverHost) []string {
			h.tombstone(t)
			if err := corrosion.InsertVM(adminCtx(), h.s.db, corrosion.VMRecord{
				Name: "other", HostName: h.s.hostName, State: "running",
			}, nil, []corrosion.DiskRecord{{
				VMName: "other", DiskName: "root", HostName: h.s.hostName,
				Path: filepath.Join(h.s.dataDir, "disks", "other-root.qcow2"), StorageType: "local",
				BackingImage: h.disk,
			}}); err != nil {
				t.Fatal(err)
			}
			return []string{h.disk}
		}, outcome{codes.OK, false}},
		{"in a local domain's backing chain", func(t *testing.T, h *leftoverHost) []string {
			h.tombstone(t)
			overlay := filepath.Join(h.s.dataDir, "disks", "stray-root.qcow2")
			if err := qcow2.CreateWithBacking(overlay, h.disk, 1<<30, nil); err != nil {
				t.Fatal(err)
			}
			h.fake.SetState("stray", libvirtfake.StateRunning)
			if err := h.fake.AttachDisk("stray", overlay, "vda", "virtio"); err != nil {
				t.Fatal(err)
			}
			return []string{h.disk}
		}, outcome{codes.OK, false}},
		{"snapshot record", func(t *testing.T, h *leftoverHost) []string {
			h.tombstone(t)
			if err := corrosion.InsertSnapshot(adminCtx(), h.s.db, corrosion.SnapshotRecord{
				ID: "snap-1", VMName: "os1", HostName: h.s.hostName, Name: "s1", State: "ready",
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				t.Fatal(err)
			}
			return []string{h.disk}
		}, outcome{codes.OK, false}},
		{"outside the disk root", func(t *testing.T, h *leftoverHost) []string {
			// Recorded at a path no disk-artifact root contains.
			outside := filepath.Join(h.s.dataDir, "os1-post1.qcow2")
			if err := os.Rename(h.disk, outside); err != nil {
				t.Fatal(err)
			}
			if _, err := h.s.db.ExecuteRows(adminCtx(), `UPDATE vm_disks SET path = ? WHERE vm_name = 'os1'`, outside); err != nil {
				t.Fatal(err)
			}
			h.disk = outside
			h.tombstone(t)
			return []string{outside}
		}, outcome{codes.OK, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLeftoverHost(t)
			paths := tc.setup(t, h)
			err := h.cleanup(paths...)
			if got := status.Code(err); got != tc.want.code {
				t.Fatalf("cleanup answered %v (%v), want %v", got, err, tc.want.code)
			}
			if !fileExists(h.disk) {
				t.Fatal("the disk was removed, but nothing proved it unused")
			}
			if got := fileExists(h.marker); got != tc.want.keepMarker {
				t.Fatalf("marker present = %v, want %v", got, tc.want.keepMarker)
			}
		})
	}
}

// A file detached with delete_with_vm unset (adopted/foreign) is never freed.
//
// Mutation: drop the DeleteWithVM condition from the recorded-here set — red.
func TestCleanupMigrationArtifacts_VMDeletedKeepsADiskNotDeletedWithTheVM(t *testing.T) {
	h := newLeftoverHost(t)
	if err := corrosion.InsertDisk(adminCtx(), h.s.db, corrosion.DiskRecord{
		VMName: "os1", DiskName: "post1", HostName: h.s.hostName, Path: h.disk,
		StorageType: "local", TargetDev: "vdb", DeviceKind: "disk", DeleteWithVM: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SoftDeleteDisk(adminCtx(), h.s.db, "os1", "post1"); err != nil {
		t.Fatal(err)
	}
	h.tombstone(t)
	if err := h.cleanup(h.disk); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !fileExists(h.disk) {
		t.Fatal("a disk recorded as not deleted with the VM was removed")
	}
}

type leftoverRecordingPeer struct {
	pb.LiteVirtClient
	host  string
	calls chan leftoverCall
}

type leftoverCall struct {
	host string
	req  *pb.CleanupMigrationArtifactsRequest
}

func (p leftoverRecordingPeer) CleanupMigrationArtifacts(_ context.Context, r *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.calls <- leftoverCall{host: p.host, req: r}
	return &emptypb.Empty{}, nil
}

// The owner's delete asks every other active workload host — once the row is
// tombstoned — to remove the VM's leftovers, naming to each only the detached
// disks its rows place there; never a witness or a host that is not active.
// A --keep-disks delete names no disks (the markers still go).
//
// Mutations: drop the fan-out from DeleteVM — no call arrives; plan it after
// the tombstone — the detached path is missing (the tombstone re-stamps every
// row); plan disks for --keep-disks — the keep-disks subtest sees a path.
func TestDeleteVM_AsksTheHostsTheVMLeftToRemoveItsLeftovers(t *testing.T) {
	for _, keepDisks := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "keep-disks"}[keepDisks], func(t *testing.T) {
			s, fake := provableCreateServer(t)
			ctx := adminCtx()
			for _, h := range []corrosion.HostRecord{
				{Name: "node-3", Address: "10.0.0.3", State: "active"},
				{Name: "node-4", Address: "10.0.0.4", State: "active"},
				{Name: "witness", Address: "10.0.0.5", State: "active", Role: "witness"},
				{Name: "fenced", Address: "10.0.0.6", State: "fenced"},
			} {
				if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
					t.Fatalf("InsertHost %s: %v", h.Name, err)
				}
			}
			calls := make(chan leftoverCall, 16)
			s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
				return leftoverRecordingPeer{host: host, calls: calls}, func() {}, nil
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
				Name: "os1", HostName: s.hostName, State: "running",
			}, nil, []corrosion.DiskRecord{
				{VMName: "os1", DiskName: "post1", HostName: "node-3", Path: "/x/os1-post1.qcow2", StorageType: "local", TargetDev: "vdb"},
				{VMName: "os1", DiskName: "shared", HostName: "node-3", Path: "/x/os1-shared.qcow2", StorageType: "nfs", TargetDev: "vdc"},
			}); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			for _, d := range []string{"post1", "shared"} {
				if err := corrosion.SoftDeleteDisk(ctx, s.db, "os1", d); err != nil {
					t.Fatal(err)
				}
			}
			fake.SetState("os1", libvirtfake.StateRunning)

			if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "os1", KeepDisks: keepDisks}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}

			got := map[string][]string{}
			for len(got) < 2 {
				select {
				case c := <-calls:
					if !c.req.VmDeleted || c.req.VmName != "os1" || c.req.RemoveCloudInit || c.req.FirmwareUuid != "" || c.req.UndefineDomain {
						t.Fatalf("unexpected request to %s: %+v", c.host, c.req)
					}
					got[c.host] = c.req.DiskPaths
				case <-time.After(5 * time.Second):
					t.Fatalf("the delete asked only %v; want node-3 and node-4", got)
				}
			}
			want := map[string][]string{"node-3": {"/x/os1-post1.qcow2"}, "node-4": nil}
			if keepDisks {
				// The markers still go; the disks stay wherever they are.
				want = map[string][]string{"node-3": nil, "node-4": nil}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("asked %v, want %v", got, want)
			}
			select {
			case c := <-calls:
				t.Fatalf("asked a host that is not an active worker: %s", c.host)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

// A host whose replica has not seen the tombstone answers ABORTED, and the
// delete asks it again.
//
// Mutation: return on ABORTED instead of retrying — only one call; red.
func TestCleanupDeletedVMLeftovers_RetriesUntilTheTombstoneArrives(t *testing.T) {
	defer func(a int, b time.Duration) { deletedVMCleanupAttempts, deletedVMCleanupBackoff = a, b }(
		deletedVMCleanupAttempts, deletedVMCleanupBackoff)
	deletedVMCleanupAttempts, deletedVMCleanupBackoff = 4, time.Millisecond
	s := testServer(t)
	n := 0
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return abortingPeer{n: &n, abortFor: 2}, func() {}, nil
	}
	s.cleanupDeletedVMLeftovers(context.Background(), deletedVMLeftovers{vm: "os1", hosts: []string{"node-3"}})
	if n != 3 {
		t.Fatalf("asked %d times, want 3 (two ABORTED, then OK)", n)
	}
}

type abortingPeer struct {
	pb.LiteVirtClient
	n        *int
	abortFor int
}

func (p abortingPeer) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	*p.n++
	if *p.n <= p.abortFor {
		return nil, status.Error(codes.Aborted, "live record here")
	}
	return &emptypb.Empty{}, nil
}

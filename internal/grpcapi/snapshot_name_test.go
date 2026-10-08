package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review R2-M3: libvirt names a snapshot's overlay <disk stem>.<name>,
// and litevirt finds the disk again by cutting the last extension, so a
// name with a dot splits the disk's stem (vm-root.a.b reads as disk
// vm-root.a): the record is never brought to the overlay, and a restore's
// overlay name is cut the same way. A new snapshot name with a dot is
// refused before anything is made; a snapshot that already has one can
// still be restored and deleted.
func TestSnapshotName_ADotIsRefusedForANewSnapshotOnly(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "vd")
	_, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "vd", Name: "pre.upgrade"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreateSnapshot(pre.upgrade) = %v, want InvalidArgument", err)
	}
	if snaps, _ := corrosion.ListSnapshots(adminCtx(), s.db, "vd"); len(snaps) != 0 {
		t.Fatalf("a refused snapshot was recorded: %+v", snaps)
	}
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{ID: "vd-old", VMName: "vd", HostName: s.hostName, Name: "old.one", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: "vd", SnapshotName: "old.one"}); err != nil {
		t.Fatalf("deleting an existing dotted snapshot: %v", err)
	}
}

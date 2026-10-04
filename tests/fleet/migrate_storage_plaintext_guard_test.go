package fleet

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A storage migration sends the guest's RAM and every copied disk block in
// plaintext. libvirt's --with-storage path cannot be tunnelled, so QEMU opens a
// direct tcp:// migration stream and an NBD channel to the target, and nothing
// in litevirt asks for TLS on either (internal/libvirt/migrate.go). Anyone on
// the path between two hosts reads the guest's memory and disks.
//
// Until the migration-only CA exists, a node must refuse that transfer unless
// its operator has said, in config, that the network between hosts is trusted:
// migration.allow_unencrypted_storage. The refusal comes before any work: no
// target stub, no libvirt call.
//
// Mutation: drop the refusal in MigrateVM — the migration reaches libvirt and
// this test goes red on migrateCalls (or on the missing error).
func TestFleet_StorageMigrationIsRefusedUnlessPlaintextIsAllowed(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]

	// The fleet gives each node its own disk root; a real cluster shares one
	// layout, so the disk is named under the target's root, as the other
	// storage-migration tests do. No file is written there.
	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)

	st, err := c.SelfClient(src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err == nil {
		t.Fatal("a storage migration ran with migration.allow_unencrypted_storage off; " +
			"the guest's RAM and disks crossed the network in plaintext")
	}
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "allow_unencrypted_storage") {
		t.Fatalf("refusal = %v; want FailedPrecondition naming migration.allow_unencrypted_storage "+
			"so the operator can see why and what to change", err)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration still reached libvirt %d time(s)", n)
	}
}

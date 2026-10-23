// Fleet scenario: lv rm of a VM whose disk record names a pool this host does
// not have.
//
// A cold move keeps the disk record's pool name, so a disk moved off the host
// that has the pool (rc6 lab 1: a `dir` pool made on the witness for the
// promote) names a pool the VM's new host never had. `lv rm` then failed on the
// disk with `construct dir driver: dir driver requires Target`, left the VM
// half deleted ("its domain is gone but not every disk was removed") and needed
// `lv rm --keep-disks` and a hand clean-up. Removing a file is by its recorded
// path, so the delete frees it where it is; nothing is lost, because the file
// is the one the record names on the host that owns the VM, and nothing is
// orphaned, because the record goes only after the file is gone.

package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Red on ba91f3c21: the delete fails with `dir driver requires Target`, the
// disk file is still there and the VM record is kept.
//
// Mutation: drop the dir-pool-missing fallback in diskDriver - red again.
func TestFleet_RmFreesADirDiskWhosePoolIsNotOnThisHost(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	ctx := context.Background()
	here, other := c.Nodes[0], c.Nodes[1]

	// The pool exists on the other host only.
	poolDir := filepath.Join(c.tmpRoot, other.Name, "wpool")
	if err := corrosion.UpsertStoragePool(ctx, other.DB, corrosion.StoragePoolRecord{
		HostName: other.Name, Name: "wonly", Driver: "dir", Target: poolDir, State: "active"}); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(c.tmpRoot, here.Name, "data", "disks", "mv-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disk, []byte("the VM's data"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mv", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, here.DB, corrosion.VMRecord{
		Name: "mv", HostName: here.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "mv", DiskName: "root", HostName: here.Name, Path: disk, SizeBytes: 13,
			StorageType: "dir", StorageVolume: "wonly", TargetDev: "vda", DeleteWithVM: true},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := c.SelfClient(here).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "mv"}); err != nil {
		t.Fatalf("lv rm of a VM whose disk's pool is not on %s: %v", here.Name, err)
	}
	if _, err := os.Stat(disk); !os.IsNotExist(err) {
		t.Errorf("the delete left the disk file behind (stat: %v)", err)
	}
	if vm, _ := corrosion.GetVM(ctx, here.DB, "mv"); vm != nil {
		t.Errorf("the VM record is still there after the delete: %+v", vm)
	}
}

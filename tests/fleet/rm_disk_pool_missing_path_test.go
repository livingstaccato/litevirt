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

// The fallback that frees a dir disk whose pool is not on this host has no pool
// to anchor it, so the recorded path itself must be a place this host keeps
// disks, or one a pool may write into: a crafted record naming a file in the
// PKI directory fails the delete and the file stays (review M1).
//
// Mutation: drop the path check in the diskDriver fallback - the delete removes
// the file and this goes red.
func TestFleet_RmDoesNotFreeADirDiskWhosePathIsInTheHostsPKIDir(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	t.Cleanup(c.Stop)
	ctx := context.Background()
	here := c.Nodes[0]
	victim := filepath.Join(here.PKIDir, "victim.qcow2")
	if err := os.WriteFile(victim, []byte("not a disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mp", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, here.DB, corrosion.VMRecord{
		Name: "mp", HostName: here.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "mp", DiskName: "root", HostName: here.Name, Path: victim, SizeBytes: 10,
			StorageType: "dir", StorageVolume: "gone", TargetDev: "vda", DeleteWithVM: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(here).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "mp"}); err == nil {
		t.Errorf("the delete freed a disk file in the PKI directory")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the file in the PKI directory was removed: %v", err)
	}
}

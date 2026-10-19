package fleet

// Reviewer probe (round 12): the stub ledger's binding is host#owner_epoch.
// A live --with-storage move commits through CommitMigrationOwnership, which
// moves host_name WITHOUT bumping vm_owner_epoch, so after A->B->A the mark
// B recorded in the first move (A#E) is current again.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestR12Rev_LiveStorageStubRecordDoesNotOutliveItsMove(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]
	pool := filepath.Join(c.tmpRoot, "pool")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, b} {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: pool}})
	}
	p := filepath.Join(pool, "pp1-root.qcow2")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), a.DB, corrosion.VMRecord{
		Name: "pp1", HostName: a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp1", DiskName: "root", HostName: a.Name, Path: p,
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}
	a.Virt.SetState("pp1", "running")
	epoch := func() string {
		vm, _ := corrosion.GetVM(context.Background(), a.DB, "pp1")
		return fmt.Sprintf("%s#%d", vm.HostName, vm.OwnerEpoch)
	}
	t.Logf("start: %s", epoch())

	if err := migrateWithStorageAt(t, c, a, "pp1", b.Name); err != nil {
		t.Fatalf("A->B: %v", err)
	}
	t.Logf("after A->B: %s", epoch())
	_ = os.Remove(p) // separate filesystems in production: B's file is B's
	b.Virt.SetState("pp1", "running")
	if err := migrateWithStorageAt(t, c, b, "pp1", a.Name); err != nil {
		t.Fatalf("B->A: %v", err)
	}
	t.Logf("after B->A: %s", epoch())
	_ = os.Remove(p)
	a.Virt.SetState("pp1", "running")

	before := writeDisk(t, p, 1<<30) // a stray at the path on B, same virtual size
	err := migrateWithStorageAt(t, c, a, "pp1", b.Name)
	after, _ := os.ReadFile(p)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "this migration did not create it") {
		t.Fatalf("third move over a stray file = %v, want FailedPrecondition naming the file (stray unchanged: %v)", err, string(after) == string(before))
	}
}

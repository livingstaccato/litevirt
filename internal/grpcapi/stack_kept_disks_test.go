package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The disks the stack reconciler names as kept for want of proof are judged
// like every other kept disk (keptThere): one on this host that is positively
// gone — the other deleter removed it — is not named; one still there is
// (re-review 2, m-1).
//
// Mutation: drop the keptThere filter — the gone disk is named, red.
func TestNameStackTeardownKeptDisks_ADiskGoneFromItsHostIsNotNamed(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	dir := t.TempDir()
	there, gone := filepath.Join(dir, "web-root.qcow2"), filepath.Join(dir, "web-data.qcow2")
	if err := os.WriteFile(there, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "st", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, []corrosion.DiskRecord{
			{VMName: "web", DiskName: "root", HostName: "test-host", Path: there},
			{VMName: "web", DiskName: "data", HostName: "test-host", Path: gone},
		}); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "web")
	if err != nil || vm == nil {
		t.Fatalf("seeded row = %+v, %v", vm, err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "web"); err != nil {
		t.Fatal(err)
	}

	s.NameStackTeardownKeptDisks(ctx, "st", *vm, "the teardown recorded no disk choice")

	records, _ := s.diskKeptRecords()
	named := map[string]bool{}
	for _, r := range records {
		named[r.Path] = true
	}
	if !named[there] {
		t.Errorf("the kept disk still on this host was not named: %+v", records)
	}
	if named[gone] {
		t.Errorf("a disk gone from this host was named: %+v", records)
	}
}

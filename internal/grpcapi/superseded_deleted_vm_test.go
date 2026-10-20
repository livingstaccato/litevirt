package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv host superseded-disks` names the deleted VM a copy was set aside from,
// with vm_state "deleted", and does not retain it: it follows the retention
// (lab2-drain anomaly 7; round-12 review M3). The copy here is in a pool
// directory only the deleted VM's disks used.
//
// Mutation: answer the copy without the deleted VM's name and state (an
// empty name, as before round 12) — red.
func TestSupersededDisks_NamesTheDeletedVMOfACopy(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := context.Background()
	disk := filepath.Join(t.TempDir(), "pools", "default", "gone-root.qcow2")
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "gone", HostName: s.hostName, State: "stopped", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "gone", DiskName: "root", HostName: s.hostName, Path: disk, StorageType: "dir"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "gone"); err != nil {
		t.Fatal(err)
	}
	cp := health.SupersededName(disk, time.Now().Add(-time.Hour))
	if err := os.MkdirAll(filepath.Dir(cp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte("old copy"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, err := s.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var got *pb.SupersededDisk
	for _, d := range resp.Disks {
		if d.Path == cp {
			got = d
		}
	}
	if got == nil {
		t.Fatalf("the deleted VM's copy is not listed: %+v", resp.Disks)
	}
	if got.VmName != "gone" || got.VmState != supersededVMDeleted || got.Retained != "" || got.Held != "" {
		t.Fatalf("listed as %+v; want VM gone, state %q, neither retained nor held", got, supersededVMDeleted)
	}
}

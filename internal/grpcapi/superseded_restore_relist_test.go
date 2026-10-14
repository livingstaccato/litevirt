package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Review M7: `lv host superseded-disks --restore` that succeeded, and was
// audited, used to answer Internal when the listing after it failed (a
// directory whose storage stopped answering meanwhile). The disk was already
// swapped, so the operator was told a restore failed that had happened. The
// answer now carries the restore, with no list.
//
// Mutation: the re-list's failure returned as Internal again — red.
func TestSupersededDisks_ARestoreIsReportedWhenTheListAfterItFails(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := adminCtx()
	path := filepath.Join(s.dataDir, "disks", "web-root.qcow2")
	copyPath := path + ".superseded-20261001T000000.000000000Z"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("the real disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("rebuilt blank"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: s.hostName, State: "stopped", StateDetail: "operator-stop", Spec: "{}",
	}, nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	old := supersededRelist
	supersededRelist = func(context.Context, *corrosion.Client, string) ([]health.SupersededCopy, error) {
		return nil, errors.New("lstat /mnt/nfs/x: did not return within 5s (does its server answer?)")
	}
	t.Cleanup(func() { supersededRelist = old })

	resp, err := s.SupersededDisks(ctx, &pb.SupersededDisksRequest{RestorePath: copyPath})
	if err != nil {
		t.Fatalf("a restore that happened answered %v", err)
	}
	if resp.Restored != copyPath || resp.RestoredTo != path || resp.SetAside == "" {
		t.Fatalf("answer %+v, want the restore of %s to %s with the replaced disk set aside", resp, copyPath, path)
	}
	if b, _ := os.ReadFile(path); string(b) != "the real disk" {
		t.Fatalf("the disk is %q, want the restored copy", b)
	}
}

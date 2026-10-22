package grpcapi

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// An in-place backup restore on a host in write quarantine is refused
// before the disk is replaced: the restore clears the disk's backing record
// once the restored disk is standalone, and a record it cannot clear pins
// the old base and makes a later restore rebuild onto it.
//
// Mutation: drop the refusal in inPlaceRestoreTarget: the disk is replaced:
// red.
func TestRestoreFromBackup_InPlaceRefusedUnderWriteQuarantine(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	own := disks[0].Path
	if err := os.WriteFile(own, []byte("changed since the backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(own)
	f.s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): test" })

	err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "write quarantine") {
		t.Fatalf("in-place restore under write quarantine: %v, want FailedPrecondition naming it", err)
	}
	if after, _ := os.ReadFile(own); !bytes.Equal(before, after) {
		t.Error("the disk was replaced under write quarantine")
	}

	f.s.db.SetWriteQuarantine(nil)
	if err := f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, InPlace: true,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: f.alice}); err != nil {
		t.Fatalf("in-place restore after the lift: %v", err)
	}
}

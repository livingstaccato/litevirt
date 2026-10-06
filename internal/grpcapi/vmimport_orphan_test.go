package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A file at the disk's name that nothing in the cluster records — a crashed
// earlier import's output — is moved aside under a new name, kept, and the
// re-import goes ahead.
func TestImportVM_AnOrphanAtTheDisksNameIsMovedAsideAndKept(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(poolDir, "imp-again-root.qcow2")
	if err := os.WriteFile(dst, []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-again", false)}}); err != nil {
		t.Fatalf("a re-import over an orphan: %v", err)
	}
	aside, _ := filepath.Glob(dst + ".orphan-*")
	if len(aside) != 1 {
		t.Fatalf("orphan kept as %v, want one file beside the disk", aside)
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != "leftover" {
		t.Fatalf("the orphan kept aside holds %q", b)
	}
	if b, _ := os.ReadFile(dst); string(b) == "leftover" {
		t.Fatal("the disk's name still holds the orphan")
	}
}

// A file a disk row names is not an orphan even when the row is a tombstone:
// a deleted VM's kept disk belongs to its project. It is refused and left as
// it is.
func TestImportVM_AKeptDiskOfADeletedVMIsNotAnOrphan(t *testing.T) {
	for _, col := range []string{"path", "backing_disk"} {
		t.Run(col, func(t *testing.T) {
			s := concurrentImportServer(t, 10*oneDiskNeed())
			stubQemuImg(t)
			poolDir, err := s.importPoolDir(adminCtx(), "")
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(poolDir, "imp-kept-root.qcow2")
			if err := os.WriteFile(dst, []byte("their kept disk"), 0o600); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			path, backing := "/elsewhere/x.qcow2", ""
			if col == "path" {
				path = dst
			} else {
				backing = dst
			}
			if err := s.db.Execute(context.Background(),
				`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, backing_disk, storage_type, updated_at, deleted_at)
				 VALUES ('gone', 'root', 'other-host', ?, ?, 'local', ?, ?)`, path, nullIfEmptyTest(backing), now, now); err != nil {
				t.Fatal(err)
			}
			err = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-kept", false)}})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "gone") {
				t.Fatalf("an import over a deleted VM's kept disk: %v, want a refusal naming the VM", err)
			}
			if b, _ := os.ReadFile(dst); string(b) != "their kept disk" {
				t.Fatalf("the kept disk now holds %q", b)
			}
			if aside, _ := filepath.Glob(dst + ".orphan-*"); len(aside) != 0 {
				t.Fatalf("the kept disk was moved aside: %v", aside)
			}
			if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-kept"); rec != nil {
				t.Fatal("a refused import persisted a row")
			}
		})
	}
}

func nullIfEmptyTest(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// An image a host stores at that name is not an orphan either.
func TestImportVM_AnImageAtTheDisksNameIsNotAnOrphan(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(poolDir, "imp-img-root.qcow2")
	if err := os.WriteFile(dst, []byte("an image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(),
		`INSERT INTO image_hosts (image_name, host_name, path, status, updated_at) VALUES ('base', 'test-host', ?, 'ready', ?)`,
		dst, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	err = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-img", false)}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "image base") {
		t.Fatalf("an import over a stored image: %v, want a refusal naming the image", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "an image" {
		t.Fatalf("the image now holds %q", b)
	}
}

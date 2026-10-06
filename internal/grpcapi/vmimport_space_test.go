package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The conversion writes a disk the size of its capacity into the pool, after
// the quota admitted it; the filesystem has to hold it with the headroom a
// cold migration also keeps, or the import is refused before writing.
func TestImportVM_RefusedWhenThePoolFilesystemCannotHoldTheDisk(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{DiskGiBLimit: 4, NICLimit: 2})
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 2 << 30, 10 << 30, nil }

	err := importSmallVM(t, s, "imp-short", "acme", 512, false)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("import of a 1 GiB disk into a filesystem with 1 GiB above its headroom: %v, want a free-space refusal", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-short"); rec != nil {
		t.Fatal("a refused import persisted a row")
	}
}

// Imports on one host write one at a time: each checks free space before it
// writes, and two that checked together would both pass against space only one
// of them can have.
func TestImportVM_WaitsForAnotherImportsWrites(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	stubQemuImg(t)
	release, err := s.acquireImportWrites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(adminCtx(), 300*time.Millisecond)
	defer cancel()
	st := &fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{{
		Name: "imp-wait", SourceFormat: "proxmox",
		Chunk:   []byte("name: imp-wait\ncores: 1\nmemory: 512\nscsi0: local-lvm:imp-wait-disk-0,size=1M\n"),
		DiskMap: map[string]string{"scsi0": raw},
	}}}
	if err := s.ImportVM(st); err == nil {
		t.Fatal("an import ran its writes while another import held them")
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-wait"); rec != nil {
		t.Fatal("an import that never got to write persisted a row")
	}
}

func TestAcquireImportWrites_OneHolderAtATime(t *testing.T) {
	s := &Server{}
	release, err := s.acquireImportWrites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.acquireImportWrites(ctx); err == nil {
		t.Fatal("a second import acquired the writes while the first held them")
	}
	release()
	release() // releasing twice must not free a slot someone else holds
	r2, err := s.acquireImportWrites(context.Background())
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	ctx3, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel3()
	if _, err := s.acquireImportWrites(ctx3); err == nil {
		t.Fatal("a double release let two imports hold the writes")
	}
	r2()
}

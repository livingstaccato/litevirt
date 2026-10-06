package grpcapi

import (
	"context"
	"strings"
	"sync"
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
	if err := s.ImportVM(st); status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "another import") {
		t.Fatalf("import while another held the writes: %v, want it to wait for the slot and give up", err)
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

// stuckStream is a client that stops reading: Send blocks until the test ends.
type stuckStream struct {
	fakeImportStream
	entered chan struct{}
	once    sync.Once
	unblock chan struct{}
}

func (f *stuckStream) Send(p *pb.ImportVMProgress) error {
	f.once.Do(func() { close(f.entered) })
	<-f.unblock
	return nil
}

// progressQemuImg is stubQemuImg that also reports convert progress, so the
// import sends to its client during the conversion.
func progressQemuImg(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		"if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":1048576}'; exit 0; fi\n" +
		"printf '    (50.00/100%%)\\r'\n" +
		"prev=\"\"; last=\"\"\n" +
		"for a; do prev=\"$last\"; last=\"$a\"; done\n" +
		"cp \"$prev\" \"$last\"\n"
	if err := writeFileHelper(dir+"/qemu-img", []byte(shim)); err != nil {
		t.Fatal(err)
	}
	if err := chmodHelper(dir+"/qemu-img", 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+envPath())
}

func smallImportFrame(t *testing.T, name string, inspect bool) *pb.ImportVMRequest {
	t.Helper()
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	return &pb.ImportVMRequest{
		Name: name, SourceFormat: "proxmox", Inspect: inspect,
		Chunk:   []byte("name: " + name + "\ncores: 1\nmemory: 512\nscsi0: local-lvm:" + name + "-disk-0,size=1M\n"),
		DiskMap: map[string]string{"scsi0": raw},
	}
}

// A client that stops reading its progress must not hold the host's import
// writes: every other import on the host would wait for it forever.
func TestImportVM_AClientThatStopsReadingDoesNotHoldOtherImports(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		name := "stuck"
		if inspect {
			name = "stuck-inspect"
		}
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			admissionHost(t, s)
			s.virt = libvirtfake.New()
			progressQemuImg(t)

			stuck := &stuckStream{
				fakeImportStream: fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-a", inspect)}},
				entered:          make(chan struct{}),
				unblock:          make(chan struct{}),
			}
			done := make(chan struct{})
			go func() { _ = s.ImportVM(stuck); close(done) }()
			t.Cleanup(func() { close(stuck.unblock); <-done })
			select {
			case <-stuck.entered:
			case <-time.After(20 * time.Second):
				t.Fatal("the first import never sent to its client")
			}

			ctx, cancel := context.WithTimeout(adminCtx(), 10*time.Second)
			defer cancel()
			st := &fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-b", false)}}
			if err := s.ImportVM(st); err != nil {
				t.Fatalf("an import behind a client that stopped reading: %v", err)
			}
		})
	}
}

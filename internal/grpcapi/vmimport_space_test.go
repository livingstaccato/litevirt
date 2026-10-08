package grpcapi

import (
	"context"
	"os"
	"path/filepath"
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

// The conversion writes what qemu-img measures into the pool, after the
// quota admitted it; the filesystem has to hold it, or the import is refused
// before writing.
func TestImportVM_RefusedWhenThePoolFilesystemCannotHoldTheDisk(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{DiskGiBLimit: 4, NICLimit: 2})
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 512 << 20, 10 << 30, nil }
	// A 1 GiB disk full of data: the conversion writes all of it.
	thinQemuImg(t, 1<<30, 1<<30+1<<20)
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
		Name: "imp-short", SourceFormat: "proxmox", Project: "acme",
		Chunk:   []byte("name: imp-short\ncores: 1\nmemory: 512\nscsi0: local-lvm:imp-short-disk-0,size=1G\n"),
		DiskMap: map[string]string{"scsi0": raw},
	}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("import of a disk measured at 1 GiB into a filesystem with 512 MiB free: %v, want a free-space refusal", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-short"); rec != nil {
		t.Fatal("a refused import persisted a row")
	}
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
		"if [ \"$1\" = measure ]; then echo '{\"required\":134217728,\"fully-allocated\":134217728}'; exit 0; fi\n" +
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

// A client that stops reading its progress must not hold the disk space its
// import reserved: every other import on the host would be refused for as long
// as it does not read.
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
			// Room for one import's disk at a time: what the first reserved
			// must be released before it waits on its client.
			s.diskSpaceOverride = func(string) (uint64, uint64, error) {
				return 3 * oneDiskNeed() / 2, 100 << 30, nil
			}

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
			// Its writes finish while its client is not reading; once they
			// do, it holds no reservation.
			deadline := time.Now().Add(10 * time.Second)
			for heldImports(s) != 0 {
				if time.Now().After(deadline) {
					t.Fatal("an import waiting on its client still holds its reservation")
				}
				time.Sleep(20 * time.Millisecond)
			}

			ctx, cancel := context.WithTimeout(adminCtx(), 10*time.Second)
			defer cancel()
			st := &fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-b", false)}}
			if err := s.ImportVM(st); err != nil {
				t.Fatalf("an import behind a client that stopped reading: %v", err)
			}

			// Nor does it keep its unpacked source on disk while it waits.
			deadline = time.Now().Add(10 * time.Second)
			for {
				left, _ := filepath.Glob(filepath.Join(s.dataDir, "imports", "imp-a-*"))
				if len(left) == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("an import waiting on its client still holds %v", left)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// A compressed image can name a virtual size far beyond the file it arrives
// in; the conversion writes up to that size, so it must fit what the import
// was admitted for.
func TestConvertForeignDisk_RefusesAnImageLargerThanItsLimit(t *testing.T) {
	dir := t.TempDir()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	shim := "#!/bin/sh\n" +
		"echo \"$*\" >> '" + log + "'\n" +
		"for a; do last=$a; done\n" +
		"if [ \"$1\" = info ]; then printf '{\"filename\":\"%s\",\"format\":\"raw\",\"virtual-size\":35184372088832}' \"$last\"; exit 0; fi\n" +
		": > \"$last\"\n"
	if err := writeFileHelper(bin+"/qemu-img", []byte(shim)); err != nil {
		t.Fatal(err)
	}
	if err := chmodHelper(bin+"/qemu-img", 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+envPath())
	src := filepath.Join(dir, "disk.raw")
	if err := writeFileHelper(src, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if err := convertForeignDisk(context.Background(), src, "raw", filepath.Join(t.TempDir(), "out.qcow2"), dir, 1<<30, nil, nil); err == nil {
		t.Fatal("an image whose virtual size is 32 TiB converted under a 1 GiB limit")
	}
	if b, _ := os.ReadFile(log); strings.Contains(string(b), "convert") {
		t.Fatalf("qemu-img convert ran on an image past its limit: %s", b)
	}
}

// heldImports is how many imports on s hold a reservation.
func heldImports(s *Server) int {
	s.importSpace.mu.Lock()
	defer s.importSpace.mu.Unlock()
	return len(s.importSpace.held)
}

// I-A (final-rereview-integrate-3.md): main (3e4ba50b) checked no free space
// for an import — vmimport.go:201-240 reserved project quota and host cpu/mem
// only — so an import that fits was imported. One measuring 10 GiB into a pool
// on a 2 TiB filesystem with 50 GiB free fits, and is admitted: the
// reservation is what the import writes, with no margin a cold migration
// keeps (64 GiB there) on top.
func TestImportVM_AnImportThatFitsANearlyFullFilesystemIsAdmitted(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{DiskGiBLimit: 64, NICLimit: 2})
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 50 << 30, 2 << 40, nil }
	thinQemuImg(t, 10<<30, 10<<30)
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
		Name: "imp-fits", SourceFormat: "proxmox", Project: "acme",
		Chunk:   []byte("name: imp-fits\ncores: 1\nmemory: 512\nscsi0: local-lvm:imp-fits-disk-0,size=10G\n"),
		DiskMap: map[string]string{"scsi0": raw},
	}}})
	if err != nil {
		t.Fatalf("import of a disk measured at 10 GiB into a filesystem with 50 GiB free (main imported it): %v", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-fits"); rec == nil {
		t.Fatal("the admitted import persisted no row")
	}
}

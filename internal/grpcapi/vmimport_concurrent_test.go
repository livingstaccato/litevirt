package grpcapi

import (
	"archive/tar"
	"bytes"
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
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// gatedQemuImg is stubQemuImg whose convert marks its arrival in gate and
// then waits for gate/go before it writes, so a test can hold an import in
// the middle of its conversion. A convert left waiting 20 s fails.
func gatedQemuImg(t *testing.T, gate string) {
	t.Helper()
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		"if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":1048576}'; exit 0; fi\n" +
		"if [ \"$1\" = measure ]; then echo '{\"required\":134217728,\"fully-allocated\":134217728}'; exit 0; fi\n" +
		"touch '" + gate + "'/arrived.$$\n" +
		"i=0\n" +
		"while [ ! -e '" + gate + "'/go ]; do i=$((i+1)); [ $i -gt 400 ] && exit 1; sleep 0.05; done\n" +
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

// waitArrivals waits until n conversions are inside the gate.
func waitArrivals(t *testing.T, gate string, n int) bool {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := filepath.Glob(filepath.Join(gate, "arrived.*")); len(got) >= n {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func openGate(t *testing.T, gate string) {
	t.Helper()
	if err := writeFileHelper(filepath.Join(gate, "go"), nil); err != nil {
		t.Fatal(err)
	}
}

// oneDiskNeed is what a smallImportFrame import reserves while it converts
// its one disk: a private copy of the mapped 1 MiB file (its allocated
// blocks) and what the stubs' qemu-img measure says the conversion writes
// (128 MiB: more than an upload step, so a conversion's reservation, not an
// upload's, is what decides whether two imports fit together).
func oneDiskNeed() uint64 {
	return 1<<20 + 128<<20 + importConvertSlack
}

// concurrentImportServer is a server whose import filesystem has room for
// room bytes.
func concurrentImportServer(t *testing.T, room uint64) *Server {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	const total = 100 << 30
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return room, total, nil }
	return s
}

// Two imports that each fit the free space run side by side: neither waits
// for the other to finish writing.
func TestImportVM_TwoImportsThatFitRunTogether(t *testing.T) {
	gate := t.TempDir()
	gatedQemuImg(t, gate)
	s := concurrentImportServer(t, 5*oneDiskNeed()/2)

	errs := make(chan error, 2)
	for _, name := range []string{"imp-a", "imp-b"} {
		st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, name, false)}}
		go func() { errs <- s.ImportVM(st) }()
	}
	overlapped := waitArrivals(t, gate, 2)
	openGate(t, gate)
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("import: %v", err)
		}
	}
	if !overlapped {
		t.Fatal("two imports that fit the free space together did not convert at the same time")
	}
	for _, name := range []string{"imp-a", "imp-b"} {
		if rec, _ := corrosion.GetVM(context.Background(), s.db, name); rec == nil {
			t.Errorf("%s: no row", name)
		}
	}
}

// Two imports that together need more than the free space: the second is
// refused while the first holds its reservation, not admitted against the
// same bytes, and the first completes.
func TestImportVM_TheSecondOfTwoImportsThatDoNotFitIsRefused(t *testing.T) {
	gate := t.TempDir()
	gatedQemuImg(t, gate)
	s := concurrentImportServer(t, 3*oneDiskNeed()/2)

	errA := make(chan error, 1)
	stA := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-a", false)}}
	go func() { errA <- s.ImportVM(stA) }()
	opened := false
	t.Cleanup(func() {
		if !opened {
			openGate(t, gate)
			<-errA
		}
	})
	if !waitArrivals(t, gate, 1) {
		t.Fatal("the first import never reached its conversion")
	}

	ctx, cancel := context.WithTimeout(adminCtx(), 10*time.Second)
	defer cancel()
	stB := &fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-b", false)}}
	err := s.ImportVM(stB)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("an import that fits only without the other's reservation: %v, want a free-space refusal naming the reservation", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-b"); rec != nil {
		t.Fatal("a refused import persisted a row")
	}
	if left, _ := filepath.Glob(filepath.Join(s.dataDir, "imports", "imp-b-*")); len(left) != 0 {
		t.Fatalf("a refused import left %v", left)
	}

	opened = true
	openGate(t, gate)
	if err := <-errA; err != nil {
		t.Fatalf("the first import: %v", err)
	}
	// Its reservation went with it: the same import now fits.
	stC := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-c", false)}}
	if err := s.ImportVM(stC); err != nil {
		t.Fatalf("an import after the first finished: %v", err)
	}
}

// An archive's extraction is a write phase like a conversion: it reserves
// what it unpacks, against what other imports have reserved.
func TestImportVM_AnArchiveReservesWhatItUnpacks(t *testing.T) {
	s := uploadImportServer(t, 5<<20)
	var ova bytes.Buffer
	tw := tar.NewWriter(&ova)
	for _, m := range []struct {
		name string
		size int
	}{{"vm.ovf", 16}, {"disk.vmdk", 2 << 20}} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(m.size), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(bytes.Repeat([]byte{1}, m.size)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	staged := filepath.Join(s.dataDir, "imports", "staging", "vm.ova")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, ova.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// 3 MiB free; another import holds 2 of them.
	other := s.reserveImportSpace(t.TempDir())
	defer other.release()
	if err := other.reserve(s.dataDir, 2<<20, "another import"); err != nil {
		t.Fatal(err)
	}
	st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
		Name: "imp-ova", SourceFormat: "ova", SourcePath: staged,
	}}}
	err := s.ImportVM(st)
	if err == nil || !strings.Contains(err.Error(), "unpacking the source") || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("an OVA unpacking into room another import reserved: %v, want a refusal naming the reservation", err)
	}
}

// The conversion names its scratch file in the pool before qemu-img writes
// it, so its import's reservation shrinks as the output grows, and names the
// disk again once it is placed, so it stays measured as the import's.
func TestConvertForeignDisk_TracksItsScratchFileBeforeWriting(t *testing.T) {
	stubQemuImg(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "disk.raw")
	if err := writeFileHelper(src, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	pool := t.TempDir()
	dst := filepath.Join(pool, "out.qcow2")
	var tracked []string
	err := convertForeignDisk(context.Background(), src, "raw", dst, dir, 1<<30, nil, &importDiskWrites{
		created: func(p string) {
			if fi, err := os.Stat(p); err != nil || fi.Size() != 0 {
				t.Errorf("tracked %s after it was written (%v)", p, err)
			}
			tracked = append(tracked, p)
		},
		placed: func(_, p string) {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("tracked the disk before it was placed: %v", err)
			}
			tracked = append(tracked, p)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tracked) != 2 || filepath.Dir(tracked[0]) != pool || tracked[0] == dst || tracked[1] != dst {
		t.Fatalf("tracked %v, want the scratch file in %s and then %s", tracked, pool, dst)
	}
}

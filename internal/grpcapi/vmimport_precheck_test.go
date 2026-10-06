package grpcapi

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// fakeQemuImg puts a qemu-img on PATH that records every invocation and
// answers as if each disk were a standalone raw image. It needs no real
// qemu-img, so these tests run (and fail) on every runner. The returned
// function reads the recorded command lines.
func fakeQemuImg(t *testing.T) func() []string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> '" + log + "'\n" +
		"for a; do last=$a; done\n" +
		"case \"$1\" in\n" +
		"info) printf '{\"filename\":\"%s\",\"format\":\"raw\"}' \"$last\" ;;\n" +
		"convert) : > \"$last\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(bin, "qemu-img"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, err := os.ReadFile(log)
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

// refusedUnopened asserts that converting src (declared as format) is refused
// and that qemu-img was never run on it: qemu-img opening a descriptor's
// extents, or a data file, as root is itself the exposure (a FIFO, a device).
func refusedUnopened(t *testing.T, src, format string) {
	t.Helper()
	calls := fakeQemuImg(t)
	importDir := filepath.Dir(src)
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	if err := convertForeignDisk(context.Background(), src, format, dst, importDir, nil); err == nil {
		t.Fatalf("convert %s as %q: got nil, want refusal", filepath.Base(src), format)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("qemu-img ran on a disk that was refused: %q", c)
	}
}

func TestConvertForeignDisk_RefusesAVMDKDescriptorBeforeQemuOpensIt(t *testing.T) {
	dir := t.TempDir()
	desc := filepath.Join(dir, "disk.vmdk")
	body := "CID=fffffffe\nversion=1\ncreateType=\"monolithicFlat\"\nRW\t2048\tFLAT\t\"/dev/zero\"\t0\n"
	if err := os.WriteFile(desc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refusedUnopened(t, desc, "vmdk")
}

// vmdk4Header is a sparse VMDK header with the given capacity and embedded
// descriptor offset (both in sectors).
func vmdk4Header(capacity, descOffset uint64) []byte {
	b := make([]byte, 4096)
	copy(b, "KDMV")
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint64(b[12:], capacity)
	binary.LittleEndian.PutUint64(b[20:], 128)
	binary.LittleEndian.PutUint64(b[28:], descOffset)
	binary.LittleEndian.PutUint64(b[36:], 1)
	return b
}

// A sparse VMDK with no capacity is opened through its embedded descriptor,
// whose extents qemu then opens like a text descriptor's.
func TestConvertForeignDisk_RefusesAnEmbeddedDescriptorVMDK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "disk.vmdk")
	b := vmdk4Header(0, 1)
	copy(b[512:], "version=1\ncreateType=\"monolithicFlat\"\nRW\t2048\tFLAT\t\"/dev/zero\"\t0\n")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	refusedUnopened(t, p, "vmdk")
}

func TestConvertForeignDisk_RefusesAQcow2DataFileBeforeQemuOpensIt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "disk.qcow2")
	if err := qcow2.Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(buf, binary.BigEndian.Uint64(buf)|4)
	if _, err := f.WriteAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	f.Close()
	refusedUnopened(t, p, "qcow2")
}

// Only formats whose every file reference the check understands are
// imported; anything else is converted to one of them first.
func TestConvertForeignDisk_RefusesAFormatOutsideTheAllowlist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "disk.qed")
	if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	refusedUnopened(t, p, "qed")
}

// An undeclared format is read from the header by litevirt, never probed by
// qemu-img: a probe opens the disk in whatever format qemu guesses, before
// anything has been judged.
func TestConvertForeignDisk_AnUndeclaredDiskIsNeverProbedByQemu(t *testing.T) {
	calls := fakeQemuImg(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "disk.img")
	if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convertForeignDisk(context.Background(), p, "", filepath.Join(t.TempDir(), "out.qcow2"), dir, nil); err != nil {
		t.Fatalf("convert: %v", err)
	}
	c := calls()
	if len(c) == 0 {
		t.Fatal("qemu-img was never run")
	}
	for _, line := range c {
		if !strings.Contains(" "+line+" ", " -f ") {
			t.Fatalf("qemu-img ran without a format, so it probed: %q", line)
		}
	}
}

// A disk outside the import directory is a file its caller can still write:
// a staged file, a --disk-map path. Checked there and converted there, it can
// gain a backing file between the two. It is copied into the import directory
// first, and only that copy is ever handed to qemu-img.
func TestConvertForeignDisk_ConvertsAPrivateCopyOfAnOutsideDisk(t *testing.T) {
	calls := fakeQemuImg(t)
	staging := t.TempDir()
	importDir := t.TempDir()
	src := filepath.Join(staging, "vm-100-disk-0.raw")
	if err := os.WriteFile(src, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := convertForeignDisk(context.Background(), src, "raw", filepath.Join(t.TempDir(), "out.qcow2"), importDir, nil); err != nil {
		t.Fatalf("convert: %v", err)
	}
	c := calls()
	if len(c) == 0 {
		t.Fatal("qemu-img was never run")
	}
	for _, line := range c {
		if strings.Contains(line, src) {
			t.Fatalf("qemu-img was handed the caller's file rather than a private copy: %q", line)
		}
	}
}

func TestConvertForeignDisk_RefusesAnOutsideDiskReachedThroughALink(t *testing.T) {
	calls := fakeQemuImg(t)
	staging := t.TempDir()
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "disk.raw"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(staging, "dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "disk.raw"), filepath.Join(staging, "disk.raw")); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{filepath.Join(staging, "disk.raw"), filepath.Join(staging, "dir", "disk.raw")} {
		if runtime.GOOS != "linux" && strings.Contains(src, "/dir/") {
			continue // only the final component is checked off Linux
		}
		err := convertForeignDisk(context.Background(), src, "raw", filepath.Join(t.TempDir(), "out.qcow2"), t.TempDir(), nil)
		if err == nil {
			t.Fatalf("%s: a disk reached through a link was converted, want refusal", src)
		}
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("qemu-img ran on a refused disk: %q", c)
	}
}

func TestConvertForeignDisk_RefusesAnOutsideDiskThatIsNotAPlainFile(t *testing.T) {
	calls := fakeQemuImg(t)
	fifo := filepath.Join(t.TempDir(), "disk.raw")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Outside the import directory, so it reaches the private copy; a FIFO
	// must be refused there without the open blocking on a writer.
	err := convertForeignDisk(context.Background(), fifo, "raw", filepath.Join(t.TempDir(), "out.qcow2"), t.TempDir(), nil)
	if err == nil {
		t.Fatal("a FIFO was converted, want refusal")
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("qemu-img ran on a refused disk: %q", c)
	}
}

// The private copy keeps a sparse disk sparse: a thin volume staged for
// import costs its data, not its virtual size, in the import directory (which
// usually shares a filesystem with state.db).
func TestPrivateImportDisk_KeepsAnOutsideDiskSparse(t *testing.T) {
	src := filepath.Join(t.TempDir(), "thin.raw")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	const size = 256 << 20
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("data in the middle"), 100<<20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	importDir := t.TempDir()
	cp, err := privateImportDisk(context.Background(), src, importDir)
	if err != nil {
		t.Fatalf("privateImportDisk: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cp, &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != size {
		t.Fatalf("copy is %d bytes, want %d", st.Size, size)
	}
	if used := st.Blocks * 512; used > 8<<20 {
		t.Fatalf("copy of a sparse disk allocates %d bytes; the holes were written out", used)
	}
	got := make([]byte, 18)
	g, _ := os.Open(cp)
	defer g.Close()
	if _, err := g.ReadAt(got, 100<<20); err != nil || string(got) != "data in the middle" {
		t.Fatalf("copy lost the data: %q, %v", got, err)
	}
}

func TestPrivateImportDisk_StopsWhenTheImportIsCancelled(t *testing.T) {
	src := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	importDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := privateImportDisk(ctx, src, importDir); err == nil {
		t.Fatal("a cancelled import copied the disk anyway")
	}
	if left, _ := os.ReadDir(importDir); len(left) != 0 {
		t.Fatalf("a cancelled copy was left behind: %v", left)
	}
}

// A disk whose header says it is a format the import does not convert is
// refused, not converted byte for byte as raw into a disk that will not boot.
func TestStaticDiskFormat_RefusesAFormatItRecognisesButDoesNotImport(t *testing.T) {
	vdi := make([]byte, 4096)
	binary.LittleEndian.PutUint32(vdi[0x40:], 0xbeda107f)
	for name, head := range map[string][]byte{
		"vhdx": append([]byte("vhdxfile"), make([]byte, 4088)...),
		"qed":  append([]byte("QED\x00"), make([]byte, 4092)...),
		"vdi":  vdi,
	} {
		p := filepath.Join(t.TempDir(), "disk."+name)
		if err := os.WriteFile(p, head, 0o600); err != nil {
			t.Fatal(err)
		}
		if f, err := staticDiskFormat(p); err == nil {
			t.Errorf("%s header: read as %q, want refusal", name, f)
		}
	}
}

// The conversion writes to a fresh name of its own, never to a fixed
// "<dst>.tmp" another writer to the pool directory could plant first.
func TestConvertForeignDisk_DoesNotWriteThroughAPlantedTempName(t *testing.T) {
	fakeQemuImg(t)
	importDir := t.TempDir()
	src := filepath.Join(importDir, "disk.raw")
	if err := os.WriteFile(src, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("not the import's to write"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(pool, "vm-root.qcow2")
	if err := os.Symlink(victim, dst+".tmp"); err != nil {
		t.Fatal(err)
	}
	_ = convertForeignDisk(context.Background(), src, "raw", dst, importDir, nil)
	if b, err := os.ReadFile(victim); err != nil || string(b) != "not the import's to write" {
		t.Fatalf("the conversion wrote through a planted temp name: %q, %v", b, err)
	}
}

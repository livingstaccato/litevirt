package pitoverlay

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

func needQemu(t *testing.T) {
	t.Helper()
	for _, b := range []string{"qemu-img", "qemu-io"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not on PATH", b)
		}
	}
}

// window makes a disk and its overlay holding a write the disk lacks: the
// state a layer-2 copy leaves when its daemon dies or its commit fails.
func window(t *testing.T) string {
	t.Helper()
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(Path(disk), disk, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 65536 65536", Path(disk)).CombinedOutput(); err != nil {
		t.Fatalf("write into the overlay: %v %s", err, out)
	}
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	return disk
}

var owner = Owner{VM: "web", VMUUID: "u-1", Disk: "root"}

func readDisk(t *testing.T, disk string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "o.raw")
	if b, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, out).CombinedOutput(); err != nil {
		t.Fatalf("convert: %v %s", err, b)
	}
	b, _ := os.ReadFile(out)
	return b
}

// The window's writes end up in the disk, and only then does the overlay go.
//
// Mutation "settle deletes": Settle removes the overlay without committing —
// red (the write is lost).
func TestSettle_KeepsTheWindowsWrites(t *testing.T) {
	needQemu(t)
	disk := window(t)
	out, _, err := Settle(context.Background(), disk, owner, "t")
	if err != nil || out != Committed {
		t.Fatalf("Settle = %v, %v", out, err)
	}
	if Present(disk) {
		t.Error("the committed overlay is still there")
	}
	if got := readDisk(t, disk); !bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x5a}, 65536)) {
		t.Fatal("the window's write is not in the disk: it was lost")
	}
}

// An overlay that cannot be committed is never removed.
//
// Mutation "remove on failure": Settle removes the overlay after a failed
// commit — red.
func TestSettle_NeverDeletesAnOverlayItCannotCommit(t *testing.T) {
	needQemu(t)
	disk := window(t)
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	defer func() { Command = prev }()
	if _, _, err := Settle(context.Background(), disk, owner, "t"); err == nil {
		t.Fatal("a failed commit reported success")
	}
	if !Present(disk) {
		t.Fatal("the overlay holding the window's writes was deleted")
	}
}

// A commit interrupted part-way (a crash) is simply run again: the overlay
// was kept, so the second run finishes the job.
//
// Mutation "no committing state": CommitOffline does not MarkCommitting —
// red (the written disk no longer matches the window and the overlay is set
// aside instead of committed).
func TestSettle_ACrashMidCommitIsFinishedByTheNextSettle(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if _, err := CommitOffline(context.Background(), disk, owner); err != nil { // the crash: committed, never removed
		t.Fatal(err)
	}
	if !Present(disk) {
		t.Fatal("CommitOffline removed the overlay; only Remove may")
	}
	// The commit wrote the disk; the binding, now "committing", still
	// vouches for the file, so the next settle finishes the job.
	if out, _, err := Settle(context.Background(), disk, owner, "t"); err != nil || out != Committed {
		t.Fatalf("the next Settle = %v, %v", out, err)
	}
	if got := readDisk(t, disk); !bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x5a}, 65536)) {
		t.Fatal("the window's write is not in the disk")
	}
}

// A file at the overlay's name that is not this disk's overlay is refused
// and left alone.
func TestCommitOffline_RefusesAnotherDisksOverlay(t *testing.T) {
	needQemu(t)
	disk := filepath.Join(t.TempDir(), "a.qcow2")
	other := filepath.Join(t.TempDir(), "b.qcow2")
	for _, d := range []string{disk, other} {
		if err := qcow2.Create(d, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := qcow2.CreateWithBackingFormat(Path(disk), other, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	out, aside, err := Settle(context.Background(), disk, owner, "t")
	if err != nil || out != SetAsideO {
		t.Fatalf("Settle = %v, %v; an overlay of another disk must be set aside", out, err)
	}
	if _, err := os.Stat(aside); err != nil {
		t.Fatalf("the set-aside overlay is gone: %v", err)
	}
}

// (a) A disk deleted and re-created at the same path (a VM re-created under
// the same name) never receives the old overlay's data: the overlay is set
// aside, kept.
//
// Mutation "binding ignored": Check accepts any sidecar — red.
func TestSettle_ARecreatedDiskNeverReceivesTheOldOverlay(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	reborn := Owner{VM: "web", VMUUID: "u-2", Disk: "root"}
	out, aside, err := Settle(context.Background(), disk, reborn, "t")
	if err != nil || out != SetAsideO {
		t.Fatalf("Settle = %v, %v, want the old overlay set aside", out, err)
	}
	if got := readDisk(t, disk); bytes.Contains(got, bytes.Repeat([]byte{0x5a}, 4096)) {
		t.Fatal("the re-created disk received the old VM's data")
	}
	if _, err := os.Stat(aside); err != nil {
		t.Fatalf("the old overlay was not kept: %v", err)
	}
	if _, err := os.Stat(aside + ".id"); err != nil {
		t.Errorf("its binding was not kept beside it: %v", err)
	}
}

// (c) A base written after the overlay was taken (a build that knows nothing
// of overlays restarted the VM on it) never has the overlay committed over
// it.
//
// Mutation "window not checked": Check skips the size/mtime comparison in the
// window state — red.
func TestSettle_ABaseWrittenSinceIsNeverOverwritten(t *testing.T) {
	needQemu(t)
	disk := window(t)
	time.Sleep(10 * time.Millisecond)
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x33 65536 65536", disk).CombinedOutput(); err != nil {
		t.Fatalf("write the base: %v %s", err, out)
	}
	out, _, err := Settle(context.Background(), disk, owner, "t")
	if err != nil || out != SetAsideO {
		t.Fatalf("Settle = %v, %v, want set aside", out, err)
	}
	if got := readDisk(t, disk); !bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x33}, 65536)) {
		t.Fatal("the newer write in the base was overwritten by the old overlay")
	}
}

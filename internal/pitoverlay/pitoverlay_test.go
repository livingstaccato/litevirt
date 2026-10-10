package pitoverlay

import (
	"bytes"
	"context"
	"errors"
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

func windowWrite(t *testing.T, disk string) bool {
	t.Helper()
	got := readDisk(t, disk)
	return len(got) >= 131072 && bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x5a}, 65536))
}

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
	if out, err := Settle(context.Background(), disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle = %v, %v", out, err)
	}
	if Present(disk) {
		t.Error("the committed overlay is still there")
	}
	if !windowWrite(t, disk) {
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
	if _, err := Settle(context.Background(), disk, owner); err == nil {
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
// red (the written disk no longer matches the window and the VM is held
// instead of the overlay being committed).
func TestSettle_ACrashMidCommitIsFinishedByTheNextSettle(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if _, err := CommitOffline(context.Background(), disk, owner); err != nil { // the crash: committed, never removed
		t.Fatal(err)
	}
	if !Present(disk) {
		t.Fatal("CommitOffline removed the overlay; only Remove may")
	}
	if out, err := Settle(context.Background(), disk, owner); err != nil || out != Committed {
		t.Fatalf("the next Settle = %v, %v", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// An overlay whose backing file is another disk is held, never committed.
func TestSettle_HoldsAnotherDisksOverlay(t *testing.T) {
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
	out, err := Settle(context.Background(), disk, owner)
	if out != Held || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("Settle = %v, %v; another disk's overlay must hold", out, err)
	}
	if !Present(disk) {
		t.Fatal("the held overlay was moved or removed")
	}
}

// (a) A disk re-created at the same path never receives the old overlay's
// data: the VM is held and the overlay left as it was.
//
// Mutation "file identity ignored": Check takes the file's identity from the
// sidecar instead of the file — red.
func TestSettle_ARecreatedDiskNeverReceivesTheOldOverlay(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	// The same owner (a rebuild keeps the VM's identity): only the file's
	// own identity tells the new disk from the old.
	out, err := Settle(context.Background(), disk, owner)
	if out != Held || err == nil {
		t.Fatalf("Settle = %v, %v, want held", out, err)
	}
	if windowWrite(t, disk) {
		t.Fatal("the re-created disk received the old VM's data")
	}
	if !Present(disk) || !Bound(disk) {
		t.Fatal("the held overlay or its binding was not left in place")
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
	if out, err := Settle(context.Background(), disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v, want held", out, err)
	}
	if got := readDisk(t, disk); !bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x33}, 65536)) {
		t.Fatal("the newer write in the base was overwritten by the old overlay")
	}
}

// An overlay bound to another VM incarnation (same name, another uuid) is
// never committed, even into an unchanged file.
//
// Mutation "owner not checked": Check skips the owner comparison — red.
func TestSettle_AnotherIncarnationsOverlayIsHeld(t *testing.T) {
	needQemu(t)
	disk := window(t)
	out, err := Settle(context.Background(), disk, Owner{VM: "web", VMUUID: "u-2", Disk: "root"})
	if out != Held || err == nil {
		t.Fatalf("Settle = %v, %v, want held", out, err)
	}
	if windowWrite(t, disk) {
		t.Fatal("another incarnation's data was committed")
	}
}

// R1: the same unchanged file seen under another device number — another
// host mounting the same NFS export, or a remount or reboot renumbering it —
// is the same file, and the overlay is committed.
//
// Mutation "device compared": Check also requires the recorded device number
// — red.
func TestSettle_AnotherDeviceNumberIsTheSameFile(t *testing.T) {
	needQemu(t)
	disk := window(t)
	prev := identity
	identity = func(d string) (uint64, uint64, int64, int64, error) {
		dev, ino, size, mt, err := prev(d)
		return dev + 7, ino, size, mt, err
	}
	defer func() { identity = prev }()
	if out, err := Settle(context.Background(), disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle on another host's device number = %v, %v, want committed", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// R1: an overlay names its base by the absolute path it had where it was
// taken; on a host that mounts the pool elsewhere the base is the file of
// that name beside it, and the commit goes there.
//
// Mutation "no rebase": commitInto skips repointing the overlay — red.
func TestSettle_ABaseNamedByAnotherHostsMountPath(t *testing.T) {
	needQemu(t)
	disk := window(t)
	elsewhere := filepath.Join("/srv/another-mount", filepath.Base(disk))
	if out, err := exec.Command("qemu-img", "rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b", elsewhere, Path(disk)).CombinedOutput(); err != nil {
		t.Fatalf("rebase: %v %s", err, out)
	}
	if err := Bind(disk, owner); err != nil { // the rebase wrote nothing to the base; rebind is idempotent
		t.Fatal(err)
	}
	if out, err := Settle(context.Background(), disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle = %v, %v, want committed", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// R4: a "committing" binding vouches for the base only near its latest
// commit attempt. A base written long after it — a build that knows nothing of
// overlays ran the VM on it — is held, never overwritten.
//
// Mutation "committing unbounded": Check skips the CommitBound comparison —
// red.
func TestSettle_ACommitLongAgoAndABaseWrittenSinceIsHeld(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	b, _ := readBinding(disk)
	b.CommitStartedNs = time.Now().Add(-3 * time.Hour).UnixNano()
	b.CommitAttemptNs = b.CommitStartedNs // the last attempt, too, long ago
	if err := writeBinding(disk, b); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x33 65536 65536", disk).CombinedOutput(); err != nil {
		t.Fatalf("write the base: %v %s", err, out)
	}
	if out, err := Settle(context.Background(), disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v, want held", out, err)
	}
}

// SetAside never replaces an earlier orphan.
//
// Mutation "orphan clobbered": SetAside renames over an existing orphan — red.
func TestSetAside_NeverOverAnEarlierOrphan(t *testing.T) {
	needQemu(t)
	disk := window(t)
	first, err := SetAside(disk, "same")
	if err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(Path(disk), disk, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	second, err := SetAside(disk, "same")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both set-asides landed on %s", first)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("the first orphan is gone: %v", err)
	}
}

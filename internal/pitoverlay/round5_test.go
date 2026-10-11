package pitoverlay

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// Round 5 of the colonelpanik/litevirt#256 review (re-review 4).

// restampKeep rewrites the binding and puts the sidecar's modification time
// back: an edit that models a state the daemon left, not a daemon write.
func restampKeep(t *testing.T, disk string, f func(*Binding)) {
	t.Helper()
	fi, err := os.Stat(SidecarPath(disk))
	if err != nil {
		t.Fatal(err)
	}
	restamp(t, disk, f)
	if err := os.Chtimes(SidecarPath(disk), fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func failingCommit(t *testing.T) {
	t.Helper()
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "qemu-img" && len(args) > 0 && args[0] == "commit" {
			return exec.CommandContext(ctx, "false")
		}
		return exec.CommandContext(ctx, name, args...)
	}
	t.Cleanup(func() { Command = prev })
}

// I1: a commit attempt failed (the disk is half-written), and the admin
// restores yesterday's disk by overwriting it in place — `cp` without -p
// onto the existing file. The inode and the token xattr survive, the time is
// now, and the size is the same. The disk is not the one the attempt left,
// so the VM is held; the overlay is never committed into the restore.
//
// Mutation "no end record" (committing ignores EndMtimeNs/EndSize) — red.
func TestSettle_AnInPlaceRestoreOverAHalfWrittenDiskIsHeld(t *testing.T) {
	needQemu(t)
	dir := t.TempDir()
	disk := filepath.Join(dir, "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, disk, "write -P 0x01 65536 65536")
	bak := filepath.Join(t.TempDir(), "yesterday.qcow2")
	cpP(t, disk, bak)
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, disk, "write -P 0x11 65536 65536") // same cluster: same size
	overlayOn(t, disk)
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	failingCommit(t)
	if _, err := CommitOffline(context.Background(), disk, owner); err == nil {
		t.Fatal("setup: the failing attempt reported success")
	}
	b, _ := readBinding(disk)
	time.Sleep(20 * time.Millisecond)
	if out, err := exec.Command("cp", bak, disk).CombinedOutput(); err != nil { // in place: O_TRUNC
		t.Fatalf("cp: %v %s", err, out)
	}
	if _, ino, size, _, _ := identity(disk); ino != b.Ino || size != b.Size {
		t.Fatalf("setup: the in-place restore changed the inode (%d→%d) or the size (%d→%d)", b.Ino, ino, b.Size, size)
	}
	if b.Token != "" {
		if got, err := getXattr(disk); err != nil || string(got) != b.Token {
			t.Fatalf("setup: the token did not survive the in-place restore (%q, %v)", got, err)
		}
	}
	Command = exec.CommandContext
	out, err := Settle(context.Background(), openGate, disk, owner)
	if out != Held || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("Settle = %v, %v; an in-place restore must hold", out, err)
	}
	if !regionIs(t, disk, 0x01) {
		t.Fatal("the overlay was committed into the restored disk")
	}
}

// N3 with I1's end record: a daemon that dies in the middle of a retry
// leaves no end record; the bound is then the last time the daemon recorded
// the attempt (the sidecar's own time, in the filesystem's clock), which the
// retry renewed — so its base writes are its own, not something else's.
//
// Mutation "a retry renews nothing" (MarkCommitting leaves a committing
// binding as it is) — red.
func TestSettle_ACrashMidRetryIsBoundedByTheRetry(t *testing.T) {
	needQemu(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlayOn(t, disk)
	old := time.Now().Add(-4 * time.Hour) // the window, long ago
	if err := os.Chtimes(disk, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	long := time.Now().Add(-3 * time.Hour) // the first attempt, long ago, died
	if err := os.Chtimes(SidecarPath(disk), long, long); err != nil {
		t.Fatal(err)
	}
	// The retry: it records itself, writes part of the base and dies before
	// recording its end. atStart is the sidecar's time when it began writing.
	var atStart time.Time
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "qemu-img" && len(args) > 0 && args[0] == "commit" {
			if fi, err := os.Stat(SidecarPath(disk)); err == nil {
				atStart = fi.ModTime()
			}
			return exec.CommandContext(ctx, "sh", "-c", `sleep 0.05; qemu-io -f qcow2 -c "write -P 0x11 0 512" "$1" >/dev/null; exit 1`, "sh", disk)
		}
		return exec.CommandContext(ctx, name, args...)
	}
	_, _ = CommitOffline(context.Background(), disk, owner)
	Command = prev
	// The crash: no end record, and the sidecar as the retry's start left it.
	restamp(t, disk, func(b *Binding) { b.EndMtimeNs, b.EndSize = 0, 0 })
	if err := os.Chtimes(SidecarPath(disk), atStart, atStart); err != nil {
		t.Fatal(err)
	}
	if out, err := Settle(context.Background(), openGate, disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle after a crashed retry = %v, %v; want it finished", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// I3: a pivot recorded long before the disk's last write is not taken for a
// landed pivot, even with the VM running on its disk: something else may
// have started it there.
//
// Mutation "pivoting uncapped" — red.
func TestAssess_APivotRecordedLongBeforeTheDisksLastWriteIsNotLanded(t *testing.T) {
	needQemu(t)
	disk := window(t)
	_ = MarkCommitting(disk)
	_ = MarkPivoting(disk)
	long := time.Now().Add(-time.Hour)
	if err := os.Chtimes(SidecarPath(disk), long, long); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, disk, "write -P 0x33 0 512")
	if a := Assess(disk, owner, true); a.Verdict == Pivoted {
		t.Fatalf("a pivot recorded an hour before the disk's last write was taken as landed: %+v", a)
	}
	// Right after the pivot it still is.
	if err := os.Chtimes(SidecarPath(disk), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if a := Assess(disk, owner, true); a.Verdict != Pivoted {
		t.Fatalf("a fresh pivot was not recognised: %+v", a)
	}
}

// m3: a live pivot is recorded committed only from pivoting.
//
// Mutation "committed from any state" — red.
func TestMarkCommitted_OnlyFromPivoting(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := MarkCommitted(disk); err == nil {
		t.Error("a window was recorded committed")
	}
	_ = MarkCommitting(disk)
	if err := MarkCommitted(disk); err == nil {
		t.Error("a committing binding with no recorded pivot was recorded committed")
	}
	_ = MarkPivoting(disk)
	if err := MarkCommitted(disk); err != nil {
		t.Errorf("a recorded pivot could not be recorded committed: %v", err)
	}
}

// I3, rollback: a host that does not hold the pit_overlay release feature
// never settles an overlay — not even one it could verify. It holds the VM,
// with the reason.
//
// Mutation "gate ignored when settling" — red.
func TestSettle_BelowThePITOverlayFeatureEveryOverlayHolds(t *testing.T) {
	needQemu(t)
	disk := window(t)
	out, err := Settle(context.Background(), closedGate, disk, owner)
	if out != Held || err == nil || !strings.Contains(err.Error(), "pit_overlay") {
		t.Fatalf("Settle below the feature = %v, %v; want held, naming pit_overlay", out, err)
	}
	if windowWrite(t, disk) || !Present(disk) {
		t.Fatal("the overlay was settled below the feature")
	}
	// A nil gate (unwired) is closed too.
	if out, err := Settle(context.Background(), nil, disk, owner); out != Held || err == nil || !Present(disk) {
		t.Fatalf("Settle with no gate wired = %v, %v; want held", out, err)
	}
}

// For future rollbacks: a binding a newer build wrote (a later format) is
// never settled by this one.
//
// Mutation "format unchecked" — red.
func TestSettle_ANewerBuildsBindingHolds(t *testing.T) {
	needQemu(t)
	disk := window(t)
	restamp(t, disk, func(b *Binding) { b.Format = 99 })
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle of a format-99 binding = %v, %v; want held", out, err)
	}
}

// Nit: the backing check compares the directory too when the backing path
// exists here: an overlay of /poolB/x is never committed into /poolA/x.
//
// Mutation "names only" — red.
func TestForceCommit_NeverIntoAFileOfTheSameNameElsewhere(t *testing.T) {
	needQemu(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	other := filepath.Join(t.TempDir(), "web-root.qcow2")
	for _, d := range []string{disk, other} {
		if err := qcow2.Create(d, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := qcow2.CreateWithBackingFormat(Path(disk), other, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, Path(disk), "write -P 0x5a 65536 65536")
	if err := ForceCommit(context.Background(), disk); err == nil {
		t.Fatal("an overlay of a same-named file in another directory was committed into this disk")
	}
	if windowWrite(t, disk) {
		t.Fatal("the other file's overlay is in this disk")
	}
}

// I1, the advice: a disk that cannot be trusted is restored only after the
// overlay is discarded — otherwise the restore meets the overlay — and the
// in-place restore, which does both, is offered.
//
// Mutation "restore advised before the discard" — red.
func TestHoldAdvice_DiscardBeforeRestoring(t *testing.T) {
	a := Assessment{Verdict: Unknown, Reason: "x", CommitBegan: true, Binding: &Binding{State: StateCommitting}}
	for _, txt := range []string{HoldAdvice("web", "root", a), func() string { _, d := a.Consequences(); return d }()} {
		d, r := strings.Index(txt, "--discard --accept-torn-disk"), strings.Index(txt, "restor")
		if d < 0 || r < 0 || d > r {
			t.Errorf("advice %q: the discard must come before the restore", txt)
		}
	}
	if adv := HoldAdvice("web", "root", a); !strings.Contains(adv, "restore-from") || !strings.Contains(adv, "--in-place") {
		t.Errorf("advice %q does not offer the in-place restore", adv)
	}
	_, d := Assessment{Verdict: HalfWritten, CommitBegan: true}.Consequences()
	if i, r := strings.Index(d, "--discard --accept-torn-disk"), strings.Index(d, "restor"); r >= 0 && (i < 0 || i > r) {
		t.Errorf("half-written discard text %q: the discard must come before the restore", d)
	}
}

// m2: a pivot under way with the VM off — the advice compares the two files'
// times (one clock: the filesystem's). Disk written after the overlay: the
// pivot landed, discard. Overlay written last: it did not, commit.
//
// Mutation "no comparison" — red.
func TestAssess_APivotUnderWayIsAdvisedFromTheFilesTimes(t *testing.T) {
	needQemu(t)
	disk := window(t)
	_ = MarkCommitting(disk)
	_ = MarkPivoting(disk)
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, disk, "write -P 0x33 0 512")
	a := Assess(disk, owner, false)
	if adv := HoldAdvice("web", "root", a); !strings.Contains(adv, "--discard") || strings.Contains(adv, "--force-commit") {
		t.Errorf("disk written last: advice %q, want discard only", adv)
	}
	if a.OverlayCurrent == "" {
		t.Error("the assessment does not show the overlay's time")
	}
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, Path(disk), "write -P 0x44 0 512")
	a = Assess(disk, owner, false)
	if adv := HoldAdvice("web", "root", a); !strings.Contains(adv, "--force-commit") || strings.Contains(adv, "--discard") {
		t.Errorf("overlay written last: advice %q, want a forced commit only", adv)
	}
}

package pitoverlay

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// Round 4 of the colonelpanik/litevirt#256 review: the identity of the
// "committing" state, the per-window token, the refreshed commit stamp, the
// pivot record, the verdicts and the overlay's placement.

func qemuIO(t *testing.T, img, cmd string) {
	t.Helper()
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", cmd, img).CombinedOutput(); err != nil {
		t.Fatalf("qemu-io %q %s: %v %s", cmd, img, err, out)
	}
}

// cpP copies src to dst as `cp -p` does: data, mode, owner and times — and
// no extended attributes.
func cpP(t *testing.T, src, dst string) {
	t.Helper()
	if out, err := exec.Command("cp", "-p", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("cp -p %s %s: %v %s", src, dst, err, out)
	}
}

// reuseInode makes identity report ino for disk: the file a restore wrote
// there was given the deleted disk's inode number back, as ext4 and XFS
// commonly do.
func reuseInode(t *testing.T, disk string, ino uint64) {
	t.Helper()
	prev := identity
	identity = func(d string) (uint64, uint64, int64, int64, error) {
		dev, i, size, mt, err := prev(d)
		if d == disk {
			i = ino
		}
		return dev, i, size, mt, err
	}
	t.Cleanup(func() { identity = prev })
}

// noXattrs models a filesystem without user extended attributes (NFSv3, or
// NFSv4 before 4.2): the window has no token and the bounds alone decide.
func noXattrs(t *testing.T) {
	t.Helper()
	ps, pg := setXattr, getXattr
	setXattr = func(string, []byte) error { return syscall.ENOTSUP }
	getXattr = func(string) ([]byte, error) { return nil, syscall.ENOTSUP }
	t.Cleanup(func() { setXattr, getXattr = ps, pg })
}

// needXattrs skips unless dir's filesystem takes user extended attributes.
func needXattrs(t *testing.T, dir string) {
	t.Helper()
	f := filepath.Join(dir, ".xattr-probe")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f)
	if err := setXattr(f, []byte("probe")); err != nil {
		t.Skipf("no user xattrs on %s: %v", dir, err)
	}
}

// overlayOn gives disk an overlay holding the window's write (0x5a at 64 KiB).
func overlayOn(t *testing.T, disk string) {
	t.Helper()
	if err := qcow2.CreateWithBackingFormat(Path(disk), disk, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, Path(disk), "write -P 0x5a 65536 65536")
}

func restamp(t *testing.T, disk string, f func(*Binding)) {
	t.Helper()
	b, err := readBinding(disk)
	if err != nil {
		t.Fatal(err)
	}
	f(&b)
	if err := writeBinding(disk, b); err != nil {
		t.Fatal(err)
	}
}

func regionIs(t *testing.T, disk string, b byte) bool {
	t.Helper()
	got := readDisk(t, disk)
	return len(got) >= 131072 && bytes.Equal(got[65536:131072], bytes.Repeat([]byte{b}, 65536))
}

// N1 (ruling 1): a commit began — the disk may be torn — and the operator,
// told so, deletes the disk and restores last night's copy with `cp -p`. The
// restored file gets the freed inode number back. It is not the file the
// commit was writing, so the VM is held; the overlay is never committed into
// it.
//
// Mutation "committing checks the inode only" (round 3's Check) — red.
func TestSettle_ARestoreThatReusesTheInodeIsHeld(t *testing.T) {
	needQemu(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(t.TempDir(), "last-night.qcow2")
	cpP(t, disk, bak)
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, disk, "write -P 0x11 0 65536") // the guest's writes since the backup
	overlayOn(t, disk)
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	b, _ := readBinding(disk)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	cpP(t, bak, disk)
	reuseInode(t, disk, b.Ino)

	out, err := Settle(context.Background(), openGate, disk, owner)
	if out != Held || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("Settle = %v, %v; a restored disk must hold the VM", out, err)
	}
	if windowWrite(t, disk) {
		t.Fatal("the overlay was committed into the restored disk")
	}
	if !Present(disk) {
		t.Fatal("the held overlay was moved or removed")
	}
}

// N1, the token: a copy of the disk taken while the commit was starting has
// the window's size and modification time, so every bound passes — but a
// copy does not carry the window's token (cp -p, rsync -a without -X), so it
// is not the file, and the VM is held.
//
// Mutation "token unchecked" — red.
func TestSettle_ACopyWithTheWindowsTimesButNotItsTokenIsHeld(t *testing.T) {
	needQemu(t)
	dir := t.TempDir()
	needXattrs(t, dir)
	disk := filepath.Join(dir, "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlayOn(t, disk)
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	b, _ := readBinding(disk)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(t.TempDir(), "copy.qcow2")
	cpP(t, disk, cp)
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	cpP(t, cp, disk)
	reuseInode(t, disk, b.Ino)

	out, err := Settle(context.Background(), openGate, disk, owner)
	if out != Held || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("Settle = %v, %v; a copy without the window's token must hold", out, err)
	}
	if windowWrite(t, disk) {
		t.Fatal("the overlay was committed into a copy of the disk")
	}
}

// N1 without xattrs: on a filesystem without them the window has no token,
// and the bounds decide. A restore of an older copy — modified before the
// window was taken — is held by the lower bound on the modification time.
//
// Mutation "no lower bound on mtime" — red.
func TestSettle_WithoutXattrsAnOlderRestoreIsHeld(t *testing.T) {
	needQemu(t)
	noXattrs(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, disk, "write -P 0x01 0 65536")
	bak := filepath.Join(t.TempDir(), "older.qcow2")
	cpP(t, disk, bak)
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, disk, "write -P 0x11 0 65536") // same cluster: same size, newer time
	overlayOn(t, disk)
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	b, _ := readBinding(disk)
	if b.Token != "" {
		t.Fatalf("a window on a filesystem without xattrs recorded a token %q", b.Token)
	}
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	cpP(t, bak, disk)
	reuseInode(t, disk, b.Ino)
	if fi, _ := os.Stat(disk); fi.Size() != b.Size {
		t.Fatalf("setup: the older copy is %d bytes, the window's file %d; only the time may differ", fi.Size(), b.Size)
	}
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v; an older restore must hold", out, err)
	}
}

// N1 without xattrs: a commit only grows the disk, so a smaller file — even
// one stamped later — is not the one the commit was writing.
//
// Mutation "no lower bound on size" — red.
func TestSettle_WithoutXattrsASmallerFileIsHeld(t *testing.T) {
	needQemu(t)
	noXattrs(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(t.TempDir(), "small.qcow2")
	cpP(t, disk, bak)
	qemuIO(t, disk, "write -P 0x11 0 65536") // allocates a cluster: the disk grows
	overlayOn(t, disk)
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	b, _ := readBinding(disk)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	cpP(t, bak, disk)
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(disk, later, later); err != nil {
		t.Fatal(err)
	}
	reuseInode(t, disk, b.Ino)
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v; a smaller file must hold", out, err)
	}
}

// Nit: a "committing" binding with no stamp (written by an earlier build of
// this branch) cannot be bounded, so it holds.
//
// Mutation "a zero stamp skips the bound" — red.
func TestSettle_ACommittingBindingWithoutAStampIsHeld(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	restamp(t, disk, func(b *Binding) { b.CommitStartedNs, b.CommitAttemptNs = 0, 0 })
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v; an unstamped commit must hold", out, err)
	}
}

// N3: every commit attempt refreshes the stamp. A commit first tried three
// hours ago and retried now is cut short again; its base writes are recent
// and belong to the retry, so the next settle finishes it — no false hold.
//
// Mutation "MarkCommitting keeps the first stamp" — red.
func TestMarkCommitting_EveryAttemptRefreshesTheBound(t *testing.T) {
	needQemu(t)
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlayOn(t, disk)
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(disk, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	first := time.Now().Add(-3 * time.Hour).UnixNano()
	restamp(t, disk, func(b *Binding) { b.CommitStartedNs, b.CommitAttemptNs = first, first })

	// The retry writes part of the base and dies.
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "qemu-img" && len(args) > 0 && args[0] == "commit" {
			return exec.CommandContext(ctx, "sh", "-c", `qemu-io -f qcow2 -c "write -P 0x11 0 512" "$1" >/dev/null; exit 1`, "sh", disk)
		}
		return exec.CommandContext(ctx, name, args...)
	}
	if _, err := CommitOffline(context.Background(), disk, owner); err == nil {
		t.Fatal("setup: the cut-short retry reported success")
	}
	Command = prev

	if out, err := Settle(context.Background(), openGate, disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle after a retry = %v, %v; want the retry finished", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// N3: a commit that runs past the bound refreshes its stamp while it runs, so
// a crash right after it (before it is recorded as finished) is finished by
// the next settle — no false hold.
//
// Mutation "CommitOffline does not keep its stamp fresh" — red.
func TestCommitOffline_ALongCommitKeepsItsStampFresh(t *testing.T) {
	needQemu(t)
	pb, pr := CommitMargin, RefreshEvery
	CommitMargin, RefreshEvery = 300*time.Millisecond, 25*time.Millisecond
	defer func() { CommitMargin, RefreshEvery = pb, pr }()
	disk := window(t)
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "qemu-img" && len(args) > 0 && args[0] == "commit" {
			return exec.CommandContext(ctx, "sh", append([]string{"-c", `sleep 1; exec qemu-img "$@"`, "sh"}, args...)...)
		}
		return exec.CommandContext(ctx, name, args...)
	}
	if _, err := CommitOffline(context.Background(), disk, owner); err != nil {
		t.Fatal(err)
	}
	Command = prev
	// The crash: the commit finished, its end was never recorded (the
	// sidecar keeps the time of the last keep-alive).
	restampKeep(t, disk, func(b *Binding) { b.State, b.EndMtimeNs, b.EndSize = StateCommitting, 0, 0 })

	if out, err := Settle(context.Background(), openGate, disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle after a long commit = %v, %v; want it finished, not held", out, err)
	}
	if !windowWrite(t, disk) {
		t.Fatal("the window's write is not in the disk")
	}
}

// N3: a crash right after the pivot. The live commit's overlay is merged and
// left whole (an active commit does not empty it); the guest then wrote the
// disk. The overlay is removed, never committed again over the newer writes.
//
// Mutation "a committed binding is committed again" — red.
func TestSettle_AMergedOverlayIsRemovedNeverCommittedAgain(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	if err := MarkPivoting(disk); err != nil {
		t.Fatal(err)
	}
	if err := MarkCommitted(disk); err != nil {
		t.Fatal(err)
	}
	qemuIO(t, disk, "write -P 0x33 65536 65536") // the guest, after the pivot
	if out, err := Settle(context.Background(), openGate, disk, owner); err != nil || out != Committed {
		t.Fatalf("Settle = %v, %v; want the merged overlay removed", out, err)
	}
	if Present(disk) {
		t.Error("the merged overlay is still there")
	}
	if !regionIs(t, disk, 0x33) {
		t.Fatal("the guest's writes after the pivot were overwritten by the merged overlay")
	}
}

// A committed overlay written since (a VM ran on it again) is not merged any
// more: held, never removed.
//
// Mutation "the overlay's own time unchecked" — red.
func TestSettle_AnOverlayWrittenAfterItsCommitIsHeld(t *testing.T) {
	needQemu(t)
	disk := window(t)
	for _, f := range []func(string) error{MarkCommitting, MarkPivoting, MarkCommitted} {
		if err := f(disk); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	qemuIO(t, Path(disk), "write -P 0x77 0 512")
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v; an overlay written after its commit must hold", out, err)
	}
	if !Present(disk) {
		t.Fatal("an overlay holding writes was removed")
	}
}

// A pivot under way when the daemon stopped, seen with the VM off: whether it
// landed cannot be told, so the VM is held (committing again could overwrite
// newer writes; removing could drop the overlay's).
//
// Mutation "pivoting taken for committing" — red.
func TestSettle_APivotUnderWayIsHeldWithTheVMOff(t *testing.T) {
	needQemu(t)
	disk := window(t)
	if err := MarkCommitting(disk); err != nil {
		t.Fatal(err)
	}
	if err := MarkPivoting(disk); err != nil {
		t.Fatal(err)
	}
	if out, err := Settle(context.Background(), openGate, disk, owner); out != Held || err == nil {
		t.Fatalf("Settle = %v, %v; want held", out, err)
	}
	if !Present(disk) {
		t.Fatal("the overlay was removed")
	}
}

// N2: the verdicts, and the advice a hold gives for each — never a blind
// "commit".
//
// Mutation "no verdicts" (Assess reports matches for anything Check passes) —
// red.
func TestAssess_TheVerdictsAndTheirAdvice(t *testing.T) {
	needQemu(t)
	disk := window(t)
	type want struct {
		v     Verdict
		began bool
	}
	check := func(step string, live bool, w want) Assessment {
		t.Helper()
		a := Assess(disk, owner, live)
		if a.Verdict != w.v || a.CommitBegan != w.began {
			t.Fatalf("%s: verdict %q (commit began %v, %s), want %q (%v)", step, a.Verdict, a.CommitBegan, a.Reason, w.v, w.began)
		}
		return a
	}
	if adv := HoldAdvice("web", "root", check("window", false, want{Matches, false})); !strings.Contains(adv, "--commit") {
		t.Errorf("matches: advice %q does not say commit", adv)
	}
	_ = MarkCommitting(disk)
	if adv := HoldAdvice("web", "root", check("committing", false, want{HalfWritten, true})); !strings.Contains(adv, "--commit") {
		t.Errorf("half-written: advice %q does not say commit", adv)
	}
	_ = MarkPivoting(disk)
	unk := check("pivoting, VM off", false, want{Unknown, true})
	check("pivoting, VM on its disk", true, want{Pivoted, true})
	_ = MarkCommitted(disk)
	if adv := HoldAdvice("web", "root", check("committed", false, want{Pivoted, true})); !strings.Contains(adv, "--discard") || strings.Contains(adv, "--commit") {
		t.Errorf("pivoted: advice %q, want discard and never commit", adv)
	}
	for _, a := range []Assessment{unk, {Verdict: Unknown, Reason: "no readable binding"}} {
		adv := HoldAdvice("web", "root", a)
		if !strings.Contains(adv, "lv resolve-pit-overlay web root") || strings.Contains(adv, "--commit --confirm") {
			t.Errorf("unknown: advice %q must name the dry run and never recommend a commit", adv)
		}
	}
	if err := os.Remove(SidecarPath(disk)); err != nil {
		t.Fatal(err)
	}
	if a := check("no binding", false, want{Unknown, false}); a.Binding != nil {
		t.Error("an assessment without a binding reports one")
	}
}

// Ruling 6: a layer-2 overlay goes beside its disk. A disk that is not a
// regular file (a /dev block device) would put it on devtmpfs, and a pool on
// tmpfs on a volatile filesystem: a reboot or a failover loses either. Both
// are refused.
//
// Mutation "placement unchecked" — red.
func TestPlacement_RefusesDevicesAndVolatileFilesystems(t *testing.T) {
	if err := Placement("/dev/null"); err == nil {
		t.Error("an overlay beside a device node (devtmpfs) was allowed")
	}
	disk := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prevT, prevOK := dirFSType, volatileOK
	defer func() { dirFSType, volatileOK = prevT, prevOK }()
	volatileOK = false
	dirFSType = func(string) (int64, error) { return fsTmpfs, nil }
	if err := Placement(disk); err == nil {
		t.Error("an overlay on tmpfs was allowed")
	}
	dirFSType = func(string) (int64, error) { return 0xEF53, nil } // ext4
	if err := Placement(disk); err != nil {
		t.Errorf("an overlay on ext4 was refused: %v", err)
	}
}

// Nit: a set-aside never replaces an earlier orphan's binding either.
//
// Mutation "only the orphan's name checked" — red.
func TestSetAside_NeverOverAnEarlierOrphansBinding(t *testing.T) {
	needQemu(t)
	disk := window(t)
	stray := Path(disk) + ".orphan-same.id"
	if err := os.WriteFile(stray, []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
	to, err := SetAside(disk, "same")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(stray); string(got) != "earlier" {
		t.Fatalf("set aside to %s over an earlier orphan's binding", to)
	}
}

// N2: the admin's forced commit still never repoints an overlay at a file of
// another name: the backing file's name is the identity check it keeps.
//
// Mutation "ForceCommit rebases unconditionally" — red.
func TestForceCommit_NeverRepointsAtAnotherFile(t *testing.T) {
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
	qemuIO(t, Path(disk), "write -P 0x5a 65536 65536")
	if err := ForceCommit(context.Background(), disk); err == nil {
		t.Fatal("a forced commit repointed another disk's overlay at this one")
	}
	if windowWrite(t, disk) || !Present(disk) {
		t.Fatal("another disk's overlay was committed into this one")
	}
}

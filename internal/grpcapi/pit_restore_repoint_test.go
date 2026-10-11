package grpcapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// P-1 of lab 2 run c2: an in-place restore over a VM held on its
// point-in-time overlay set the overlay aside but left the domain's
// definition naming it, so the restored VM could not start ("Cannot access
// storage file …lv-pit").

// heldOnItsOverlay is a stopped VM "web" whose definition still names its
// overlay — a live commit that never landed (libvirtfake keeps the domain on
// the overlay it snapshotted) — and whose disk was written after the window,
// so the overlay cannot be verified: the VM is held.
func heldOnItsOverlay(t *testing.T) (*Server, *libvirtfake.Fake, string) {
	t.Helper()
	recordQemuImg(t)
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not on PATH")
	}
	s, _, live := pitServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	s.SetPointInTimeSnapshotter(fake)
	overlay := pitoverlay.Path(live)
	if _, err := fake.SnapshotDiskExternal("web", live, overlay); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 65536 65536", overlay).CombinedOutput(); err != nil {
		t.Fatalf("write into the overlay: %v %s", err, out)
	}
	if err := pitoverlay.Bind(live, pitoverlay.Owner{VM: "web", Disk: "root"}); err != nil {
		t.Fatal(err)
	}
	fake.SetState("web", libvirtfake.StateShutdown)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	writeBase(t, live, "write -P 0x33 0 512")
	if err := healWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("setup: heal = %v; want the VM held", err)
	}
	if on, _ := fake.DomainUsesFile("web", overlay); !on {
		t.Fatal("setup: the definition does not name the overlay")
	}
	return s, fake, live
}

// setAsideOverlays are the overlays set aside beside disk.
func setAsideOverlays(t *testing.T, disk string) []string {
	t.Helper()
	m, err := filepath.Glob(pitoverlay.Path(disk) + ".orphan-*")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range m {
		if filepath.Ext(p) != ".id" {
			out = append(out, p)
		}
	}
	return out
}

func startWeb(t *testing.T, s *Server) error {
	t.Helper()
	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	return err
}

// The restore points the definition back at the restored disk, keeps the
// overlay (set aside, its data intact), and the VM starts.
//
// Mutation "no repoint in the set-aside" — red.
func TestInPlaceRestore_OverAHeldOverlay_TheVMStartsOnTheRestoredDisk(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatalf("in-place restore target: %v", err)
	}
	if err := dest.place(stagedImage(t, live)); err != nil {
		t.Fatalf("place: %v", err)
	}
	if on, _ := fake.DomainUsesFile("web", overlay); on {
		t.Fatalf("after the restore the definition still names the set-aside overlay %s", overlay)
	}
	aside := setAsideOverlays(t, live)
	if len(aside) != 1 || !holdsTheWindowsWrite(t, aside[0]) {
		t.Fatalf("set-aside overlays %v; want one, holding the window's write", aside)
	}
	if err := startWeb(t, s); err != nil {
		t.Fatalf("start after the restore: %v", err)
	}
}

// A definition left on an overlay that has since been set aside (a restore
// by a build without the repoint, which lab 2 hit) is pointed back at the
// disk by the next start: the overlay is not there to be the disk's current
// layer, and nothing is deleted.
//
// Mutation "heal leaves a dangling definition" — red.
func TestStart_ADefinitionLeftOnASetAsideOverlayIsPointedAtTheDisk(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	// What the restore without the repoint left: the restored disk in
	// place, the overlay set aside, the hold cleared, the definition on it.
	if err := os.Rename(stagedImage(t, live), live); err != nil {
		t.Fatal(err)
	}
	if _, err := pitoverlay.SetAside(live, "20261011-161109"); err != nil {
		t.Fatal(err)
	}
	s.ClearPITOverlayHold(context.Background(), "web", "root")
	if on, _ := fake.DomainUsesFile("web", overlay); !on {
		t.Fatal("setup: the definition does not name the overlay")
	}
	if err := startWeb(t, s); err != nil {
		t.Fatalf("start with the definition left on the set-aside overlay: %v", err)
	}
	if on, _ := fake.DomainUsesFile("web", overlay); on {
		t.Fatal("the definition still names the set-aside overlay")
	}
	if aside := setAsideOverlays(t, live); len(aside) != 1 || !holdsTheWindowsWrite(t, aside[0]) {
		t.Fatalf("set-aside overlays %v; want the one, kept with its data", aside)
	}
}

// A crash after the repoint and before the set-aside: the definition is on
// the restored disk and the overlay still beside it, bound to the file the
// restore replaced. The VM stays held — the overlay is never committed into
// the restored disk, and the start is refused, so the two are never both
// current — and re-running the restore finishes the job.
//
// Mutation "set aside before the repoint" (then a crash between them leaves
// the definition on a missing overlay with no hold) — red.
func TestInPlaceRestore_ACrashBetweenRepointAndSetAsideStaysHeldAndRecovers(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	dest, err := s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatal(err)
	}
	type crash struct{}
	prev := restorePlaceStep
	restorePlaceStep = func(step string) {
		if step == "repointed" {
			panic(crash{})
		}
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(crash); !ok {
					panic(r)
				}
			}
		}()
		_ = dest.place(stagedImage(t, live))
	}()
	restorePlaceStep = prev

	if !pitoverlay.Present(live) {
		t.Fatal("the overlay moved before the crash point")
	}
	if on, _ := fake.DomainUsesFile("web", overlay); on {
		t.Fatal("the definition still names the overlay after the repoint")
	}
	if err := startWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after a crash between the repoint and the set-aside = %v; want refused, held", err)
	}
	if !pitoverlay.Present(live) || !holdsTheWindowsWrite(t, overlay) {
		t.Fatal("the refused start touched the overlay")
	}
	if row, found := heldCondition(t, s, "web", "root"); !found || row.Lifecycle == "resolved" {
		t.Fatalf("not held after the crash: %+v", row)
	}

	// The restore, run again, sets the overlay aside; the VM starts.
	dest, err = s.inPlaceRestoreLocked(context.Background(), "web", "root")
	if err != nil {
		t.Fatalf("re-run restore target: %v", err)
	}
	if err := dest.place(stagedImage(t, live)); err != nil {
		t.Fatalf("re-run place: %v", err)
	}
	if aside := setAsideOverlays(t, live); len(aside) != 1 || !holdsTheWindowsWrite(t, aside[0]) {
		t.Fatalf("set-aside overlays %v; want one, holding the window's write", aside)
	}
	if err := startWeb(t, s); err != nil {
		t.Fatalf("start after the re-run restore: %v", err)
	}
}

// C-1 of the pit-restore review: the start-time repoint acts only on proof
// that the overlay was set aside — the overlay and its binding both ENOENT
// and an orphan of it beside the disk. Anything less leaves the definition
// as it is, and the start fails as it does on main: booting the base would
// fork the VM away from writes the overlay may hold.

// moveOverlayOut moves live's overlay and binding out of the pool (an admin's
// safety copy): the overlay is gone from beside the disk, and nothing says
// it was set aside.
func moveOverlayOut(t *testing.T, live string) string {
	t.Helper()
	keep := t.TempDir()
	for _, p := range []string{pitoverlay.Path(live), pitoverlay.SidecarPath(live)} {
		if err := os.Rename(p, filepath.Join(keep, filepath.Base(p))); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(keep, filepath.Base(pitoverlay.Path(live)))
}

// Mutation "repoint on any absent overlay" (no set-aside evidence asked) — red.
func TestStart_AnOverlayMovedAwayIsNotTakenAsSetAside(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	kept := moveOverlayOut(t, live)
	if err := startWeb(t, s); err == nil {
		t.Fatal("the VM started on its base with its overlay moved out of the pool")
	}
	if on, _ := fake.DomainUsesFile("web", overlay); !on {
		t.Fatal("the definition was pointed at the base with no evidence the overlay was set aside")
	}
	if !holdsTheWindowsWrite(t, kept) {
		t.Fatal("the moved overlay lost its write")
	}
}

// Mutation "a stat error reads as absent" — red.
func TestStart_AnUnreadableOverlayIsNotTakenAsGone(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	// The set-aside evidence is there, but the overlay's own path cannot be
	// read (EIO on an NFS dentry, say): nothing is established.
	if err := os.Rename(stagedImage(t, live), live); err != nil {
		t.Fatal(err)
	}
	if _, err := pitoverlay.SetAside(live, "20261011-161109"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
		if p == overlay {
			return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.EIO}
		}
		return os.Lstat(p)
	}))
	if err := startWeb(t, s); err == nil {
		t.Fatal("the VM started on its base while its overlay's path could not be read")
	}
	if on, _ := fake.DomainUsesFile("web", overlay); !on {
		t.Fatal("the definition was pointed at the base on a stat error")
	}
}

// Re-review 1, I-1: an orphan from an OLDER window is no evidence that the
// overlay the definition names now was set aside. Window A's overlay was set
// aside; later window B strands on the same disk (a new token on the disk),
// and the admin moves B's overlay out of the pool. The definition stays on
// B's overlay and the start fails, as on main.
//
// Mutation "the evidence ignores the window token" — red.
func TestStart_AnOlderWindowsOrphanIsNoEvidenceForANewWindow(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t) // window A: bound, token on the disk
	if b, err := pitoverlay.BindingOf(live); err != nil || b.Token == "" {
		t.Skipf("no user xattrs here (binding %+v, %v): windows cannot be told apart", b, err)
	}
	overlay := pitoverlay.Path(live)
	if _, err := pitoverlay.SetAside(live, "20261001-000000"); err != nil {
		t.Fatal(err)
	}
	// Window B: a new overlay, a new token on the disk, and its commit never
	// lands — the domain stays on it — and the VM stops.
	fake.SetState("web", libvirtfake.StateRunning)
	if _, err := fake.SnapshotDiskExternal("web", live, overlay); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 65536 65536", overlay).CombinedOutput(); err != nil {
		t.Fatalf("write into window B's overlay: %v %s", err, out)
	}
	if err := pitoverlay.Bind(live, pitoverlay.Owner{VM: "web", Disk: "root"}); err != nil {
		t.Fatal(err)
	}
	fake.SetState("web", libvirtfake.StateShutdown)
	kept := moveOverlayOut(t, live)
	if err := startWeb(t, s); err == nil {
		t.Fatal("the VM started on its base: window A's orphan was taken as evidence for window B")
	}
	if on, _ := fake.DomainUsesFile("web", overlay); !on {
		t.Fatal("the definition was pointed at the base on an older window's orphan")
	}
	if !holdsTheWindowsWrite(t, kept) {
		t.Fatal("window B's moved overlay lost its write")
	}
}

// Re-review 1, m2: a heal that cannot tell whether the overlay is there
// (a stat error) keeps the VM's hold; only an established absence clears it.
//
// Mutation "clear the hold on any not-Present" — red.
func TestHeal_AnUnreadableOverlayKeepsTheHold(t *testing.T) {
	s, _, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	if _, err := pitoverlay.SetAside(live, "20261011-161109"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
		if p == overlay {
			return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.ESTALE}
		}
		return os.Lstat(p)
	}))
	_ = healWeb(t, s)
	if row, found := heldCondition(t, s, "web", "root"); !found || row.Lifecycle == "resolved" {
		t.Fatalf("the hold was cleared while the overlay's path could not be read: %+v", row)
	}
}

// Package pitoverlay is the one place the point-in-time copy's external
// snapshot overlay (grpcapi/pit_copy.go, layer 2) is named and settled.
//
// While a layer-2 copy runs — and after one whose commit failed, or whose
// daemon died mid-window — the guest's newest writes are in an overlay beside
// the disk, not in the disk file the vm_disks row names. Nothing replicated
// records that. So the overlay has ONE deterministic name, beside the disk on
// the same pool: any host that can see the disk (a shared pool carries it to
// a failover target) can see the overlay, and every path that defines,
// starts, moves or copies the disk settles it first.
//
// The rule: an overlay that may hold data is never deleted. It is committed
// into the disk — offline here with qemu-img, WITHOUT -U, so a qemu still
// holding either file fails the commit rather than racing it — and only a
// committed (emptied) overlay is removed.
package pitoverlay

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// Suffix ends every overlay's name.
const Suffix = ".lv-pit"

// Path is disk's overlay: ".<disk file>.lv-pit" beside it.
func Path(disk string) string {
	return filepath.Join(filepath.Dir(disk), "."+filepath.Base(disk)+Suffix)
}

// Present reports whether disk has an overlay (anything at its path).
func Present(disk string) bool {
	_, err := os.Lstat(Path(disk))
	return err == nil
}

// Command builds the qemu-img process. A variable so a test can see the
// argv or fail it.
var Command = exec.CommandContext

// ErrNotOurs refuses an overlay this package cannot show is disk's: not a
// regular qcow2 file, or one whose backing file is not disk. It is left as it
// is.
var ErrNotOurs = errors.New("not a point-in-time overlay of this disk")

// CommitOffline commits disk's overlay, if it has one, into disk with
// qemu-img commit (no -U). The overlay is kept: qemu-img empties it, and the
// caller removes it (Remove) once whatever names it — a persistent domain
// definition — has been pointed back at disk. It reports whether there was an
// overlay to commit.
//
// The caller must know no running domain uses the overlay or the disk; the
// missing -U makes qemu's own lock the backstop if it is wrong.
func CommitOffline(ctx context.Context, disk string) (bool, error) {
	ov := Path(disk)
	fi, err := os.Lstat(ov)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if !fi.Mode().IsRegular() {
		return true, fmt.Errorf("%s: %w (not a regular file)", ov, ErrNotOurs)
	}
	info, err := qcow2.Info(ov)
	if err != nil {
		return true, fmt.Errorf("%s: %w (%v)", ov, ErrNotOurs, err)
	}
	if info.BackingFile != disk && filepath.Join(filepath.Dir(ov), info.BackingFile) != disk {
		return true, fmt.Errorf("%s: %w (its backing file is %q)", ov, ErrNotOurs, info.BackingFile)
	}
	if out, err := Command(ctx, "qemu-img", "commit", "-f", "qcow2", ov).CombinedOutput(); err != nil {
		return true, fmt.Errorf("qemu-img commit %s into %s: %v: %s", ov, disk, err, out)
	}
	return true, nil
}

// Remove removes disk's overlay. Call it only after CommitOffline (or a live
// commit) succeeded and nothing names the overlay any more.
func Remove(disk string) error {
	if err := os.Remove(Path(disk)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// SetAside renames disk's overlay out of every path's way — it is NEVER
// deleted — and returns its new name. For an overlay that must not be
// committed (the disk has moved on without it): its data is kept for an
// operator.
func SetAside(disk, stamp string) (string, error) {
	to := Path(disk) + ".orphan-" + stamp
	return to, os.Rename(Path(disk), to)
}

// Settle commits disk's overlay offline and removes it: for a caller about
// to define the disk afresh from its record (so no definition names the
// overlay). It reports whether there was one.
func Settle(ctx context.Context, disk string) (bool, error) {
	had, err := CommitOffline(ctx, disk)
	if err != nil || !had {
		return had, err
	}
	return true, Remove(disk)
}

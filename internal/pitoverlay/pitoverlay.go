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
// An overlay is bound to the very base file it was taken from: a sidecar
// beside it (Bind) records the VM, its disk, and the base's device, inode,
// size and modification time. A path can be reused — a VM deleted and
// re-created under the same name, a disk restored or rebuilt in place — and
// a base can be written after the overlay was taken (a build that knows
// nothing of overlays restarted the VM on it). Committing the overlay into
// such a file would write stale blocks over newer data. So:
//
//   - an overlay is committed only into the base its sidecar names, unchanged
//     since (or, in the "committing" state a commit enters first, the same
//     file a commit was already writing);
//   - any other overlay — no sidecar, another VM or disk, another or changed
//     base — is set aside under a new name, kept, never committed and never
//     deleted;
//   - a committed (emptied) overlay is removed with its sidecar; an overlay is
//     deleted otherwise only with its disk, by the disk's own deletion.
//
// Commits run offline here with qemu-img, WITHOUT -U, so a qemu still
// holding either file fails the commit rather than racing it.
package pitoverlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// Suffix ends every overlay's name.
const Suffix = ".lv-pit"

// Path is disk's overlay: ".<disk file>.lv-pit" beside it.
func Path(disk string) string {
	return filepath.Join(filepath.Dir(disk), "."+filepath.Base(disk)+Suffix)
}

// SidecarPath is the overlay's binding record.
func SidecarPath(disk string) string { return Path(disk) + ".id" }

// Present reports whether disk has an overlay (anything at its path).
func Present(disk string) bool {
	_, err := os.Lstat(Path(disk))
	return err == nil
}

// Command builds the qemu-img process. A variable so a test can see the
// argv or fail it.
var Command = exec.CommandContext

// Owner is the VM disk an overlay belongs to.
type Owner struct {
	VM     string `json:"vm"`
	VMUUID string `json:"vm_uuid,omitempty"`
	Disk   string `json:"disk"`
}

// States of a binding.
const (
	StateWindow     = "window"     // the base is frozen under the overlay
	StateCommitting = "committing" // a commit has started writing the base
)

// Binding is the sidecar: the owner, and the base file's identity when the
// overlay was taken.
type Binding struct {
	Owner
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	State   string `json:"state"`
}

func identity(disk string) (dev, ino uint64, size, mtimeNs int64, err error) {
	fi, err := os.Stat(disk)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("%s: no device and inode", disk)
	}
	return uint64(st.Dev), uint64(st.Ino), fi.Size(), fi.ModTime().UnixNano(), nil
}

// Bind records that disk's overlay, just taken, belongs to owner and to the
// base file as it is now. Call it once the snapshot has frozen the base.
func Bind(disk string, owner Owner) error {
	dev, ino, size, mt, err := identity(disk)
	if err != nil {
		return err
	}
	return writeBinding(disk, Binding{Owner: owner, Dev: dev, Ino: ino, Size: size, MtimeNs: mt, State: StateWindow})
}

func writeBinding(disk string, b Binding) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tmp := SidecarPath(disk) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, SidecarPath(disk))
}

func readBinding(disk string) (Binding, error) {
	var b Binding
	data, err := os.ReadFile(SidecarPath(disk))
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(data, &b)
}

// MarkCommitting moves the binding to StateCommitting: a commit is about to
// write the base, after which the base no longer matches the window but is
// still the file this overlay must go into.
func MarkCommitting(disk string) error {
	b, err := readBinding(disk)
	if err != nil {
		return err
	}
	if b.State == StateCommitting {
		return nil
	}
	b.State = StateCommitting
	return writeBinding(disk, b)
}

// ErrNotOurs refuses an overlay that cannot be shown to belong to this disk
// file as it is now. The caller sets it aside (SetAside); it is never
// committed.
var ErrNotOurs = errors.New("not this disk's point-in-time overlay")

// Check reports whether disk's overlay is bound to owner and to disk's file
// as it is now (ErrNotOurs, with the reason, if not).
func Check(disk string, owner Owner) error {
	ov := Path(disk)
	fi, err := os.Lstat(ov)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w (not a regular file)", ov, ErrNotOurs)
	}
	b, err := readBinding(disk)
	if err != nil {
		return fmt.Errorf("%s: %w (no readable binding: %v)", ov, ErrNotOurs, err)
	}
	if b.VM != owner.VM || b.Disk != owner.Disk || (b.VMUUID != "" && owner.VMUUID != "" && b.VMUUID != owner.VMUUID) {
		return fmt.Errorf("%s: %w (taken of vm %q disk %q, not vm %q disk %q)", ov, ErrNotOurs, b.VM, b.Disk, owner.VM, owner.Disk)
	}
	dev, ino, size, mt, err := identity(disk)
	if err != nil {
		return fmt.Errorf("%s: %w (its disk: %v)", ov, ErrNotOurs, err)
	}
	if dev != b.Dev || ino != b.Ino {
		return fmt.Errorf("%s: %w (the disk at %s is another file than the one it was taken of)", ov, ErrNotOurs, disk)
	}
	if b.State != StateCommitting && (size != b.Size || mt != b.MtimeNs) {
		return fmt.Errorf("%s: %w (the disk %s was written after it was taken)", ov, ErrNotOurs, disk)
	}
	info, err := qcow2.Info(ov)
	if err != nil {
		return fmt.Errorf("%s: %w (%v)", ov, ErrNotOurs, err)
	}
	if info.BackingFile != disk && filepath.Join(filepath.Dir(ov), info.BackingFile) != disk {
		return fmt.Errorf("%s: %w (its backing file is %q)", ov, ErrNotOurs, info.BackingFile)
	}
	return nil
}

// CommitOffline commits disk's overlay, if it has one and it is bound to
// owner and to the disk as it is (Check), into the disk with qemu-img
// commit (no -U). It enters StateCommitting first, so a commit a crash cut
// short is finished by the next one. The overlay is kept: qemu-img empties
// it, and the caller removes it (Remove) once whatever names it — a
// persistent domain definition — has been pointed back at the disk. It
// reports whether there was an overlay; an overlay that is not ours returns
// an error wrapping ErrNotOurs and is left untouched.
//
// The caller must know no running domain uses the overlay or the disk; the
// missing -U makes qemu's own lock the backstop if it is wrong.
func CommitOffline(ctx context.Context, disk string, owner Owner) (bool, error) {
	if _, err := os.Lstat(Path(disk)); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err := Check(disk, owner); err != nil {
		return true, err
	}
	if err := MarkCommitting(disk); err != nil {
		return true, fmt.Errorf("mark %s committing: %w", Path(disk), err)
	}
	if out, err := Command(ctx, "qemu-img", "commit", "-f", "qcow2", Path(disk)).CombinedOutput(); err != nil {
		return true, fmt.Errorf("qemu-img commit %s into %s: %v: %s", Path(disk), disk, err, out)
	}
	return true, nil
}

// Remove removes disk's overlay and its binding. Call it only after a commit
// succeeded and nothing names the overlay any more, or with the disk itself
// when the disk is deleted.
func Remove(disk string) error {
	for _, p := range []string{Path(disk), SidecarPath(disk)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// SetAside renames disk's overlay (and its binding) out of every path's way —
// it is NEVER deleted — and returns its new name.
func SetAside(disk, stamp string) (string, error) {
	to := Path(disk) + ".orphan-" + stamp
	if err := os.Rename(Path(disk), to); err != nil {
		return "", err
	}
	if err := os.Rename(SidecarPath(disk), to+".id"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return to, err
	}
	return to, nil
}

// Outcome is what Settle did.
type Outcome int

const (
	None      Outcome = iota // no overlay
	Committed                // committed into the disk and removed
	SetAsideO                // not this disk's: set aside, kept
)

// Settle commits disk's overlay offline and removes it when it is owner's
// overlay of the disk as it is; any other overlay is set aside (aside names
// it). For a caller about to define or rewrite the disk from its record (so
// no definition names the overlay).
func Settle(ctx context.Context, disk string, owner Owner, stamp string) (out Outcome, aside string, err error) {
	had, err := CommitOffline(ctx, disk, owner)
	switch {
	case !had:
		return None, "", nil
	case errors.Is(err, ErrNotOurs):
		to, serr := SetAside(disk, stamp)
		if serr != nil {
			return None, "", fmt.Errorf("%v; and setting it aside: %w", err, serr)
		}
		return SetAsideO, to, nil
	case err != nil:
		return None, "", err
	}
	return Committed, "", Remove(disk)
}

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
// An overlay is bound to the very base file it was taken from:
//
//   - before the window opens, a random token is written durably into an
//     extended attribute of the base (user.litevirt.pit_window, OpenWindow).
//     It lives on the base's inode: a copy or restore of the file (cp -p,
//     rsync -a without -X) does not carry it, and a re-created file does not
//     have it. A filesystem without user xattrs (NFSv3, NFSv4 before 4.2)
//     records "no token", and the bounds below decide alone;
//   - a sidecar beside the overlay (Bind) records the VM, its disk, the token,
//     and the base's inode, size and modification time — WITHOUT the device
//     number, which differs between two hosts mounting one NFS export and can
//     change across a remount or reboot.
//
// The binding moves through states as a commit writes the base:
//
//	window ─► committing ─► pivoting ─► committed
//	   │          │  ▲          │
//	   └──────────┴──┴──────────┴─► diverged (the VM ran on its disk without it)
//
// and Assess turns the binding and the file as it is now into a verdict:
//
//   - matches: window, and the file is the one taken, unchanged — commit;
//   - half-written: a commit began, and the file is the one it was writing
//     (the token; size and mtime no smaller than the window's; not written
//     long after the last commit attempt) — only a commit makes it whole;
//   - pivoted: the overlay is already in the disk (a recorded commit, or a
//     pivot under way and the domain seen running on the disk) — remove it,
//     never commit it again over the guest's newer writes;
//   - unknown: anything else. The caller HOLDS the VM — never starts it on
//     the bare disk, which would drop the overlay's writes — until an admin
//     resolves it with `lv resolve-pit-overlay`.
//
// An overlay is deleted only once committed (or found merged), with its disk
// by the disk's own deletion, or by an admin's discard. Commits run offline
// here with qemu-img, WITHOUT -U, so a qemu still holding either file fails
// the commit rather than racing it.
package pitoverlay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// Suffix ends every overlay's name.
const Suffix = ".lv-pit"

// xattrName carries the window token on the base file.
const xattrName = "user.litevirt.pit_window"

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
	StatePivoting   = "pivoting"   // a live commit is ready and pivoting onto the base
	StateCommitted  = "committed"  // the overlay is in the base; it only waits to be removed
	StateDiverged   = "diverged"   // the VM ran on its base without the overlay
)

// Binding is the sidecar: the owner, and the base file's identity when the
// overlay was taken.
type Binding struct {
	Owner
	// Name is the base's file name in its directory. Diagnostics only: the
	// sidecar is found by that very name, so it cannot tell files apart.
	Name    string `json:"name"`
	Dev     uint64 `json:"dev"` // diagnostics only: never compared
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	State   string `json:"state"`
	// Token is the window's token, also in the base's xattr. NoXattr: the
	// base's filesystem has no user xattrs, so there is none.
	Token   string `json:"token,omitempty"`
	NoXattr bool   `json:"no_xattr,omitempty"`
	// CommitStartedNs is when the first commit began; CommitAttemptNs when
	// the latest attempt began or last reported progress (KeepCommitting).
	CommitStartedNs int64 `json:"commit_started_ns,omitempty"`
	CommitAttemptNs int64 `json:"commit_attempt_ns,omitempty"`
	// OverlayMtimeNs is the overlay's modification time when it was recorded
	// committed: an overlay written after that is not merged any more.
	OverlayMtimeNs int64 `json:"overlay_mtime_ns,omitempty"`
	// Diverged says how the VM was found running on its base without it.
	Diverged string `json:"diverged,omitempty"`
}

// CommitBound is how long after the latest commit attempt (or its last sign
// of progress) the base may still be written by that commit. A base modified
// later than that was written by something else (a build that knows nothing
// of overlays ran the VM on it), and the overlay is not committed over it.
var CommitBound = 2 * time.Hour

// RefreshEvery is how often a running commit renews its attempt stamp, so a
// commit that runs past CommitBound is not mistaken for something else.
var RefreshEvery = 10 * time.Minute

// identity is the base file's identity. A variable so a test can model a
// host that sees the same file under another device number, or a restore
// that reused an inode number.
var identity = func(disk string) (dev, ino uint64, size, mtimeNs int64, err error) {
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

// The token's xattr, and the filesystem type of an overlay's directory.
// Variables so a test can model a filesystem without xattrs or a tmpfs.
var (
	setXattr  = osSetXattr
	getXattr  = osGetXattr
	dirFSType = osDirFSType
)

func xattrUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

// bindingMu serialises every read-modify-write of a sidecar in this process
// (a commit's keep-alive and its pivot record run concurrently).
var bindingMu sync.Mutex

// Window is a window's token, written on the base before the window opens.
type Window struct {
	Token   string
	NoXattr bool
}

// OpenWindow writes a new random token into disk's xattr, durably, and reads
// it back. Call it BEFORE the snapshot opens the window. A filesystem without
// user xattrs gives a Window with NoXattr; any other failure is an error, and
// no window may be opened.
func OpenWindow(disk string) (Window, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Window{}, err
	}
	tok := hex.EncodeToString(raw)
	if err := setXattr(disk, []byte(tok)); err != nil {
		if xattrUnsupported(err) {
			return Window{NoXattr: true}, nil
		}
		return Window{}, fmt.Errorf("write the window token on %s: %w", disk, err)
	}
	f, err := os.Open(disk)
	if err != nil {
		return Window{}, err
	}
	serr := f.Sync()
	f.Close()
	if serr != nil {
		return Window{}, fmt.Errorf("sync the window token on %s: %w", disk, serr)
	}
	if got, err := getXattr(disk); err != nil || string(got) != tok {
		return Window{}, fmt.Errorf("the window token on %s did not hold (%v)", disk, err)
	}
	return Window{Token: tok}, nil
}

// BindWindow records that disk's overlay, just taken in window w, belongs to
// owner and to the base file as it is now. Call it once the snapshot has
// frozen the base.
func BindWindow(disk string, owner Owner, w Window) error {
	dev, ino, size, mt, err := identity(disk)
	if err != nil {
		return err
	}
	bindingMu.Lock()
	defer bindingMu.Unlock()
	return writeBinding(disk, Binding{Owner: owner, Name: filepath.Base(disk), Dev: dev, Ino: ino, Size: size, MtimeNs: mt,
		State: StateWindow, Token: w.Token, NoXattr: w.NoXattr})
}

// Bind opens a new window token on disk and binds its overlay to it: for an
// overlay found unbound while the domain runs on it (the base is frozen).
func Bind(disk string, owner Owner) error {
	w, err := OpenWindow(disk)
	if err != nil {
		return err
	}
	return BindWindow(disk, owner, w)
}

// Bound reports whether disk's overlay has a readable binding.
func Bound(disk string) bool {
	_, err := readBinding(disk)
	return err == nil
}

// BindingOf returns disk's overlay's binding.
func BindingOf(disk string) (Binding, error) { return readBinding(disk) }

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
	if err := os.Rename(tmp, SidecarPath(disk)); err != nil {
		return err
	}
	// Durable before anything relies on it: a "committing" binding must
	// survive a crash that happens after the commit's first base write.
	d, err := os.Open(filepath.Dir(disk))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readBinding(disk string) (Binding, error) {
	var b Binding
	data, err := os.ReadFile(SidecarPath(disk))
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(data, &b)
}

// update applies f to disk's binding under bindingMu and writes it durably.
func update(disk string, f func(*Binding) error) error {
	bindingMu.Lock()
	defer bindingMu.Unlock()
	b, err := readBinding(disk)
	if err != nil {
		return err
	}
	if err := f(&b); err != nil {
		return err
	}
	return writeBinding(disk, b)
}

// MarkCommitting records, durably, that a commit attempt is about to write
// the base: from here the binding vouches for the file, not its unchanged
// contents. Every attempt renews the attempt stamp the bound is measured
// from, so a retry long after a failed attempt is not mistaken for something
// else writing the base.
func MarkCommitting(disk string) error {
	return update(disk, func(b *Binding) error {
		now := time.Now().UnixNano()
		b.State = StateCommitting
		if b.CommitStartedNs == 0 {
			b.CommitStartedNs = now
		}
		b.CommitAttemptNs = now
		return nil
	})
}

// MarkPivoting records that a ready live commit is about to pivot the domain
// onto the base. Seen later with the domain running on its base, it means
// the pivot landed and the overlay is merged.
func MarkPivoting(disk string) error {
	return update(disk, func(b *Binding) error {
		if b.State != StateCommitting {
			return fmt.Errorf("a pivot recorded from state %q", b.State)
		}
		b.State = StatePivoting
		return nil
	})
}

// MarkCommitted records that the overlay is in the base (the pivot landed,
// or an offline commit finished), with the overlay's own time: removing it
// is then all that is left, and committing it again would write its old
// blocks over the guest's newer ones.
func MarkCommitted(disk string) error {
	fi, err := os.Stat(Path(disk))
	if err != nil {
		return err
	}
	return update(disk, func(b *Binding) error {
		b.State = StateCommitted
		b.OverlayMtimeNs = fi.ModTime().UnixNano()
		return nil
	})
}

// MarkDiverged records that the VM was found running on its base without the
// overlay: the overlay may never be committed automatically after that.
func MarkDiverged(disk, why string) error {
	return update(disk, func(b *Binding) error {
		b.State = StateDiverged
		b.Diverged = why
		return nil
	})
}

// KeepCommitting renews the attempt stamp every RefreshEvery while a commit
// runs, so a commit that runs past CommitBound keeps its own base writes
// within the bound. stop ends it and waits.
func KeepCommitting(ctx context.Context, disk string) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(RefreshEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = update(disk, func(b *Binding) error {
					if b.State != StateCommitting && b.State != StatePivoting {
						return errors.New("not committing")
					}
					b.CommitAttemptNs = time.Now().UnixNano()
					return nil
				})
			}
		}
	}()
	return func() { cancel(); <-done }
}

// ErrNotOurs refuses an overlay that cannot be shown to belong to this disk
// file as it is now. The caller holds the VM; the overlay is never committed
// or removed automatically.
var ErrNotOurs = errors.New("not this disk's point-in-time overlay")

// Verdict is what an assessment found.
type Verdict string

const (
	Matches     Verdict = "matches"      // the file it was taken of, unchanged: commit
	HalfWritten Verdict = "half-written" // the file a commit was writing: only a commit completes it
	Pivoted     Verdict = "pivoted"      // already in the disk: remove it, never commit it again
	Unknown     Verdict = "unknown"      // cannot be verified: hold
)

// Assessment is an overlay judged against its disk as it is now.
type Assessment struct {
	Verdict Verdict
	Reason  string   // why it is not matches / half-written / pivoted
	Binding *Binding // nil without a readable one
	// Current is the disk's identity now; Backing the overlay's backing file.
	Current string
	Backing string
	// CommitBegan: the binding records that a commit began writing the
	// disk, so it may be partly written.
	CommitBegan bool
}

func (a *Assessment) unknown(format string, args ...any) Assessment {
	a.Verdict = Unknown
	a.Reason = fmt.Sprintf(format, args...)
	return *a
}

// Assess judges disk's overlay against owner and the disk file as it is now.
// liveOnDisk says the caller saw the domain RUNNING on the disk itself, not
// on the overlay: a pivot recorded as under way then landed.
func Assess(disk string, owner Owner, liveOnDisk bool) Assessment {
	var a Assessment
	ov := Path(disk)
	fi, err := os.Lstat(ov)
	if err != nil {
		return a.unknown("no overlay (%v)", err)
	}
	if !fi.Mode().IsRegular() {
		return a.unknown("the overlay is not a regular file")
	}
	b, err := readBinding(disk)
	if err != nil {
		return a.unknown("no readable binding (%v)", err)
	}
	a.Binding = &b
	a.CommitBegan = b.CommitStartedNs != 0 || b.State == StateCommitting || b.State == StatePivoting || b.State == StateCommitted
	if b.VM != owner.VM || b.Disk != owner.Disk || (b.VMUUID != "" && owner.VMUUID != "" && b.VMUUID != owner.VMUUID) {
		return a.unknown("it was taken of vm %q disk %q, not vm %q disk %q", b.VM, b.Disk, owner.VM, owner.Disk)
	}
	_, ino, size, mt, err := identity(disk)
	if err != nil {
		return a.unknown("its disk: %v", err)
	}
	a.Current = fmt.Sprintf("inode %d, %d bytes, modified %s", ino, size, time.Unix(0, mt).UTC().Format(time.RFC3339Nano))
	if ino != b.Ino {
		return a.unknown("the disk is another file (inode %d) than the one it was taken of (inode %d)", ino, b.Ino)
	}
	if err := checkToken(disk, b); err != nil {
		return a.unknown("%v", err)
	}
	info, err := qcow2.Info(ov)
	if err != nil {
		return a.unknown("the overlay: %v", err)
	}
	a.Backing = info.BackingFile
	// The overlay names its base by the absolute path it had on the host
	// that took it; another host may mount the pool elsewhere. Its base is
	// the file of that name beside it, and only that.
	if filepath.Base(info.BackingFile) != filepath.Base(disk) {
		return a.unknown("its backing file is %q, not this disk", info.BackingFile)
	}
	notSmaller := func() bool { return size >= b.Size && mt >= b.MtimeNs }
	const older = "the disk is smaller or older than the file the overlay was taken of, so it is not that file (restored from an earlier copy?)"
	switch b.State {
	case StateWindow, "":
		if size != b.Size || mt != b.MtimeNs {
			return a.unknown("the disk was written after the overlay was taken")
		}
		a.Verdict = Matches
	case StateCommitting:
		attempt := max(b.CommitAttemptNs, b.CommitStartedNs)
		if attempt == 0 {
			return a.unknown("its binding does not record when its commit began")
		}
		if !notSmaller() {
			return a.unknown("%s", older)
		}
		if mt > attempt+int64(CommitBound) {
			return a.unknown("the disk was written long after the last attempt to commit into it, by something else")
		}
		a.Verdict = HalfWritten
	case StatePivoting:
		if !notSmaller() {
			return a.unknown("%s", older)
		}
		if !liveOnDisk {
			return a.unknown("a pivot onto the disk was under way when the daemon stopped, and with the VM off it cannot be told whether it landed")
		}
		a.Verdict = Pivoted
	case StateCommitted:
		if !notSmaller() {
			return a.unknown("%s", older)
		}
		if ofi, err := os.Stat(ov); err != nil || ofi.ModTime().UnixNano() != b.OverlayMtimeNs {
			return a.unknown("the overlay was written after it was committed (a VM ran on it since)")
		}
		a.Verdict = Pivoted
	case StateDiverged:
		return a.unknown("the VM ran on its disk without the overlay (%s), so the disk holds newer writes than the overlay's", b.Diverged)
	default:
		return a.unknown("its binding is in an unknown state %q", b.State)
	}
	return a
}

// checkToken compares the window token the binding recorded with the one on
// the disk. A binding without a token (a filesystem without xattrs) leaves
// the decision to the bounds.
func checkToken(disk string, b Binding) error {
	if b.Token == "" {
		return nil
	}
	got, err := getXattr(disk)
	switch {
	case err == nil && string(got) == b.Token:
		return nil
	case err == nil:
		return errors.New("the disk carries another window's token: it is not the file the overlay was taken of")
	case errors.Is(err, errNoAttr):
		return errors.New("the disk does not carry the window's token: it is not the file the overlay was taken of (a copy, a restore or a new file)")
	case xattrUnsupported(err):
		return errors.New("the window's token cannot be read here (no user xattrs on this mount; NFS needs 4.2), so the disk cannot be verified")
	default:
		return fmt.Errorf("the window's token: %v", err)
	}
}

// Check reports whether disk's overlay may be committed into disk now: the
// verdict is matches or half-written (ErrNotOurs, with the reason, if not).
func Check(disk string, owner Owner) error {
	a := Assess(disk, owner, false)
	if a.Verdict == Matches || a.Verdict == HalfWritten {
		return nil
	}
	return fmt.Errorf("%s: %w (%s)", Path(disk), ErrNotOurs, a.Reason)
}

// CommitOffline commits disk's overlay, if it has one and it is bound to
// owner and to the disk as it is (matches or half-written), into the disk
// with qemu-img commit (no -U). It renews the committing state first, so a
// commit a crash cut short is finished by the next one, keeps the stamp
// fresh while it runs, and records it committed after. An overlay already
// merged (pivoted) is left as it is: nothing is written. The overlay is
// kept: the caller removes it (Remove) once whatever names it — a
// persistent domain definition — has been pointed back at the disk. It
// reports whether there was an overlay; one that cannot be verified returns
// an error wrapping ErrNotOurs and is left untouched.
//
// The caller must know no running domain uses the overlay or the disk; the
// missing -U makes qemu's own lock the backstop if it is wrong.
func CommitOffline(ctx context.Context, disk string, owner Owner) (bool, error) {
	if _, err := os.Lstat(Path(disk)); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	a := Assess(disk, owner, false)
	switch a.Verdict {
	case Pivoted:
		return true, nil
	case Matches, HalfWritten:
	default:
		return true, fmt.Errorf("%s: %w (%s)", Path(disk), ErrNotOurs, a.Reason)
	}
	if err := MarkCommitting(disk); err != nil {
		return true, fmt.Errorf("mark %s committing: %w", Path(disk), err)
	}
	stop := KeepCommitting(ctx, disk)
	err := commitInto(ctx, disk)
	stop()
	if err != nil {
		return true, err
	}
	if err := MarkCommitted(disk); err != nil {
		return true, fmt.Errorf("record %s committed: %w", Path(disk), err)
	}
	return true, nil
}

// commitInto runs qemu-img commit of disk's overlay into disk, pointing the
// overlay's header at disk first when it names the base by a path this host
// does not have (another host's mount point) — and only when the backing
// file's NAME is the disk's: an overlay of another file is never repointed.
func commitInto(ctx context.Context, disk string) error {
	info, err := qcow2.Info(Path(disk))
	if err != nil {
		return fmt.Errorf("%s: %v", Path(disk), err)
	}
	if filepath.Base(info.BackingFile) != filepath.Base(disk) {
		return fmt.Errorf("%s: %w (its backing file is %q, not this disk; it is never repointed at another file)", Path(disk), ErrNotOurs, info.BackingFile)
	}
	if info.BackingFile != disk && filepath.Join(filepath.Dir(disk), info.BackingFile) != disk {
		if out, err := Command(ctx, "qemu-img", "rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b", disk, Path(disk)).CombinedOutput(); err != nil {
			return fmt.Errorf("point %s at %s: %v: %s", Path(disk), disk, err, out)
		}
	}
	if out, err := Command(ctx, "qemu-img", "commit", "-f", "qcow2", Path(disk)).CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img commit %s into %s: %v: %s", Path(disk), disk, err, out)
	}
	return nil
}

// ForceCommit commits disk's overlay into disk whatever its verdict: an
// admin's explicit, confirmed decision (lv resolve-pit-overlay --commit
// --force-commit). The one check it keeps is the overlay's backing file
// name: an overlay of another file is never repointed at this one. The
// overlay is then removed. Still offline and without -U.
func ForceCommit(ctx context.Context, disk string) error {
	if _, err := os.Lstat(Path(disk)); err != nil {
		return err
	}
	if Bound(disk) {
		if err := MarkCommitting(disk); err != nil {
			return err
		}
	}
	stop := KeepCommitting(ctx, disk)
	err := commitInto(ctx, disk)
	stop()
	if err != nil {
		return err
	}
	return Remove(disk)
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
	// Never over an earlier orphan or its binding: a second set-aside within
	// the same stamp takes a further suffix.
	free := func(p string) bool {
		_, err := os.Lstat(p)
		return errors.Is(err, fs.ErrNotExist)
	}
	for i := 1; !free(to) || !free(to+".id"); i++ {
		to = fmt.Sprintf("%s.orphan-%s-%d", Path(disk), stamp, i)
	}
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
	Committed                // committed into the disk (or found merged) and removed
	Held                     // could not be verified: left as it is; the VM must not start
)

// Settle commits disk's overlay offline and removes it when it is owner's
// overlay of the disk as it is (an overlay already merged is only removed).
// Any other overlay is left untouched and reported Held (err wraps
// ErrNotOurs with the reason): the caller must not start or define the VM on
// the bare disk. For a caller about to define the disk from its record (so
// no definition names the overlay).
func Settle(ctx context.Context, disk string, owner Owner) (Outcome, error) {
	had, err := CommitOffline(ctx, disk, owner)
	switch {
	case !had:
		return None, nil
	case errors.Is(err, ErrNotOurs):
		return Held, err
	case err != nil:
		return None, err
	}
	return Committed, Remove(disk)
}

// Filesystem magics an overlay must not be placed on: a reboot loses them,
// and no failover target can see them. devtmpfs reports tmpfs's magic.
const (
	fsTmpfs = 0x01021994
	fsRamfs = 0x858458f6
)

// volatileOK lets an overlay sit on tmpfs. Tests only (AllowVolatileForTest):
// a suite whose temporary directory is a tmpfs.
var volatileOK bool

// AllowVolatileForTest lets overlays be placed on tmpfs, where a test
// suite's temporary directories may be. Call it from TestMain only.
func AllowVolatileForTest() { volatileOK = true }

// SetVolatileOKForTest sets it for one test and returns the restore.
func SetVolatileOKForTest(ok bool) (restore func()) {
	prev := volatileOK
	volatileOK = ok
	return func() { volatileOK = prev }
}

// Placement refuses a layer-2 overlay for disk where it would not survive:
// beside a disk that is not a regular file (a /dev block device, whose
// directory is devtmpfs) or in a directory on tmpfs or ramfs. A reboot loses
// such an overlay — the guest's newest writes with it — and a failover
// target never sees it. The overlay is not placed elsewhere instead: every
// settle finds it by its one name beside the disk.
func Placement(disk string) error {
	fi, err := os.Stat(disk)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (a block device?): its overlay would sit on devtmpfs, which a reboot or a failover loses", disk)
	}
	t, err := dirFSType(filepath.Dir(disk))
	if err != nil {
		return fmt.Errorf("the filesystem of %s: %w", filepath.Dir(disk), err)
	}
	if (t == fsTmpfs || t == fsRamfs) && !volatileOK {
		return fmt.Errorf("%s is on tmpfs or ramfs: an overlay there would not survive a reboot", filepath.Dir(disk))
	}
	return nil
}

// HoldAdvice is what an admin should do about an overlay with this
// assessment: never a blind "commit".
func HoldAdvice(vm, diskName string, a Assessment) string {
	cmd := fmt.Sprintf("lv resolve-pit-overlay %s %s", vm, diskName)
	switch a.Verdict {
	case Matches:
		return fmt.Sprintf("The disk is the file the overlay was taken of, unchanged: commit it (`%s --commit --confirm`).", cmd)
	case HalfWritten:
		return fmt.Sprintf("A commit into the disk was cut short, so the disk is partly written and only the commit makes it whole: commit it (`%s --commit --confirm`).", cmd)
	case Pivoted:
		return fmt.Sprintf("The overlay's writes are already in the disk: discard it (`%s --discard --confirm`); a second commit would overwrite newer writes.", cmd)
	}
	if a.Binding != nil && a.Binding.State == StateDiverged {
		return fmt.Sprintf("The VM ran on its disk without the overlay, so committing it now would write old blocks over newer ones. See the verdict with `%s` (no --confirm); normally the overlay is discarded (--discard, which asks for --accept-torn-disk if a commit had begun).", cmd)
	}
	if a.CommitBegan {
		return fmt.Sprintf("A commit into the disk had begun, so the disk may be partly written, and it cannot be shown to be the file that commit was writing. See the verdict with `%s` (no --confirm). If the disk cannot be trusted, restore it from a backup or a replica; otherwise decide with --force-commit or --discard --accept-torn-disk.", cmd)
	}
	return fmt.Sprintf("Its writes cannot be verified against the disk. See the verdict and what each action does with `%s` (no --confirm): discarding keeps the disk as it is and loses the overlay's writes; a commit is refused unless forced (--force-commit).", cmd)
}

// HoldDetail is the event, notification and inspect text of a VM held on an
// overlay with this assessment.
func HoldDetail(vm, diskName, disk string, a Assessment) string {
	return fmt.Sprintf("%s: the point-in-time overlay %s may hold %s's newest writes and cannot be verified against its disk %s (verdict %s: %s). The VM is held — not started on the bare disk — until an admin decides. %s",
		diskName, Path(disk), vm, disk, a.Verdict, a.Reason, HoldAdvice(vm, diskName, a))
}

// Consequences says what each admin action would do with this assessment,
// and whether it is refused without its override.
func (a Assessment) Consequences() (commit, discard string) {
	switch a.Verdict {
	case Matches:
		commit = "writes the overlay's blocks into the disk, which is the file it was taken of, unchanged: the window's writes are kept"
		discard = "deletes the overlay and the guest's writes in it; the disk stays as it was when the overlay was taken (consistent, but older)"
	case HalfWritten:
		commit = "finishes the commit that was cut short: the disk then holds every write, and is whole again"
		discard = "REFUSED without --accept-torn-disk: the disk is partly written, and without the overlay it stays inconsistent; restoring it from a backup or a replica is the alternative"
	case Pivoted:
		commit = "REFUSED without --force-commit: the overlay is already in the disk; committing it again writes its old blocks over everything the guest wrote since"
		discard = "removes the overlay, whose writes are already in the disk: nothing is lost"
	default:
		commit = "REFUSED without --force-commit: " + a.Reason + "; a commit could write stale blocks over newer data"
		if a.CommitBegan {
			discard = "REFUSED without --accept-torn-disk: a commit into the disk had begun, so without the overlay the disk may be inconsistent; restoring it from a backup or a replica is the alternative"
		} else {
			discard = "deletes the overlay and its writes; the disk is used as it is"
		}
	}
	return commit, discard
}

// SetDirFSTypeForTest makes Placement see every directory as filesystem
// magic t, and returns the restore.
func SetDirFSTypeForTest(t int64) (restore func()) {
	prev := dirFSType
	dirFSType = func(string) (int64, error) { return t, nil }
	return func() { dirFSType = prev }
}

// FSTmpfs is tmpfs's (and devtmpfs's) filesystem magic, for tests.
const FSTmpfs = fsTmpfs

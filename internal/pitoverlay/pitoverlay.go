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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cmdbound"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
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
func Present(disk string) bool { return presentWith(lstat, disk) }

func presentWith(lstat func(string) (os.FileInfo, error), disk string) bool {
	_, err := lstat(Path(disk))
	return err == nil
}

// PresentBounded is Present under storage.Bounded. A disk on a network
// filesystem whose server does not answer gets the *storage.FSNoAnswerError
// (storage.IsFSNoAnswer), never false: whether an overlay holding the guest's
// newest writes is there is then unknown, and a caller that took it as "no
// overlay" would start, copy or define the disk without them.
func PresentBounded(disk string) (bool, error) {
	stat := lstat // read here: the call below may outlive its caller
	return storage.Bounded("look for the point-in-time overlay", Path(disk), func() (bool, error) {
		return presentWith(stat, disk), nil
	})
}

// PresenceOfBounded is PresenceOf under storage.Bounded. A disk whose
// storage does not answer gets OverlayUnknown with the
// *storage.FSNoAnswerError (storage.IsFSNoAnswer); PresenceOf's own errors
// are never that.
func PresenceOfBounded(disk string) (Presence, error) {
	stat := lstat
	type presence struct {
		p   Presence
		err error
	}
	got, err := storage.Bounded("look for the point-in-time overlay and its binding", Path(disk), func() (presence, error) {
		p, err := presenceOfWith(stat, disk)
		return presence{p, err}, nil
	})
	if err != nil {
		return OverlayUnknown, err
	}
	return got.p, got.err
}

// Presence is what this host can say about a disk's overlay: there, gone,
// or neither established.
type Presence int

const (
	// OverlayAbsent: the overlay and its binding both do not exist (ENOENT).
	OverlayAbsent Presence = iota
	// OverlayPresent: something is at the overlay's path.
	OverlayPresent
	// OverlayUnknown: neither can be established — a stat error other than
	// ENOENT (EIO, ESTALE, EACCES, …), or a binding with no overlay beside it.
	OverlayUnknown
)

// lstat is os.Lstat; a test makes it fail.
var lstat = os.Lstat

// SetLstatForTest makes Present and PresenceOf stat with f, and returns the
// restore.
func SetLstatForTest(f func(string) (os.FileInfo, error)) (restore func()) {
	prev := lstat
	lstat = f
	return func() { lstat = prev }
}

// PresenceOf says whether disk's overlay is there. Unlike Present, an error
// is never read as absence. Present keeps its meaning for its callers.
func PresenceOf(disk string) (Presence, error) { return presenceOfWith(lstat, disk) }

func presenceOfWith(lstat func(string) (os.FileInfo, error), disk string) (Presence, error) {
	_, err := lstat(Path(disk))
	switch {
	case err == nil:
		return OverlayPresent, nil
	case !errors.Is(err, fs.ErrNotExist):
		return OverlayUnknown, err
	}
	_, err = lstat(SidecarPath(disk))
	switch {
	case err == nil:
		return OverlayUnknown, fmt.Errorf("%s: %w", SidecarPath(disk), ErrLoneBinding)
	case !errors.Is(err, fs.ErrNotExist):
		return OverlayUnknown, err
	}
	return OverlayAbsent, nil
}

// ErrLoneBinding is PresenceOf's reason for a binding with no overlay beside
// it (a crash inside Remove): unknown, but not a fault worth a warning.
var ErrLoneBinding = errors.New("a binding with no overlay beside it")

// SetAsideEvidence reports whether the overlay of disk's CURRENT window was
// set aside beside it: an <overlay>.orphan-<stamp> file (SetAside), not its
// binding alone, bound to the window the disk carries now.
//
//   - The disk carries no window token: no window has opened on this file
//     since it was placed (a restore writes a new file), so any orphan of it
//     is evidence.
//   - The disk carries a token: only an orphan whose binding recorded that
//     very token is. An older window's orphan says nothing about the overlay
//     a later window made (re-review 1 of the pit-restore branch, I-1).
//   - The token cannot be read (no user xattrs here, or any other error):
//     windows cannot be told apart, and nothing counts.
func SetAsideEvidence(disk string) bool { return setAsideEvidenceWith(glob, disk, "") }

// SetAsideEvidenceFor is SetAsideEvidence for the VM of uuid vmUUID: an
// orphan whose binding records ANOTHER VM's uuid (an earlier VM of the name,
// whose disk sat at the same path) is never evidence for it. An empty
// vmUUID, or a binding that records none, is judged as SetAsideEvidence does.
func SetAsideEvidenceFor(disk, vmUUID string) bool { return setAsideEvidenceWith(glob, disk, vmUUID) }

// SetAsideEvidenceBoundedFor is SetAsideEvidenceFor under storage.Bounded: a
// disk on a network filesystem whose server does not answer gets the
// *storage.FSNoAnswerError (storage.IsFSNoAnswer), never false. The look
// lists the disk's directory, which a hard NFS mount answers only from its
// server, even where a stat of the disk is answered from the attribute cache.
func SetAsideEvidenceBoundedFor(disk, vmUUID string) (bool, error) {
	g := glob // read here: the call below may outlive its caller
	// The uuid is in the op: the bound merges concurrent calls on one op and
	// path, and the answer depends on the VM asked for.
	return storage.Bounded("look for set-aside point-in-time overlays (for vm uuid "+vmUUID+") of", disk, func() (bool, error) {
		return setAsideEvidenceWith(g, disk, vmUUID), nil
	})
}

// glob is filepath.Glob; a test makes it block.
var glob = filepath.Glob

// SetGlobForTest makes SetAsideEvidence list with f, and returns the restore.
func SetGlobForTest(f func(string) ([]string, error)) (restore func()) {
	prev := glob
	glob = f
	return func() { glob = prev }
}

func setAsideEvidenceWith(glob func(string) ([]string, error), disk, vmUUID string) bool {
	orphans, err := orphansWith(glob, disk)
	if err != nil || len(orphans) == 0 {
		return false
	}
	for _, o := range orphans {
		if orphanIsEvidence(disk, o, vmUUID) {
			return true
		}
	}
	return false
}

// Orphans returns the overlays of disk set aside beside it (SetAside), as
// paths, without their bindings.
func Orphans(disk string) ([]string, error) { return orphansWith(glob, disk) }

// OrphansBounded is Orphans under storage.Bounded: a disk whose storage does
// not answer gets the *storage.FSNoAnswerError.
func OrphansBounded(disk string) ([]string, error) {
	g := glob // read here: the call below may outlive its caller
	return storage.Bounded("look for set-aside point-in-time overlays of", disk, func() ([]string, error) {
		return orphansWith(g, disk)
	})
}

func orphansWith(glob func(string) ([]string, error), disk string) ([]string, error) {
	m, err := glob(Path(disk) + ".orphan-*")
	if err != nil {
		return nil, err
	}
	var orphans []string
	prefix := filepath.Base(Path(disk)) + ".orphan-"
	for _, p := range m {
		if stamp, ok := strings.CutPrefix(filepath.Base(p), prefix); ok && orphanStampRE.MatchString(stamp) {
			orphans = append(orphans, p)
		}
	}
	return orphans, nil
}

// orphanStampRE is the stamp SetAside ends an orphan's name with: the time,
// and a further -N when that name was taken.
var orphanStampRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}(-[0-9]+)?$`)

// orphanNameRE is SetAside's whole name shape: ".<disk file>.lv-pit.orphan-"
// and the stamp at the very end. A name that only contains the marker (a VM
// or disk named "w.lv-pit.orphan-1" has a live overlay ending ".lv-pit") is
// not an orphan.
var orphanNameRE = regexp.MustCompile(`^\.(.+)` + regexp.QuoteMeta(Suffix+".orphan-") + `([0-9]{8}-[0-9]{6}(?:-[0-9]+)?)$`)

// otherVM reports whether binding data records a VM uuid other than vmUUID.
func otherVM(data []byte, vmUUID string) bool {
	var b Binding
	return vmUUID != "" && json.Unmarshal(data, &b) == nil && b.VMUUID != "" && b.VMUUID != vmUUID
}

// orphanIsEvidence is SetAsideEvidence's per-orphan rule, read in its
// favour: anything that cannot be read is no evidence.
func orphanIsEvidence(disk, orphan, vmUUID string) bool {
	data, berr := os.ReadFile(orphan + ".id")
	if berr == nil && otherVM(data, vmUUID) {
		return false
	}
	tok, err := getXattr(disk)
	switch {
	case errors.Is(err, errNoAttr):
		return true
	case err != nil || len(tok) == 0:
		return false
	}
	if berr != nil {
		return false
	}
	var b Binding
	return json.Unmarshal(data, &b) == nil && b.Token != "" && b.Token == string(tok)
}

// OrphanInUse says why the set-aside overlay orphan of disk, beside the disk
// of the VM of uuid vmUUID, may not be removed as evidence; "" when it is not
// evidence. It is SetAsideEvidenceFor's rule read the other way: removal
// needs a positive answer, so a binding or a window token that cannot be read
// (anything but "no such file", "no such attribute" or "no user xattrs
// here") keeps it.
func OrphanInUse(disk, orphan, vmUUID string) string {
	data, berr := os.ReadFile(orphan + ".id")
	switch {
	case berr == nil:
		var b Binding
		if err := json.Unmarshal(data, &b); err != nil {
			return "its binding cannot be read: " + err.Error()
		}
		if otherVM(data, vmUUID) {
			return "" // an earlier VM's: no window of this disk
		}
	case !errors.Is(berr, fs.ErrNotExist):
		return "its binding cannot be read: " + berr.Error()
	}
	const evidence = "it is the set-aside evidence of the disk's current point-in-time window"
	tok, err := getXattr(disk)
	switch {
	case errors.Is(err, errNoAttr):
		return evidence // a disk with no window token: every orphan counts
	case xattrUnsupported(err):
		return "" // no user xattrs here: nothing counts
	case err != nil:
		return "the disk's window token cannot be read: " + err.Error()
	case len(tok) == 0:
		return evidence
	}
	if berr != nil {
		return "" // no binding: no token to match
	}
	var b Binding
	_ = json.Unmarshal(data, &b)
	if b.Token != "" && b.Token == string(tok) {
		return evidence
	}
	return ""
}

// IsOrphanName reports whether name is exactly the shape SetAside names an
// overlay it set aside, ".<disk file>.lv-pit.orphan-<stamp>" with the stamp
// YYYYMMDD-HHMMSS (or -N after it) at the end: never a live overlay, a
// binding, or a disk. base is the disk file's name.
func IsOrphanName(name string) (base string, ok bool) {
	if strings.ContainsAny(name, "/\x00") {
		return "", false
	}
	m := orphanNameRE.FindStringSubmatch(name)
	if m == nil || m[1] == "" {
		return "", false
	}
	return m[1], true
}

// DiskOfOrphan is the disk file an orphan was set aside beside.
func DiskOfOrphan(orphan string) (string, bool) {
	base, ok := IsOrphanName(filepath.Base(orphan))
	if !ok {
		return "", false
	}
	return filepath.Join(filepath.Dir(orphan), base), true
}

// OrphanOwner is the owner the orphan's binding records.
func OrphanOwner(orphan string) (Owner, error) {
	data, err := os.ReadFile(orphan + ".id")
	if err != nil {
		return Owner{}, err
	}
	var b Binding
	if err := json.Unmarshal(data, &b); err != nil {
		return Owner{}, err
	}
	return b.Owner, nil
}

// OrphanPath is disk's set-aside overlay of base name name, or an error when
// name is not one SetAside makes for disk.
func OrphanPath(disk, name string) (string, error) {
	prefix := filepath.Base(Path(disk)) + ".orphan-"
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || !orphanStampRE.MatchString(rest) {
		return "", fmt.Errorf("%q is not a set-aside overlay of %s", name, disk)
	}
	return filepath.Join(filepath.Dir(disk), name), nil
}

// RemoveOrphan removes disk's set-aside overlay orphan and its binding: the
// binding first, so a failure leaves an overlay with no binding, which is no
// evidence of anything.
func RemoveOrphan(orphan string) error {
	for _, p := range []string{orphan + ".id", orphan} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Command builds the qemu-img process. A variable so a test can see the
// argv or fail it.
var Command = cmdbound.Command

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
	// Format is the binding's format (bindingFormat).
	Format int `json:"format,omitempty"`
	// EndMtimeNs and EndSize are the base as a commit attempt left it.
	EndMtimeNs int64 `json:"end_mtime_ns,omitempty"`
	EndSize    int64 `json:"end_size,omitempty"`
}

// RefreshEvery is how often a running commit rewrites its binding (the
// keep-alive). The sidecar's own modification time — the filesystem's clock,
// the same clock as the disk's — is then the last moment the daemon vouched
// for the commit.
var RefreshEvery = 10 * time.Minute

// CommitMargin is the slack on that keep-alive bound: a commit that died
// without recording its end may have written the disk at most RefreshEvery
// plus this after its binding was last written. A disk written later than
// that was written by something else, and the overlay is not committed over
// it.
var CommitMargin = 2 * time.Minute

// bindingFormat is the sidecar format this build writes and understands. A
// binding of a later format (a newer build's, met after a rollback) is never
// settled by this one.
const bindingFormat = 1

// Gate says whether this host holds the pit_overlay release feature
// (capabilities.FeaturePITOverlay), and why not: the cluster-wide promise that
// every host serving these pools understands overlays. It is the host's own,
// local read of its release-token latch (grpcapi.Server.PITOverlayFeature);
// a nil Gate is closed. Below it this build makes no overlay (layer 2 is
// skipped: a new window needs a FeatureGrant, OpenWindow) and settles none it
// finds automatically (Settle, and grpcapi's heal): an overlay present then was
// made by a host above it, and the VM is held rather than started on its
// disk. An admin's explicit lv resolve-pit-overlay still sees the full
// verdict and may act on it.
type Gate func() (open bool, why string)

// Open reports whether g is open; a nil Gate is closed.
func (g Gate) Open() (bool, string) {
	if g == nil {
		return false, "this host has no release-feature gate for pit_overlay"
	}
	return g()
}

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
// it back: the first write of a new window, so of the pit_overlay feature's
// data, and it takes the feature's grant (capabilities.FeaturePITOverlay,
// from grpcapi.Server.WithReleaseFeature). Call it BEFORE the snapshot opens
// the window. A filesystem without user xattrs gives a Window with NoXattr;
// any other failure is an error, and no window may be opened.
func OpenWindow(g capabilities.FeatureGrant, disk string) (Window, error) {
	if err := g.Check(capabilities.FeaturePITOverlay); err != nil {
		return Window{}, err
	}
	return writeWindowToken(disk)
}

// writeWindowToken is OpenWindow's write, for a new window and for a rebind
// of an overlay that already exists (Bind).
func writeWindowToken(disk string) (Window, error) {
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
		State: StateWindow, Token: w.Token, NoXattr: w.NoXattr, Format: bindingFormat})
}

// Bind opens a new window token on disk and binds its overlay to it: for an
// overlay found unbound while the domain runs on it (the base is frozen). It
// opens no window — the overlay already exists — so it takes no grant.
func Bind(disk string, owner Owner) error {
	w, err := writeWindowToken(disk)
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
	if b.Format > bindingFormat {
		return fmt.Errorf("its binding was written by a newer build (format %d); this build does not rewrite it", b.Format)
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
		b.EndMtimeNs, b.EndSize = 0, 0 // this attempt has not ended
		return nil
	})
}

// RecordAttemptEnd records, durably, the disk as a commit attempt left it —
// failed or not — in the filesystem's own clock. After a failed attempt
// nothing writes the disk (the VM runs on the overlay, the job is gone), so
// a disk that is not exactly that later was written by something else: a
// restore over it in place, say, which keeps its inode and token.
func RecordAttemptEnd(disk string) error {
	_, _, size, mt, err := identity(disk)
	if err != nil {
		return err
	}
	return update(disk, func(b *Binding) error {
		if b.State != StateCommitting {
			return nil
		}
		b.EndMtimeNs, b.EndSize = mt, size
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

// MarkCommitted records that a recorded live pivot landed: the overlay is in
// the base, and removing it is all that is left — committing it again would
// write its old blocks over the guest's newer ones. Only from pivoting (a
// binding already committed is left as it is): it is the one record that
// leads to an automatic removal.
func MarkCommitted(disk string) error { return markCommitted(disk, StatePivoting) }

// markCommittedOffline records an offline commit that finished.
func markCommittedOffline(disk string) error { return markCommitted(disk, StateCommitting) }

func markCommitted(disk, from string) error {
	fi, err := os.Stat(Path(disk))
	if err != nil {
		return err
	}
	return update(disk, func(b *Binding) error {
		switch b.State {
		case StateCommitted:
			return nil
		case from:
		default:
			return fmt.Errorf("a commit recorded from state %q (want %q)", b.State, from)
		}
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
// runs, so a commit that runs past the keep-alive bound keeps its own base
// writes within it. stop ends it and waits.
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
	// PivotUncertain: a pivot was under way and, with the VM off, whether it
	// landed is told only by the two files' times (HoldAdvice).
	PivotUncertain bool
	// BelowFeature: this host does not hold the pit_overlay release feature
	// (Gate), so it settles nothing automatically; the verdict is still the
	// full one, for the admin (BelowWhy says why the gate is closed).
	BelowFeature bool
	BelowWhy     string
	// DiskMtimeNs and OverlayMtimeNs are both files' modification times now
	// (one clock: the filesystem's), and OverlayCurrent says so in words.
	DiskMtimeNs    int64
	OverlayMtimeNs int64
	OverlayCurrent string
}

func (a *Assessment) unknown(format string, args ...any) Assessment {
	a.Verdict = Unknown
	a.Reason = fmt.Sprintf(format, args...)
	return *a
}

// AssessAt is Assess on a host whose pit_overlay gate is g: the same verdict,
// marked BelowFeature when g is closed, so the hold's advice says why nothing
// was settled automatically.
func AssessAt(g Gate, disk string, owner Owner, liveOnDisk bool) Assessment {
	a := Assess(disk, owner, liveOnDisk)
	if open, why := g.Open(); !open {
		a.BelowFeature, a.BelowWhy = true, why
	}
	return a
}

// AssessBounded is Assess under storage.Bounded: a disk on a network
// filesystem whose server does not answer gets the *storage.FSNoAnswerError
// (storage.IsFSNoAnswer), never a verdict. Assess stats the overlay and the
// disk, reads the binding and the disk's window token, and opens the
// overlay's header, any of which only the server may answer.
func AssessBounded(disk string, owner Owner, liveOnDisk bool) (Assessment, error) {
	assess := assessFn // read here: the call below may outlive its caller
	// The owner and the flag are in the op: the bound merges concurrent calls
	// on one op and path, and the verdict depends on both.
	op := fmt.Sprintf("assess (for %s/%s uuid %s, running on the disk %t) the point-in-time overlay of", owner.VM, owner.Disk, owner.VMUUID, liveOnDisk)
	return storage.Bounded(op, disk, func() (Assessment, error) {
		return assess(disk, owner, liveOnDisk), nil
	})
}

// AssessAtBounded is AssessAt under storage.Bounded (AssessBounded).
func AssessAtBounded(g Gate, disk string, owner Owner, liveOnDisk bool) (Assessment, error) {
	a, err := AssessBounded(disk, owner, liveOnDisk)
	if err != nil {
		return a, err
	}
	if open, why := g.Open(); !open {
		a.BelowFeature, a.BelowWhy = true, why
	}
	return a, nil
}

// assessFn is Assess; a test makes it block.
var assessFn = Assess

// SetAssessForTest makes AssessBounded assess with f, and returns the restore.
func SetAssessForTest(f func(disk string, owner Owner, liveOnDisk bool) Assessment) (restore func()) {
	prev := assessFn
	assessFn = f
	return func() { assessFn = prev }
}

// Assess judges disk's overlay against owner and the disk file as it is now,
// whatever this host's pit_overlay gate says (AssessAt marks that): an admin
// deciding a hold needs the verdict on every host. liveOnDisk says the caller
// saw the domain RUNNING on the disk itself, not on the overlay: a pivot
// recorded as under way then landed.
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
	a.OverlayMtimeNs = fi.ModTime().UnixNano()
	a.OverlayCurrent = fmt.Sprintf("%d bytes, modified %s", fi.Size(), time.Unix(0, a.OverlayMtimeNs).UTC().Format(time.RFC3339Nano))
	b, err := readBinding(disk)
	if err != nil {
		return a.unknown("no readable binding (%v)", err)
	}
	a.Binding = &b
	a.CommitBegan = b.CommitStartedNs != 0 || b.State == StateCommitting || b.State == StatePivoting || b.State == StateCommitted
	if b.Format > bindingFormat {
		return a.unknown("its binding was written by a newer build (format %d; this build knows %d)", b.Format, bindingFormat)
	}
	if b.VM != owner.VM || b.Disk != owner.Disk || (b.VMUUID != "" && owner.VMUUID != "" && b.VMUUID != owner.VMUUID) {
		return a.unknown("it was taken of vm %q disk %q, not vm %q disk %q", b.VM, b.Disk, owner.VM, owner.Disk)
	}
	_, ino, size, mt, err := identity(disk)
	if err != nil {
		return a.unknown("its disk: %v", err)
	}
	a.DiskMtimeNs = mt
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
	if !backingIsDisk(info.BackingFile, disk) {
		return a.unknown("its backing file is %q, not this disk", info.BackingFile)
	}
	notSmaller := func() bool { return size >= b.Size && mt >= b.MtimeNs }
	// The last time the daemon vouched for a commit: the sidecar's own
	// modification time, in the filesystem's clock (keepAliveBound).
	sfi, err := os.Stat(SidecarPath(disk))
	if err != nil {
		return a.unknown("its binding: %v", err)
	}
	keepAliveBound := sfi.ModTime().UnixNano() + int64(RefreshEvery+CommitMargin)
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
		if b.EndMtimeNs != 0 {
			// The last attempt ended and recorded the disk as it left it;
			// nothing writes it after a failed attempt.
			if mt != b.EndMtimeNs || size != b.EndSize {
				return a.unknown("the disk was written after the last attempt to commit into it ended, so it is not the disk that attempt left (restored or overwritten in place?)")
			}
		} else if mt > keepAliveBound {
			return a.unknown("the disk was written long after the daemon last recorded its commit into it, by something else")
		}
		a.Verdict = HalfWritten
	case StatePivoting:
		if !notSmaller() {
			return a.unknown("%s", older)
		}
		if !liveOnDisk {
			a.PivotUncertain = true
			return a.unknown("a pivot onto the disk was under way when the daemon stopped, and with the VM off it cannot be told for certain whether it landed")
		}
		if mt > keepAliveBound {
			return a.unknown("the disk was written long after the pivot was recorded, so the VM on it may have been started there by something else")
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
		if eerr := RecordAttemptEnd(disk); eerr != nil {
			return true, fmt.Errorf("%v; and record its end: %v", err, eerr)
		}
		return true, err
	}
	if err := markCommittedOffline(disk); err != nil {
		return true, fmt.Errorf("record %s committed: %w", Path(disk), err)
	}
	return true, nil
}

// backingIsDisk reports whether an overlay's backing file is disk. Its name
// must be the disk's; and when the path it names exists on this host it must
// be the disk itself, not a file of the same name elsewhere. A path that does
// not exist here is another host's mount point for the pool, and the file of
// that name beside the overlay is its base.
func backingIsDisk(backing, disk string) bool {
	if filepath.Base(backing) != filepath.Base(disk) {
		return false
	}
	p := backing
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(disk), p)
	}
	if p == disk {
		return true
	}
	bfi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	dfi, err := os.Stat(disk)
	return err == nil && os.SameFile(bfi, dfi)
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
	if !backingIsDisk(info.BackingFile, disk) {
		return fmt.Errorf("%s: %w (its backing file is %q, not this disk; it is never repointed at another file)", Path(disk), ErrNotOurs, info.BackingFile)
	}
	if info.BackingFile != disk && filepath.Join(filepath.Dir(disk), info.BackingFile) != disk {
		if out, err := cmdbound.CombinedOutput(ctx, Command(ctx, "qemu-img", "rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b", disk, Path(disk))); err != nil {
			return fmt.Errorf("point %s at %s: %v: %s", Path(disk), disk, err, out)
		}
	}
	if out, err := cmdbound.CombinedOutput(ctx, Command(ctx, "qemu-img", "commit", "-f", "qcow2", Path(disk))); err != nil {
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
		// As every failed attempt does: the disk as it left it, so a later
		// assessment does not take an overwrite within the keep-alive bound
		// for this attempt's half-written disk.
		if Bound(disk) {
			if eerr := RecordAttemptEnd(disk); eerr != nil {
				return fmt.Errorf("%v; and record its end: %v", err, eerr)
			}
		}
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

// PutBack undoes SetAside: the overlay set aside as to (and its binding) is
// renamed back to disk's overlay, never over one that is there now.
//
// A binding that never moved (SetAside renamed the overlay and then failed on
// its binding) is left where it is.
func PutBack(disk, to string) error {
	if _, err := os.Lstat(Path(disk)); err == nil {
		return fmt.Errorf("%s exists: %s stays set aside", Path(disk), to)
	}
	_, aerr := os.Lstat(to + ".id")
	bindingAside := aerr == nil
	if bindingAside {
		if _, err := os.Lstat(SidecarPath(disk)); err == nil {
			return fmt.Errorf("%s exists: %s stays set aside", SidecarPath(disk), to)
		}
	}
	if err := os.Rename(to, Path(disk)); err != nil {
		return err
	}
	if bindingAside {
		return os.Rename(to+".id", SidecarPath(disk))
	}
	return nil
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
//
// Below the pit_overlay feature (g closed) nothing is committed or removed:
// an overlay present is Held, whatever its verdict.
func Settle(ctx context.Context, g Gate, disk string, owner Owner) (Outcome, error) {
	if _, err := os.Lstat(Path(disk)); errors.Is(err, fs.ErrNotExist) {
		return None, nil
	}
	if open, why := g.Open(); !open {
		return Held, fmt.Errorf("%s: %w (%s; this host settles no overlay)", Path(disk), ErrNotOurs, why)
	}
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
	if a.BelowFeature {
		// The full verdict's advice, after why nothing was settled
		// automatically (P3 of the #256 re-review 5).
		b := a
		b.BelowFeature = false
		return fmt.Sprintf("This host settles no overlay by itself (%s): that waits for the release token to latch on every host (`lv cluster upgrade-status`). To decide now: %s", a.BelowWhy, HoldAdvice(vm, diskName, b))
	}
	switch a.Verdict {
	case Matches:
		return fmt.Sprintf("The disk is the file the overlay was taken of, unchanged: commit it (`%s --commit --confirm`).", cmd)
	case HalfWritten:
		return fmt.Sprintf("A commit into the disk was cut short, so the disk is partly written and only the commit makes it whole: commit it (`%s --commit --confirm`).", cmd)
	case Pivoted:
		return fmt.Sprintf("The overlay's writes are already in the disk: discard it (`%s --discard --confirm`); a second commit would overwrite newer writes.", cmd)
	}
	if a.PivotUncertain {
		if a.DiskMtimeNs > a.OverlayMtimeNs {
			return fmt.Sprintf("The disk was written after the overlay last was, so the pivot most likely landed and the overlay is already in the disk: discard it (`%s --discard --accept-torn-disk --confirm`).", cmd)
		}
		return fmt.Sprintf("The overlay was written after the disk last was, so the pivot most likely did not land and the overlay holds the newest writes: commit it (`%s --commit --force-commit --confirm`).", cmd)
	}
	if a.Binding != nil && a.Binding.State == StateDiverged {
		return fmt.Sprintf("The VM ran on its disk without the overlay, so committing it now would write old blocks over newer ones. See the verdict with `%s` (no --confirm); normally the overlay is discarded (--discard, which asks for --accept-torn-disk if a commit had begun).", cmd)
	}
	if a.CommitBegan {
		return fmt.Sprintf("A commit into the disk had begun, so the disk may be partly written, and it cannot be shown to be the file that commit was writing. See the verdict with `%s` (no --confirm). If the disk cannot be trusted, discard the overlay first (`%s --discard --accept-torn-disk --confirm`) and only then put back a backup or replica of the disk — or let `lv backup restore-from --repo <repo> --vm %s --disk %s --timestamp <timestamp> --in-place` do both (the backup's timestamp from `lv backup repo ls <repo>`): it sets the overlay aside, kept, before it writes the disk. Otherwise decide with --force-commit.", cmd, cmd, vm, diskName)
	}
	return fmt.Sprintf("Its writes cannot be verified against the disk. See the verdict and what each action does with `%s` (no --confirm): discarding keeps the disk as it is and loses the overlay's writes; a commit is refused unless forced (--force-commit).", cmd)
}

// HoldDetail is the event, notification and inspect text of a VM held on an
// overlay with this assessment.
func HoldDetail(vm, diskName, disk string, a Assessment) string {
	why := fmt.Sprintf("cannot be verified against its disk %s (verdict %s: %s)", disk, a.Verdict, a.Reason)
	if a.BelowFeature && a.Verdict != Unknown {
		why = fmt.Sprintf("is not settled automatically on this host, which does not hold the pit_overlay release feature (verdict %s against its disk %s)", a.Verdict, disk)
	}
	return fmt.Sprintf("%s: the point-in-time overlay %s may hold %s's newest writes and %s. The VM is held — not started on the bare disk — until an admin decides. %s",
		diskName, Path(disk), vm, why, HoldAdvice(vm, diskName, a))
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
		discard = "REFUSED without --accept-torn-disk: the disk is partly written, and without the overlay it stays inconsistent. To start over from a backup or a replica instead, discard first (--discard --accept-torn-disk) and then restore the disk, or use `lv backup restore-from --repo <repo> --vm <vm> --disk <disk> --timestamp <timestamp> --in-place`, which sets the overlay aside before it writes"
	case Pivoted:
		commit = "REFUSED, even with --force-commit (only --overwrite-newer-writes overrides it): the overlay is already in the disk; committing it again writes its old blocks over everything the guest wrote since"
		discard = "removes the overlay, whose writes are already in the disk: nothing is lost"
	default:
		commit = "REFUSED without --force-commit: " + a.Reason + "; a commit could write stale blocks over newer data"
		if a.CommitBegan {
			discard = "REFUSED without --accept-torn-disk: a commit into the disk had begun, so without the overlay the disk may be inconsistent. To start over from a backup or a replica instead, discard first (--discard --accept-torn-disk) and then restore the disk, or use `lv backup restore-from --repo <repo> --vm <vm> --disk <disk> --timestamp <timestamp> --in-place`, which sets the overlay aside before it writes"
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

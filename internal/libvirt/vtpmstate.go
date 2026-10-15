package libvirt

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/safename"
)

// Firmware-state travel (G1). A VM's portable firmware state is its name-keyed
// UEFI vars file (FirmwareStore.NvramPath) plus its UUID-keyed swtpm tree
// (FirmwareStore.SwtpmDir). The store's methods bundle / restore / wipe that
// state as ONE unit so backup, migration, and snapshot carry it identically —
// vtpmstate.go is the single owner; no lifecycle handler hand-rolls
// firmware-state copy/wipe.

// DefaultSwtpmBase is libvirt's swtpm state root on a real host, the
// AppArmor-permitted location libvirt keys by domain UUID.
const DefaultSwtpmBase = "/var/lib/libvirt/swtpm"

const (
	fwBundleNvram = "nvram"  // tar entry: the UEFI vars file
	fwBundleSwtpm = "swtpm/" // tar entry prefix: the swtpm state tree
)

// FirmwareStore is one host's firmware state: the name-keyed UEFI vars files
// under DataDir and the UUID-keyed swtpm trees under SwtpmBase. A daemon has
// exactly one, shared by everything on the host that reads or writes that
// state. It is a value of its own, not package state, so the fleet harness can
// run several hosts in one process, each with roots of its own.
type FirmwareStore struct {
	DataDir   string // the daemon's data directory; NVRAM lives in DataDir/nvram
	SwtpmBase string // libvirt's swtpm root; DefaultSwtpmBase on a real host

	// guard is the firmware move guard (spec §5.1): every write and wipe of
	// the state asks it first. Installed by fwmig.Wire; none = allow.
	guard atomic.Pointer[FirmwareMoveGuard]

	// refused holds the best-effort wipes a record that cannot be read
	// refused, until TakeRefusedWipes collects them to report: a wipe that
	// silently did nothing would leak the state.
	refusedMu sync.Mutex
	refused   []RefusedWipe
}

// RefusedWipe is a best-effort wipe the firmware move guard refused because a
// record could not be read: the state it was to remove is still on disk.
type RefusedWipe struct {
	VM, UUID string
	At       time.Time
	Err      error
}

// maxRefusedWipes bounds what the store keeps between two collections.
const maxRefusedWipes = 64

// TakeRefusedWipes returns, and forgets, the wipes refused for an unreadable
// record since the last call (the oldest dropped past maxRefusedWipes).
func (f *FirmwareStore) TakeRefusedWipes() []RefusedWipe {
	f.refusedMu.Lock()
	defer f.refusedMu.Unlock()
	out := f.refused
	f.refused = nil
	return out
}

// SetFirmwareMoveGuard installs the firmware move guard every state write
// and wipe of this store asks (fwmig.Wire).
func (f *FirmwareStore) SetFirmwareMoveGuard(g FirmwareMoveGuard) { f.guard.Store(&g) }

func (f *FirmwareStore) moveGuard() FirmwareMoveGuard {
	if g := f.guard.Load(); g != nil {
		return *g
	}
	return FirmwareMoveGuard{}
}

// NewFirmwareStore is the store of a host whose daemon keeps its data in
// dataDir, with libvirt's own swtpm root. Production layout.
func NewFirmwareStore(dataDir string) *FirmwareStore {
	return &FirmwareStore{DataDir: dataDir, SwtpmBase: DefaultSwtpmBase}
}

// NvramPath is the VM's UEFI vars file in this store: NvramPath(DataDir, vm),
// the path the rendered domain names.
func (f *FirmwareStore) NvramPath(vmName string) string {
	return NvramPath(f.DataDir, vmName)
}

// HasNvram reports whether the per-VM (name-keyed) UEFI vars file exists.
func (f *FirmwareStore) HasNvram(vmName string) bool {
	fi, err := os.Stat(f.NvramPath(vmName))
	return err == nil && fi.Size() > 0
}

// RemoveNvram removes the VM's UEFI vars file. The error is os.Remove's, or
// the firmware move guard's refusal (OpWriteState).
func (f *FirmwareStore) RemoveNvram(vmName string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWriteState, Name: vmName}); err != nil {
		return fmt.Errorf("remove nvram of %s: %w", vmName, err)
	}
	return os.Remove(f.NvramPath(vmName))
}

// RenameNvram moves the UEFI vars file of from to the name to. The error is
// os.Rename's, or the firmware move guard's refusal (OpWriteState) for
// either name.
func (f *FirmwareStore) RenameNvram(from, to string) error {
	for _, n := range []string{from, to} {
		if err := f.moveGuard().check(FirmwareCall{Op: OpWriteState, Name: n}); err != nil {
			return fmt.Errorf("rename nvram %s to %s: %w", from, to, err)
		}
	}
	return os.Rename(f.NvramPath(from), f.NvramPath(to))
}

// firmwareUUIDRe is the canonical 8-4-4-4-12 form libvirt prints and
// uuid.NewString mints.
var firmwareUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidFirmwareUUID reports whether uuid is a canonical domain UUID — the
// strict check for a UUID that arrives over an RPC before it keys any path.
func ValidFirmwareUUID(uuid string) bool { return firmwareUUIDRe.MatchString(uuid) }

// SwtpmDir is the store's per-domain swtpm state directory, keyed by the
// (stable) domain UUID.
//
// It is a plain path builder: anything that reads, writes or removes the tree
// goes through swtpmDir, which refuses a key that is not exactly one path
// component below the base.
func (f *FirmwareStore) SwtpmDir(uuid string) string {
	return filepath.Join(f.SwtpmBase, uuid)
}

// swtpmDir is SwtpmDir for a key that is confined to one directory under the
// base: "", ".", "..", and anything holding a separator are refused, so a UUID
// that arrived over an RPC can never name the base itself, its parent, or any
// path outside it. A store with no base refuses every key.
func (f *FirmwareStore) swtpmDir(uuid string) (string, bool) {
	if f.SwtpmBase == "" || safename.ValidateName(uuid) != nil {
		return "", false
	}
	return f.SwtpmDir(uuid), true
}

// SnapshotFirmwareBundlePath is the sidecar tar holding a snapshot's captured
// firmware state. Derived from (dataDir, vm, snap) — no DB column; nested
// <vm>/<snap> avoids flat-name collisions (G1). filepath.Base on both components
// is defense-in-depth against an unvalidated name escaping dataDir/snapfw
// (callers must still validate names — this just guarantees containment).
func SnapshotFirmwareBundlePath(dataDir, vmName, snapName string) string {
	return filepath.Join(dataDir, "snapfw", filepath.Base(vmName), filepath.Base(snapName)+".tar")
}

// SafeSnapshotFirmwareBundlePath is SnapshotFirmwareBundlePath with the names
// validated up front (the filepath.Base in the raw builder is containment-only;
// this rejects a bad name outright so callers fail loudly).
func SafeSnapshotFirmwareBundlePath(dataDir, vmName, snapName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateSnapshotName(snapName); err != nil {
		return "", err
	}
	return SnapshotFirmwareBundlePath(dataDir, vmName, snapName), nil
}

// HasTPMState reports whether the (UUID-keyed) swtpm state exists.
func (f *FirmwareStore) HasTPMState(uuid string) bool {
	dir, ok := f.swtpmDir(uuid)
	if !ok {
		return false
	}
	ents, err := os.ReadDir(dir)
	return err == nil && len(ents) > 0
}

// PermallSHA256 is the hex sha256 of the VM's TPM permanent state,
// <swtpm>/<uuid>/tpm2/tpm2-00.permall, and of nothing else in the tree: the
// .lock and any volatile state are not part of what a live firmware move
// compares. A missing file is os.ErrNotExist; a key that is not one component
// under the swtpm base is refused without a read.
func (f *FirmwareStore) PermallSHA256(uuid string) (string, error) {
	dir, ok := f.swtpmDir(uuid)
	if !ok {
		return "", fmt.Errorf("permall hash: invalid swtpm uuid %q", uuid)
	}
	return sha256RegularFile(filepath.Join(dir, "tpm2", "tpm2-00.permall"))
}

// NvramSHA256 is the hex sha256 of the VM's UEFI vars file in this store. A
// missing file is os.ErrNotExist; an invalid VM name is refused without a read.
func (f *FirmwareStore) NvramSHA256(vmName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", fmt.Errorf("nvram hash: %w", err)
	}
	return sha256RegularFile(f.NvramPath(vmName))
}

// sha256RegularFile hashes the regular file at p. Anything else at p (a
// symlink, a directory) is an error: the state is a plain file, and hashing
// through a link would hash something the store does not own.
func sha256RegularFile(p string) (string, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file (%v)", p, fi.Mode().Type())
	}
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", fmt.Errorf("hash %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteFirmwareBundle writes a tar of the VM's firmware state (nvram + swtpm) to
// w. Returns false (no error) when the VM has no firmware state to carry.
func (f *FirmwareStore) WriteFirmwareBundle(vmName, uuid string, w io.Writer) (bool, error) {
	hasNvram := f.HasNvram(vmName)
	hasTPM := f.HasTPMState(uuid)
	if !hasNvram && !hasTPM {
		return false, nil
	}
	tw := tar.NewWriter(w)
	if hasNvram {
		if err := tarFile(tw, f.NvramPath(vmName), fwBundleNvram); err != nil {
			return false, err
		}
	}
	if hasTPM {
		dir, _ := f.swtpmDir(uuid) // hasTPM implies a confined key
		if err := tarTree(tw, dir, fwBundleSwtpm); err != nil {
			return false, err
		}
	}
	if err := tw.Close(); err != nil {
		return false, err
	}
	return true, nil
}

// ReadFirmwareBundle restores a bundle from WriteFirmwareBundle: the nvram entry
// → NvramPath(vmName); swtpm/* → SwtpmDir(uuid). It is ATOMIC — the
// bundle is staged in full (swtpm into a sibling temp dir, nvram into memory),
// then each destination is swapped into place as a unit, so a partial/aborted
// restore never leaves mixed old/new firmware state (the BitLocker failure mode).
// Slip-safe: rejects ../absolute paths and symlink/hardlink/device members (a
// backup-repo bundle is untrusted); restored modes are clamped (files 0600, dirs
// 0700), never trusting tar header modes.
//
// The firmware move guard is asked first (OpWriteState).
func (f *FirmwareStore) ReadFirmwareBundle(r io.Reader, vmName, uuid string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWriteState, Name: vmName, UUID: uuid}); err != nil {
		return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
	}
	return f.readFirmwareBundle(r, vmName, uuid)
}

func (f *FirmwareStore) readFirmwareBundle(r io.Reader, vmName, uuid string) error {
	if uuid != "" {
		if _, ok := f.swtpmDir(uuid); !ok {
			return fmt.Errorf("firmware bundle: invalid swtpm uuid %q", uuid)
		}
	}
	swtpmRoot := f.SwtpmDir(uuid)
	var (
		nvramBytes []byte
		haveNvram  bool
		swtpmStage string // sibling temp dir holding the staged swtpm tree
	)
	defer func() {
		if swtpmStage != "" {
			_ = os.RemoveAll(swtpmStage)
		}
	}()

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read firmware bundle: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != tar.TypeDir {
			return fmt.Errorf("firmware bundle: disallowed member type %d for %q", hdr.Typeflag, hdr.Name)
		}
		// Reject (don't silently re-root) absolute paths and any member that
		// escapes the tree — a backup-repo bundle is untrusted. `../nvram` and
		// `/nvram` must be rejected, not normalized to `nvram`.
		if filepath.IsAbs(hdr.Name) {
			return fmt.Errorf("firmware bundle: rejected absolute member path %q", hdr.Name)
		}
		name := filepath.Clean(hdr.Name)
		if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("firmware bundle: rejected path-escaping member %q", hdr.Name)
		}
		switch {
		case name == fwBundleNvram:
			if hdr.Size > 64<<20 {
				return fmt.Errorf("firmware bundle nvram member implausibly large (%d bytes)", hdr.Size)
			}
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return fmt.Errorf("read nvram member: %w", err)
			}
			nvramBytes, haveNvram = b, true
		case strings.HasPrefix(name, fwBundleSwtpm):
			if uuid == "" {
				return fmt.Errorf("firmware bundle carries swtpm state but no target uuid was given")
			}
			if swtpmStage == "" {
				// The swtpm base dir must be world-traversable (libvirt uses 0711)
				// so the dropped-privilege swtpm user can reach per-UUID state.
				base := filepath.Dir(swtpmRoot)
				if err := os.MkdirAll(base, 0o711); err != nil {
					return err
				}
				_ = os.Chmod(base, 0o711) // MkdirAll won't fix an existing 0700
				swtpmStage, err = os.MkdirTemp(base, ".swtpm-restore-*")
				if err != nil {
					return err
				}
			}
			rel := strings.TrimPrefix(name, fwBundleSwtpm)
			if rel == "" {
				continue
			}
			dst := filepath.Join(swtpmStage, rel)
			if !safename.Contains(swtpmStage, dst) {
				return fmt.Errorf("firmware bundle entry %q escapes the swtpm dir", hdr.Name)
			}
			if hdr.Typeflag == tar.TypeDir {
				if err := os.MkdirAll(dst, 0o700); err != nil {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := writeFileFromTar(tr, dst); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected firmware bundle entry %q", hdr.Name)
		}
	}

	// Install NVRAM + swtpm as a UNIT with rollback: back up the existing files,
	// install the staged ones, and on ANY failure restore the backups — so we
	// never leave new NVRAM with stale/missing TPM (or vice-versa).
	nvramDst := f.NvramPath(vmName)
	var nvramBak, swtpmBak string
	rollback := func() {
		if nvramBak != "" {
			_ = os.Remove(nvramDst)
			_ = os.Rename(nvramBak, nvramDst)
		}
		if swtpmBak != "" {
			_ = os.RemoveAll(swtpmRoot)
			_ = os.Rename(swtpmBak, swtpmRoot)
		}
	}

	if haveNvram {
		if err := diskmode.MkdirAll(filepath.Dir(nvramDst)); err != nil {
			return err
		}
		staged := nvramDst + ".staged"
		if err := os.WriteFile(staged, nvramBytes, 0o600); err != nil {
			return err
		}
		if err := fsyncPath(staged); err != nil {
			_ = os.Remove(staged)
			return err
		}
		if _, e := os.Stat(nvramDst); e == nil {
			nvramBak = nvramDst + ".bak"
			if err := os.Rename(nvramDst, nvramBak); err != nil {
				_ = os.Remove(staged)
				return err
			}
		}
		if err := os.Rename(staged, nvramDst); err != nil {
			_ = os.Remove(staged)
			rollback()
			return err
		}
	}
	if swtpmStage != "" {
		if _, e := os.Stat(swtpmRoot); e == nil {
			swtpmBak = swtpmRoot + ".bak"
			_ = os.RemoveAll(swtpmBak)
			if err := os.Rename(swtpmRoot, swtpmBak); err != nil {
				rollback()
				return err
			}
		}
		if err := os.Rename(swtpmStage, swtpmRoot); err != nil {
			rollback()
			return fmt.Errorf("swap swtpm state into place: %w", err)
		}
		swtpmStage = "" // consumed — don't let the defer remove it
		// libvirt runs swtpm as a dropped-privilege user (qemu.conf swtpm_user)
		// and relabels the tpm2/ contents on domain start, but it does NOT chmod
		// the per-UUID parent dir — so it must be world-traversable (0711, the mode
		// libvirt itself uses) or swtpm can't reach its state ("Could not open
		// lockfile: Permission denied" → CMD_INIT fails). os.Rename carries the
		// staging dir's 0700, so fix it explicitly here (G1; caught by a live drill).
		if err := os.Chmod(swtpmRoot, 0o711); err != nil {
			rollback()
			return fmt.Errorf("set swtpm dir traversable: %w", err)
		}
	}
	// Success — drop the backups.
	if nvramBak != "" {
		_ = os.Remove(nvramBak)
	}
	if swtpmBak != "" {
		_ = os.RemoveAll(swtpmBak)
	}
	return nil
}

// WipeFirmwareState removes a VM's firmware state (true delete). Best-effort:
// a firmware move guard refusal (OpWipe) leaves the state and is logged.
func (f *FirmwareStore) WipeFirmwareState(vmName, uuid string) {
	if f.wipeRefused(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid}) {
		return
	}
	f.wipeNameKeyed(vmName)
	f.wipeByUUID(uuid)
}

// wipeRefused asks the guard about a best-effort wipe and logs a refusal. A
// refusal for an unreadable record is also kept for TakeRefusedWipes, so it
// is reported (the daemon raises it with the unreadable record), not only
// logged; a refusal for a record that names the VM is the guard doing its
// job.
func (f *FirmwareStore) wipeRefused(c FirmwareCall) bool {
	err := f.moveGuard().check(c)
	if err == nil {
		return false
	}
	slog.Warn("firmware state wipe refused", "vm", c.Name, "uuid", c.UUID, "error", err)
	if errors.Is(err, ErrFirmwareMoveRecordUnreadable) {
		f.refusedMu.Lock()
		f.refused = append(f.refused, RefusedWipe{VM: c.Name, UUID: c.UUID, At: time.Now(), Err: err})
		if n := len(f.refused); n > maxRefusedWipes {
			f.refused = append([]RefusedWipe(nil), f.refused[n-maxRefusedWipes:]...)
		}
		f.refusedMu.Unlock()
	}
	return true
}

// WipeNameKeyedFirmwareState removes only the artifacts keyed by the VM's NAME.
//
// Split out because a name is reusable: a caller cleaning up after a VM that no
// longer owns the name — a delayed cutover cleanup, say — would otherwise delete
// the vars file of whatever VM holds it now. Callers that cannot prove the name
// is still theirs must skip this and take WipeFirmwareStateByUUID alone.
//
// Best-effort: a firmware move guard refusal (OpWipe) leaves the state.
func (f *FirmwareStore) WipeNameKeyedFirmwareState(vmName string) {
	if f.wipeRefused(FirmwareCall{Op: OpWipe, Name: vmName}) {
		return
	}
	f.wipeNameKeyed(vmName)
}

func (f *FirmwareStore) wipeNameKeyed(vmName string) {
	_ = os.Remove(f.NvramPath(vmName))
	_ = os.Remove(f.retainedMarkerPath(vmName))
}

// WipeFirmwareStateByUUID removes the swtpm tree, which is keyed by the VM's
// UUID and therefore cannot belong to anything else. Best-effort: a firmware
// move guard refusal (OpWipe; a record that names the uuid under any VM name)
// leaves the tree.
func (f *FirmwareStore) WipeFirmwareStateByUUID(uuid string) {
	if f.wipeRefused(FirmwareCall{Op: OpWipe, UUID: uuid}) {
		return
	}
	f.wipeByUUID(uuid)
}

func (f *FirmwareStore) wipeByUUID(uuid string) {
	if dir, ok := f.swtpmDir(uuid); ok {
		_ = os.RemoveAll(dir)
	}
}

// ── Exempt entry points of a live firmware move (spec §5.1, I5) ──

// WipeFirmwareMoveSource wipes a moved VM's source state (spec §6.7 step 4):
// the marker is the attempt's, in phase cleaning, with its retained bundle on
// disk. Unlike the best-effort wipes it reports a removal that failed, so
// cleanup does not drop the marker over state still on disk.
func (f *FirmwareStore) WipeFirmwareMoveSource(vmName, uuid, attempt string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaWipeFirmwareMoveSource}); err != nil {
		return fmt.Errorf("wipe source firmware state of %s: %w", vmName, err)
	}
	dir, ok := f.swtpmDir(uuid)
	if !ok {
		return fmt.Errorf("wipe source firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
	}
	for _, p := range []string{f.NvramPath(vmName), f.retainedMarkerPath(vmName)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("wipe source firmware state of %s: %w", vmName, err)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("wipe source firmware state of %s: %w", vmName, err)
	}
	return nil
}

// MaterialiseFirmwareMoveNvram writes the target's NVRAM in Prepare (spec
// §6.2 item 7): the hold is the attempt's, in state prepared. It takes the
// request's raw NVRAM bytes, not a bundle (the Prepare request carries
// bytes), and writes nothing of the swtpm tree.
func (f *FirmwareStore) MaterialiseFirmwareMoveNvram(vmName, uuid, attempt string, nvram []byte) error {
	return f.writeMoveNvram(FirmwareCall{Op: OpWriteState, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaMaterialiseFirmwareMoveNvram}, nvram)
}

// PushFirmwareMoveNvram writes the source's final NVRAM to a held target
// found shut off (spec §7 H1): the hold is the attempt's, verified or
// resuming.
func (f *FirmwareStore) PushFirmwareMoveNvram(vmName, uuid, attempt string, nvram []byte) error {
	return f.writeMoveNvram(FirmwareCall{Op: OpWriteState, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaPushFirmwareMoveNvram}, nvram)
}

// PushSourceNvramForOperator writes the source's final NVRAM to a target
// guest that is not running, for the D-5 --push-source-nvram action (spec
// §5.y): the hold is the attempt's, released_unconfirmed.
func (f *FirmwareStore) PushSourceNvramForOperator(vmName, uuid, attempt string, nvram []byte) error {
	return f.writeMoveNvram(FirmwareCall{Op: OpWriteState, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaPushSourceNvramForOperator}, nvram)
}

// writeMoveNvram replaces the VM's NVRAM with nvram durably: staged file,
// fsync, rename, directory fsync.
func (f *FirmwareStore) writeMoveNvram(c FirmwareCall, nvram []byte) error {
	if err := f.moveGuard().check(c); err != nil {
		return fmt.Errorf("write nvram of %s: %w", c.Name, err)
	}
	if err := safename.ValidateVMName(c.Name); err != nil {
		return fmt.Errorf("write nvram: %w", err)
	}
	dst := f.NvramPath(c.Name)
	if err := diskmode.MkdirAll(filepath.Dir(dst)); err != nil {
		return err
	}
	staged := dst + ".staged"
	if err := os.WriteFile(staged, nvram, 0o600); err != nil {
		return err
	}
	if err := fsyncPath(staged); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, dst); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return fsyncPath(filepath.Dir(dst))
}

// RemoveFirmwareMoveTargetState is Abort's rule D (spec §6.8): it deletes
// the target's materialised NVRAM (nvram) and the swtpm tree (swtpm). The hold
// is the attempt's, in state prepared. Absent files are not an error.
func (f *FirmwareStore) RemoveFirmwareMoveTargetState(vmName, uuid, attempt string, nvram, swtpm bool) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaRemoveFirmwareMoveTargetState}); err != nil {
		return fmt.Errorf("remove target firmware state of %s: %w", vmName, err)
	}
	if nvram {
		if err := os.Remove(f.NvramPath(vmName)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if swtpm {
		dir, ok := f.swtpmDir(uuid)
		if !ok {
			return fmt.Errorf("remove target firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return nil
}

// QuarantineFirmwareMoveTargetState is rule Q (spec §6.8): it moves the
// target's NVRAM to dir/nvram and its swtpm tree to dir/swtpm, deleting
// nothing. The hold is the attempt's, in a state whose guest is held
// (prepared, verified, resuming, mismatch). dir is created 0700. A part that
// is absent is skipped; one already in dir is not overwritten.
func (f *FirmwareStore) QuarantineFirmwareMoveTargetState(vmName, uuid, attempt, dir string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaQuarantineFirmwareMoveTargetState}); err != nil {
		return fmt.Errorf("quarantine target firmware state of %s: %w", vmName, err)
	}
	swtpm, ok := f.swtpmDir(uuid)
	if !ok {
		return fmt.Errorf("quarantine target firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, mv := range []struct{ from, to string }{
		{f.NvramPath(vmName), filepath.Join(dir, "nvram")},
		{swtpm, filepath.Join(dir, "swtpm")},
	} {
		if err := moveIntoQuarantine(mv.from, mv.to); err != nil {
			return fmt.Errorf("quarantine %s: %w", mv.from, err)
		}
	}
	// Durable on both sides: the quarantine dir and its parent hold the
	// moved entries, the parents of the sources lose them.
	for _, d := range []string{dir, filepath.Dir(dir), filepath.Dir(f.NvramPath(vmName)), filepath.Dir(swtpm)} {
		if err := fsyncPath(d); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("quarantine %s: fsync %s: %w", vmName, d, err)
		}
	}
	return nil
}

// moveIntoQuarantine renames from to to, or, across filesystems, copies it
// (files 0600, dirs 0700, each file fsynced) and then removes from.
func moveIntoQuarantine(from, to string) error {
	if _, err := os.Lstat(from); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s already exists", to)
	} else if !os.IsNotExist(err) {
		return err
	}
	err := os.Rename(from, to)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyQuarantine(from, to); err != nil {
		_ = os.RemoveAll(to)
		return err
	}
	// The copied directories are durable before the source goes.
	if err := filepath.WalkDir(to, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return fsyncPath(p)
	}); err != nil {
		_ = os.RemoveAll(to)
		return err
	}
	return os.RemoveAll(from)
}

func copyQuarantine(from, to string) error {
	return filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(dst, 0o700)
		case d.Type().IsRegular():
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			return writeFileFromTar(src, dst)
		default:
			return fmt.Errorf("unexpected firmware state entry %q (type %v)", p, d.Type())
		}
	})
}

// Retained-firmware marker (G1): `delete --keep-disks` keeps the firmware state
// but the DB row is gone, so the UUID-keyed swtpm tree would be unlocatable.
// Record name→uuid in a marker under dataDir so an explicit restore/adopt can
// find it. (The name-keyed NVRAM guard already blocks accidental same-name reuse.)
func (f *FirmwareStore) retainedMarkerPath(vmName string) string {
	return filepath.Join(f.DataDir, "nvram", vmName+".kept-uuid")
}

// WriteRetainedFirmwareMarker records name→uuid for a VM whose firmware state a
// `delete --keep-disks` keeps.
func (f *FirmwareStore) WriteRetainedFirmwareMarker(vmName, uuid string) error {
	p := f.retainedMarkerPath(vmName)
	if err := diskmode.MkdirAll(filepath.Dir(p)); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(uuid), 0o600)
}

// ReadRetainedFirmwareMarker returns the retained swtpm UUID for a name, if any.
func (f *FirmwareStore) ReadRetainedFirmwareMarker(vmName string) (string, bool) {
	b, err := os.ReadFile(f.retainedMarkerPath(vmName))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ── tar helpers ──

func tarFile(tw *tar.Writer, srcPath, name string) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func tarTree(tw *tar.Writer, srcDir, prefix string) error {
	return filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.Name() == ".lock" {
			// swtpm's runtime lock file — recreated on start; carrying it is at best
			// noise and at worst confuses a restored instance. Skip it (G1).
			return nil
		}
		if !d.Type().IsRegular() && !d.IsDir() {
			// swtpm state is plain files + dirs; anything else means a malformed or
			// tampered tree — fail rather than produce an incomplete bundle.
			return fmt.Errorf("unexpected swtpm state entry %q (type %v)", p, d.Type())
		}
		name := prefix + filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, Typeflag: tar.TypeDir})
		}
		return tarFile(tw, p, name)
	})
}

// writeFileFromTar writes a tar entry to dst, clamping the mode to 0600 (never
// trusting the header mode) and fsyncing before close.
func writeFileFromTar(tr io.Reader, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, tr); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fsyncPath fsyncs a file at path (used after staging the nvram temp file).
func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

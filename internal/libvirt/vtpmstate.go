package libvirt

import (
	"archive/tar"
	"bytes"
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
	// refusedDropped counts the refusals dropped past maxRefusedWipes since
	// the last collection, so the report's total still counts them.
	refusedDropped int
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
// record since the last call: the newest maxRefusedWipes of them, and how
// many older ones were dropped past that bound.
func (f *FirmwareStore) TakeRefusedWipes() (wipes []RefusedWipe, dropped int) {
	f.refusedMu.Lock()
	defer f.refusedMu.Unlock()
	wipes, dropped = f.refused, f.refusedDropped
	f.refused, f.refusedDropped = nil, 0
	return wipes, dropped
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
			f.refusedDropped += n - maxRefusedWipes
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
	return f.quarantineMoveState(vmName, uuid, dir)
}

// QuarantineFirmwareMoveSourceForOperator moves a moved VM's source state
// (swtpm tree, NVRAM) into dir, for the D-5 --accept-target action on a
// source cleanup that stopped (spec §17 D-5, the cleaning row): the marker is
// the attempt's, in phase cleaning. Nothing is deleted.
func (f *FirmwareStore) QuarantineFirmwareMoveSourceForOperator(vmName, uuid, attempt, dir string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaQuarantineFirmwareMoveSourceForOperator}); err != nil {
		return fmt.Errorf("quarantine source firmware state of %s: %w", vmName, err)
	}
	return f.quarantineMoveState(vmName, uuid, dir)
}

// QuarantineLeftoverFirmwareState is the reconciler's cleanup of a leftover
// that holds firmware state while no firmware move record names it here (an
// ordinary OpWipe). The NVRAM, and the swtpm tree of uuid, move into stage;
// reason is written there durably as reason.txt; then stage is renamed to
// final in one step and that entry made durable. So a quarantine is never
// split across two directories and never seen without its reason.txt: a pass
// that stopped part way leaves stage, which the next pass of the same domain
// finishes (each move is idempotent). With uuid "" (a definition that does not
// give a canonical uuid, so no swtpm tree can be told to be the domain's)
// only the NVRAM moves; libvirt's undefine keeping state leaves any swtpm tree
// where it is. Nothing is deleted.
func (f *FirmwareStore) QuarantineLeftoverFirmwareState(vmName, uuid, stage, final string, reason []byte) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid}); err != nil {
		return fmt.Errorf("quarantine firmware state of %s: %w", vmName, err)
	}
	return f.quarantineStaged(vmName, uuid, stage, final, reason, true, uuid != "")
}

// StageLeftoverFirmwareState is the first half of
// QuarantineLeftoverFirmwareState: the state moves into stage and reason.txt
// is written there durably, and stage keeps its name. While it does, the
// guard refuses the VM's start, resume and define (FirmwareStaged), so the
// reconciler undefines the leftover between the two halves and a failed
// undefine never leaves a defined domain with empty firmware paths unguarded
// (D2-18 verify, m-A). FinishStage is the second half.
func (f *FirmwareStore) StageLeftoverFirmwareState(vmName, uuid, stage string, reason []byte) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid}); err != nil {
		return fmt.Errorf("quarantine firmware state of %s: %w", vmName, err)
	}
	return f.stageParts(vmName, uuid, stage, reason, true, uuid != "")
}

// FinishStage renames a stage whose state and reason.txt are in place to
// final in one step and makes that entry durable.
func (f *FirmwareStore) FinishStage(stage, final string) error {
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("finish %s: %s already exists", stage, final)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := quarantineFinish(stage, final); err != nil {
		return fmt.Errorf("finish %s: %w", stage, err)
	}
	return quarantineSync(filepath.Dir(final))
}

// quarantineStaged is QuarantineLeftoverFirmwareState once the guard allowed
// it, for the parts named: the NVRAM and/or the swtpm tree of uuid.
func (f *FirmwareStore) quarantineStaged(vmName, uuid, stage, final string, reason []byte, nvram, swtpm bool) error {
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("quarantine firmware state of %s: %s already exists", vmName, final)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := f.stageParts(vmName, uuid, stage, reason, nvram, swtpm); err != nil {
		return err
	}
	if err := quarantineFinish(stage, final); err != nil {
		return fmt.Errorf("quarantine %s: %w", vmName, err)
	}
	if err := quarantineSync(filepath.Dir(final)); err != nil {
		return fmt.Errorf("quarantine %s: fsync %s: %w", vmName, filepath.Dir(final), err)
	}
	return nil
}

// stageParts moves the named parts into stage and writes reason.txt there
// durably.
func (f *FirmwareStore) stageParts(vmName, uuid, stage string, reason []byte, nvram, swtpm bool) error {
	if nvram && swtpm {
		if err := f.quarantineMoveState(vmName, uuid, stage); err != nil {
			return err
		}
	} else if swtpm {
		d, ok := f.swtpmDir(uuid)
		if !ok {
			return fmt.Errorf("quarantine firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
		}
		if err := mkdirAllDurable(stage); err != nil {
			return fmt.Errorf("quarantine %s: %w", vmName, err)
		}
		if err := moveIntoQuarantine(d, filepath.Join(stage, "swtpm")); err != nil {
			return fmt.Errorf("quarantine %s: %w", d, err)
		}
		for _, dd := range []string{stage, filepath.Dir(stage), filepath.Dir(d)} {
			if err := quarantineSync(dd); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("quarantine %s: fsync %s: %w", vmName, dd, err)
			}
		}
	} else {
		if err := mkdirAllDurable(stage); err != nil {
			return fmt.Errorf("quarantine %s: %w", vmName, err)
		}
		if err := moveIntoQuarantine(f.NvramPath(vmName), filepath.Join(stage, "nvram")); err != nil {
			return fmt.Errorf("quarantine %s: %w", f.NvramPath(vmName), err)
		}
		for _, d := range []string{stage, filepath.Dir(stage), filepath.Dir(f.NvramPath(vmName))} {
			if err := quarantineSync(d); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("quarantine %s: fsync %s: %w", vmName, d, err)
			}
		}
	}
	if err := writeQuarantineFile(filepath.Join(stage, "reason.txt"), reason); err != nil {
		return fmt.Errorf("quarantine %s: reason.txt: %w", vmName, err)
	}
	return nil
}

// FinishOrphanedStage finishes a reconciler stage whose leftover domain is
// gone (D2-18 re-review 4, m-2): reason is written into stage durably and
// stage is renamed to final in one step, that entry made durable. It moves
// nothing out of a domain's paths, so no guard is asked.
func (f *FirmwareStore) FinishOrphanedStage(stage, final string, reason []byte) error {
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("finish %s: %s already exists", stage, final)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := writeQuarantineFile(filepath.Join(stage, "reason.txt"), reason); err != nil {
		return fmt.Errorf("finish %s: reason.txt: %w", stage, err)
	}
	if err := quarantineFinish(stage, final); err != nil {
		return fmt.Errorf("finish %s: %w", stage, err)
	}
	return quarantineSync(filepath.Dir(final))
}

// restoreSetAsideMark records, inside a restoring directory, that the state
// the restore replaces has been set aside, so a rerun never sets aside state
// the restore itself already moved back.
const restoreSetAsideMark = ".set-aside"

// RestoreFirmwareQuarantine puts a quarantine's NVRAM (and swtpm tree of
// uuid; "" = NVRAM only) back as vmName's own (lv host superseded-disks
// --restore, D2-18 re-review 4). It is an ordinary state write, refused under
// any firmware move record of the VM; a stage of it does not refuse it.
//
//  1. from is renamed to restoring (<vm>-restoring-<uuid>), unless from is
//     already that directory (a rerun). While it exists the guard refuses the
//     VM's start.
//  2. Whatever state the VM has in place is set aside whole, as a reconciler
//     quarantine (setAsideStage → setAsideFinal, with setAsideReason), and
//     the set-aside is marked done inside restoring.
//  3. The state moves back with the quarantine's byte-checked move.
//  4. restoring, which holds only its reason.txt and the mark by then, goes.
//
// A crash anywhere leaves either the state in place or restoring, which a
// rerun on restoring finishes. Nothing is deleted that is not held elsewhere.
func (f *FirmwareStore) RestoreFirmwareQuarantine(vmName, uuid, from, restoring, setAsideStage, setAsideFinal string, setAsideReason []byte) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWriteState, Name: vmName, UUID: uuid}); err != nil {
		return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
	}
	swtpm := ""
	if uuid != "" {
		d, ok := f.swtpmDir(uuid)
		if !ok {
			return fmt.Errorf("restore firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
		}
		swtpm = d
	} else if _, err := os.Lstat(filepath.Join(from, "swtpm")); err == nil {
		return fmt.Errorf("restore firmware state of %s: %s holds a swtpm tree, and no uuid says whose", vmName, from)
	}
	if filepath.Clean(from) != filepath.Clean(restoring) {
		if _, err := os.Lstat(restoring); err == nil {
			return fmt.Errorf("restore firmware state of %s: an interrupted restore is at %s; run the restore on it", vmName, restoring)
		}
		if err := quarantineFinish(from, restoring); err != nil {
			return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
		}
		if err := quarantineSync(filepath.Dir(restoring)); err != nil {
			return fmt.Errorf("restore firmware state of %s: fsync %s: %w", vmName, filepath.Dir(restoring), err)
		}
	}
	has := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	mark := filepath.Join(restoring, restoreSetAsideMark)
	if !has(mark) {
		// Only the parts the quarantine replaces are set aside: a part it
		// does not hold (a stage a pass stopped part way) stays in place.
		nv := has(filepath.Join(restoring, "nvram")) && has(f.NvramPath(vmName))
		tpm := swtpm != "" && has(filepath.Join(restoring, "swtpm")) && has(swtpm)
		if nv || tpm {
			if err := f.quarantineStaged(vmName, uuid, setAsideStage, setAsideFinal, setAsideReason, nv, tpm); err != nil {
				return fmt.Errorf("restore firmware state of %s: set aside the state in place: %w", vmName, err)
			}
		}
		if err := writeQuarantineFile(mark, []byte(setAsideFinal+"\n")); err != nil {
			return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
		}
	}
	moves := []struct{ from, to string }{{filepath.Join(restoring, "nvram"), f.NvramPath(vmName)}}
	if swtpm != "" {
		moves = append(moves, struct{ from, to string }{filepath.Join(restoring, "swtpm"), swtpm})
	}
	for _, mv := range moves {
		if err := os.MkdirAll(filepath.Dir(mv.to), 0o755); err != nil {
			return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
		}
		if err := moveIntoQuarantine(mv.from, mv.to); err != nil {
			return fmt.Errorf("restore firmware state of %s: %s: %w", vmName, mv.from, err)
		}
		if err := quarantineSync(filepath.Dir(mv.to)); err != nil {
			return fmt.Errorf("restore firmware state of %s: fsync %s: %w", vmName, filepath.Dir(mv.to), err)
		}
	}
	if swtpm != "" && has(swtpm) {
		// As ReadFirmwareBundle: libvirt relabels the tpm2/ contents at
		// start but not the per-uuid parent, and a copy across filesystems
		// made it 0700; swtpm must traverse it (D2-18 verify, m-C). A rename
		// kept libvirt's own mode, and this changes nothing then.
		if err := os.Chmod(swtpm, 0o711); err != nil {
			return fmt.Errorf("restore firmware state of %s: chmod %s: %w", vmName, swtpm, err)
		}
	}
	for _, p := range []string{filepath.Join(restoring, "nvram"), filepath.Join(restoring, "swtpm")} {
		if has(p) {
			return fmt.Errorf("restore firmware state of %s: %s is still there; %s is kept", vmName, p, restoring)
		}
	}
	if err := os.RemoveAll(restoring); err != nil {
		return fmt.Errorf("restore firmware state of %s: %w", vmName, err)
	}
	return quarantineSync(filepath.Dir(restoring))
}

// writeQuarantineFile writes data to p (0600) durably: a temporary file,
// fsynced, renamed into place, and the directory fsynced.
func writeQuarantineFile(p string, data []byte) error {
	tmp := p + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := quarantineSync(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return quarantineSync(filepath.Dir(p))
}

// QuarantineOwedFirmwareLeftover moves the NVRAM and swtpm tree of a leftover
// an owed DISCARD names into dir, under its leftover record (D-5
// --discard-target). Nothing is deleted.
func (f *FirmwareStore) QuarantineOwedFirmwareLeftover(vmName, uuid, attempt, dir string) error {
	if err := f.moveGuard().check(FirmwareCall{Op: OpWipe, Name: vmName, UUID: uuid, Attempt: attempt, Via: ViaQuarantineOwedFirmwareLeftover}); err != nil {
		return fmt.Errorf("quarantine firmware state of %s: %w", vmName, err)
	}
	return f.quarantineMoveState(vmName, uuid, dir)
}

// quarantineMoveState moves the VM's NVRAM and swtpm tree into dir, durably,
// once the guard allowed it.
func (f *FirmwareStore) quarantineMoveState(vmName, uuid, dir string) error {
	swtpm, ok := f.swtpmDir(uuid)
	if !ok {
		return fmt.Errorf("quarantine firmware state of %s: invalid swtpm uuid %q", vmName, uuid)
	}
	if err := mkdirAllDurable(dir); err != nil {
		return fmt.Errorf("quarantine %s: %w", vmName, err)
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
		if err := quarantineSync(d); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("quarantine %s: fsync %s: %w", vmName, d, err)
		}
	}
	return nil
}

// The quarantine's rename, its placing rename (a whole cross-filesystem copy
// renamed into place within the quarantine dir) and directory fsync;
// variables so a test can fail a step and check what is left.
var (
	quarantineRename = os.Rename
	quarantinePlace  = os.Rename
	quarantineSync   = fsyncPath
	// quarantineFinish renames a reconciler's staged quarantine to its name.
	quarantineFinish = os.Rename
)

// mkdirAllDurable creates dir (0700) and every missing parent, then fsyncs
// each directory it created and the existing one that gained the topmost
// entry, so the quarantine's directory survives a crash.
func mkdirAllDurable(dir string) error {
	var missing []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		_, err := os.Lstat(d)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, d := range missing {
		if err := quarantineSync(d); err != nil {
			return fmt.Errorf("fsync %s: %w", d, err)
		}
	}
	if n := len(missing); n > 0 {
		if p := filepath.Dir(missing[n-1]); p != missing[n-1] {
			if err := quarantineSync(p); err != nil {
				return fmt.Errorf("fsync %s: %w", p, err)
			}
		}
	}
	return nil
}

// moveIntoQuarantine renames from to to, or, across filesystems, copies it
// (files 0600, dirs 0700, each file fsynced) under a temporary name beside
// to, makes the copy durable (every copied directory and the directory
// holding it), renames it to to, makes that entry durable, and only then
// removes from: a crash at any point leaves at least one whole copy, and to,
// once it exists, is always whole.
//
// So a retry after a crash finishes the move (D2-6 re-review 2, m-14): a
// leftover temporary copy is never whole and is replaced; an existing to is
// whole, and what is left of from (all of it, or what a crash in the final
// RemoveAll left) is removed once every file of it is found byte-equal in to
// and to is durable. A from that differs from to is kept, with to, and
// refused: nothing is ever removed that the quarantine does not hold.
func moveIntoQuarantine(from, to string) error {
	if _, err := os.Lstat(from); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(to); err == nil {
		return finishQuarantine(from, to)
	} else if !os.IsNotExist(err) {
		return err
	}
	err := quarantineRename(from, to)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	tmp := to + quarantineCopySuffix
	// A leftover of a copy a crash interrupted: never renamed into place, so
	// never whole, while from still is.
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := copyQuarantine(from, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	// The copy is durable before it takes its name: each copied directory
	// (the files were fsynced as written) and the directory holding it. A
	// failure here keeps the source, whole.
	if err := syncQuarantineTree(tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := quarantinePlace(tmp, to); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := quarantineSync(filepath.Dir(to)); err != nil {
		// Not known durable: the source stays, whole, and the copy goes.
		_ = os.RemoveAll(to)
		return err
	}
	return os.RemoveAll(from)
}

// quarantineCopySuffix names a cross-filesystem copy until it is whole and
// durable.
const quarantineCopySuffix = ".copying"

// syncQuarantineTree fsyncs every directory of tree and the one holding it.
func syncQuarantineTree(tree string) error {
	err := filepath.WalkDir(tree, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return quarantineSync(p)
	})
	if err != nil {
		return err
	}
	return quarantineSync(filepath.Dir(tree))
}

// finishQuarantine is a move whose destination already exists: what is left
// of from goes only if the quarantine holds every file of it, byte for byte,
// durably. Anything else keeps both and refuses.
func finishQuarantine(from, to string) error {
	if err := quarantineHolds(from, to); err != nil {
		return fmt.Errorf("%s already exists and does not hold %s (%v); both are kept: compare them, and move the one that is not wanted out of the way", to, from, err)
	}
	fi, err := os.Lstat(to)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		err = syncQuarantineTree(to)
	} else {
		err = quarantineSync(filepath.Dir(to))
	}
	if err != nil {
		return err
	}
	return os.RemoveAll(from)
}

// quarantineHolds checks that every regular file under from (or from itself)
// is in to at the same relative path with the same bytes, and that every
// directory under from is a directory in to. Any other entry fails it.
func quarantineHolds(from, to string) error {
	return filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		fi, err := os.Lstat(dst)
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", dst)
			}
			return nil
		case d.Type().IsRegular():
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", dst)
			}
			a, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(dst)
			if err != nil {
				return err
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("%s differs from %s", p, dst)
			}
			return nil
		default:
			return fmt.Errorf("unexpected firmware state entry %q (type %v)", p, d.Type())
		}
	})
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

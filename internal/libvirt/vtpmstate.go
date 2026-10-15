package libvirt

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

// RemoveNvram removes the VM's UEFI vars file. The error is os.Remove's.
func (f *FirmwareStore) RemoveNvram(vmName string) error {
	return os.Remove(f.NvramPath(vmName))
}

// RenameNvram moves the UEFI vars file of from to the name to. The error is
// os.Rename's.
func (f *FirmwareStore) RenameNvram(from, to string) error {
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
func (f *FirmwareStore) ReadFirmwareBundle(r io.Reader, vmName, uuid string) error {
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

// WipeFirmwareState removes a VM's firmware state (true delete). Best-effort.
func (f *FirmwareStore) WipeFirmwareState(vmName, uuid string) {
	f.WipeNameKeyedFirmwareState(vmName)
	f.WipeFirmwareStateByUUID(uuid)
}

// WipeNameKeyedFirmwareState removes only the artifacts keyed by the VM's NAME.
//
// Split out because a name is reusable: a caller cleaning up after a VM that no
// longer owns the name — a delayed cutover cleanup, say — would otherwise delete
// the vars file of whatever VM holds it now. Callers that cannot prove the name
// is still theirs must skip this and take WipeFirmwareStateByUUID alone.
func (f *FirmwareStore) WipeNameKeyedFirmwareState(vmName string) {
	_ = os.Remove(f.NvramPath(vmName))
	_ = os.Remove(f.retainedMarkerPath(vmName))
}

// WipeFirmwareStateByUUID removes the swtpm tree, which is keyed by the VM's
// UUID and therefore cannot belong to anything else.
func (f *FirmwareStore) WipeFirmwareStateByUUID(uuid string) {
	if dir, ok := f.swtpmDir(uuid); ok {
		_ = os.RemoveAll(dir)
	}
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

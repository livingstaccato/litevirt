package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A VM can be handed a host file to READ: an installer ISO is attached as a
// read-only CD-ROM, and qemu opens it as root-equivalent on the daemon's
// behalf. Whoever names that file reads it from inside the guest, so a path
// that reaches the daemon's PKI directory hands over the host key, its data
// directory hands over state.db, and /etc hands over /etc/shadow.
//
// CheckReadFile is the backstop that applies to everyone, Admin included. The
// boundary is authority (only a cluster-root caller may name an arbitrary host
// path); this refuses the places no guest should ever be given, whoever asks.

// secretRoots are directories holding host credentials or live kernel and
// hypervisor state. /usr and the library directories are deliberately absent:
// they hold nothing secret, and distribution ISOs live there (virtio-win
// installs into /usr/share/virtio-win).
var secretRoots = []string{
	"/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys",
	"/var/backups", "/var/run", "/var/spool",
	// LXC container root filesystems and configs.
	"/var/lib/lxc",
	// libvirt's per-domain state (master-key.aes) and vTPM state.
	"/var/lib/libvirt/qemu", "/var/lib/libvirt/swtpm",
}

// ISOLibraryDir is the directory under the data directory that holds the
// built-in global ISO library pool (pools/, beside the other daemon-made
// pools). A guest may be given a file in it to read;
// no pool other than that library may be created in it (CheckWriteRoot still
// refuses it, as it does the rest of the data directory).
const ISOLibraryDir = "pools/isos"

// CheckReadFile refuses a host file no VM may be given to read: a relative or
// unclean path (one that still carries a "." or ".." to resolve), anything
// under a secret system directory, anything in or below the daemon's PKI
// directory, and anything in its data directory outside disks/, mounts/ and
// pools/isos/ (state.db, cloudinit/, nvram/, imports/, images/ …). The path is judged as
// written and after resolving symlinks, so a link at an innocent name does not
// reach a refused file. It must also exist and be a regular file once resolved:
// a device, directory or FIFO is never an ISO.
func CheckReadFile(p, dataDir, pkiDir string) error {
	if err := checkReadPathLexical(p); err != nil {
		return err
	}
	for _, cand := range pathForms(p) {
		if err := refuseSecretPath(p, cand, dataDir, pkiDir); err != nil {
			return err
		}
	}
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%q does not exist on this host", p)
		}
		return fmt.Errorf("%q: %w", p, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", p)
	}
	return nil
}

// CheckReadPathLexical is CheckReadFile without touching the filesystem, for a
// node judging a path that lives on another host: it refuses what the path
// says as written, and leaves symlinks and existence to the owning host.
func CheckReadPathLexical(p, dataDir, pkiDir string) error {
	if err := checkReadPathLexical(p); err != nil {
		return err
	}
	return refuseSecretPath(p, p, dataDir, pkiDir)
}

// CheckRefusedReadPath refuses only the protected places — what no caller may
// name, judged as written and after resolving symlinks on this host — without
// insisting the path be absolute, clean or present. It is for a path stored
// before these checks existed, where anything else is not this check's to
// reject.
func CheckRefusedReadPath(p, dataDir, pkiDir string) error {
	if p == "" || !filepath.IsAbs(p) {
		return nil
	}
	for _, cand := range pathForms(p) {
		if err := refuseSecretPath(p, cand, dataDir, pkiDir); err != nil {
			return err
		}
	}
	return nil
}

func checkReadPathLexical(p string) error {
	if p == "" {
		return errors.New("an empty path names no file")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("%q is not a clean path (no '.', '..' or repeated '/')", p)
	}
	return nil
}

func refuseSecretPath(p, cand, dataDir, pkiDir string) error {
	for _, root := range secretRoots {
		for _, r := range pathForms(root) {
			if within(r, cand) {
				return fmt.Errorf("%q is under %s, which holds host secrets or live system state", p, root)
			}
		}
	}
	if pkiDir != "" {
		for _, d := range pathForms(pkiDir) {
			if within(d, cand) {
				return fmt.Errorf("%q is in the daemon's PKI directory %s", p, pkiDir)
			}
		}
	}
	if dataDir != "" {
		for _, d := range pathForms(dataDir) {
			if within(d, cand) && !inPoolArea(d, cand) && !within(filepath.Join(d, ISOLibraryDir), cand) {
				return fmt.Errorf("%q is inside the daemon's data directory %s; only its disks/, mounts/ and pools/isos/ hold pool content", p, dataDir)
			}
		}
	}
	return nil
}

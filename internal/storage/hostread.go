package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	"/boot", "/dev", "/etc", "/proc", "/root", "/sys",
	"/var/backups", "/var/spool",
	// LXC container root filesystems and configs.
	"/var/lib/lxc",
	// libvirt's per-domain state (master-key.aes) and vTPM state.
	"/var/lib/libvirt/qemu", "/var/lib/libvirt/swtpm",
}

// userDataRoots are where people keep their own files — installer ISOs
// downloaded into a home directory, a USB stick udisks mounts under
// /run/media — next to things no guest may read (~/.ssh, ~/.gnupg, the
// runtime directories under /run). A file under one is a file a guest may be
// given only when it is an optical disc image (OpticalImageAt) and a regular
// file, reached without a link leading into a dot-directory the path as named
// does not name (introducedDotComponent); everything else under them is
// refused like a secret root. /var/run is /run.
var userDataRoots = []string{"/home", "/run", "/var/run"}

// SetUserDataRootsForTest replaces the user-data roots and returns what
// restores them, so a test can stand a temporary directory in for /home or
// /run/media.
func SetUserDataRootsForTest(roots []string) (restore func()) {
	old := userDataRoots
	userDataRoots = roots
	return func() { userDataRoots = old }
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
// pools/isos/ (state.db, cloudinit/, nvram/, imports/, images/ …). Under a
// user-data root (/home, /run) only an optical disc image passes, and not one
// a link reaches through a dot-directory the named path does not name
// (userDataRoots). The path is judged as written and
// after resolving symlinks, so a link at an innocent name does not reach a
// refused file. It must also exist and be a regular file once resolved: a
// device, directory or FIFO is never an ISO.
func CheckReadFile(p, dataDir, pkiDir string) error {
	if err := checkReadPathLexical(p); err != nil {
		return err
	}
	userData := false
	for _, cand := range pathForms(p) {
		if err := refuseSecretPath(p, cand, dataDir, pkiDir); err != nil {
			return err
		}
		userData = userData || underUserDataRoot(cand)
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
	if userData {
		return checkUserDataFile(p)
	}
	return nil
}

// UnderUserDataRoot reports whether p, as written or resolved, is under a
// user-data root, where only an optical image is a file a guest may read.
func UnderUserDataRoot(p string) bool {
	for _, cand := range pathForms(p) {
		if underUserDataRoot(cand) {
			return true
		}
	}
	return false
}

func underUserDataRoot(cand string) bool {
	for _, root := range userDataRoots {
		for _, r := range pathForms(root) {
			if within(r, cand) {
				return true
			}
		}
	}
	return false
}

// dotComponents returns the path components that start with a dot.
func dotComponents(p string) map[string]bool {
	out := map[string]bool{}
	for _, c := range strings.Split(filepath.Clean(p), string(filepath.Separator)) {
		if strings.HasPrefix(c, ".") {
			out[c] = true
		}
	}
	return out
}

// introducedDotComponent returns a dot-directory (or dot-file) that resolved,
// the path named resolved, has and named does not: a link leading into
// ~/.ssh, ~/.gnupg or ~/.config, where keys and tokens live. A dot-directory
// the path names itself (~/.local/share/libvirt/images) is what whoever named
// it meant.
func introducedDotComponent(named, resolved string) string {
	have := dotComponents(named)
	for c := range dotComponents(resolved) {
		if !have[c] {
			return c
		}
	}
	return ""
}

// checkUserDataFile is the rule for a file under a user-data root: no link on
// the way to it leads into a dot-directory the path as named does not name,
// and the file the resolved path opens — opened without following a link, and
// confirmed to be that path — is a regular file carrying an ISO 9660 or UDF
// volume signature. A key, a token or a database carries none.
func checkUserDataFile(p string) error {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return fmt.Errorf("%q: %w", p, err)
	}
	if c := introducedDotComponent(p, resolved); c != "" {
		return fmt.Errorf("%q is a link into %s (%s), a dot-directory under a home or runtime directory, where keys and tokens live", p, c, resolved)
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("%q could not be opened as the file itself: %w", p, err)
	}
	defer f.Close()
	if real, rerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); rerr == nil && real != resolved {
		return fmt.Errorf("%q changed while it was being checked", p)
	}
	if err := OpticalImageAt(f); err != nil {
		return fmt.Errorf("%q is under a home or runtime directory, where only an ISO image may be attached: %w", p, err)
	}
	return nil
}

// isoSector is the logical sector size of ISO 9660 and of UDF's volume
// recognition sequence on optical media.
const isoSector = 2048

// OpticalImageAt reads, from an open file, the volume descriptors an optical
// disc image starts with at sector 16 (byte 0x8000), and refuses a file that
// has none: an ISO 9660 primary or supplementary descriptor ("CD001", a
// hybrid image too), or a UDF volume recognition sequence ("BEA01" followed by
// "NSR02" or "NSR03"). It reads with ReadAt, so it neither moves nor needs
// the file offset. The file must be a regular file.
func OpticalImageAt(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("it is not a regular file")
	}
	id := func(i int) string {
		b := make([]byte, 6)
		if n, err := f.ReadAt(b, int64(16+i)*isoSector); n < len(b) || (err != nil && !errors.Is(err, io.EOF)) {
			return ""
		}
		return string(b[1:6])
	}
	if id(0) == "CD001" {
		return nil
	}
	if id(0) == "BEA01" {
		for i := 1; i < 16; i++ {
			switch id(i) {
			case "NSR02", "NSR03":
				return nil
			case "TEA01", "":
				return errors.New("it carries no ISO 9660 or UDF volume signature")
			}
		}
	}
	return errors.New("it carries no ISO 9660 or UDF volume signature")
}

// CheckReadPathLexical is CheckReadFile without touching the filesystem, for a
// node judging a path that lives on another host: it refuses what the path
// says as written, and leaves symlinks, existence and an optical image's
// signature to the owning host.
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
// reject. Under a user-data root that is a link into a dot-directory the path
// does not name; a present file there is judged in full by CheckReadFile.
func CheckRefusedReadPath(p, dataDir, pkiDir string) error {
	if p == "" || !filepath.IsAbs(p) {
		return nil
	}
	for _, cand := range pathForms(p) {
		if err := refuseSecretPath(p, cand, dataDir, pkiDir); err != nil {
			return err
		}
		if underUserDataRoot(cand) {
			if c := introducedDotComponent(p, cand); c != "" {
				return fmt.Errorf("%q is a link into %s, a dot-directory under a home or runtime directory, where keys and tokens live", p, c)
			}
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

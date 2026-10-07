package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Opening pool content where nosymfollow is missing.
//
// An NFS export's server decides what is on it, symlinks included. A pool
// mount carries nosymfollow wherever the kernel has it (Linux 5.10+), and then
// the kernel follows none of them. On an older kernel the pool is still used
// (it was on every build before the hardening), mounted with the other
// options, and the daemon's own opens of pool content follow no symlink on
// the export instead: the path is resolved through the host's own symlinks
// down to the mount point, and from there opened one component at a time
// with no symlink followed (openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH, or an
// O_NOFOLLOW walk where openat2 is missing). Everywhere else these are the
// plain os calls.

// errPoolSymlink is what an open that met a symlink on an export without
// nosymfollow returns (wrapped with the path).
var errPoolSymlink = errors.New("a symlink on an NFS export mounted without nosymfollow is never followed")

// unhardenedNFSMounts returns the mount points whose top mount is NFS without
// nosymfollow. Empty when there are none, which is the common case and costs
// one read of the mount table.
func unhardenedNFSMounts() (map[string]bool, error) {
	all, err := mounts()
	if err != nil {
		return nil, err
	}
	top := map[string]mountEntry{}
	for _, e := range all {
		top[e.dir] = e
	}
	out := map[string]bool{}
	for dir, e := range top {
		if isNFSFstype(e.fstype) && !containsFlag(e.flags, "nosymfollow") {
			out[dir] = true
		}
	}
	return out, nil
}

func containsFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// splitPath splits a cleaned path into its components, without empty ones.
func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, string(filepath.Separator)) {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// poolPathBeneath resolves path through this host's own symlinks until it
// reaches the mount point of an NFS export without nosymfollow. ok: path is on
// such an export, at rel below root (root is the mount point, with no symlink
// in it). Not ok: path is on no such export, and is opened as usual. A symlink
// on the export itself is never resolved here.
func poolPathBeneath(path string) (root, rel string, ok bool, err error) {
	tops, err := unhardenedNFSMounts()
	if err != nil {
		return "", "", false, fmt.Errorf("read the mount table: %w", err)
	}
	if len(tops) == 0 {
		return "", "", false, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", false, err
	}
	comps := splitPath(abs)
	cur := string(filepath.Separator)
	hops := 0
	for {
		if tops[cur] {
			for _, c := range comps {
				if c == ".." {
					return "", "", false, fmt.Errorf("%s: %w", path, errPoolSymlink)
				}
			}
			rel = strings.Join(comps, string(filepath.Separator))
			if rel == "" {
				rel = "."
			}
			return cur, rel, true, nil
		}
		if len(comps) == 0 {
			return "", "", false, nil
		}
		c := comps[0]
		comps = comps[1:]
		if c == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, lerr := os.Lstat(next)
		if lerr != nil || fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		// A symlink of this host's own (not on an unhardened export: that
		// would have been reached above): followed, as the kernel would.
		hops++
		if hops > 40 {
			return "", "", false, fmt.Errorf("%s: %w", path, syscall.ELOOP)
		}
		target, rerr := os.Readlink(next)
		if rerr != nil {
			return "", "", false, rerr
		}
		if filepath.IsAbs(target) {
			cur = string(filepath.Separator)
		}
		comps = append(splitPath(filepath.Clean(target)), comps...)
	}
}

// OpenPoolFile is os.OpenFile for a file in a storage pool. On an NFS export
// mounted without nosymfollow, no symlink on the export is followed (the open
// fails instead); anywhere else it is os.OpenFile.
func OpenPoolFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	root, rel, ok, err := poolPathBeneath(path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return os.OpenFile(path, flag, perm)
	}
	f, err := openBeneath(root, rel, flag, perm, path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}

// ReadPoolFile is os.ReadFile through OpenPoolFile.
func ReadPoolFile(path string) ([]byte, error) {
	f, err := OpenPoolFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// CreatePoolTemp is os.CreateTemp(dir, pattern) for a directory in a storage
// pool: a new file (O_EXCL, 0600), opened as OpenPoolFile opens. The file's
// Name is dir joined with the name made.
func CreatePoolTemp(dir, pattern string) (*os.File, error) {
	if _, _, ok, err := poolPathBeneath(dir); err != nil {
		return nil, err
	} else if !ok {
		return os.CreateTemp(dir, pattern)
	}
	prefix, suffix, _ := strings.Cut(pattern, "*")
	if !strings.Contains(pattern, "*") {
		suffix = ""
	}
	for i := 0; i < 10000; i++ {
		var r [6]byte
		if _, err := rand.Read(r[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(r[:])+suffix)
		f, err := OpenPoolFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &fs.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: fs.ErrExist}
}

// CheckPoolPathNoSymlinks refuses a path, on an NFS export mounted without
// nosymfollow, any existing component of which below the mount point is a
// symlink: for a pool file handed by name to a tool (qemu-img) that would
// follow it. Anywhere else: nil.
func CheckPoolPathNoSymlinks(path string) error {
	root, rel, ok, err := poolPathBeneath(path)
	if err != nil || !ok {
		return err
	}
	cur := root
	for _, c := range splitPath(rel) {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s: %w", cur, errPoolSymlink)
		}
	}
	return nil
}

// openBeneath opens rel below root following no symlink: openat2 where the
// kernel has it, an O_NOFOLLOW walk otherwise. name is the File's name.
func openBeneath(root, rel string, flag int, perm os.FileMode, name string) (*os.File, error) {
	f, err := openat2Beneath(root, rel, flag, perm, name)
	if !errors.Is(err, errNoOpenat2) {
		return f, err
	}
	return walkNoFollow(root, rel, flag, perm, name)
}

// errNoOpenat2: the kernel (before 5.6) or the OS has no openat2.
var errNoOpenat2 = errors.New("openat2 unavailable")

// walkNoFollow opens rel below root one component at a time, every one
// O_NOFOLLOW: a directory that is a symlink fails with ELOOP or ENOTDIR, and
// so does a final component that is one.
func walkNoFollow(root, rel string, flag int, perm os.FileMode, name string) (*os.File, error) {
	comps := splitPath(rel)
	if len(comps) == 0 {
		return nil, syscall.EISDIR
	}
	dfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, c := range comps[:len(comps)-1] {
		if c == ".." {
			unix.Close(dfd)
			return nil, errPoolSymlink
		}
		nfd, err := unix.Openat(dfd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dfd)
		if err != nil {
			return nil, err
		}
		dfd = nfd
	}
	last := comps[len(comps)-1]
	if last == ".." {
		unix.Close(dfd)
		return nil, errPoolSymlink
	}
	fd, err := unix.Openat(dfd, last, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	unix.Close(dfd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// kernelAtLeast parses a release string ("5.4.0-150-generic", "4.18.0-553.el8")
// and compares its major.minor.
func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return true
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi := parts[1]
	if i := strings.IndexFunc(mi, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		mi = mi[:i]
	}
	mn, err2 := strconv.Atoi(mi)
	if err1 != nil || err2 != nil {
		return true
	}
	return ma > major || (ma == major && mn >= minor)
}

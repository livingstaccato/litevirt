package grpcapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/diskmode"
)

// errBeneath is the answer of openPinnedDir for a directory that is not
// reachable below its root without following a link (or that leaves it).
var errBeneath = errors.New("a path component is a link or leaves the disk root")

// openat2Disabled makes openPinnedDir take the per-component O_NOFOLLOW walk a
// kernel older than 5.6 (no openat2) takes. Tests only.
var openat2Disabled bool

// pinnedDir is a directory held open by descriptor. Its dir() and path(name)
// are /proc/self/fd/<n> forms: the kernel resolves them to THAT directory,
// whatever happens to the names that led to it afterwards, so every create,
// link, rename and unlink through them is relative to the directory that was
// judged (the same as openat, linkat, renameat and unlinkat on the descriptor)
// while the code that makes them stays path-shaped. name is a single file
// name, never a path.
type pinnedDir struct{ f *os.File }

func (d *pinnedDir) dir() string { return "/proc/self/fd/" + strconv.Itoa(int(d.f.Fd())) }

func (d *pinnedDir) path(name string) string { return d.dir() + "/" + name }

func (d *pinnedDir) close() {
	if d != nil && d.f != nil {
		d.f.Close()
	}
}

// relUnder is dir as a path below root ("." for root itself).
func relUnder(root, dir string) string {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return ".."
	}
	return rel
}

// openPinnedDir opens the directory rel below rootFS and holds it. rootFS is
// the disk root itself (an operator's own directory: its symlinks are
// resolved, so a disks/ that is a link to a bigger volume works); rel is
// walked one component at a time with no symlink followed and never leaving
// the root (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS,
// or O_NOFOLLOW|O_DIRECTORY openat where the kernel has no openat2). With
// create, the root and each missing component are made (mkdirat on the
// descriptor of its parent). A component that is a link, not a directory, or
// outside the root is errBeneath.
func openPinnedDir(rootFS, rel string, create bool) (*pinnedDir, error) {
	if create {
		if err := diskmode.MkdirAll(rootFS); err != nil {
			return nil, err
		}
	}
	real, err := filepath.EvalSymlinks(rootFS)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(real, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
		if c == "" || c == "." {
			continue
		}
		if c == ".." || strings.ContainsRune(c, 0) {
			unix.Close(fd)
			return nil, errBeneath
		}
		if create {
			if err := unix.Mkdirat(fd, c, uint32(diskmode.Dir)); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return nil, err
			}
		}
		next, err := openBeneath(fd, c)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return &pinnedDir{f: os.NewFile(uintptr(fd), real)}, nil
}

// openBeneath opens the single component name of the directory dirfd as a
// directory, following no link.
func openBeneath(dirfd int, name string) (int, error) {
	if !openat2Disabled {
		fd, err := unix.Openat2(dirfd, name, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM):
			// No openat2 here (kernel before 5.6) or a sandbox that refuses
			// it: the component walk below is the same rule.
		default:
			return -1, beneathErr(name, err)
		}
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, beneathErr(name, err)
	}
	return fd, nil
}

// beneathErr maps the errors a link, a non-directory or an escape cause to
// errBeneath; anything else (absent, no permission) is as it was.
func beneathErr(name string, err error) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EXDEV):
		return fmt.Errorf("%w: %s", errBeneath, name)
	}
	return err
}

// removeBeneath removes the file p (a path below root) through the directory
// pinned by openPinnedDir, never through a link. A directory that is not there
// is a file that is not there.
func removeBeneath(rootFS, root, p string) error {
	pd, err := openPinnedDir(rootFS, relUnder(root, filepath.Dir(p)), false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer pd.close()
	if err := os.Remove(pd.path(filepath.Base(p))); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

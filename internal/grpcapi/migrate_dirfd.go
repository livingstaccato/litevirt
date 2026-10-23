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
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// errBeneath is the answer of openPinnedDir for a directory that is not
// reachable below its root without following a link (or that leaves it), or
// whose root is not one this host lets a disk live in.
var errBeneath = errors.New("a path component is a link or leaves the disk root")

// errNoProcFD is the answer when /proc/self/fd cannot be used: nothing is
// written, read or removed through a directory it cannot name.
var errNoProcFD = errors.New("/proc/self/fd is not usable, so a held directory cannot be named")

// openat2Disabled makes openPinnedDir take the per-component O_NOFOLLOW walk a
// kernel older than 5.6 (no openat2) takes. Tests only.
var openat2Disabled bool

// SetEnsureStubCreatedHookForTest runs fn after EnsureDisks creates a stub and
// before it creates the next (tests: swap a directory for a link there).
func (s *Server) SetEnsureStubCreatedHookForTest(fn func()) { s.ensureStubCreatedHook = fn }

// procFDPrefix is where the held directory's /proc form lives; a test points it
// somewhere that does not exist to stand in for a host without /proc.
var procFDPrefix = "/proc/self/fd/"

// pinnedDir is a directory held open by descriptor. Its dir() and path(name)
// are /proc/self/fd/<n> forms: the kernel resolves them to THAT directory,
// whatever happens to the names that led to it afterwards, so every create,
// link, rename and unlink through them is relative to the directory that was
// judged (the same as openat, linkat, renameat and unlinkat on the descriptor)
// while the code that makes them stays path-shaped. name is a single file
// name, never a path. A removal does not use the /proc form: it is unlinkat on
// the descriptor (unlink).
type pinnedDir struct{ f *os.File }

func (d *pinnedDir) dir() string { return procFDPrefix + strconv.Itoa(int(d.f.Fd())) }

func (d *pinnedDir) path(name string) string { return d.dir() + "/" + name }

func (d *pinnedDir) close() {
	if d != nil && d.f != nil {
		d.f.Close()
	}
}

// unlink removes the file name (a single file name) in the held directory,
// with unlinkat on its descriptor; a file that is not there is not an error.
func (d *pinnedDir) unlink(name string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return errBeneath
	}
	if err := unix.Unlinkat(int(d.f.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "unlinkat", Path: name, Err: err}
	}
	return nil
}

// relUnder is dir as a path below root ("." for root itself).
func relUnder(root, dir string) string {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return ".."
	}
	return rel
}

// openPinnedDir is openPinnedDirChecked with no judgement of the root.
func openPinnedDir(rootFS, rel string, create bool) (*pinnedDir, error) {
	return openPinnedDirChecked(rootFS, rel, create, nil)
}

// openPinnedDirChecked opens the directory rel below rootFS and holds it.
// rootFS is the disk root itself: its symlinks are resolved (a disks/ that is a
// link to a bigger volume works), and when check is not nil the path the opened
// root descriptor actually names is handed to it, so a root that is a link is
// judged for what it leads to, without a race (readlink of the descriptor,
// not of a name). rel is then walked one component at a time with no symlink
// followed and never leaving the root (openat2
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, or
// O_NOFOLLOW|O_DIRECTORY openat where the kernel has no openat2). With create,
// the root and each missing component are made (mkdirat on the descriptor of
// its parent). A component that is a link, not a directory, or outside the
// root is errBeneath; a root the check refuses is errBeneath too. When
// /proc/self/fd cannot name the held directory, nothing is opened (errNoProcFD).
func openPinnedDirChecked(rootFS, rel string, create bool, check func(realFS string) error) (*pinnedDir, error) {
	return openPinnedDirAnchored(rootFS, "", rel, create, create, check)
}

// rootOpenHook runs between resolving the anchor and opening it (tests).
var rootOpenHook func()

// openPinnedDirAnchored is openPinnedDirChecked for a root that lies below an
// anchor the operator owns (a data-dir area): the anchor is opened (made first
// when mkAnchor), anchorRel is walked from it to the root with each missing
// component made by mkdirat on its parent's descriptor and no link followed,
// and only then is the root judged and rel walked. A root that is a link, or
// has a link on the way from the anchor, is refused before anything is created
// through it. With no anchorRel the anchor is the root itself.
func openPinnedDirAnchored(anchorFS, anchorRel, rel string, create, mkAnchor bool, check func(realFS string) error) (*pinnedDir, error) {
	if create && mkAnchor {
		if err := diskmode.MkdirAll(anchorFS); err != nil {
			return nil, err
		}
	}
	real, err := filepath.EvalSymlinks(anchorFS)
	if err != nil {
		return nil, err
	}
	if rootOpenHook != nil {
		rootOpenHook()
	}
	fd, err := unix.Open(real, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	walk := func(rel string) error {
		for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
			if c == "" || c == "." {
				continue
			}
			if c == ".." || strings.ContainsRune(c, 0) {
				unix.Close(fd)
				return errBeneath
			}
			if create {
				if err := unix.Mkdirat(fd, c, uint32(diskmode.Dir)); err != nil && !errors.Is(err, unix.EEXIST) {
					unix.Close(fd)
					return err
				}
			}
			next, err := openBeneath(fd, c)
			unix.Close(fd)
			if err != nil {
				return err
			}
			fd = next
		}
		return nil
	}
	if err := walk(anchorRel); err != nil {
		return nil, err
	}
	if check != nil {
		named, lerr := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if lerr != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("%w: %v", errNoProcFD, lerr)
		}
		if cerr := check(named); cerr != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("%w: %v", errBeneath, cerr)
		}
	}
	if err := walk(rel); err != nil {
		return nil, err
	}
	pd := &pinnedDir{f: os.NewFile(uintptr(fd), real)}
	// Every path-shaped use of the held directory goes through its /proc form;
	// without /proc it names nothing (or, worse, reads as "no such file"), so
	// refuse here, once, rather than let a removal report a file gone.
	if fi, serr := os.Stat(pd.dir()); serr != nil || !fi.IsDir() {
		pd.close()
		return nil, fmt.Errorf("%w: %v", errNoProcFD, serr)
	}
	return pd, nil
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

// diskRootCheck is the judgement of what a disk root's descriptor names (see
// openPinnedDirChecked) for the root logical path root; mapped is whether the
// per-node test root applies (hostDiskFile). A root that is a data-dir area
// (disks/, pools/, mounts/) is the operator's own, link or not. A root below an
// area (pools/<name>, mounts/<export>/<dir>) must still lie inside that area
// once resolved: a pool directory swapped for a link to somewhere else is not
// followed. A root outside the areas (an operator's own pool directory) may be
// a link to another volume, if where it leads is a directory a pool may be in
// (storage.CheckWriteRoot).
func (s *Server) diskRootCheck(root string, mapped bool) func(string) error {
	return func(namedFS string) error {
		named := namedFS
		if mapped && s.hostDiskRoot != "" {
			named = "/" + strings.TrimPrefix(strings.TrimPrefix(namedFS, filepath.Clean(s.hostDiskRoot)), "/")
		}
		for _, area := range []string{"disks", "pools", "mounts"} {
			ar := filepath.Join(s.dataDir, area)
			if filepath.Clean(root) == ar {
				return nil
			}
			if safename.Contains(ar, root) {
				resolved, err := filepath.EvalSymlinks(s.rootFS(ar, mapped))
				if err != nil {
					return err
				}
				if !safename.Contains(resolved, namedFS) {
					return fmt.Errorf("disk root %s leads to %s, outside %s", root, named, ar)
				}
				return nil
			}
		}
		if err := storage.CheckWriteRoot(named, s.dataDir, s.pkiDir); err != nil {
			return fmt.Errorf("disk root %s leads to %s: %w", root, named, err)
		}
		return nil
	}
}

// rootFS is the file-system path of the logical path p.
func (s *Server) rootFS(p string, mapped bool) string {
	if mapped {
		return s.hostDiskFile(p)
	}
	return p
}

// openDiskDir holds open the directory rel below the disk root root, judging
// the root (diskRootCheck).
func (s *Server) openDiskDir(root, rel string, create, mapped bool) (*pinnedDir, error) {
	if create {
		// A root below a data-dir area is made from the area's own descriptor,
		// level by level with no link followed, so a link on the way is refused
		// before anything is created through it.
		for _, area := range []string{"disks", "pools", "mounts"} {
			ar := filepath.Join(s.dataDir, area)
			if safename.Contains(ar, root) {
				return openPinnedDirAnchored(s.rootFS(ar, mapped), relUnder(ar, root), rel, true, true, s.diskRootCheck(root, mapped))
			}
		}
	}
	return openPinnedDirChecked(s.rootFS(root, mapped), rel, create, s.diskRootCheck(root, mapped))
}

// removeUnderRoot removes the file p (below the disk root root) through the
// directory held open beneath it (unlinkat), never through a link. A directory
// that is not there is a file that is not there.
func (s *Server) removeUnderRoot(root, p string, mapped bool) error {
	pd, err := s.openDiskDir(root, relUnder(root, filepath.Dir(p)), false, mapped)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer pd.close()
	return pd.unlink(filepath.Base(p))
}

// removeDiskFileBeneath removes the file at p, which lies in one of this
// host's disk roots, through its held directory. mapped is whether p is a
// logical path the per-node test root maps (hostDiskFile), as the cold-move and
// firmware paths do; EnsureDisks names the file itself.
func (s *Server) removeDiskFileBeneath(p string, mapped bool) error {
	root, ok := s.diskArtifactRootOf(p)
	if !ok {
		return fmt.Errorf("%s is not in a disk-artifact root of %s", p, s.hostName)
	}
	return s.removeUnderRoot(root, p, mapped)
}

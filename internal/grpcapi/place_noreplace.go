package grpcapi

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// noReplacePlace gives the file at tmp the name dst and drops tmp's own name,
// never replacing a file at dst: an existing dst is an error satisfying
// errors.Is(err, fs.ErrExist), and keeps its bytes. It is the one no-clobber
// placement every flow uses (placeNoClobber, placeColdDisk, the import's
// linkOrRenameNoReplace); they differ only in which call they try first.
//
// The two calls are a hard link, which refuses an existing name atomically
// (on an NFS server too), and renameat2(RENAME_NOREPLACE), which the Linux
// NFS client answers EINVAL. The second is tried only when the first was
// refused because the filesystem cannot do it (linkUnsupported,
// renameUnsupported); any other refusal is returned as it is. unsupported
// reports a filesystem that can do neither; err then names both refusals.
// A plain rename, which could replace a file, is never used.
func noReplacePlace(tmp, dst string, linkFirst bool) (unsupported bool, err error) {
	if linkFirst {
		lerr := linkIntoPlace(tmp, dst)
		if lerr == nil || errors.Is(lerr, fs.ErrExist) || !linkUnsupported(lerr) {
			return false, lerr
		}
		rerr := coldRenameNoReplace(tmp, dst)
		if rerr == nil || errors.Is(rerr, fs.ErrExist) || !renameUnsupported(rerr) {
			return false, rerr
		}
		return true, neitherPlacement(dst, lerr, rerr)
	}
	rerr := coldRenameNoReplace(tmp, dst)
	if rerr == nil || errors.Is(rerr, fs.ErrExist) || !renameUnsupported(rerr) {
		return false, rerr
	}
	lerr := linkIntoPlace(tmp, dst)
	if lerr == nil || errors.Is(lerr, fs.ErrExist) || !linkUnsupported(lerr) {
		return false, lerr
	}
	return true, neitherPlacement(dst, lerr, rerr)
}

// linkIntoPlace hard-links tmp at dst, then removes tmp's name.
//
// An NFS link whose reply was lost is retransmitted and answered EEXIST
// although the first one made the link: dst is then tmp itself, and placed.
// Once the link has given the file its name it is placed: a tmp name that
// then cannot be removed is logged and left for the sweep of its pattern, so
// a retry is not refused over a file that is the copy itself.
func linkIntoPlace(tmp, dst string) error {
	err := coldLink(tmp, dst)
	if err != nil && errors.Is(err, fs.ErrExist) && sameFileAt(tmp, dst) {
		err = nil
	}
	if err != nil {
		return err
	}
	if rerr := coldRemove(tmp); rerr != nil {
		slog.Warn("placed a file by a hard link but could not remove its temporary name",
			"temp", tmp, "path", dst, "error", rerr)
	}
	return nil
}

// sameFileAt reports whether a and b are both names of one file (neither
// followed through a symlink).
func sameFileAt(a, b string) bool {
	fa, err := os.Lstat(a)
	if err != nil {
		return false
	}
	fb, err := os.Lstat(b)
	return err == nil && os.SameFile(fa, fb)
}

// linkUnsupported is a link() refused because the filesystem cannot make
// hard links (link(2): EPERM; FUSE and others: ENOTSUP, EOPNOTSUPP, ENOSYS,
// EINVAL; EXDEV where the filesystem presents one directory as several).
func linkUnsupported(err error) bool {
	return errnoIn(err, syscall.EPERM, syscall.EXDEV, syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EINVAL, syscall.ENOSYS)
}

// renameUnsupported is a renameat2(RENAME_NOREPLACE) refused because the
// filesystem cannot do the flag (the Linux NFS client and most others answer
// EINVAL). EPERM and EXDEV are not: they come from permissions or a
// cross-mount rename, which a link would not get past either, and are
// returned as they are.
func renameUnsupported(err error) bool {
	return errnoIn(err, syscall.EINVAL, syscall.ENOSYS, syscall.ENOTSUP, syscall.EOPNOTSUPP)
}

func errnoIn(err error, errnos ...syscall.Errno) bool {
	for _, e := range errnos {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// neitherPlacement is the refusal of a filesystem that can do neither call.
func neitherPlacement(dst string, lerr, rerr error) error {
	return fmt.Errorf("the filesystem holding %s supports neither hard links (%v) nor a rename that cannot replace a file (%v)",
		filepath.Dir(dst), lerr, rerr)
}

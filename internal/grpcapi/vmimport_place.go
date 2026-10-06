package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"
)

// placeNoReplace gives the file at src the name dst and removes src, never
// replacing a file at dst: an existing dst is an error satisfying
// errors.Is(err, os.ErrExist), and keeps its bytes.
//
// A hard link is tried first, then renameat2(RENAME_NOREPLACE). A filesystem
// that has neither (some FUSE filesystems) gets the file copied into a dst
// created exclusively (O_EXCL, never following a link), which cannot replace a
// file either; it costs a second write where nothing cheaper is safe.
func placeNoReplace(src, dst string) error {
	lerr := coldLink(src, dst)
	if lerr == nil {
		_ = coldRemove(src)
		return nil
	}
	if errors.Is(lerr, os.ErrExist) || !placementUnsupported(lerr) {
		return lerr
	}
	rerr := coldRenameNoReplace(src, dst)
	if rerr == nil || errors.Is(rerr, os.ErrExist) || !placementUnsupported(rerr) {
		return rerr
	}
	if err := copyExclusive(src, dst); err != nil {
		return fmt.Errorf("neither a hard link (%v) nor a rename that cannot replace a file (%v), and copying: %w", lerr, rerr, err)
	}
	return nil
}

// placementUnsupported is a link or rename refused because the filesystem
// cannot do it, not because of the files.
func placementUnsupported(err error) bool {
	for _, e := range []error{syscall.EPERM, syscall.EXDEV, syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EINVAL, syscall.ENOSYS} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// copyExclusive copies src into a new file dst, keeping holes, its
// modification time and its import origin, and then removes src. A dst that
// exists is never opened.
func copyExclusive(src, dst string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, fi.Mode().Perm())
	if err != nil {
		return err
	}
	fail := func(err error) error {
		out.Close()
		_ = os.Remove(dst) // created above, exclusively: ours
		return err
	}
	if err := copySparse(context.Background(), out, in, math.MaxInt64); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if o, ok := getImportOrigin(src); ok {
		_ = setImportOrigin(dst, o)
	}
	_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
	return os.Remove(src)
}

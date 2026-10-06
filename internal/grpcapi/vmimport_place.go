package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
// file either; it costs a second write where nothing cheaper is safe. That
// write is announced to copying first, with its size, and a copying error
// refuses it; the copy stops when ctx ends.
func placeNoReplace(ctx context.Context, src, dst string, copying func(n uint64) error) error {
	unsupported, err := linkOrRenameNoReplace(src, dst)
	if !unsupported {
		return err
	}
	if cerr := copyExclusive(ctx, src, dst, copying); cerr != nil {
		return fmt.Errorf("%v, and copying: %w", err, cerr)
	}
	return nil
}

// linkOrRenameNoReplace gives src the name dst with link() (then removing
// src) or renameat2(RENAME_NOREPLACE). unsupported is a filesystem that can do
// neither; err then says why.
func linkOrRenameNoReplace(src, dst string) (unsupported bool, err error) {
	lerr := coldLink(src, dst)
	if lerr == nil {
		_ = coldRemove(src)
		return false, nil
	}
	if errors.Is(lerr, os.ErrExist) || !placementUnsupported(lerr) {
		return false, lerr
	}
	rerr := coldRenameNoReplace(src, dst)
	if rerr == nil || errors.Is(rerr, os.ErrExist) || !placementUnsupported(rerr) {
		return false, rerr
	}
	return true, fmt.Errorf("neither a hard link (%v) nor a rename that cannot replace a file (%v)", lerr, rerr)
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

// placeCopy copies a file's bytes for copyExclusive; a variable so a test can
// act while it runs.
var placeCopy = copySparse

// removeIfSame removes p only while it is still the file fi describes: a file
// another flow put at the name meanwhile keeps it.
func removeIfSame(p string, fi os.FileInfo) error {
	cur, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !os.SameFile(cur, fi) {
		return fmt.Errorf("%s is no longer the file it was; left in place", p)
	}
	return os.Remove(p)
}

// copyExclusive copies src into a new file dst, keeping holes, its
// modification time and its import origin, and then removes src. A dst that
// exists is never opened. The copy is announced to copying before dst is
// created, and stops when ctx ends. Neither name is removed once another file
// has taken it.
func copyExclusive(ctx context.Context, src, dst string, copying func(n uint64) error) error {
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
	if copying != nil {
		if err := copying(uint64(fi.Size())); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, fi.Mode().Perm())
	if err != nil {
		return err
	}
	ofi, err := out.Stat()
	if err != nil {
		out.Close()
		return err // created exclusively, but not known well enough to remove
	}
	fail := func(err error) error {
		out.Close()
		_ = removeIfSame(dst, ofi)
		return err
	}
	if err := placeCopy(ctx, out, in, math.MaxInt64); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		_ = removeIfSame(dst, ofi)
		return err
	}
	if o, ok := getImportOrigin(src); ok {
		_ = setImportOrigin(dst, o)
	}
	_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
	// The copy is placed. Its source goes only while its name still holds
	// the file copied: a file another flow put there meanwhile is theirs.
	if err := removeIfSame(src, fi); err != nil {
		slog.Warn("import: a placed copy's source was not removed", "src", src, "dst", dst, "error", err)
	}
	return nil
}

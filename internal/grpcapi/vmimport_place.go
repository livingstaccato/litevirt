package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"syscall"
)

// placeNoReplace gives the file at src the name dst and removes src, never
// replacing a file at dst: an existing dst is an error satisfying
// errors.Is(err, os.ErrExist), and keeps its bytes.
//
// A hard link is tried first, then renameat2(RENAME_NOREPLACE). A filesystem
// that has neither (some FUSE filesystems) gets the file copied (see
// copyIntoPlace), which cannot replace a file either; it costs a second write
// where nothing cheaper is safe. w, when set, is told of the copy as of any
// file the import writes.
func placeNoReplace(ctx context.Context, src, dst string, w *importDiskWrites) error {
	unsupported, err := linkOrRenameNoReplace(src, dst)
	if !unsupported {
		return err
	}
	if cerr := copyIntoPlace(ctx, src, dst, w); cerr != nil {
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

// placeCopy copies a file's bytes for copyIntoPlace; a variable so a test can
// act while it runs.
var placeCopy = copySparse

// placeRename is the rename copyIntoPlace puts its copy in place with; a
// variable so a test can stand in a filesystem whose rename cannot replace.
var placeRename = os.Rename

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

// copyIntoPlace copies src to dst on a filesystem with neither link() nor
// RENAME_NOREPLACE. The copy is announced to w (copying) with its size first,
// and stops when ctx ends.
//
// It is written into a fresh temp name beside dst, created exclusively and
// recorded (w.created) before its first byte, so a crash mid-copy leaves a
// partial at a name no flow writes, which a re-import knows dead and removes.
// Only the finished, flushed copy takes dst's name: dst is first created
// empty and exclusively (an existing dst is ErrExist, and never opened), the
// copy's state is recorded for dst (w.placing), and the copy is renamed over
// that empty file while dst still is it. dst is never written in place.
//
// Neither src nor a temp is removed once another file has taken its name.
func copyIntoPlace(ctx context.Context, src, dst string, w *importDiskWrites) error {
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
	if err := w.copy(uint64(fi.Size())); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".place-*")
	if err != nil {
		return err
	}
	temp := out.Name()
	tfi, err := out.Stat()
	if err != nil {
		out.Close()
		return err // created exclusively, but not known well enough to remove
	}
	w.didCreate(temp)
	dropTemp := func() {
		_ = removeIfSame(temp, tfi)
		w.discard(temp)
	}
	fail := func(err error) error {
		out.Close()
		dropTemp()
		return err
	}
	if err := out.Chmod(fi.Mode().Perm()); err != nil {
		return fail(err)
	}
	if err := placeCopy(ctx, out, in, math.MaxInt64); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		dropTemp()
		return err
	}
	_ = os.Chtimes(temp, fi.ModTime(), fi.ModTime())
	cur, err := os.Lstat(temp)
	if err != nil || !os.SameFile(cur, tfi) {
		w.discard(temp)
		return fmt.Errorf("the copy at %s is no longer the file written; left in place", temp)
	}
	// Recorded for dst first (a durable write), so the moments between
	// taking the name and putting the copy there hold no slow step.
	w.willPlace(dst, cur)
	// Take dst's name exclusively, then put the copy there.
	hold, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, fi.Mode().Perm())
	if err != nil {
		w.discard(dst)
		dropTemp()
		return err
	}
	hfi, err := hold.Stat()
	hold.Close()
	if err != nil {
		w.discard(dst)
		dropTemp()
		return err
	}
	if now, err := os.Lstat(dst); err != nil || !os.SameFile(now, hfi) {
		w.discard(dst)
		dropTemp()
		return fmt.Errorf("%s was replaced while the copy took its name: %w", dst, os.ErrExist)
	}
	if err := placeRename(temp, dst); err != nil {
		// A filesystem whose rename cannot replace a file (SFTP without
		// the OpenSSH extensions): free the name of the empty placeholder
		// and rename once more. There that rename cannot replace a file
		// either, which is what this path needs.
		if ctx.Err() != nil || removeIfSame(dst, hfi) != nil {
			w.discard(dst)
			dropTemp()
			return err
		}
		if err2 := placeRename(temp, dst); err2 != nil {
			w.discard(dst)
			dropTemp()
			if errors.Is(err2, syscall.EEXIST) {
				return fmt.Errorf("%v; %s appeared meanwhile: %w", err, dst, os.ErrExist)
			}
			return fmt.Errorf("%v; and onto the free name: %w", err, err2)
		}
	}
	w.discard(temp)
	// The copy is placed. Its source goes only while its name still holds
	// the file copied: a file another flow put there meanwhile is theirs.
	if err := removeIfSame(src, fi); err != nil {
		slog.Warn("import: a placed copy's source was not removed", "src", src, "dst", dst, "error", err)
	}
	return nil
}

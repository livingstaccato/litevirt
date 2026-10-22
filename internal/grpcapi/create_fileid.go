package grpcapi

import (
	"os"
	"syscall"
)

// pinnedFile is a file a create (or a clone, or a cold-copy receive) made,
// held open from right after it was made until the create returns: its seed,
// each host-local disk or copy it wrote, and the copy a receive placed. Its device and inode then name that file and no other for as
// long as the create could compare them: the kernel does not free an inode
// while a descriptor holds it, even once its last name is removed, so no file
// made at the path since can be given its number (on ext4, xfs and btrfs, and
// on NFS, where the client keeps an open file it unlinks under a silly-rename
// name). A device and inode merely read and kept can be reused once the file
// goes, and then name the new one; a birth time beside them does not tell the
// two apart where the filesystem keeps none (NFS) or stamps both in one tick.
type pinnedFile struct {
	f  *os.File
	fi os.FileInfo
}

// pinFile opens p and holds it. O_NOFOLLOW and O_NONBLOCK: a link or a FIFO
// planted at p is not followed or waited on.
func pinFile(p string) (*pinnedFile, bool) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, false
	}
	return &pinnedFile{f: f, fi: fi}, true
}

// stillAt reports whether the file at p is still the pinned one.
func (pf *pinnedFile) stillAt(p string) bool {
	if pf == nil {
		return false
	}
	now, err := os.Lstat(p)
	return err == nil && os.SameFile(now, pf.fi)
}

// release closes the pinned file; a nil one is a no-op.
func (pf *pinnedFile) release() {
	if pf != nil {
		pf.f.Close()
	}
}

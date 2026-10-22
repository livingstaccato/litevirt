package grpcapi

import (
	"os"
	"syscall"
)

// madeFileID is a file a create (or clone) made, as it was right after it was
// made: its device and inode, and where the filesystem records one its birth
// time. A failed create removes a path only while the file there is still
// this one. The inode alone is not enough: ext4 and xfs often give a file
// unlinked and recreated at the same path the same inode number, so a file
// another made there since would read as this create's own. The birth time
// tells them apart; where the filesystem keeps none (fileBirth is zero) the
// inode is all there is, and the comparison is that weak.
type madeFileID struct {
	fi    os.FileInfo
	birth int64
}

// madeFileIdentity reads p's identity now.
func madeFileIdentity(p string) (madeFileID, bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return madeFileID{}, false
	}
	return madeFileID{fi: fi, birth: fileBirth(p)}, true
}

// stillAt reports whether the file at p is still id's.
func (id madeFileID) stillAt(p string) bool {
	now, ok := madeFileIdentity(p)
	if !ok || id.fi == nil || !os.SameFile(now.fi, id.fi) {
		return false
	}
	return id.birth == 0 || now.birth == 0 || id.birth == now.birth
}

// pinnedFile is a file a create made, held open from right after it was made
// until the create returns. Its device and inode then name that file and no
// other for as long as the create could compare them: the kernel does not
// free an inode while a descriptor holds it, even once its last name is
// removed, so no file made at the path since can be given its number (on
// ext4, xfs and btrfs, and on NFS, where the client keeps an open file it
// unlinks under a silly-rename name). A device and inode merely read and kept
// (madeFileID) can be reused once the file goes, and then name the new one.
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

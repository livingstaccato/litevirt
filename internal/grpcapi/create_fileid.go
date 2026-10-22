package grpcapi

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"google.golang.org/grpc/status"
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
func pinFile(p string) (*pinnedFile, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", p)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &pinnedFile{f: f, fi: fi}, nil
}

// pinDir opens the directory p and holds it, as pinFile does a file.
func pinDir(p string) (*pinnedFile, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &pinnedFile{f: f, fi: fi}, nil
}

// pinMade pins a file a create or clone just made (pinFile), failing as
// s.pinFault says first where a test set it.
func (s *Server) pinMade(p string) (*pinnedFile, error) {
	if s.pinFault != nil {
		if err := s.pinFault(p); err != nil {
			return nil, err
		}
	}
	return pinFile(p)
}

// pinMadeDir is pinMade for a directory a create just made (pinDir).
func (s *Server) pinMadeDir(p string) (*pinnedFile, error) {
	if s.pinFault != nil {
		if err := s.pinFault(p); err != nil {
			return nil, err
		}
	}
	return pinDir(p)
}

// stillAt reports whether the file at p is still the pinned one.
func (pf *pinnedFile) stillAt(p string) bool {
	if pf == nil {
		return false
	}
	now, err := os.Lstat(p)
	return err == nil && os.SameFile(now, pf.fi)
}

// release closes the pinned file; a nil one is a no-op. A file is released
// as soon as it is removed: the pin protects nothing once the file is gone,
// and on NFS a removed file still held lingers at a .nfsXXXX name, taking its
// full size, until it is released.
func (pf *pinnedFile) release() {
	if pf != nil {
		pf.f.Close()
	}
}

// withLeftovers adds to a failed create's or clone's error the files it made
// and leaves (left), so the operator sees them and not only the daemon log:
// a retry of the name may meet them. The error's code is kept.
func withLeftovers(err error, op string, left []string) error {
	if err == nil || len(left) == 0 {
		return err
	}
	st := status.Convert(err)
	return status.Errorf(st.Code(), "%s; the failed %s left what it made: %s (remove each once nothing uses it)",
		st.Message(), op, strings.Join(left, "; "))
}

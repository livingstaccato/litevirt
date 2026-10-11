// Package diskmode is the one place the permission bits of VM disk files, and
// of the directories litevirt makes to hold them, are decided.
//
// A disk file is the guest's data, so it is the owner's alone: File (0600).
// Nobody but the owner has to open one. The daemon is root. qemu runs as the
// distro's qemu user, and libvirt's DAC driver (dynamic_ownership, the
// default) chowns every image of a disk's chain to that user when the domain
// starts — so qemu opens it as its owner. Main already made most of its disk
// files this way (every temp converted and renamed into a disk, and every
// pulled base image), and those start.
//
// A directory holding disks is Dir (0711): searchable by every user, listable
// by none but root. libvirt labels the files and never the directories above
// them, so a non-root qemu must be able to resolve a path through each one;
// 0700 would refuse it before the file's own mode is consulted. 0750 would need
// qemu's group, which is per-host libvirt configuration that can change after
// the directory exists. With the files 0600, a searchable directory gives
// nothing away but a name's existence.
//
// Only what litevirt creates is narrowed. A file or directory that already
// exists is never chmod-ed here (no backfill): MkdirAll leaves an existing
// directory as it is, and Narrow is for a file the caller has just made.
// docs/storage.md, "File modes".
package diskmode

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// File is the mode of a VM disk file, an overlay, an image, a seed ISO or a
// firmware bundle litevirt creates.
const File fs.FileMode = 0o600

// Dir is the mode of a directory litevirt creates to hold disk files.
const Dir fs.FileMode = 0o711

// MkdirAll is os.MkdirAll with Dir: the directories it makes are Dir (less
// what the umask takes), and one that already exists keeps its mode.
func MkdirAll(path string) error {
	return os.MkdirAll(path, Dir)
}

// Create makes path as a NEW, empty file of mode File — never over an
// existing name and never through a symlink — for a tool (qemu-img,
// genisoimage) to write into. A tool that opens an existing file keeps its
// mode, so the content never sits at a wider one, not even for the moment a
// chmod afterwards would leave open.
func Create(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, File)
	if err != nil {
		return err
	}
	return f.Close()
}

// Narrow clears the group and other bits of the regular file at path, which
// the caller has just created (or had created for it: libvirt's snapshot
// overlays), without following a symlink there. The owner keeps exactly the
// access it had, so whoever opens the file as its owner — qemu, after
// libvirt's label — is never refused.
func Narrow(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	return f.Chmod(perm &^ 0o077)
}

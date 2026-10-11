//go:build linux

package filerestore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// A restore VM reaches /dev/kvm through a POSIX ACL_GROUP entry on the device
// for its slot's group (the reserved gid equal to its uid), a supplementary
// group of the session credential. It is set when the slot is handed out
// (allocUID), checked again just before exec (ensureKVMGrant), and removed
// when the slot is released, or by the next daemon's startup sweep
// (SweepStale) when a daemon died holding it.
//
// A GROUP entry, not a user one: on systemd 255 (Ubuntu 24.04) /dev/kvm is
// tagged uaccess, and udev rewrites its ACL on the change uevent every KVM VM
// create and destroy emits, dropping every named-USER entry (seen in the lab
// within a second of the grant). Named-group entries survive that rewrite.
// The slot gid is in the reserved range, which the launcher refuses unless no
// account or group NSS knows has an id in it (reservedRangeConflict), and
// nothing the daemon creates is owned by it.
//
// The VM is never put in the kvm group: libvirt's
// qemu creates group-writable sockets as libvirt-qemu:kvm — among them the
// pull-mode backup's NBD export of a live guest disk — and Landlock does not
// mediate connect() to a pathname unix socket, so a restore qemu in kvm
// could reach another tenant's disk.

const aclAccessXattr = "system.posix_acl_access"

// The xattr form of a POSIX ACL (linux/posix_acl_xattr.h): a little-endian
// version word, then {tag u16, perm u16, id u32} entries.
const (
	aclXattrVersion = 2
	aclUserObj      = 0x01
	aclUser         = 0x02
	aclGroupObj     = 0x04
	aclGroup        = 0x08
	aclMask         = 0x10
	aclOther        = 0x20
	aclUndefinedID  = 0xffffffff
	aclRW           = 0o6
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// aclWrites counts ACL writes (tests assert that a present grant is not rewritten).
var aclWrites atomic.Int64

// deviceACLMu serializes this daemon's read-modify-write of a device's ACL.
var deviceACLMu sync.Mutex

// staleACLDevice is the device whose stale grants SweepStale removes (a var
// for tests).
var staleACLDevice = "/dev/kvm"

// readAccessACL returns path's access ACL; a file without one has the three
// entries its mode bits stand for.
func readAccessACL(path string) ([]aclEntry, error) {
	for try := 0; try < 4; try++ {
		n, err := unix.Getxattr(path, aclAccessXattr, nil)
		if errors.Is(err, unix.ENODATA) {
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err != nil {
				return nil, err
			}
			return []aclEntry{
				{aclUserObj, uint16(st.Mode >> 6 & 7), aclUndefinedID},
				{aclGroupObj, uint16(st.Mode >> 3 & 7), aclUndefinedID},
				{aclOther, uint16(st.Mode & 7), aclUndefinedID},
			}, nil
		}
		if err != nil {
			return nil, err
		}
		if n > 1<<16 {
			return nil, fmt.Errorf("ACL of %s is %d bytes", path, n)
		}
		b := make([]byte, n)
		m, err := unix.Getxattr(path, aclAccessXattr, b)
		if errors.Is(err, unix.ERANGE) {
			continue // it grew in between
		}
		if err != nil {
			return nil, err
		}
		return parseACL(b[:m])
	}
	return nil, fmt.Errorf("ACL of %s keeps changing", path)
}

func parseACL(b []byte) ([]aclEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != aclXattrVersion {
		return nil, errors.New("malformed ACL")
	}
	var out []aclEntry
	for off := 4; off < len(b); off += 8 {
		out = append(out, aclEntry{
			tag:  binary.LittleEndian.Uint16(b[off:]),
			perm: binary.LittleEndian.Uint16(b[off+2:]),
			id:   binary.LittleEndian.Uint32(b[off+4:]),
		})
	}
	return out, nil
}

// writeAccessACL writes ents as path's access ACL, in the kernel's order,
// with the mask recomputed as setfacl does: the union of the group class
// (named users, the owning group, named groups), present only while there is
// a named entry. With none left the kernel folds the ACL back into the mode
// bits and drops the xattr.
func writeAccessACL(path string, ents []aclEntry) error {
	aclWrites.Add(1)
	var kept []aclEntry
	named := false
	var mask uint16
	for _, e := range ents {
		switch e.tag {
		case aclMask:
			continue
		case aclUser, aclGroup:
			named = true
			mask |= e.perm
		case aclGroupObj:
			mask |= e.perm
		}
		kept = append(kept, e)
	}
	if named {
		kept = append(kept, aclEntry{aclMask, mask & 7, aclUndefinedID})
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].tag != kept[j].tag {
			return kept[i].tag < kept[j].tag
		}
		return kept[i].id < kept[j].id
	})
	b := make([]byte, 4+8*len(kept))
	binary.LittleEndian.PutUint32(b, aclXattrVersion)
	for i, e := range kept {
		off := 4 + 8*i
		binary.LittleEndian.PutUint16(b[off:], e.tag)
		binary.LittleEndian.PutUint16(b[off+2:], e.perm)
		binary.LittleEndian.PutUint32(b[off+4:], e.id)
	}
	return unix.Setxattr(path, aclAccessXattr, b, 0)
}

// deviceGroupHasRW reports whether path's access ACL has a named-group entry
// for gid that is read-write (and so, through the mask, effective).
func deviceGroupHasRW(path string, gid uint32) bool {
	ents, err := readAccessACL(path)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.tag == aclGroup && e.id == gid && e.perm&aclRW == aclRW {
			return true
		}
	}
	return false
}

// worldRW reports whether path is read-write for every uid by its mode
// (systemd's dev-kvm default is 0666): no grant is then needed.
func worldRW(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&aclRW == aclRW
}

// grantDeviceACL gives group gid read-write on path by an ACL_GROUP entry. It
// is idempotent: calling it again re-establishes an entry something removed.
func grantDeviceACL(path string, gid uint32) error {
	deviceACLMu.Lock()
	defer deviceACLMu.Unlock()
	ents, err := readAccessACL(path)
	if err == nil {
		found := false
		for i := range ents {
			if ents[i].tag == aclGroup && ents[i].id == gid {
				ents[i].perm |= aclRW
				found = true
			}
		}
		if !found {
			ents = append(ents, aclEntry{aclGroup, aclRW, gid})
		}
		err = writeAccessACL(path, ents)
	}
	if err != nil && worldRW(path) && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)) {
		return nil
	}
	return err
}

// revokeDeviceACL removes every named entry of path, user or group, for an id
// in [lo, hi), leaving the rest, and returns how many it removed. User
// entries are included for the ones a daemon that granted by user left. Nothing to remove
// writes nothing.
func revokeDeviceACL(path string, lo, hi uint32) (int, error) {
	deviceACLMu.Lock()
	defer deviceACLMu.Unlock()
	ents, err := readAccessACL(path)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOENT) {
			return 0, nil // nothing could have been granted
		}
		return 0, err
	}
	kept := ents[:0:0]
	n := 0
	for _, e := range ents {
		if (e.tag == aclUser || e.tag == aclGroup) && e.id >= lo && e.id < hi {
			n++
			continue
		}
		kept = append(kept, e)
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeAccessACL(path, kept)
}

// deviceACLUsable reports whether the per-session uids can be given path:
// its filesystem takes POSIX ACLs, or it is world read-write already.
func deviceACLUsable(path string) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	if st.Mode&aclRW == aclRW {
		return nil
	}
	if _, err := unix.Getxattr(path, aclAccessXattr, nil); err != nil && !errors.Is(err, unix.ENODATA) {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("%s does not take POSIX ACLs, by which each restore VM's uid is given KVM (mode %o)", path, st.Mode&0o777)
		}
		return fmt.Errorf("read the ACL of %s: %v", path, err)
	}
	return nil
}

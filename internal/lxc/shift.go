package lxc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Shifting a rootfs into a container's id range.
//
// An unprivileged container sees host uid Base+n as its own uid n, so every
// file of its rootfs must be owned in that range: the owner and group, the
// user and group entries of POSIX ACLs, and the root id a file capability is
// valid for. chown(2) clears setuid/setgid bits and file capabilities, so both
// are put back after it. Symlinks are changed, never followed.

type chownCall struct {
	path     string
	uid, gid int
}

// lchown is os.Lchown, and lookupOwner reads an entry's owner; variables so
// tests run without root (UseOwnershipOverlayForTest).
var (
	lchown      = os.Lchown
	lookupOwner = func(_ string, fi fs.FileInfo) (int, int) { return ownerOf(fi) }
)

func setChownForTest(fn func(string, int, int) error) (restore func()) {
	old := lchown
	lchown = fn
	return func() { lchown = old }
}

// shiftID maps id from the `from` range (nil: host ids 0..to.Size-1) into
// `to`. An id already inside `to` is kept (a resumed shift), and an id in
// neither range is not the container's: -1 leaves it alone.
func shiftID(id int64, from, to *IDMap) int64 {
	if id >= to.Base && id < to.Base+to.Size {
		return id
	}
	base := int64(0)
	if from != nil {
		base = from.Base
	}
	if id >= base && id < base+to.Size {
		return id - base + to.Base
	}
	return -1
}

// shiftTree shifts every entry under root (root included) from `from` into
// `to`, without following symlinks.
func shiftTree(root string, from, to *IDMap) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		uid, gid := lookupOwner(p, fi)
		if uid < 0 {
			return fmt.Errorf("%s: no owner", p)
		}
		nu, ng := shiftID(int64(uid), from, to), shiftID(int64(gid), from, to)
		if nu < 0 {
			nu = int64(uid)
		}
		if ng < 0 {
			ng = int64(gid)
		}
		isLink := fi.Mode()&fs.ModeSymlink != 0
		var caps []byte
		if !isLink {
			caps = getXattr(p, xattrCapability)
		}
		if nu != int64(uid) || ng != int64(gid) {
			if err := lchown(p, int(nu), int(ng)); err != nil {
				return fmt.Errorf("chown %s: %w", p, err)
			}
			// chown cleared setuid/setgid (and file capabilities): put the
			// mode back as it was.
			if !isLink && fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
				if err := os.Chmod(p, fi.Mode()); err != nil {
					return fmt.Errorf("restore mode of %s: %w", p, err)
				}
			}
		}
		if isLink {
			return nil
		}
		if caps != nil {
			if out, ok := shiftCapability(caps, from, to); ok {
				if err := setXattr(p, xattrCapability, out); err != nil {
					return fmt.Errorf("restore file capability of %s: %w", p, err)
				}
			}
		}
		for _, a := range []string{xattrACLAccess, xattrACLDefault} {
			if acl := getXattr(p, a); acl != nil {
				if out, ok := shiftACL(acl, from, to); ok {
					if err := setXattr(p, a, out); err != nil {
						return fmt.Errorf("shift ACL of %s: %w", p, err)
					}
				}
			}
		}
		return nil
	})
}

const (
	xattrCapability = "security.capability"
	xattrACLAccess  = "system.posix_acl_access"
	xattrACLDefault = "system.posix_acl_default"

	capRevisionMask = 0xff000000
	capRevision2    = 0x02000000
	capRevision3    = 0x03000000
)

// shiftCapability re-roots a file capability: v2 (valid for host root) and v3
// (valid for a namespace whose root is rootid) become v3 rooted at to's root.
// ok=false leaves an unrecognised value as it is.
func shiftCapability(v []byte, from, to *IDMap) ([]byte, bool) {
	if len(v) < 4 {
		return nil, false
	}
	magic := binary.LittleEndian.Uint32(v)
	switch magic & capRevisionMask {
	case capRevision2:
		if len(v) != 20 {
			return nil, false
		}
		out := make([]byte, 24)
		copy(out, v)
		binary.LittleEndian.PutUint32(out, (magic&^capRevisionMask)|capRevision3)
		binary.LittleEndian.PutUint32(out[20:], uint32(to.Base))
		return out, true
	case capRevision3:
		if len(v) != 24 {
			return nil, false
		}
		root := shiftID(int64(binary.LittleEndian.Uint32(v[20:])), from, to)
		if root < 0 {
			return nil, false
		}
		out := append([]byte(nil), v...)
		binary.LittleEndian.PutUint32(out[20:], uint32(root))
		return out, true
	}
	return nil, false
}

// POSIX ACL xattr: a 4-byte version header, then 8-byte entries of tag (2),
// perm (2) and id (4), little-endian. Only USER and GROUP entries carry an id.
const (
	aclTagUser  = 0x02
	aclTagGroup = 0x08
)

func shiftACL(v []byte, from, to *IDMap) ([]byte, bool) {
	if len(v) < 4 || (len(v)-4)%8 != 0 || binary.LittleEndian.Uint32(v) != 2 {
		return nil, false
	}
	out := append([]byte(nil), v...)
	changed := false
	for off := 4; off < len(out); off += 8 {
		tag := binary.LittleEndian.Uint16(out[off:])
		if tag != aclTagUser && tag != aclTagGroup {
			continue
		}
		id := shiftID(int64(binary.LittleEndian.Uint32(out[off+4:])), from, to)
		if id < 0 {
			continue
		}
		binary.LittleEndian.PutUint32(out[off+4:], uint32(id))
		changed = true
	}
	return out, changed
}

var errNoXattr = errors.New("extended attributes are not supported here")

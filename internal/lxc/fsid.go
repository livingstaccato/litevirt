package lxc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Protected trees are compared by filesystem identity as well as by path. A
// tree is the same tree wherever the host mounts it: /var/lib/litevirt bound
// again under an allowed prefix, or a second mount of the NFS export a pool
// lives on, reaches the same files under a path no string check recognises.
// The identity of a path is the filesystem it is on (mountinfo's
// major:minor) and the path within that filesystem (the mount's root joined
// with the path below its mount point). Two paths overlap when they are on the
// same filesystem and one identity path lies within the other.

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	id         uint64
	dev        string // major:minor of the filesystem
	root       string // the path within the filesystem mounted here
	mountPoint string
}

// fsIdentity is a path's filesystem and its path within it.
type fsIdentity struct {
	dev string
	rel string
}

// readMountTable reads and parses mountinfoPath.
func readMountTable() ([]mountEntry, error) {
	b, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, mountEntry{id: id, dev: f[2], root: unescapeMountinfo(f[3]), mountPoint: unescapeMountinfo(f[4])})
	}
	return out, nil
}

// unescapeMountinfo undoes mountinfo's octal escapes (\040 for a space,
// \011, \012, \134).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// identityIn is p's identity on mount m; ok is false when p is not at or
// below m's mount point.
func identityIn(m mountEntry, p string) (fsIdentity, bool) {
	if !within(p, m.mountPoint) {
		return fsIdentity{}, false
	}
	rel, err := filepath.Rel(m.mountPoint, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fsIdentity{}, false
	}
	return fsIdentity{dev: m.dev, rel: filepath.Join("/", m.root, rel)}, true
}

// identityByPath is the identity of a canonical path: the mount with the
// longest mount point containing it, the last listed when several share one
// (the topmost of a stack).
func identityByPath(mounts []mountEntry, p string) (fsIdentity, bool) {
	best := -1
	for i, m := range mounts {
		if !within(p, m.mountPoint) {
			continue
		}
		if best < 0 || len(m.mountPoint) >= len(mounts[best].mountPoint) {
			best = i
		}
	}
	if best < 0 {
		return fsIdentity{}, false
	}
	return identityIn(mounts[best], p)
}

// identityByMount is the identity of p, a path on the mount whose id is
// mntID (an opened fd's mount: exact, even where a later mount shadows it).
func identityByMount(mounts []mountEntry, mntID uint64, p string) (fsIdentity, bool) {
	for _, m := range mounts {
		if m.id == mntID {
			return identityIn(m, p)
		}
	}
	return fsIdentity{}, false
}

// deniedTreeByIdentity reports the protected tree p shares files with — p on
// the same filesystem as a tree and inside it, or containing it — or "".
// mntID, when non-zero, is the mount p is known to be on (an opened fd's);
// otherwise the mount is found by path. On Linux a mount table that cannot be
// read, or a mount id it does not list, refuses: identity is what this check
// rests on.
func deniedTreeByIdentity(p string, mntID uint64, trees []string) string {
	mounts, err := readMountTable()
	if err != nil {
		if runtime.GOOS == "linux" {
			return fmt.Sprintf("(this host's mount table cannot be read: %v)", err)
		}
		return ""
	}
	var id fsIdentity
	var ok bool
	if mntID != 0 {
		if id, ok = identityByMount(mounts, mntID, p); !ok {
			return fmt.Sprintf("(an unknown mount, id %d)", mntID)
		}
	} else if id, ok = identityByPath(mounts, p); !ok {
		return ""
	}
	for _, d := range trees {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		for _, form := range []string{filepath.Clean(d), resolveIfExists(d)} {
			did, ok := identityByPath(mounts, form)
			if ok && did.dev == id.dev && (within(id.rel, did.rel) || within(did.rel, id.rel)) {
				return fmt.Sprintf("%s (the same filesystem, %s, at %s)", form, did.dev, did.rel)
			}
		}
	}
	return ""
}

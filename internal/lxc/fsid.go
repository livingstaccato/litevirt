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
	fsType     string // after the " - " separator
	source     string // the mount source (srv:/export for NFS)
}

// fsIdentity is a path's filesystem and its path within it. An ambiguous
// identity cannot be compared: the path within the filesystem is not known
// for certain, and the resolved-path check alone decides.
type fsIdentity struct {
	dev       string
	rel       string
	ambiguous bool
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
		m := mountEntry{id: id, dev: f[2], root: unescapeMountinfo(f[3]), mountPoint: unescapeMountinfo(f[4])}
		// The optional fields end at a lone "-"; the filesystem type and the
		// source follow it.
		for i := 5; i < len(f); i++ {
			if f[i] == "-" {
				if i+1 < len(f) {
					m.fsType = f[i+1]
				}
				if i+2 < len(f) {
					m.source = unescapeMountinfo(f[i+2])
				}
				break
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// nfsExportRoot is the path within the server's filesystem that an NFS
// mount's source names (srv:/export/share → /export/share), and ok=false for
// a source that names none. An NFS mount's root column is not that path: two
// mounts of DIFFERENT exports of one server filesystem can share a superblock
// (NFSv3, sharecache, the same options), and each mount's root then reads "/"
// until a lookup through its parent splices the dentry — so the column
// changes with the dentry cache. The source does not.
func nfsExportRoot(source string) (string, bool) {
	i := strings.Index(source, ":/")
	if i < 0 {
		return "", false
	}
	return filepath.Clean(source[i+1:]), true
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

// isNFS reports an NFS mount.
func (m mountEntry) isNFS() bool { return m.fsType == "nfs" || m.fsType == "nfs4" }

// sharedNFS is the set of NFS filesystems (by major:minor) that mounts of
// more than one export share: on them a mount's root column depends on the
// dentry cache (nfsExportRoot).
func sharedNFS(mounts []mountEntry) map[string]bool {
	exports := map[string]string{}
	out := map[string]bool{}
	for _, m := range mounts {
		if !m.isNFS() {
			continue
		}
		er, ok := nfsExportRoot(m.source)
		if !ok {
			continue
		}
		if e, seen := exports[m.dev]; seen && e != er {
			out[m.dev] = true
		}
		exports[m.dev] = er
	}
	return out
}

// nfsRoot is the path within the server's filesystem that NFS mount m's root
// is, and ok=false when that is not known for certain (m-1):
//   - one export on the filesystem: the export path joined with the root
//     column, which is then relative to that export (a bind of a
//     subdirectory reads "/sub");
//   - several exports sharing it: the export path when the root column is
//     "/" (the mount's own export, not yet spliced) or the tail of the
//     export path (spliced beneath another export); anything else is not
//     known;
//   - a source that names no export path: not known.
func nfsRoot(m mountEntry, shared map[string]bool) (string, bool) {
	er, ok := nfsExportRoot(m.source)
	if !ok {
		return "", false
	}
	root := filepath.Clean("/" + m.root)
	switch {
	case !shared[m.dev]:
		return filepath.Join(er, root), true
	case root == "/" || er == root || strings.HasSuffix(er, root):
		return er, true
	}
	return "", false
}

// identityIn is p's identity on mount m; ok is false when p is not at or
// below m's mount point.
func identityIn(m mountEntry, p string, shared map[string]bool) (fsIdentity, bool) {
	if !within(p, m.mountPoint) {
		return fsIdentity{}, false
	}
	rel, err := filepath.Rel(m.mountPoint, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fsIdentity{}, false
	}
	root := m.root
	if m.isNFS() {
		// m-1: from the export path, which does not depend on the dentry
		// cache; where that is not certain, the identity is ambiguous.
		r, ok := nfsRoot(m, shared)
		if !ok {
			return fsIdentity{dev: m.dev, ambiguous: true}, true
		}
		root = r
	}
	return fsIdentity{dev: m.dev, rel: filepath.Join("/", root, rel)}, true
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
	return identityIn(mounts[best], p, sharedNFS(mounts))
}

// identityByMount is the identity of p, a path on the mount whose id is
// mntID (an opened fd's mount: exact, even where a later mount shadows it).
func identityByMount(mounts []mountEntry, mntID uint64, p string) (fsIdentity, bool) {
	for _, m := range mounts {
		if m.id == mntID {
			return identityIn(m, p, sharedNFS(mounts))
		}
	}
	return fsIdentity{}, false
}

// deniedTreeByIdentity reports the protected tree p shares files with — p on
// the same filesystem as a tree and inside it, or containing it — or "".
// mntID, when non-zero, is the mount p is known to be on (an opened fd's);
// otherwise the mount is found by path. On Linux a mount id the table does not
// list refuses, and a mount table that cannot be read is an error
// (transient: the check could not be made, not a verdict): identity is what
// this check rests on. An ambiguous identity (an NFS mount whose source names
// no export path) is not compared; the resolved-path check decides alone.
func deniedTreeByIdentity(p string, mntID uint64, trees []string) (string, error) {
	mounts, err := readMountTable()
	if err != nil {
		if runtime.GOOS == "linux" {
			return "", transient(fmt.Errorf("this host's mount table cannot be read: %w", err))
		}
		return "", nil
	}
	var id fsIdentity
	var ok bool
	if mntID != 0 {
		if id, ok = identityByMount(mounts, mntID, p); !ok {
			return fmt.Sprintf("(an unknown mount, id %d)", mntID), nil
		}
	} else if id, ok = identityByPath(mounts, p); !ok {
		return "", nil
	}
	if id.ambiguous {
		return "", nil
	}
	for _, d := range trees {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		for _, form := range []string{filepath.Clean(d), resolveIfExists(d)} {
			did, ok := identityByPath(mounts, form)
			if ok && !did.ambiguous && did.dev == id.dev && (within(id.rel, did.rel) || within(did.rel, id.rel)) {
				return fmt.Sprintf("%s (the same filesystem, %s, at %s)", form, did.dev, did.rel), nil
			}
		}
	}
	return "", nil
}

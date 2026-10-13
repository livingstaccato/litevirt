package storage

import (
	"net/netip"
	"path/filepath"
	"strings"
)

// SharedStore says whether a directory's files are this host's alone, or on
// storage other hosts may mount too, and if so what that storage is.
//
// Records of whose a file is (internal/grpcapi, pool_records.go) are kept
// cluster-wide for a directory on shared storage, keyed by ID. A host that
// cannot compute an ID cannot see those records, and falls back to matching a
// replica by its name, as before records existed.
type SharedStore struct {
	// Shared: a network or cluster filesystem. Unknown counts as shared.
	Shared bool
	// ID is the directory's identity on that storage, computed the same way
	// on every host that mounts it the same way: the server as spelled in the
	// mount source, canonicalised (NFS, CIFS), the cluster's filesystem id
	// (CephFS), the volume name (GlusterFS), plus the path below the export.
	// Not the address the kernel connected to: behind round-robin DNS or
	// after a re-IP that changes from mount to mount. Two spellings of one
	// server are two identities, so neither host sees the other's records
	// and both match by name. "" when it cannot be told.
	ID string
}

// SharedStoreOf judges dir by this host's mount table (and the filesystem's
// magic number, for a network filesystem the mount table does not name). A
// mount table that cannot be read is "shared, no identity".
func SharedStoreOf(dir string) SharedStore {
	t, err := ReadMountTable()
	if err != nil {
		return SharedStore{Shared: true}
	}
	return t.SharedStoreOf(dir)
}

// SharedStoreOfErr is SharedStoreOf for a caller that writes on the strength
// of its answer (a record, a marker): a directory whose resolution, or
// statfs, does not finish in time (a network filesystem that does not answer)
// is an error (IsFSNoAnswer), not "no identity", which such a caller would
// read as "nothing to record".
func SharedStoreOfErr(dir string) (SharedStore, error) {
	t, err := ReadMountTable()
	if err != nil {
		return SharedStore{Shared: true}, nil
	}
	return t.SharedStoreOfErr(dir)
}

// SharedStoreOf is SharedStoreOf against this table. A directory whose
// resolution, or statfs, does not finish in time (a network filesystem that
// does not answer: resolveBounded, Bounded) is "shared, no identity", as is
// one whose mount table cannot be read: the conservative answer for a
// reader.
func (t MountTable) SharedStoreOf(dir string) SharedStore {
	st, err := t.SharedStoreOfErr(dir)
	if err != nil {
		return SharedStore{Shared: true}
	}
	return st
}

// SharedStoreOfErr is SharedStoreOfErr against this table.
func (t MountTable) SharedStoreOfErr(dir string) (SharedStore, error) {
	var out SharedStore
	forms, err := pathFormsBounded(&t, dir)
	if err != nil {
		return SharedStore{Shared: true}, err
	}
	for _, p := range forms { // the resolved form, last, wins
		var under mountEntry
		for _, e := range t.all {
			if within(e.dir, p) && len(e.dir) >= len(under.dir) {
				under = e
			}
		}
		rel, err := filepath.Rel(under.dir, p)
		if under.dir == "" || err != nil {
			continue
		}
		var serr error
		if out, serr = sharedStoreOfMount(under, rel, dir); serr != nil {
			return SharedStore{Shared: true}, serr
		}
	}
	if !out.Shared {
		info := statfsInfo.get()
		magic, err := Bounded("statfs (magic)", dir, func() (uint32, error) {
			m, _, err := info(dir)
			return m, err
		})
		if IsFSNoAnswer(err) {
			return SharedStore{Shared: true}, err
		}
		if err == nil && networkMagic(magic) {
			out = SharedStore{Shared: true}
		}
	}
	return out, nil
}

// sharedStoreOfMount is the store of the path rel below mount e. A CephFS
// statfs that does not answer is an error.
func sharedStoreOfMount(e mountEntry, rel, dir string) (SharedStore, error) {
	if e.fstype == "ceph" {
		// The kernel client's f_fsid folds the cluster's fsid with the
		// filesystem's id within it: the same on every client.
		info := statfsInfo.get()
		fsid, err := Bounded("statfs (fsid)", dir, func() (string, error) {
			_, id, err := info(dir)
			return id, err
		})
		if IsFSNoAnswer(err) {
			return SharedStore{Shared: true}, err
		}
		path, ok := cephSourcePath(e.source)
		if err != nil || fsid == "" || !ok {
			return SharedStore{Shared: true}, nil
		}
		return SharedStore{Shared: true, ID: "ceph:" + fsid + ":" + filepath.Clean("/"+filepath.Join(path, rel))}, nil
	}
	return sharedStoreOfMountNoErr(e, rel), nil
}

func sharedStoreOfMountNoErr(e mountEntry, rel string) SharedStore {
	below := func(base string) string { return filepath.Clean("/" + filepath.Join(base, rel)) }
	switch {
	case isNFSFstype(e.fstype):
		exp, err := ParseNFSExport(e.source)
		if err != nil {
			return SharedStore{Shared: true}
		}
		exp.Path = below(exp.Path)
		return SharedStore{Shared: true, ID: "nfs:" + exp.String()}
	case e.fstype == "cifs" || e.fstype == "smb3":
		rest, ok := strings.CutPrefix(strings.ReplaceAll(e.source, `\`, "/"), "//")
		server, sharePath, found := strings.Cut(rest, "/")
		if !ok || !found || server == "" {
			return SharedStore{Shared: true}
		}
		share, sub, _ := strings.Cut(sharePath, "/")
		if a, ok := canonicalAddr(server); ok {
			server = a
		} else {
			server = strings.ToLower(strings.TrimSuffix(server, "."))
		}
		return SharedStore{Shared: true, ID: "cifs:" + server + "/" + strings.ToLower(share) + below(sub)}
	case e.fstype == "fuse.glusterfs" || e.fstype == "glusterfs":
		// Any server of the trusted pool serves the volume: the volume name
		// is its identity.
		_, vol, ok := strings.Cut(e.source, ":")
		name, sub, _ := strings.Cut(strings.TrimPrefix(vol, "/"), "/")
		if !ok || name == "" {
			return SharedStore{Shared: true}
		}
		return SharedStore{Shared: true, ID: "gluster:" + name + below(sub)}
	case networkFstype(e.fstype):
		return SharedStore{Shared: true}
	}
	return SharedStore{}
}

// networkFstype reports a filesystem other hosts may mount too, of a kind
// whose identity is not computed here.
func networkFstype(t string) bool {
	switch t {
	case "smbfs", "ocfs2", "gfs2", "virtiofs", "9p", "lustre", "beegfs", "gpfs", "afs", "davfs", "orangefs", "fuse":
		return true
	}
	return strings.HasPrefix(t, "fuse.")
}

// networkMagic reports a statfs magic number of a network or cluster
// filesystem: NFS, CephFS, CIFS/SMB, FUSE, OCFS2, GFS2, 9p, Lustre, AFS.
func networkMagic(m uint32) bool {
	switch m {
	case 0x6969, 0x00c36400, 0xFF534D42, 0xFE534D42, 0x517B, 0x65735546,
		0x7461636f, 0x01161970, 0x01021997, 0x0BD00BD0, 0x5346414F:
		return true
	}
	return false
}

func canonicalAddr(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return "", false
	}
	return a.Unmap().WithZone("").String(), true
}

// cephSourcePath is the path within the filesystem of a kernel CephFS mount
// source: "mon1,mon2:/path" or "user@fsid.fsname=/path".
func cephSourcePath(src string) (string, bool) {
	if i := strings.LastIndex(src, "="); i >= 0 && strings.HasPrefix(src[i+1:], "/") {
		return src[i+1:], true
	}
	if i := strings.LastIndex(src, ":/"); i >= 0 {
		return src[i+1:], true
	}
	return "", false
}

// OverrideStatfsForTest replaces how a directory's filesystem magic and
// f_fsid are read, for tests in other packages. It returns the restore
// function.
func OverrideStatfsForTest(f func(path string) (uint32, string, error)) func() {
	return statfsInfo.set(f)
}

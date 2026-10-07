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
	// ID is the directory's identity on that storage, the same on every host
	// that mounts it however that host spells the source: the server's
	// address where the kernel reports it (NFS and CIFS addr=), the
	// cluster's filesystem id (CephFS), the volume name (GlusterFS), plus the
	// path below the export. "" when it cannot be told.
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

// SharedStoreOf is SharedStoreOf against this table.
func (t MountTable) SharedStoreOf(dir string) SharedStore {
	var out SharedStore
	for _, p := range pathForms(dir) { // the resolved form, last, wins
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
		out = sharedStoreOfMount(under, rel, dir)
	}
	if !out.Shared {
		if magic, _, err := statfsInfo(dir); err == nil && networkMagic(magic) {
			out = SharedStore{Shared: true}
		}
	}
	return out
}

func sharedStoreOfMount(e mountEntry, rel, dir string) SharedStore {
	below := func(base string) string { return filepath.Clean("/" + filepath.Join(base, rel)) }
	switch {
	case isNFSFstype(e.fstype):
		exp, err := ParseNFSExport(e.source)
		if err != nil {
			return SharedStore{Shared: true}
		}
		if a, ok := canonicalAddr(superOption(e.super, "addr")); ok {
			exp.Server = a
		}
		exp.Path = below(exp.Path)
		return SharedStore{Shared: true, ID: "nfs:" + exp.String()}
	case e.fstype == "ceph":
		// The kernel client's f_fsid folds the cluster's fsid with the
		// filesystem's id within it: the same on every client.
		_, fsid, err := statfsInfo(dir)
		path, ok := cephSourcePath(e.source)
		if err != nil || fsid == "" || !ok {
			return SharedStore{Shared: true}
		}
		return SharedStore{Shared: true, ID: "ceph:" + fsid + ":" + below(path)}
	case e.fstype == "cifs" || e.fstype == "smb3":
		rest, ok := strings.CutPrefix(strings.ReplaceAll(e.source, `\`, "/"), "//")
		server, sharePath, found := strings.Cut(rest, "/")
		if !ok || !found || server == "" {
			return SharedStore{Shared: true}
		}
		share, sub, _ := strings.Cut(sharePath, "/")
		if a, ok := canonicalAddr(superOption(e.super, "addr")); ok {
			server = a
		} else {
			server = strings.ToLower(server)
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

func superOption(opts []string, key string) string {
	for _, o := range opts {
		if v, ok := strings.CutPrefix(o, key+"="); ok {
			return v
		}
	}
	return ""
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

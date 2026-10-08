package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// snapshotFileUsers names the VMs, other than vmName, whose disks use one of
// files: the files a delete of one of vmName's snapshots merges into or
// removes. A VM uses a file when its disk's recorded backing_disk names it
// (a linked clone), or when the qcow2 header chain of its disk file on this
// host reaches it (a clone whose record does not say, as an earlier build's
// may not). Neither libvirt's delete nor litevirt's flatten looks for them:
// on the lab, deleting the snapshot a linked clone backed on merged the
// overlay away and the clone could never start again (snapshot-repro.md,
// scenario 3).
//
// A disk this host cannot read is not one of them: the files are this
// host's, and a chain that cannot be read here does not reach them. A
// database error is returned as is; the caller treats "cannot tell" as "in
// use".
func (s *Server) snapshotFileUsers(ctx context.Context, vmName string, files []string) ([]string, error) {
	mine := map[string]bool{}
	for _, f := range files {
		if f == "" {
			continue
		}
		mine[filepath.Clean(f)] = true
		mine[resolvedOr(f)] = true
	}
	if len(mine) == 0 {
		return nil, nil
	}
	uses := func(p string) bool {
		return p != "" && (mine[filepath.Clean(p)] || mine[resolvedOr(s.hostDiskFile(p))])
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, vm := range vms {
		if vm.Name == vmName {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			return nil, err
		}
		for _, d := range disks {
			if uses(d.BackingDisk) || chainReaches(s.hostDiskFile(d.Path), uses) {
				out = append(out, vm.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// chainReaches reports whether file, or a layer of its qcow2 backing chain,
// satisfies hit. Headers only, bounded; a layer that cannot be read, or a
// protocol backing, ends the walk.
func chainReaches(file string, hit func(string) bool) bool {
	if file == "" || !filepath.IsAbs(file) {
		return false
	}
	path := file
	for depth := 0; depth <= maxBackingDepth; depth++ {
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return false
		}
		if hit(path) {
			return true
		}
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return false
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path = b
	}
	return false
}

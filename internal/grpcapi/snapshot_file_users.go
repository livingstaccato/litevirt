package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

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
			file := s.hostDiskFile(d.Path)
			if uses(d.BackingDisk) || chainReaches(file, s.namedQcow2(ctx, vm.Name, file), uses) {
				out = append(out, vm.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// namedQcow2 reports whether vm's disk file is one litevirt names as qcow2:
// <...>.qcow2, or an overlay named after one of vm's snapshots (libvirt
// writes those as qcow2). Anything else may be a raw disk, whose first bytes
// are the guest's and must not be read as a header.
func (s *Server) namedQcow2(ctx context.Context, vm, file string) bool {
	if strings.HasSuffix(file, ".qcow2") {
		return true
	}
	ext := strings.TrimPrefix(filepath.Ext(file), ".")
	if ext == "" {
		return false
	}
	snaps, err := corrosion.ListSnapshots(ctx, s.db, vm)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(snaps, func(sn corrosion.SnapshotRecord) bool { return sn.Name == ext })
}

// chainReaches reports whether file, or a layer of its qcow2 backing chain,
// satisfies hit. Headers only, bounded. A header is read only from a layer
// known to be qcow2: file itself when parseTop says so, and below it only a
// layer its parent's header declares qcow2. A raw layer (a raw disk, or a
// raw base) holds guest data — a guest could write a header there naming
// any file — so it is checked by its path and ends the walk (re-review
// R1-M1). A layer that cannot be read, or a protocol backing, ends it too.
func chainReaches(file string, parseTop bool, hit func(string) bool) bool {
	if file == "" || !filepath.IsAbs(file) {
		return false
	}
	path, parse := file, parseTop
	for depth := 0; depth <= maxBackingDepth; depth++ {
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return false
		}
		if hit(path) {
			return true
		}
		if !parse {
			return false
		}
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return false
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path, parse = b, info.BackingFormat == "qcow2"
	}
	return false
}

// headerUsersKeep reports whether a file vmName's delete would remove must
// be kept because another VM's disk reaches it through its qcow2 header
// chain or its recorded backing_disk (snapshotFileUsers). "Cannot tell"
// keeps it.
func (s *Server) headerUsersKeep(ctx context.Context, vmName, path string) bool {
	users, err := s.snapshotFileUsers(ctx, vmName, []string{path})
	if err != nil {
		slog.Error("delete: cannot tell whether another VM backs on a disk file; keeping it",
			"vm", vmName, "path", path, "error", err)
		return true
	}
	if len(users) > 0 {
		slog.Warn("delete: another VM backs on a disk file of this VM; keeping it",
			"vm", vmName, "path", path, "users", users)
		return true
	}
	return false
}

// ownDiskLayers lists the files of vmName's disks on this host that its
// rows do not free, and that are certainly its own (re-review R1-C1):
//   - a layer of a recorded disk's own chain: below the recorded file, each
//     layer its parent's header declares qcow2, as long as it has the disk's
//     name (<vm>-<disk>.<anything>, in the disk's directory) — the snapshot
//     overlays between the live layer and the disk they were taken of;
//   - a qcow2 file of the disk's name beside it whose own header backs into
//     that chain, or whose extension names one of the VM's snapshots: an
//     overlay a restore of an older snapshot left out of the chain.
//
// Nothing of a disk recorded delete_with_vm=false, and nothing of a disk
// whose name has a dash (<vm>-<a>-<b> can be another VM's disk, as the
// debris sweep reasons). removeOwnDiskLayers then spares uploads and files
// other VMs use. Read before anything is deleted, since the chain is read
// from the files.
func (s *Server) ownDiskLayers(ctx context.Context, vmName string) []string {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("delete: cannot list the VM's disks; its snapshot overlays are kept", "vm", vmName, "error", err)
		return nil
	}
	snapNames := map[string]bool{}
	if snaps, err := corrosion.ListSnapshots(ctx, s.db, vmName); err == nil {
		for _, sn := range snaps {
			snapNames[sn.Name] = true
		}
	}
	recorded := map[string]bool{}
	for _, d := range disks {
		recorded[filepath.Clean(s.hostDiskFile(d.Path))] = true
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !recorded[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, d := range disks {
		file := filepath.Clean(s.hostDiskFile(d.Path))
		if d.Path == "" || !d.DeleteWithVM || !filepath.IsAbs(file) {
			continue
		}
		stem := filepath.Base(diskStem(file))
		rest, ok := strings.CutPrefix(stem, vmName+"-")
		if !ok || rest == "" || strings.Contains(rest, "-") {
			continue
		}
		dir := filepath.Dir(file)
		own := func(p string) bool {
			return filepath.Dir(p) == dir && filepath.Base(diskStem(p)) == stem
		}
		chain := map[string]bool{file: true}
		path, parse := file, s.namedQcow2(ctx, vmName, file)
		for depth := 0; parse && depth <= maxBackingDepth; depth++ {
			info, err := qcow2.Info(path)
			if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) || info.BackingFormat != "qcow2" {
				break
			}
			b := info.BackingFile
			if !filepath.IsAbs(b) {
				b = filepath.Join(filepath.Dir(path), b)
			}
			b = filepath.Clean(b)
			if !own(b) {
				break
			}
			chain[b] = true
			add(b)
			path = b
		}
		matches, _ := filepath.Glob(filepath.Join(dir, globEscape(stem)+".*"))
		for _, m := range matches {
			m = filepath.Clean(m)
			if chain[m] || !own(m) {
				continue
			}
			if fi, err := os.Lstat(m); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			info, err := qcow2.Info(m)
			if err != nil {
				continue // not a qcow2: a user's file, an ISO, a raw image
			}
			b := info.BackingFile
			if b != "" && !filepath.IsAbs(b) {
				b = filepath.Join(dir, b)
			}
			named := snapNames[strings.TrimPrefix(filepath.Ext(m), ".")]
			if named || (b != "" && info.BackingFormat == "qcow2" && chain[filepath.Clean(b)]) {
				add(m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// removeOwnDiskLayers removes files ownDiskLayers listed, except one another
// VM names in its record or reaches through its qcow2 chain.
func (s *Server) removeOwnDiskLayers(ctx context.Context, vmName string, files []string) {
	for _, f := range files {
		// A user's upload is a project's file whatever its name; unreadable
		// records protect, as for the debris sweep (protectedDiskPathsFrom).
		if recs, rerr := s.recordsOf(ctx, f); rerr != nil || slices.ContainsFunc(recs, func(u poolUpload) bool { return u.VM == "" && !u.Peer }) {
			continue
		}
		refs, err := corrosion.DisksReferencingPath(ctx, s.db, f)
		if err != nil {
			slog.Warn("delete: cannot tell whether a snapshot overlay is referenced; keeping it", "vm", vmName, "path", f, "error", err)
			continue
		}
		if slices.ContainsFunc(refs, func(r corrosion.DiskRecord) bool { return r.VMName != vmName }) || s.headerUsersKeep(ctx, vmName, f) {
			continue
		}
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			slog.Warn("delete: remove snapshot overlay", "vm", vmName, "path", f, "error", err)
		}
	}
}

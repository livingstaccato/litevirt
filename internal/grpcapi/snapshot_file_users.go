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

// ownDiskLayers lists the files of vmName's disks on this host other than
// the recorded ones, which their rows free: every layer of each recorded
// disk's qcow2 chain that has the disk's name (<vm>-<disk>.<anything>, in
// the disk's directory — snapshot overlays and the disk they were taken
// of), and every other file of that name there (an overlay a restore of an
// older snapshot left out of the chain). A disk name with a dash is skipped,
// as the debris sweep skips it: <vm>-<a>-<b> can be another VM's disk. Read
// before anything is deleted, since the chain is read from the files.
func (s *Server) ownDiskLayers(ctx context.Context, vmName string) []string {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("delete: cannot list the VM's disks; its snapshot overlays are kept", "vm", vmName, "error", err)
		return nil
	}
	recorded := map[string]bool{}
	for _, d := range disks {
		recorded[filepath.Clean(s.hostDiskFile(d.Path))] = true
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if !recorded[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, d := range disks {
		file := s.hostDiskFile(d.Path)
		if d.Path == "" || !filepath.IsAbs(file) {
			continue
		}
		stem := filepath.Base(diskStem(file))
		rest, ok := strings.CutPrefix(stem, vmName+"-")
		if !ok || rest == "" || strings.Contains(rest, "-") {
			continue
		}
		dir := filepath.Dir(file)
		own := func(p string) bool {
			return filepath.Dir(filepath.Clean(p)) == dir && filepath.Base(diskStem(p)) == stem
		}
		path := file
		for depth := 0; depth <= maxBackingDepth; depth++ {
			info, err := qcow2.Info(path)
			if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
				break
			}
			b := info.BackingFile
			if !filepath.IsAbs(b) {
				b = filepath.Join(filepath.Dir(path), b)
			}
			if !own(b) {
				break
			}
			add(b)
			path = b
		}
		matches, _ := filepath.Glob(filepath.Join(dir, globEscape(stem)+".*"))
		for _, m := range matches {
			if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() && own(m) {
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

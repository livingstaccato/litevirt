package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// vmLayerFiles returns file and every file of its qcow2 backing chain,
// resolved through symlinks, stopping before the image store (a base any VM
// may share, which nothing here merges into or deletes). It reads headers
// only; a layer it cannot read, or a protocol backing, ends the walk.
func vmLayerFiles(file string, images []string) []string {
	var out []string
	path := resolvedOr(file)
	for depth := 0; depth <= maxBackingDepth; depth++ {
		if withinAny(path, images) {
			return out
		}
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return out
		}
		out = append(out, path)
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return out
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path = resolvedOr(b)
	}
	return out
}

// vmChainDependents names the VMs, other than vmName, whose disks use a file
// of vmName's own disk chain on this host: a linked clone's recorded
// backing_disk naming any layer of it (not only the top file a snapshot
// moved the record off), or — for a clone whose record does not say, as an
// earlier build's may not — a disk file here whose qcow2 header chain reaches
// one, read as a start reads it. Every layer above the image store counts.
//
// A delete that would merge into or remove a file of that chain must not run
// while this is non-empty. An error is returned as is: the caller treats
// "cannot tell" as "in use".
func (s *Server) vmChainDependents(ctx context.Context, vmName string) ([]string, error) {
	images := s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	own, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, err
	}
	mine := map[string]bool{}
	for _, d := range own {
		if d.HostName != "" && d.HostName != s.hostName && !corrosion.DiskIsShared(d) {
			continue
		}
		mine[filepath.Clean(d.Path)] = true
		for _, f := range vmLayerFiles(s.hostDiskFile(d.Path), images) {
			mine[f] = true
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, vm := range vms {
		if vm.Name == vmName {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			return nil, err
		}
		for _, d := range disks {
			if d.BackingDisk != "" && (mine[filepath.Clean(d.BackingDisk)] || mine[resolvedOr(s.hostDiskFile(d.BackingDisk))]) {
				found[vm.Name] = true
				break
			}
			uses := false
			for _, f := range vmLayerFiles(s.hostDiskFile(d.Path), images) {
				if mine[f] {
					uses = true
					break
				}
			}
			if uses {
				found[vm.Name] = true
				break
			}
		}
	}
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

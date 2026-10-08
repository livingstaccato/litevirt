package grpcapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// maxMergeWalk bounds a chain walk here. It is far above the start's cap
// (maxBackingDepth) on purpose: a chain grown past the cap is exactly what a
// merge collapses.
const maxMergeWalk = 256

// errLayerUnknown: a layer of a chain could not be read, so what it backs on
// is unknown.
var errLayerUnknown = fmt.Errorf("a disk's backing chain cannot be read")

// diskLayers returns file and every file of its backing chain, resolved,
// top first, stopping before the image store (a base any VM may share, which
// a merge never writes into or removes). A block device or a regular file
// that is not qcow2 is a layer with no backing. A file that cannot be stat'ed
// or opened, or a qcow2 header that cannot be read, is errLayerUnknown —
// never "no backing". A protocol backing ends the walk (it is no local file).
func diskLayers(file string, images []string) ([]string, error) {
	var out []string
	path := resolvedOr(file)
	for depth := 0; depth < maxMergeWalk; depth++ {
		if withinAny(path, images) {
			return out, nil
		}
		fi, err := os.Stat(path)
		if err != nil {
			return out, fmt.Errorf("%w: %s: %v", errLayerUnknown, path, err)
		}
		out = append(out, path)
		if !fi.Mode().IsRegular() {
			return out, nil // a block device: raw, no backing
		}
		isQcow2, err := hasQcow2Magic(path)
		if err != nil {
			return out, fmt.Errorf("%w: %s: %v", errLayerUnknown, path, err)
		}
		if !isQcow2 {
			return out, nil // raw content, never parsed for a header
		}
		info, err := qcow2.Info(path)
		if err != nil {
			return out, fmt.Errorf("%w: %s: %v", errLayerUnknown, path, err)
		}
		if info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return out, nil
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path = resolvedOr(b)
	}
	return out, fmt.Errorf("%w: %s: deeper than %d layers", errLayerUnknown, file, maxMergeWalk)
}

func hasQcow2Magic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var m [4]byte
	if _, err := io.ReadFull(f, m[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return binary.BigEndian.Uint32(m[:]) == qcow2.Magic, nil
}

// layerUsers maps each file another VM's disk uses — its recorded
// backing_disk, and every layer of its disk file's chain — to those VMs.
// Only disks whose files this host can see are walked (this host's, or on
// shared storage). A disk that cannot be read fails the whole answer
// (errLayerUnknown): a disk whose chain is unknown may back on any layer, so
// the caller must neither merge nor remove anything.
func (s *Server) layerUsers(ctx context.Context, vmName string, images []string) (map[string][]string, error) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	users := map[string][]string{}
	add := func(f, vm string) {
		for _, u := range users[f] {
			if u == vm {
				return
			}
		}
		users[f] = append(users[f], vm)
	}
	for _, vm := range vms {
		if vm.Name == vmName {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			return nil, err
		}
		for _, d := range disks {
			if d.BackingDisk != "" {
				add(filepath.Clean(d.BackingDisk), vm.Name)
				add(resolvedOr(s.hostDiskFile(d.BackingDisk)), vm.Name)
			}
			if d.HostName != "" && d.HostName != s.hostName && !corrosion.DiskIsShared(d) {
				continue
			}
			if !strings.HasPrefix(d.Path, "/") {
				continue // not a file path (an rbd name, say): no local chain
			}
			layers, err := diskLayers(s.hostDiskFile(d.Path), images)
			if err != nil {
				return nil, fmt.Errorf("disk %q of %q: %w", d.DiskName, vm.Name, err)
			}
			for _, l := range layers {
				add(l, vm.Name)
			}
		}
	}
	return users, nil
}

// snapshotMergeBases decides, for deleting vmName's last snapshot, which
// layer each of its disks merges into: the lowest layer of the disk's chain
// such that neither it nor anything above it is used by another VM (a linked
// clone of any layer, recorded or found by its header, of this build or an
// earlier one). Layers under it — the image store, a template another VM is
// a clone of — are never written or removed. A disk whose active layer is
// already that layer is not listed.
//
// Any layer that cannot be read, here or in another VM's chain, is an error:
// nothing is merged when what depends on a layer is unknown.
func (s *Server) snapshotMergeBases(ctx context.Context, vmName string) (map[string]string, error) {
	images := s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	srcs, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		return nil, err
	}
	users, err := s.layerUsers(ctx, vmName, images)
	if err != nil {
		return nil, err
	}
	bases := map[string]string{}
	for dev, top := range srcs {
		if !strings.HasPrefix(top, "/") {
			continue
		}
		chain, err := diskLayers(s.hostDiskFile(top), images)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", dev, err)
		}
		target := -1
		for i, l := range chain {
			if len(users[l]) > 0 {
				break
			}
			target = i
		}
		if target <= 0 {
			continue // the active layer itself, or used: nothing to merge
		}
		bases[dev] = s.domainPathOf(chain[target])
	}
	return bases, nil
}

// domainPathOf is the path the domain names for host file p: p itself,
// unless a test roots this host's files elsewhere (hostDiskRoot).
func (s *Server) domainPathOf(p string) string {
	if s.hostDiskRoot == "" {
		return p
	}
	root := resolvedOr(s.hostDiskRoot)
	if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "/" + rel
	}
	return p
}

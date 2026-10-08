package grpcapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// maxMergeWalk bounds a chain walk here. It is far above the start's cap
// (maxBackingDepth) on purpose: a chain grown past the cap is exactly what a
// merge collapses.
const maxMergeWalk = 256

// errLayerUnknown: a layer of a chain could not be read, so what it backs on
// is unknown.
var errLayerUnknown = fmt.Errorf("a disk's backing chain cannot be read")

// chainLayer is one layer of a disk's backing chain: name, the path the
// chain spells it by (the domain's source for the top, then each backing
// name as the layer above gives it, a relative one joined to that layer's
// directory — never resolved), and file, the file it is on this host,
// resolved through symlinks.
type chainLayer struct{ name, file string }

// diskLayers returns file and every file of its backing chain, resolved,
// top first, stopping before the image store (a base any VM may share, which
// a merge never writes into or removes). See walkChain.
func diskLayers(file string, images []string) ([]string, error) {
	layers, err := walkChain(file, file, images, func(p string) string { return p })
	out := make([]string, len(layers))
	for i, l := range layers {
		out[i] = l.file
	}
	return out, err
}

// chainOf is the chain of the disk the domain names top, as walkChain.
func (s *Server) chainOf(top string, images []string) ([]chainLayer, error) {
	return walkChain(top, s.hostDiskFile(top), images, s.domainPathOf)
}

// walkChain walks a chain from its top, named name and found on this host
// at host, stopping before the image store. A block device or a regular
// file that is not qcow2 is a layer with no backing. A file that cannot be
// stat'ed or opened, or a qcow2 header that cannot be read, is
// errLayerUnknown — never "no backing". A protocol backing ends the walk (it
// is no local file). spell is how an absolute backing name is named.
func walkChain(name, host string, images []string, spell func(string) string) ([]chainLayer, error) {
	var out []chainLayer
	for depth := 0; depth < maxMergeWalk; depth++ {
		path := resolvedOr(host)
		if withinAny(path, images) {
			return out, nil
		}
		fi, err := os.Stat(path)
		if err != nil {
			// %w twice: a missing file (fs.ErrNotExist) is told apart.
			return out, fmt.Errorf("%w: %s: %w", errLayerUnknown, path, err)
		}
		out = append(out, chainLayer{name: name, file: path})
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
		if filepath.IsAbs(b) {
			name, host = spell(b), b
		} else {
			// Relative to the directory of the layer as it was opened,
			// as qemu resolves it.
			name, host = filepath.Join(filepath.Dir(name), b), filepath.Join(filepath.Dir(host), b)
		}
	}
	return out, fmt.Errorf("%w: %s: deeper than %d layers", errLayerUnknown, name, maxMergeWalk)
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
//
// A merge writes and removes only the deleting VM's own snapshot layers
// (snapshotMergeBases), so only a disk that could back on them matters, and
// every build records backing_disk for the one kind that does, a linked
// clone (re-review 2, I-A):
//   - another host's disk, and a disk on shared storage, are judged by their
//     recorded backing_disk alone — never by whether this host can read
//     them (an NFS pool another host mounted, an earlier build's clone
//     recorded "nfs");
//   - a disk of this host whose file is not there has no header, so it backs
//     on nothing beyond its backing_disk (a VM in error whose disk was never
//     made, a pool not mounted);
//   - a disk of this host that is there is walked by its headers, which also
//     finds a clone whose record names no backing. One that cannot be read
//     (an unreadable header, a permission error) fails the whole answer
//     (errLayerUnknown): it may back on any layer, so the caller must
//     neither merge nor remove anything.
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
			if remote := d.HostName != "" && d.HostName != s.hostName; remote || corrosion.DiskIsShared(d) {
				continue
			}
			if !strings.HasPrefix(d.Path, "/") {
				continue // not a file path (an rbd name, say): no local chain
			}
			layers, err := diskLayers(s.hostDiskFile(d.Path), images)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("disk %q of %q: %w", d.DiskName, vm.Name, err)
			}
			for _, l := range layers {
				add(l, vm.Name)
			}
		}
	}
	return users, nil
}

// mergeTarget is where one disk's chain merges: base, as the disk's chain
// spells it (what the domain is repointed at), and disk, the record of it.
type mergeTarget struct{ base, disk string }

// snapshotMergeBases decides, for deleting vmName's snapshot deleting, which
// layer each of its disks merges into (controller ruling, round 4). Only
// this VM's own snapshot layers are merged:
//
//   - the family: from the domain's active layer down, each layer the one
//     above was made from by libvirt's external-snapshot naming (same
//     directory, named <stem>.<snapshot> after the layer's own stem). The
//     record of the disk must name one of them (compared resolved), and the
//     lowest is the VM's own disk: nothing under it is ever a target — a
//     pool's shared image, a template, a replica;
//   - the record's backing_disk and backing image are never targets, nor is
//     anything in the image store;
//   - a frozen layer of any snapshot libvirt holds other than deleting,
//     recorded by litevirt or not, stops it; a snapshot litevirt records
//     that libvirt does not hold froze an unknown layer: nothing is merged;
//   - a layer another VM uses (a linked clone of it, recorded or found by
//     its header) stops it;
//   - a target is a qcow2 file.
//
// The target is the lowest layer reached with none of these met; a disk
// whose active layer is already that layer is not listed. Deleting the
// VM's current snapshot so merges its overlay into its parent (the VM's
// own disk, or the previous snapshot's layer), as main did on libvirt 10.
//
// Any layer that cannot be read, here or in another VM's chain, is an error:
// nothing is merged when what depends on a layer is unknown.
func (s *Server) snapshotMergeBases(ctx context.Context, vmName, deleting string) (map[string]mergeTarget, error) {
	images := s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	srcs, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		return nil, err
	}
	users, err := s.layerUsers(ctx, vmName, images)
	if err != nil {
		return nil, err
	}
	recorded, err := corrosion.ListSnapshots(ctx, s.db, vmName)
	if err != nil {
		return nil, err
	}
	held, err := s.virt.SnapshotBaseFiles(vmName)
	if err != nil {
		return nil, fmt.Errorf("list libvirt's snapshots: %w", err)
	}
	known := map[string]bool{deleting: true}
	for _, r := range recorded {
		known[r.Name] = true
		if _, ok := held[r.Name]; !ok && r.Name != deleting {
			return nil, fmt.Errorf("snapshot %q has no libvirt metadata: the layer it froze is unknown", r.Name)
		}
	}
	frozen := map[string]string{} // resolved file → a snapshot that froze it
	for name, files := range held {
		if name == deleting {
			continue
		}
		if !known[name] {
			slog.Warn("snapshot merge: libvirt holds a snapshot litevirt has no record of — its layers are kept",
				"vm", vmName, "libvirt_snapshot", name, "layers", files)
		}
		for _, f := range files {
			if strings.HasPrefix(f, "/") {
				frozen[resolvedOr(s.hostDiskFile(f))] = name
			}
		}
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, err
	}
	out := map[string]mergeTarget{}
	for dev, top := range srcs {
		if !strings.HasPrefix(top, "/") {
			continue
		}
		chain, err := s.chainOf(top, images)
		if err != nil {
			return nil, fmt.Errorf("disk %s: %w", dev, err)
		}
		fam := ownFamily(chain)
		d, ok := s.recordOfFamily(disks, chain[:fam])
		if !ok {
			slog.Warn("snapshot merge: no record of this VM names the disk's layers — not merged",
				"vm", vmName, "dev", dev, "top", top)
			continue
		}
		target := -1
		for i := 0; i < fam; i++ {
			if why := s.mergeStop(d, chain[i], i > 0, users, frozen); why != "" {
				if i > 0 {
					slog.Info("snapshot merge: stopped above a layer", "vm", vmName, "dev", dev, "layer", chain[i].name, "why", why)
				}
				break
			}
			target = i
		}
		if target <= 0 {
			continue // the active layer itself, or used: nothing to merge
		}
		out[dev] = mergeTarget{base: chain[target].name, disk: d.DiskName}
	}
	return out, nil
}

// ownFamily is how many layers, from the top, are one disk's own: each
// layer below the top is in the family when the layer above it was named
// from it the way libvirt names an external snapshot's overlay — in the
// same directory, <its stem>.<snapshot> (diskStem; a dotted snapshot name
// keeps the rule, as libvirt replaces only the last extension).
func ownFamily(chain []chainLayer) int {
	if len(chain) == 0 {
		return 0
	}
	n := 1
	for i := 1; i < len(chain); i++ {
		if !overlayOf(chain[i-1].name, chain[i].name) && !overlayOf(chain[i-1].file, chain[i].file) {
			break
		}
		n++
	}
	return n
}

func overlayOf(overlay, base string) bool {
	if filepath.Dir(overlay) != filepath.Dir(base) {
		return false
	}
	return strings.HasPrefix(filepath.Base(overlay), diskStem(filepath.Base(base))+".")
}

// recordOfFamily is the one record of the VM whose file (resolved) is a
// layer of fam.
func (s *Server) recordOfFamily(disks []corrosion.DiskRecord, fam []chainLayer) (corrosion.DiskRecord, bool) {
	var found []corrosion.DiskRecord
	for _, d := range disks {
		if !strings.HasPrefix(d.Path, "/") {
			continue
		}
		rf := resolvedOr(s.hostDiskFile(d.Path))
		for _, l := range fam {
			if l.file == rf {
				found = append(found, d)
				break
			}
		}
	}
	if len(found) != 1 {
		return corrosion.DiskRecord{}, false
	}
	return found[0], true
}

// mergeStop says why layer l of d's chain may not be merged into, or
// written as part of a merge ("" when it may).
func (s *Server) mergeStop(d corrosion.DiskRecord, l chainLayer, target bool, users map[string][]string, frozen map[string]string) string {
	if d.BackingDisk != "" && (l.file == resolvedOr(s.hostDiskFile(d.BackingDisk)) || l.file == filepath.Clean(d.BackingDisk)) {
		return "the disk's recorded backing_disk"
	}
	if b := d.BackingImage; b != "" && (filepath.Base(l.file) == b || filepath.Base(l.name) == b) {
		return "the disk's backing image"
	}
	if u := users[l.file]; len(u) > 0 {
		return "used by " + strings.Join(u, ", ")
	}
	if snap, ok := frozen[l.file]; ok {
		return "frozen by snapshot " + snap
	}
	if target {
		if q, err := hasQcow2Magic(l.file); err != nil || !q {
			return "not a qcow2 file"
		}
	}
	return ""
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

// recordMergedBases moves the record of each merged disk onto the file the
// domain now names for it, when that file is the merge's base (compared
// resolved): the record names the same file as the domain, in the domain's
// spelling, whatever the directory's symlinks (review I-4).
//
// Only a disk the merge settled (merged lists it: its persistent definition
// names the base) is moved. One whose definition could not be repointed
// keeps its record on the old top, which its definition still names.
func (s *Server) recordMergedBases(ctx context.Context, vmName string, targets map[string]mergeTarget, merged map[string][]string) {
	if len(merged) == 0 {
		return
	}
	live, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		slog.Warn("snapshot merge: read the domain's disks to record the merge", "vm", vmName, "error", err)
		return
	}
	for dev, t := range targets {
		if _, ok := merged[dev]; !ok {
			continue
		}
		src := live[dev]
		if src == "" || resolvedOr(s.hostDiskFile(src)) != resolvedOr(s.hostDiskFile(t.base)) {
			continue // not merged (a fallback): the domain is where it was
		}
		if err := corrosion.UpdateVMDiskPath(ctx, s.db, vmName, t.disk, src); err != nil {
			slog.Warn("snapshot merge: record the merged base", "vm", vmName, "disk", t.disk, "error", err)
		}
	}
}

// removeMergedLayers removes the layers a merge gave back, keeping (with a
// WARN) any that a record of the VM or the domain still names: a layer is
// removed only once nothing of this VM points at it.
func (s *Server) removeMergedLayers(ctx context.Context, vmName string, merged map[string][]string) {
	var layers []string
	for _, ls := range merged {
		layers = append(layers, ls...)
	}
	if len(layers) == 0 {
		return
	}
	named := map[string]bool{}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("snapshot merge: cannot read the VM's records — the merged layers are kept", "vm", vmName, "layers", layers, "error", err)
		return
	}
	for _, d := range disks {
		if strings.HasPrefix(d.Path, "/") {
			named[resolvedOr(s.hostDiskFile(d.Path))] = true
		}
	}
	live, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		slog.Warn("snapshot merge: cannot read the domain's disks — the merged layers are kept", "vm", vmName, "layers", layers, "error", err)
		return
	}
	for _, src := range live {
		named[resolvedOr(s.hostDiskFile(src))] = true
	}
	for _, l := range layers {
		if named[resolvedOr(l)] {
			slog.Warn("snapshot merge: a merged layer is still named by the VM — kept", "vm", vmName, "layer", l)
			continue
		}
		if err := os.Remove(l); err != nil && !os.IsNotExist(err) {
			slog.Warn("snapshot merge: a merged layer could not be removed", "vm", vmName, "layer", l, "error", err)
		}
	}
}

// chainHolders says what keeps file's layers from merging, for a start
// refused on a too-deep chain: the other VMs layered on them (each a linked
// clone to delete, or re-create with --mode full), or the disk whose chain
// cannot be read, which stops every merge on this host until it can be.
func (s *Server) chainHolders(ctx context.Context, vmName, file string) string {
	images := s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	users, err := s.layerUsers(ctx, vmName, images)
	if err != nil {
		return fmt.Sprintf("No merge runs on this host while a disk's chain cannot be read (%v): make it readable, "+
			"or delete that VM, first.", err)
	}
	layers, _ := diskLayers(file, images)
	var holders []string
	seen := map[string]bool{}
	for _, l := range layers {
		for _, u := range users[l] {
			if !seen[u] {
				seen[u] = true
				holders = append(holders, u)
			}
		}
	}
	if len(holders) == 0 {
		return "Nothing else holds its layers."
	}
	return fmt.Sprintf("Its layers are held by %s, layered on them: delete it, or re-create it with "+
		"`lv clone <source> <name> --mode full`, first.", strings.Join(holders, ", "))
}

// overlayName is the file libvirt names an external snapshot snap of a disk
// on src: src's basename with the text after its last '.' replaced by snap,
// or with ".snap" appended when it has none.
func overlayName(src, snap string) string {
	base := filepath.Base(src)
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	return filepath.Join(filepath.Dir(src), base+"."+snap)
}

// clearLeftoverOverlays removes, before snapshot snap of vmName is taken, a
// file already at the name libvirt will give the snapshot's overlay — what a
// failed merge leaves — when nothing uses it: no VM's record or chain
// (layerUsers over every VM, this one too), no source of this domain, live
// or persistent, and no layer a snapshot of it froze. A file that is used,
// or whose use cannot be told, is kept, and the create is refused naming it
// (libvirt would refuse it too).
func (s *Server) clearLeftoverOverlays(ctx context.Context, vmName, snap string) error {
	srcs := map[string]bool{}
	if live, err := s.virt.DomainDiskSources(vmName); err == nil {
		for _, p := range live {
			srcs[p] = true
		}
	}
	if x, err := s.virt.DumpXMLInactive(vmName); err == nil {
		for _, p := range lv.DomainDiskFiles(x) {
			srcs[p] = true
		}
	}
	var leftovers []string
	named := map[string]bool{}
	for src := range srcs {
		if !strings.HasPrefix(src, "/") {
			continue
		}
		named[resolvedOr(s.hostDiskFile(src))] = true
		ov := overlayName(src, snap)
		if _, err := os.Lstat(s.hostDiskFile(ov)); err == nil {
			leftovers = append(leftovers, ov)
		}
	}
	if len(leftovers) == 0 {
		return nil
	}
	images := s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	users, uerr := s.layerUsers(ctx, "", images)
	held, herr := s.virt.SnapshotBaseFiles(vmName)
	frozen := map[string]bool{}
	for _, files := range held {
		for _, f := range files {
			frozen[resolvedOr(s.hostDiskFile(f))] = true
		}
	}
	for _, ov := range leftovers {
		file := resolvedOr(s.hostDiskFile(ov))
		why := ""
		switch {
		case uerr != nil:
			why = "what uses it cannot be told: " + uerr.Error()
		case herr != nil:
			why = "the VM's snapshots cannot be listed: " + herr.Error()
		case named[file]:
			why = "the VM's definition names it"
		case len(users[file]) > 0:
			why = "used by " + strings.Join(users[file], ", ")
		case frozen[file]:
			why = "a snapshot of the VM froze it"
		}
		if why != "" {
			return status.Errorf(codes.FailedPrecondition,
				"snapshot %q of %q: its overlay would be %s, which is already there and kept (%s); choose another snapshot name",
				snap, vmName, ov, why)
		}
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return status.Errorf(codes.FailedPrecondition,
				"snapshot %q of %q: remove the unused leftover %s: %v", snap, vmName, ov, err)
		}
		_ = os.Remove(lv.MergedLayerMarker(file))
		slog.Warn("snapshot create: removed an unused leftover at the overlay's name (a failed merge's)",
			"vm", vmName, "snapshot", snap, "file", ov)
	}
	return nil
}

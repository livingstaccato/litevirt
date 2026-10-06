package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// maxBackingDepth bounds a pre-checked backing chain.
const maxBackingDepth = 16

// chainRule judges one backing file of a chain before anything opens it:
// layer (the file naming it, resolved through symlinks) names resolved
// (resolved through symlinks) and declares its format ("qcow2" or "raw").
// A nil chainRule accepts no backing at all.
type chainRule func(layer, resolved, format string) error

// precheckQcow2Input is precheckChain with every backing passed to
// allowBacking and no raw backing allowed.
func precheckQcow2Input(path string, allowBacking func(resolved string) error) error {
	_, err := precheckChain(path, confinedRule(allowBacking, ""))
	return err
}

// confinedRule accepts a backing allow accepts, and a raw one only when it is
// exactly rawBacking (resolved). nil allow: no backing at all.
func confinedRule(allow func(resolved string) error, rawBacking string) chainRule {
	if allow == nil {
		return nil
	}
	return func(layer, resolved, format string) error {
		if err := allow(resolved); err != nil {
			return err
		}
		if format == "raw" && (rawBacking == "" || resolved != rawBacking) {
			return fmt.Errorf("%s names a raw backing %q that is not this disk's recorded backing", layer, resolved)
		}
		return nil
	}
}

// precheckChain judges a qcow2 file's header before qemu-img opens it with
// -f qcow2, then each file of its backing chain the same way:
//   - no external data file: qemu opens that with the image itself, so a
//     conversion would copy whatever file the header names;
//   - at most one backing-format extension: this package reads the first,
//     qemu the last, and the two must not be able to disagree;
//   - a backing file only if rule (nil: none) accepts it, judged by its path
//     resolved through symlinks and the format the layer above declares; a
//     protocol-looking name never;
//   - a backing declared qcow2 is judged in turn; one declared raw must be a
//     regular file and ends the chain: raw is opened as raw (qemu honours the
//     declared format) and never interpreted. Any other declared format, or
//     none, is refused.
//
// It returns every backing it accepted, resolved: a reader that follows the
// chain itself (qcow2.ConvertConfined) is confined to exactly these
// (onlyAccepted).
func precheckChain(path string, rule chainRule) ([]string, error) {
	var accepted []string
	layer := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		layer = r
	}
	for depth := 0; ; depth++ {
		if depth > maxBackingDepth {
			return nil, fmt.Errorf("backing chain deeper than %d", maxBackingDepth)
		}
		if err := precheckQcow2Header(path); err != nil {
			return nil, err
		}
		info, err := qcow2.Info(path)
		if err != nil {
			return nil, fmt.Errorf("%s is not a qcow2 image: %w", path, err)
		}
		if info.BackingFile == "" {
			return accepted, nil
		}
		if rule == nil {
			return nil, fmt.Errorf("%s names backing file %q; a standalone image is required", path, info.BackingFile)
		}
		if looksLikeProtocol(info.BackingFile) {
			return nil, fmt.Errorf("%s names backing %q, which is a protocol, not a file", path, info.BackingFile)
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		resolved, err := filepath.EvalSymlinks(b)
		if err != nil {
			return nil, fmt.Errorf("%s: backing file %q: %w", path, info.BackingFile, err)
		}
		if info.BackingFormat != "qcow2" && info.BackingFormat != "raw" {
			return nil, fmt.Errorf("%s names backing file %q with format %q; only a declared qcow2 or (recorded) raw backing is accepted",
				path, info.BackingFile, info.BackingFormat)
		}
		if err := rule(layer, resolved, info.BackingFormat); err != nil {
			return nil, err
		}
		accepted = append(accepted, resolved)
		if info.BackingFormat == "raw" {
			if fi, err := os.Lstat(resolved); err != nil || !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("raw backing %q is not a regular file", resolved)
			}
			return accepted, nil
		}
		path, layer = resolved, resolved
	}
}

// onlyAccepted confines a chain reader to exactly the backings precheckChain
// accepted.
func onlyAccepted(accepted []string) func(string) error {
	return func(resolved string) error {
		for _, a := range accepted {
			if a == resolved {
				return nil
			}
		}
		return fmt.Errorf("backing %q was not pre-checked", resolved)
	}
}

// looksLikeProtocol reports a backing name qemu would read as a protocol
// ("json:{...}", "nbd:...", "file:...") rather than a path: a ':' before
// the first '/'.
func looksLikeProtocol(name string) bool {
	c := strings.IndexByte(name, ':')
	sl := strings.IndexByte(name, '/')
	return c >= 0 && (sl < 0 || c < sl)
}

// confineTo accepts resolved only strictly inside one of roots (each
// resolved through symlinks when it exists).
func confineTo(resolved string, roots ...string) error {
	for _, r := range roots {
		if r == "" {
			continue
		}
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			r = rr
		}
		if resolved != r && safename.Contains(r, resolved) {
			return nil
		}
	}
	return fmt.Errorf("backing %q is outside the image store and the disk's pool directory", resolved)
}

// diskChainRule is the rule every backing of VM disk d's chain is judged by,
// before a copy, move, replication, clone, migration, image build or in-place
// restore reads it. A layer may be:
//
//   - in the image store, and then standalone (no backing, no external data
//     file): an image is a base, never a way to name another file;
//   - exactly the backing_disk recorded on the layer naming it — d's own
//     record for d's file, or any disk row whose path is that layer: a
//     linked clone's template disk (in whichever pool, of whichever project
//     the clone was authorized from), a --no-localize promotion's replica.
//     A backing declared raw is accepted ONLY this way;
//   - in the directory of a file-based pool on this host that d's VM's project
//     may use (global, or owned by that project), or d's own pool;
//   - in <data_dir>/disks or d's own directory (outside those pools) only as a
//     file the VM's project owns by record — a disk row of a VM in that
//     project, or that project's recorded replica — or as the base an external
//     snapshot of d's VM left (same directory and stem, the layer named after
//     one of the VM's recorded snapshots).
//
// Paths are compared resolved through symlinks. Under the hostDiskRoot test
// seam, records name files as a host would, and are mapped onto it.
func (s *Server) diskChainRule(ctx context.Context, d corrosion.DiskRecord) chainRule {
	c := &diskChain{s: s, ctx: ctx, d: d, projects: map[string]string{}}
	c.project = c.projectOf(d.VMName)
	c.self = resolvedOr(s.hostDiskFile(d.Path))
	c.images = s.rootsAsFound(filepath.Join(s.dataDir, "images"))
	c.pools = s.chainPoolDirs(ctx, d, c.project)
	c.own = s.rootsAsFound(filepath.Join(s.dataDir, "disks"))
	if dir := filepath.Dir(d.Path); !atOrWithinAny(resolvedOr(s.hostDiskFile(dir)), c.pools) {
		c.own = append(c.own, s.rootsAsFound(dir)...)
	}
	return c.judge
}

type diskChain struct {
	s        *Server
	ctx      context.Context
	d        corrosion.DiskRecord
	project  string
	self     string
	images   []string
	pools    []string
	own      []string
	projects map[string]string // vm → normalized project ("" unknown)
}

func (c *diskChain) judge(layer, resolved, format string) error {
	if withinAny(resolved, c.images) {
		if err := qcow2.AssertStandalone(resolved); err != nil {
			return fmt.Errorf("image-store layer %q is refused: %w", resolved, err)
		}
		return nil
	}
	if c.recordedBacking(layer, resolved) {
		return nil
	}
	if format == "raw" {
		return fmt.Errorf("%s names a raw backing %q that is not the backing_disk recorded for it", layer, resolved)
	}
	if withinAny(resolved, c.pools) {
		return nil
	}
	if withinAny(resolved, c.own) && (c.ownedByProject(resolved) || c.snapshotBase(layer, resolved)) {
		return nil
	}
	return fmt.Errorf("backing %q is outside the image store and every pool project %q may use, and is not a file that project owns by record",
		resolved, c.project)
}

// recordedBacking reports whether resolved is the backing_disk recorded on the
// layer naming it: d's own record when layer is d's file, or any disk row
// whose path is layer.
func (c *diskChain) recordedBacking(layer, resolved string) bool {
	if layer == c.self && c.d.BackingDisk != "" && resolvedOr(c.s.hostDiskFile(c.d.BackingDisk)) == resolved {
		return true
	}
	for _, r := range c.rowsAt(layer) {
		if r.BackingDisk != "" && resolvedOr(c.s.hostDiskFile(r.BackingDisk)) == resolved {
			return true
		}
	}
	return false
}

// ownedByProject reports a file the VM's project owns by record: some disk
// row's own file, of a VM in that project, or that project's recorded
// replica.
func (c *diskChain) ownedByProject(resolved string) bool {
	if c.project == "" {
		return false
	}
	for _, r := range c.rowsAt(resolved) {
		if c.projectOf(r.VMName) == c.project {
			return true
		}
	}
	if rec, ok := replicaRecordFor(resolved); ok && tenancy.NormalizeProject(rec.Project) == c.project {
		return true
	}
	return false
}

// snapshotBase reports the base an external disk-only snapshot of d's VM
// left: libvirt names the overlay after the snapshot, beside its source, with
// the same stem (vm-root.qcow2 → vm-root.<snap>), and the VM's record keeps
// the overlay as its path. The layer must carry d's own stem and one of the
// VM's recorded snapshot names; the base the same stem, in the same
// directory.
func (c *diskChain) snapshotBase(layer, resolved string) bool {
	if filepath.Dir(layer) != filepath.Dir(resolved) {
		return false
	}
	stem := func(p string) string { b := filepath.Base(p); return strings.TrimSuffix(b, filepath.Ext(b)) }
	if stem(layer) != stem(c.self) || stem(resolved) != stem(c.self) || layer == resolved {
		return false
	}
	ext := strings.TrimPrefix(filepath.Ext(layer), ".")
	if ext == "" {
		return false
	}
	snaps, err := corrosion.ListSnapshots(c.ctx, c.s.db, c.d.VMName)
	if err != nil {
		return false
	}
	for _, sn := range snaps {
		if sn.Name == ext {
			return true
		}
	}
	return false
}

// rowsAt is every disk row whose own file is resolved.
func (c *diskChain) rowsAt(resolved string) []corrosion.DiskRecord {
	var out []corrosion.DiskRecord
	seen := map[string]bool{}
	for _, p := range []string{c.s.recordPath(resolved), resolved} {
		if seen[p] {
			continue
		}
		seen[p] = true
		rows, err := corrosion.DisksReferencingPath(c.ctx, c.s.db, p)
		if err != nil {
			continue
		}
		for _, r := range rows {
			if r.Path != "" && resolvedOr(c.s.hostDiskFile(r.Path)) == resolved {
				out = append(out, r)
			}
		}
	}
	return out
}

// projectOf is vm's normalized project, "" when it has no record.
func (c *diskChain) projectOf(vm string) string {
	if p, ok := c.projects[vm]; ok {
		return p
	}
	p := ""
	if rec, err := corrosion.GetVM(c.ctx, c.s.db, vm); err == nil && rec != nil {
		p = tenancy.NormalizeProject(rec.Project)
	}
	c.projects[vm] = p
	return p
}

// chainPoolDirs are the pool directories a chain of d may read from without a
// record tying the file to it: d's own pool, and every file-based pool on this
// host that project may use and that is not refused. A pool whose directory
// overlaps <data_dir>/disks (a default local pool) adds nothing: that
// directory holds every project's disks and is judged file by file.
func (s *Server) chainPoolDirs(ctx context.Context, d corrosion.DiskRecord, project string) []string {
	disks := resolvedOr(filepath.Join(s.dataDir, "disks"))
	var dirs []string
	add := func(dir string) {
		if rd := resolvedOr(dir); dir == "" || safename.Contains(rd, disks) || safename.Contains(disks, rd) {
			return
		}
		dirs = append(dirs, s.rootsAsFound(dir)...)
	}
	if d.StorageVolume != "" {
		if ref, ok := s.resolvePool(ctx, d.StorageVolume); ok {
			if dir, err := fileBasedPoolDir(s.dataDir, ref); err == nil {
				add(dir)
			}
		}
	}
	if project == "" {
		return dirs
	}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return dirs
	}
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) || !tenancy.AdmitAttach(project, p.Project) {
			continue
		}
		ref := StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options}
		if !s.poolUsableForWrite(ctx, p.Name, ref) {
			continue
		}
		if dir, err := fileBasedPoolDir(s.dataDir, ref); err == nil {
			add(dir)
		}
	}
	return dirs
}

// rootsAsFound is dir resolved through symlinks, and under the hostDiskRoot
// test seam also where this host finds it.
func (s *Server) rootsAsFound(dir string) []string {
	out := []string{resolvedOr(dir)}
	if s.hostDiskRoot != "" {
		out = append(out, resolvedOr(s.hostDiskFile(dir)))
	}
	return out
}

// recordPath is the path a record names for the file resolved: itself, or
// under the hostDiskRoot test seam the path below that root.
func (s *Server) recordPath(resolved string) string {
	if s.hostDiskRoot == "" {
		return resolved
	}
	root := resolvedOr(s.hostDiskRoot)
	if rel, err := filepath.Rel(root, resolved); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return string(filepath.Separator) + rel
	}
	return resolved
}

// resolvedOr is p resolved through symlinks, or p as given when it cannot be.
func resolvedOr(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// atOrWithinAny reports dir at or inside one of roots (already resolved).
func atOrWithinAny(dir string, roots []string) bool {
	for _, r := range roots {
		if r != "" && r != "." && safename.Contains(r, dir) {
			return true
		}
	}
	return false
}

// withinAny reports resolved strictly inside one of roots (already resolved).
func withinAny(resolved string, roots []string) bool {
	for _, r := range roots {
		if r != "" && r != "." && resolved != r && safename.Contains(r, resolved) {
			return true
		}
	}
	return false
}

// precheckQcow2Header judges one qcow2 header without following its backing
// file: it parses as qcow2, keeps no data in an external file, and declares
// its backing format at most once.
func precheckQcow2Header(path string) error {
	if _, err := qcow2.Info(path); err != nil {
		return fmt.Errorf("%s is not a qcow2 image: %w", path, err)
	}
	if err := qcow2.AssertNoExternalData(path); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	n, err := qcow2.BackingFormatExtensionCount(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if n > 1 {
		return fmt.Errorf("%s declares its backing format %d times", path, n)
	}
	return nil
}

// imageStoreBaseOnly accepts a backing file only inside dataDir's image store
// (both sides resolved through symlinks), and only a base that is itself
// standalone — the image a VM was created from.
func imageStoreBaseOnly(dataDir string) func(string) error {
	return func(resolved string) error {
		images, err := filepath.EvalSymlinks(filepath.Join(dataDir, "images"))
		if err != nil {
			return fmt.Errorf("image store: %w", err)
		}
		if !safename.Contains(images, resolved) || resolved == images {
			return fmt.Errorf("backing file %q is not in the image store %s", resolved, images)
		}
		if err := qcow2.AssertStandalone(resolved); err != nil {
			return fmt.Errorf("image-store base %q: %w", resolved, err)
		}
		return nil
	}
}

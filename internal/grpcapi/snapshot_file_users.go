package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
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
// use". So is a path whose resolution does not answer (resolvedStrict): a
// file named in one form and reached in another would be missed, and merged
// or removed under the VM built on it.
func (s *Server) snapshotFileUsers(ctx context.Context, vmName string, files []string) ([]string, error) {
	mine := map[string]bool{}
	for _, f := range files {
		if f == "" {
			continue
		}
		r, err := resolvedStrict(f)
		if err != nil {
			return nil, err
		}
		mine[filepath.Clean(f)] = true
		mine[r] = true
	}
	if len(mine) == 0 {
		return nil, nil
	}
	var noAnswer error
	uses := func(p string) bool {
		if p == "" {
			return false
		}
		if mine[filepath.Clean(p)] {
			return true
		}
		r, err := resolvedStrict(s.hostDiskFile(p))
		if err != nil {
			if noAnswer == nil {
				noAnswer = err
			}
			return true // cannot tell: in use
		}
		return mine[r]
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	var out []string
	formats := map[string]map[string]string{}
	for i := range vms {
		vm := &vms[i]
		if vm.Name == vmName {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			return nil, err
		}
		for _, d := range disks {
			file := s.hostDiskFile(d.Path)
			if uses(d.BackingDisk) {
				out = append(out, vm.Name)
				break
			}
			reached, rerr := chainReaches(file, s.diskFormatOf(vm, d.Path, formats), uses)
			if rerr != nil {
				// Not read: in use, and the call fails (Unavailable).
				if noAnswer == nil {
					noAnswer = rerr
				}
				reached = true
			}
			if reached {
				out = append(out, vm.Name)
				break
			}
		}
	}
	if noAnswer != nil {
		return nil, noAnswer
	}
	sort.Strings(out)
	return out, nil
}

// snapshotFileUsersCode is the status code of a refusal because
// snapshotFileUsers could not tell: Unavailable (retry once it answers) when
// storage did not answer, Internal otherwise.
func snapshotFileUsersCode(err error) codes.Code {
	if storage.IsFSNoAnswer(err) {
		return codes.Unavailable
	}
	return codes.Internal
}

// diskFormatOf is the driver type vm's domain on this host gives file
// ("qcow2", "raw", ...), or "" when that cannot be told: the VM is on another
// host, its domain is not defined here, or the file is not among its disks.
// formats caches each VM's definition for one scan.
func (s *Server) diskFormatOf(vm *corrosion.VMRecord, file string, formats map[string]map[string]string) string {
	if vm == nil || vm.HostName != s.hostName || s.virt == nil {
		return ""
	}
	m, ok := formats[vm.Name]
	if !ok {
		m, _ = s.virt.DomainDiskFormats(vm.Name)
		formats[vm.Name] = m
	}
	return m[file]
}

// chainReaches reports whether file, or a layer of its qcow2 backing chain,
// satisfies hit. Headers only, bounded.
//
// A layer known to be raw is checked by its path and ends the walk: its
// bytes are the guest's, and a guest could write a header there naming any
// file (re-review R1-M1). What a layer is comes from outside it: the top's
// from topFormat (its VM's domain on this host), every other layer's from
// its parent's header. A layer nothing says is raw is parsed — when it
// cannot be told, parsing can only find a user too many, which stops or
// keeps, never one too few, which would delete or merge a file in use
// (re-review R2-C2). A layer that cannot be read, or a protocol backing,
// ends the walk.
//
// The headers are read under storage.Bounded, per disk: a disk on a network
// filesystem whose server does not answer gets the *storage.FSNoAnswerError
// within the bound, never false. "Not reached" from a chain that was not
// read would let a delete merge or remove a file the disk is built on.
func chainReaches(file, topFormat string, hit func(string) bool) (bool, error) {
	if file == "" || !filepath.IsAbs(file) {
		return false, nil
	}
	stat := chainStat // read here: the walk may outlive this call
	layers, err := storage.Bounded("read the backing chain ("+topFormat+") of", file, func() ([]string, error) {
		return chainLayers(stat, file, topFormat), nil
	})
	if err != nil {
		return false, err
	}
	for _, l := range layers {
		if hit(l) {
			return true, nil
		}
	}
	return false, nil
}

// chainStat stats a layer of a disk's chain (chainLayers, layerBacking); a
// test replaces it.
var chainStat = os.Stat

// chainLayers is file and each layer of its backing chain that chainReaches
// tests, top first: the walk reads only headers and touches nothing else,
// so it can be left behind when its storage does not answer.
func chainLayers(stat func(string) (os.FileInfo, error), file, topFormat string) []string {
	var out []string
	path, format := file, topFormat
	for depth := 0; depth <= maxBackingDepth; depth++ {
		if fi, err := stat(path); err != nil || !fi.Mode().IsRegular() {
			return out
		}
		out = append(out, path)
		if format != "" && format != "qcow2" {
			return out
		}
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return out
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path, format = b, info.BackingFormat
	}
	return out
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
	names := s.snapshotNamesOf(ctx, vmName)
	snapNames := map[string]bool{}
	for _, n := range names {
		snapNames[n] = true
	}
	recorded := map[string]bool{}
	for _, d := range disks {
		recorded[filepath.Clean(s.hostDiskFile(d.Path))] = true
	}
	self, _ := corrosion.GetVM(ctx, s.db, vmName)
	formats := map[string]map[string]string{}
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
		stem := filepath.Base(diskStemNamed(file, names))
		rest, ok := strings.CutPrefix(stem, vmName+"-")
		if !ok || rest == "" || strings.Contains(rest, "-") {
			continue
		}
		dir := filepath.Dir(file)
		own := func(p string) bool {
			return filepath.Dir(p) == dir && filepath.Base(diskStemNamed(p, names)) == stem
		}
		chain := map[string]bool{file: true}
		top := s.diskFormatOf(self, d.Path, formats)
		for path, depth := file, 0; (top == "" || top == "qcow2") && depth <= maxBackingDepth; depth++ {
			info, err := qcow2.Info(path)
			if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) || (info.BackingFormat != "" && info.BackingFormat != "qcow2") {
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
		// The disk's canonical file <stem>.qcow2 is its own too — the debris
		// sweep takes it by that name — even when the chain no longer
		// reaches it (a migration copies the chain flat, and leaves the
		// out-of-chain layers on the old host: snapshot-lab.md, Round 3
		// row 6). Siblings backing onto it count as backing into the chain.
		chain[filepath.Join(dir, stem+".qcow2")] = true
		// Out-of-chain siblings: an overlay a restore of an older snapshot
		// left, and the later snapshots' layers above it, each backing into
		// the chain or into one already taken — so repeated until no more.
		matches, _ := filepath.Glob(filepath.Join(dir, globEscape(stem)+".*"))
		for changed := true; changed; {
			changed = false
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
				named := snapNames[strings.TrimPrefix(filepath.Base(m), stem+".")]
				if named || (b != "" && info.BackingFormat == "qcow2" && chain[filepath.Clean(b)]) {
					chain[m], changed = true, true
					add(m)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// removeOwnDiskLayers removes files ownDiskLayers listed, except one another
// VM names in its record or reaches through its qcow2 chain.
func (s *Server) removeOwnDiskLayers(ctx context.Context, vmName string, files []string) {
	kept := s.keptDiskFiles(ctx, vmName)
	for _, f := range files {
		if kept == nil || kept[filepath.Clean(f)] {
			continue
		}
		if held, why := s.keptNoteHolds(f); held {
			s.reportKeptNoteHold(ctx, vmName, "the delete's snapshot-layer cleanup", f, why)
			continue
		}
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

// keptDiskFiles is the files of vmName's disks recorded delete_with_vm=false
// — each one's file and every layer of its qcow2 chain (parsed unless
// declared raw: keeping a file too many is the safe side) — which no VM
// delete path may remove. nil when the records cannot be read: the caller
// then keeps everything.
func (s *Server) keptDiskFiles(ctx context.Context, vmName string) map[string]bool {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Error("delete: cannot read which disks are kept; keeping every file", "vm", vmName, "error", err)
		return nil
	}
	kept := map[string]bool{}
	for _, d := range disks {
		if d.DeleteWithVM || d.Path == "" {
			continue
		}
		if _, err := chainReaches(s.hostDiskFile(d.Path), "", func(p string) bool {
			kept[filepath.Clean(p)] = true
			return false
		}); err != nil {
			// A chain not read keeps every file: what it is built on is
			// unknown.
			slog.Error("delete: cannot read a kept disk's backing chain; keeping every file", "vm", vmName, "disk", d.DiskName, "error", err)
			return nil
		}
		kept[filepath.Clean(s.hostDiskFile(d.Path))] = true
	}
	return kept
}

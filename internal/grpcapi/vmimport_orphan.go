package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// importOrphanMinAge is how long a file at a converted disk's name, and every
// unrecorded file beside it named like it, must have gone unmodified before an
// import may take it for a crashed flow's leftover. Another host importing the
// same name into a shared pool, or any flow that has not recorded its file
// yet, is still writing it, or has just finished; a leftover that is
// re-imported is older than this. A leftover this host's placement record
// shows is a dead import's, unchanged since, needs no wait.
const importOrphanMinAge = 15 * time.Minute

// resolvedPath is p with every symlink resolved, or p cleaned if it cannot be.
func resolvedPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// namesFile reports whether a recorded path v names the file at dst (resolved
// to rdst, with stat fi): the same path once symlinks are resolved, the same
// file, the same name in the same directory compared without case (a
// case-insensitive pool), or an overlay in that directory whose name is the
// disk's stem plus a suffix (an external snapshot's overlay, whose base is the
// disk's plain name, named only in its header).
func namesFile(v, rdst string, fi os.FileInfo) bool {
	if v == "" {
		return false
	}
	rv := resolvedPath(v)
	if rv == rdst {
		return true
	}
	if vi, err := os.Stat(rv); err == nil && fi != nil && os.SameFile(vi, fi) {
		return true
	}
	if !strings.EqualFold(filepath.Dir(rv), filepath.Dir(rdst)) {
		return false
	}
	vb, db := strings.ToLower(filepath.Base(rv)), strings.ToLower(filepath.Base(rdst))
	stem := strings.TrimSuffix(db, ".qcow2")
	return vb == db || strings.HasPrefix(vb, stem+".")
}

// importPathReferences names what in the cluster records the file at dst, on
// any host: a disk row (live, or the tombstone of a deleted VM whose disk was
// kept) that is the file, its backing image, its backing disk or an overlay
// on it, or an image a host stores there. An empty answer means nothing does.
// A lookup that fails is an error, never "nothing".
func (s *Server) importPathReferences(ctx context.Context, dst string, fi os.FileInfo) (string, error) {
	rdst := resolvedPath(dst)
	// Candidates by name, without case; namesFile decides.
	like := "%" + strings.ToLower(strings.TrimSuffix(filepath.Base(rdst), ".qcow2")) + "%"
	var refs []string
	rows, err := s.db.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, backing_image, backing_disk, deleted_at FROM vm_disks
		 WHERE LOWER(path) LIKE ? OR LOWER(COALESCE(backing_image, '')) LIKE ? OR LOWER(COALESCE(backing_disk, '')) LIKE ?`,
		like, like, like)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if !namesFile(r.String("path"), rdst, fi) && !namesFile(r.String("backing_image"), rdst, fi) && !namesFile(r.String("backing_disk"), rdst, fi) {
			continue
		}
		what := fmt.Sprintf("disk %s of VM %s on %s", r.String("disk_name"), r.String("vm_name"), r.String("host_name"))
		if r.String("deleted_at") != "" {
			what += " (a deleted VM's kept disk)"
		}
		refs = append(refs, what)
	}
	rows, err = s.db.Query(ctx, `SELECT image_name, host_name, path FROM image_hosts WHERE LOWER(path) LIKE ?`, like)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if namesFile(r.String("path"), rdst, fi) {
			refs = append(refs, fmt.Sprintf("image %s on %s", r.String("image_name"), r.String("host_name")))
		}
	}
	return strings.Join(refs, ", "), nil
}

// importDiskNameInFlight names a flow that may be creating the file at dst
// right now and has not recorded it yet: an operation in flight on a VM whose
// disks are named like it (CreateVM, CloneVM and restore hold one across
// their disk writes; disk names may hold '-', so VM web's disk x-root and VM
// web-x's disk root share a name), another import on this host whose name
// prefixes it, or an operation that journaled it as the file it publishes (a
// disk attach).
func (s *Server) importDiskNameInFlight(ctx context.Context, importName, dst string, fi os.FileInfo) (string, error) {
	base := strings.ToLower(filepath.Base(dst))
	claims := func(vm string) bool { return vm != "" && strings.HasPrefix(base, strings.ToLower(vm)+"-") }
	ids, err := corrosion.InFlightResourceIDs(ctx, s.db)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		if vm, ok := strings.CutPrefix(id, "vm:"); ok && claims(vm) {
			return fmt.Sprintf("an operation in flight on VM %s", vm), nil
		}
	}
	for _, n := range s.importNamesInFlight() {
		if n != importName && claims(n) {
			return fmt.Sprintf("an import of VM %s in flight on %s", n, s.hostName), nil
		}
	}
	if s.opJournal != nil {
		entries, corrupt, err := s.opJournal.List()
		if err != nil {
			return "", err
		}
		if len(corrupt) > 0 {
			return fmt.Sprintf("%d unreadable operation journal entries on %s, which may name it", len(corrupt), s.hostName), nil
		}
		rdst := resolvedPath(dst)
		for _, e := range entries {
			for _, v := range e.Artifacts {
				if filepath.IsAbs(v) && namesFile(v, rdst, fi) {
					return fmt.Sprintf("operation %s on %s", e.OperationID, e.ResourceID), nil
				}
			}
		}
	}
	return "", nil
}

// orphanNow stamps an orphan's new name and judges its age; a variable so a
// test can fix it.
var orphanNow = time.Now

// moveOrphanAside gives the file at p a new name beside it, never replacing
// a file, and returns the new name. The file keeps its bytes.
func moveOrphanAside(p string) (string, error) {
	aside := fmt.Sprintf("%s.orphan-%d", p, orphanNow().Unix())
	unsupported, err := linkOrRenameNoReplace(p, aside)
	if !unsupported {
		if err != nil {
			return "", err
		}
		return aside, nil
	}
	// A filesystem with neither link() nor RENAME_NOREPLACE: a plain rename
	// to a name no other flow can choose, seen free first. It replaces
	// nothing, and needs no second copy of the orphan's bytes.
	aside = fmt.Sprintf("%s.orphan-%d-%s", p, orphanNow().Unix(), randid.New())
	if _, err := os.Lstat(aside); !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%s is taken (%v)", aside, err)
	}
	if err := os.Rename(p, aside); err != nil {
		return "", err
	}
	return aside, nil
}

// freshSiblings names every file beside dst that a flow writing dst's VM may
// be writing now: one whose name starts like dst's up to any '-' (a VM's other
// disks; disk names may hold '-'), or another host's conversion scratch file
// or partial copy for such a name, modified within importOrphanMinAge, that
// nothing records.
// A multi-disk create, clone or import leaves its first disks quiet while it
// writes the next, and records them only at its end.
//
// Not a flow: leftovers of imports no longer running here, this import's own
// files, and files of another import running here whose VM's names do not
// start dst's (by their placement records); a file a disk row (live, or a
// deleted VM's kept disk) or an image records — a running VM's disk changes
// all the time; and a file named for an existing VM whose name does not
// prefix dst's (that VM's replica, for now — nothing of its writes dst).
func (s *Server) freshSiblings(ctx context.Context, dst, importID string) ([]importSibling, error) {
	dir, base := filepath.Dir(dst), filepath.Base(dst)
	lb := strings.ToLower(base)
	var prefixes []string
	for i := 0; i < len(lb); i++ {
		if lb[i] == '-' {
			prefixes = append(prefixes, lb[:i+1])
		}
	}
	if len(prefixes) == 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fresh []importSibling
	for _, e := range entries {
		name := e.Name()
		ln := strings.ToLower(name)
		if name == base || strings.Contains(ln, ".orphan-") {
			continue
		}
		match := false
		for _, p := range prefixes {
			if strings.HasPrefix(ln, p) || (strings.HasPrefix(ln, "."+p) && (strings.Contains(ln, ".convert-") || strings.Contains(ln, ".place-"))) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		info, err := e.Info()
		if err != nil || orphanNow().Sub(info.ModTime()) >= importOrphanMinAge {
			continue
		}
		p := filepath.Join(dir, name)
		if s.importLeftover(p, info) {
			continue
		}
		// This import's own file, or one of another import running here
		// whose VM's files dst is not named for.
		if n, id, ok := s.importRunningFile(p, info); ok && (id == importID || !strings.HasPrefix(lb, strings.ToLower(n)+"-")) {
			continue
		}
		fresh = append(fresh, importSibling{name, p, info})
	}
	if len(fresh) == 0 {
		return nil, nil
	}
	recorded, err := s.pathsRecordedLike(ctx, prefixes[0])
	if err != nil {
		return nil, err
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, err
	}
	var out []importSibling
	for _, f := range fresh {
		if recordedAmong(recorded, f.path, f.fi) || namedForAnotherVM(vms, strings.ToLower(f.name), lb) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// importSibling is a file beside a disk's name.
type importSibling struct {
	name, path string
	fi         os.FileInfo
}

// pathsRecordedLike is every path a disk row (live or kept) or an image
// records whose name holds part, in one read.
func (s *Server) pathsRecordedLike(ctx context.Context, part string) ([]string, error) {
	like := "%" + strings.ToLower(part) + "%"
	var out []string
	rows, err := s.db.Query(ctx,
		`SELECT path, backing_image, backing_disk FROM vm_disks
		 WHERE LOWER(path) LIKE ? OR LOWER(COALESCE(backing_image, '')) LIKE ? OR LOWER(COALESCE(backing_disk, '')) LIKE ?`,
		like, like, like)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, r.String("path"), r.String("backing_image"), r.String("backing_disk"))
	}
	rows, err = s.db.Query(ctx, `SELECT path FROM image_hosts WHERE LOWER(path) LIKE ?`, like)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, r.String("path"))
	}
	return out, nil
}

// recordedAmong reports whether one of the recorded paths names the file fi
// describes at p.
func recordedAmong(recorded []string, p string, fi os.FileInfo) bool {
	rp := resolvedPath(p)
	for _, v := range recorded {
		if namesFile(v, rp, fi) {
			return true
		}
	}
	return false
}

// namedForAnotherVM reports whether the file named ln is named for an
// existing VM (its name followed by '-' starts ln) whose name does not start
// lb, dst's name, the same way.
func namedForAnotherVM(vms []corrosion.VMRecord, ln, lb string) bool {
	for _, vm := range vms {
		if vm.Name == "" {
			continue
		}
		v := strings.ToLower(vm.Name) + "-"
		if strings.HasPrefix(ln, v) && !strings.HasPrefix(lb, v) {
			return true
		}
	}
	return false
}

// liveVMNamedLike names a VM whose name followed by '-' starts dst's name:
// its disks, or a replica of one (which this branch keeps no record of), take
// names like that.
func (s *Server) liveVMNamedLike(ctx context.Context, dst string) (string, error) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return "", err
	}
	lb := strings.ToLower(filepath.Base(dst))
	for _, vm := range vms {
		if vm.Name != "" && strings.HasPrefix(lb, strings.ToLower(vm.Name)+"-") {
			return vm.Name, nil
		}
	}
	return "", nil
}

// clearImportDiskName makes way for a converted disk at dst in pool. A file
// there is an orphan — a crashed import's output, moved aside and kept — only
// when nothing records it, nothing in flight may be creating it, nothing
// beside it is still being written, and either a placement record shows it a
// dead import's leftover, unchanged since (this host's, or that of a host
// sharing the pool, asked), or it is named for no existing VM and has been
// quiet for importOrphanMinAge. Anything else refuses the import.
func (s *Server) clearImportDiskName(ctx context.Context, pool, importName, importID, disk, dst string) error {
	s.removeDeadPartialCopies(dst)
	fi, err := os.Lstat(dst)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("disk %q would be written to %s, which already exists in the pool and %s; "+
			"an import never replaces a file there — import under another --name", disk, dst, why)
	}
	if err != nil {
		return refuse(fmt.Sprintf("cannot be read (%v)", err))
	}
	refs, err := s.importPathReferences(ctx, dst, fi)
	if err != nil {
		return refuse(fmt.Sprintf("what records it could not be read (%v); retry", err))
	}
	if refs != "" {
		return refuse("is " + refs)
	}
	busy, err := s.importDiskNameInFlight(ctx, importName, dst, fi)
	if err != nil {
		return refuse(fmt.Sprintf("what may be creating it could not be read (%v); retry", err))
	}
	if busy != "" {
		return refuse("may still be being created by " + busy + "; retry once it finishes")
	}
	// A leftover of an import that is no longer running, that nothing has
	// written since, is nobody's now: not a replica or a hotplug file of the
	// VM it is named like, and not still being written.
	leftover := s.importLeftover(dst, fi)
	liveVM := ""
	if !leftover {
		if liveVM, err = s.liveVMNamedLike(ctx, dst); err != nil {
			return refuse(fmt.Sprintf("the VMs whose disks it may be could not be read (%v); retry", err))
		}
	}
	sibs, err := s.freshSiblings(ctx, dst, importID)
	if err != nil {
		return refuse(fmt.Sprintf("what is being written beside it could not be read (%v); retry", err))
	}
	age := orphanNow().Sub(fi.ModTime())
	fresh := age < importOrphanMinAge
	// What this host cannot prove, a host sharing the pool may: a leftover of
	// its own dead import (it crashed there; this is the re-import).
	var unasked []string
	ask := sibs
	if !leftover && (liveVM != "" || fresh) {
		ask = append([]importSibling{{filepath.Base(dst), dst, fi}}, sibs...)
	}
	if len(ask) > 0 {
		var dead map[string]bool
		dead, unasked = s.peerDeadImportFiles(ctx, pool, ask)
		if !leftover && dead[filepath.Base(dst)] {
			leftover, liveVM = true, ""
		}
		var still []importSibling
		for _, sb := range sibs {
			if !dead[sb.name] {
				still = append(still, sb)
			} else if isPartialCopyOf(sb.name, filepath.Base(dst)) {
				_ = removeIfSame(sb.path, sb.fi) // a dead import's partial copy
			}
		}
		sibs = still
	}
	notAsked := ""
	if len(unasked) > 0 {
		notAsked = fmt.Sprintf(" (%s, sharing the pool, could not be asked whether it is their crashed import's)", strings.Join(unasked, ", "))
	}
	if liveVM != "" {
		return refuse(fmt.Sprintf("is named like the disks of VM %s, which exists%s", liveVM, notAsked))
	}
	if len(sibs) > 0 {
		return refuse(fmt.Sprintf("%s beside it was written in the last %s, so the flow writing them may still be running%s; retry once it is quiet",
			sibs[0].name, importOrphanMinAge, notAsked))
	}
	// Anything else has to have gone quiet.
	if fresh && !leftover {
		return refuse(fmt.Sprintf("was written %s ago, so it may still be being created%s; "+
			"a leftover nothing records is moved aside once it is %s old — retry then", age.Round(time.Second), notAsked, importOrphanMinAge))
	}
	// Judged on fi: it must still be that file, in that state, as it moves.
	if now, err := os.Lstat(dst); err != nil || !sameFileState(fi, now) {
		return refuse("changed while it was being judged; retry")
	}
	aside, err := moveOrphanAside(dst)
	if err != nil {
		return refuse(fmt.Sprintf("could not be moved aside (%v); remove it if it is a leftover", err))
	}
	slog.Warn("import: moved aside a file at a converted disk's name that no disk, image or VM records and nothing is creating",
		"host", s.hostName, "path", dst, "kept_as", aside, "modified", fi.ModTime(), "dead_import_leftover", leftover)
	return nil
}

// sameFileState reports whether a and b are one file in one state.
func sameFileState(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && fileCtimeNs(a) == fileCtimeNs(b)
}

// isPartialCopyOf reports whether name is a copy on its way to base's name.
func isPartialCopyOf(name, base string) bool {
	return strings.HasPrefix(strings.ToLower(name), "."+strings.ToLower(base)+".place-")
}

// removeDeadPartialCopies removes the copies on their way to dst's name that
// this host's dead imports left (a crash mid-copy on a pool with neither
// link() nor RENAME_NOREPLACE): partial, at names no flow writes, and
// nobody's.
func (s *Server) removeDeadPartialCopies(dst string) {
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), "."+globEscape(filepath.Base(dst))+".place-*"))
	for _, p := range matches {
		fi, err := os.Lstat(p)
		if err != nil || !s.importLeftover(p, fi) {
			continue
		}
		if err := removeIfSame(p, fi); err == nil {
			s.forgetImportPlacement(p, "")
			slog.Info("import: removed a dead import's partial copy", "host", s.hostName, "path", p)
		}
	}
}

// globEscape quotes s for filepath.Glob.
func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`).Replace(s)
}

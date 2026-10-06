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
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// importOrphanMinAge is how long a file at a converted disk's name must have
// gone unmodified before an import may take it for a crashed import's
// leftover. Another host importing the same name into a shared pool, or any
// flow that has not recorded its file yet, is still writing it, or has just
// finished; a leftover that is re-imported is older than this.
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
	err := renameNoReplace(p, aside)
	if err == nil {
		return aside, nil
	}
	if errors.Is(err, os.ErrExist) {
		return "", err
	}
	// No renameat2 here: a hard link never replaces a file either.
	if lerr := os.Link(p, aside); lerr != nil {
		return "", fmt.Errorf("rename (%v) or link (%v)", err, lerr)
	}
	if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, syscall.ENOENT) {
		_ = os.Remove(aside)
		return "", rerr
	}
	return aside, nil
}

// clearImportDiskName makes way for a converted disk at dst. A file there is
// an orphan — a crashed import's output, moved aside and kept — only when
// nothing records it, nothing in flight may be creating it, and it has been
// quiet for importOrphanMinAge. Anything else refuses the import.
func (s *Server) clearImportDiskName(ctx context.Context, importName, disk, dst string) error {
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
	if age := orphanNow().Sub(fi.ModTime()); age < importOrphanMinAge {
		return refuse(fmt.Sprintf("was written %s ago, so it may still be being created; "+
			"a leftover nothing records is moved aside once it is %s old — retry then", age.Round(time.Second), importOrphanMinAge))
	}
	aside, err := moveOrphanAside(dst)
	if err != nil {
		return refuse(fmt.Sprintf("could not be moved aside (%v); remove it if it is a leftover", err))
	}
	slog.Warn("import: moved aside a file at a converted disk's name that no disk, image or VM records and nothing is creating",
		"host", s.hostName, "path", dst, "kept_as", aside, "modified", fi.ModTime())
	return nil
}

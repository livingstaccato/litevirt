package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// importPathReferences names what in the cluster records the file at p, on
// any host: a disk row (live, or the tombstone of a deleted VM whose disk was
// kept) that is the file, its backing image or its backing disk, or an image
// a host stores there. An empty answer means nothing does. A lookup that
// fails is an error, never "nothing".
func (s *Server) importPathReferences(ctx context.Context, p string) (string, error) {
	paths := []string{p}
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		paths = append(paths, r)
	}
	var refs []string
	for _, q := range paths {
		rows, err := s.db.Query(ctx,
			`SELECT vm_name, disk_name, host_name, deleted_at FROM vm_disks
			 WHERE path = ? OR backing_image = ? OR backing_disk = ?`, q, q, q)
		if err != nil {
			return "", err
		}
		for _, r := range rows {
			what := fmt.Sprintf("disk %s of VM %s on %s", r.String("disk_name"), r.String("vm_name"), r.String("host_name"))
			if r.String("deleted_at") != "" {
				what += " (a deleted VM's kept disk)"
			}
			refs = append(refs, what)
		}
		rows, err = s.db.Query(ctx, `SELECT image_name, host_name FROM image_hosts WHERE path = ?`, q)
		if err != nil {
			return "", err
		}
		for _, r := range rows {
			refs = append(refs, fmt.Sprintf("image %s on %s", r.String("image_name"), r.String("host_name")))
		}
	}
	return strings.Join(refs, ", "), nil
}

// moveOrphanAside gives the file at p a new name beside it, never replacing
// a file, and returns the new name. The file keeps its bytes.
func moveOrphanAside(p string) (string, error) {
	aside := fmt.Sprintf("%s.orphan-%d", p, time.Now().Unix())
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

// clearImportDiskName makes way for a converted disk at dst. A file there
// that something records is refused; one nothing records is an orphan (a
// crashed import's output), moved aside and kept.
func (s *Server) clearImportDiskName(ctx context.Context, disk, dst string) error {
	if _, err := os.Lstat(dst); err != nil {
		return nil
	}
	refs, err := s.importPathReferences(ctx, dst)
	if err != nil {
		return fmt.Errorf("disk %q would be written to %s, which already exists in the pool, and what records it could not be read (%v); "+
			"an import never replaces a file there — retry, or import under another --name", disk, dst, err)
	}
	if refs != "" {
		return fmt.Errorf("disk %q would be written to %s, which already exists in the pool and is %s; "+
			"an import never replaces a file there — import under another --name", disk, dst, refs)
	}
	aside, err := moveOrphanAside(dst)
	if err != nil {
		return fmt.Errorf("disk %q would be written to %s, which already exists in the pool and could not be moved aside (%v); "+
			"remove it if it is a leftover, or import under another --name", disk, dst, err)
	}
	slog.Warn("import: moved aside a file at a converted disk's name that no disk, image or VM records",
		"host", s.hostName, "path", dst, "kept_as", aside)
	return nil
}

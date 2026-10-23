package pooltrust

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// qcow2Magic opens every qcow2 image ("QFI\xfb").
var qcow2Magic = []byte{'Q', 'F', 'I', 0xfb}

// adoptDiskRowsLimit bounds how many disk rows one pool's adoption reads.
const adoptDiskRowsLimit = 64

// Adoption is what AdoptOnUpgrade did.
type Adoption struct {
	Ran     bool
	Adopted []string // pools recorded in the ledger, with the evidence
	Held    []string // pools left untrusted, with why
}

// AdoptOnUpgrade runs while the ledger does not record that it has run
// (adopted): on the first start of a build that keeps the ledger — whether or
// not a ledger file was already written, by the daemon's own pools or a
// create — or after the ledger and every kept copy of it were removed. Every
// row naming host that needs trust and is not already trusted (config, area)
// is recorded in the ledger only when the host's own disk shows it in use
// (upgradeEvidence); an nfs pool whose export is not mounted then is judged
// once more when it first mounts (PendingNFS); any other is left untrusted,
// for pool_row_untrusted to name and `lv pool trust` to confirm. The ledger
// is then written with adopted set, so this does not run again: a row
// arriving later is trusted only through a create on this host or a
// confirmation.
//
// When the rows cannot be listed, or the ledger cannot be written, adopted
// stays unset, and the adoption runs at the next start.
func (s *Store) AdoptOnUpgrade(ctx context.Context, db *corrosion.Client, host string) (Adoption, error) {
	if s.Initialised() {
		return Adoption{}, nil
	}
	rows, err := corrosion.ListStoragePoolsForHost(ctx, db, host)
	if err != nil {
		return Adoption{}, fmt.Errorf("list this host's pools: %w", err)
	}
	out := Adoption{Ran: true}
	add := map[string]Entry{}
	pend := map[string]Binding{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range rows {
		b := BindingOf(r.Driver, r.Source, r.Target, r.Options)
		if v := s.Judge(r.Name, b); v.Trusted {
			continue
		}
		ok, why := s.upgradeEvidence(ctx, db, host, r.Name, b)
		if !ok {
			// An nfs export not mounted now (an upgrade together with a
			// reboot) shows nothing either way: judged once more when it
			// first mounts (ResolvePending).
			if b.Driver == "nfs" && !nfsMountedNow(s.dataDir, b) {
				pend[r.Name] = b
				why += "; judged again when its export first mounts"
			}
			out.Held = append(out.Held, fmt.Sprintf("%s (%s)", r.Name, why))
			continue
		}
		add[r.Name] = Entry{Binding: b, How: HowUpgrade, At: now}
		out.Adopted = append(out.Adopted, fmt.Sprintf("%s (%s)", r.Name, why))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Entry, len(s.entries)+len(add))
	for k, v := range s.entries {
		next[k] = v
	}
	for k, v := range add {
		next[k] = v
	}
	prevPending := s.pending
	if len(pend) > 0 {
		s.pending = map[string]Binding{}
		for k, v := range prevPending {
			s.pending[k] = v
		}
		for k, v := range pend {
			s.pending[k] = v
		}
	}
	s.initialised = true
	if err := s.writeLocked(next); err != nil {
		s.initialised = false
		s.pending = prevPending
		return out, err
	}
	s.entries = next
	return out, nil
}

// nfsMountedNow reports whether an nfs pool's export is mounted at its mount
// point now.
func nfsMountedNow(dataDir string, b Binding) bool {
	st, err := storage.CheckNFSPoolMount(dataDir, storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target})
	return err == nil && st.Mounted
}

// PendingEvidence judges a pending nfs pool (PendingNFS) once its export is
// mounted at mountedAt — its own mount point, or a staging one the daemon
// mounted it at for this: the evidence rules of upgradeEvidence, with the
// files read under mountedAt. A disk of this host's recorded on the pool
// whose directory, resolved, is the pool's mount point, resolved, must be a
// regular qcow2 file (opened without following a link) at that name in the
// mounted export.
func (s *Store) PendingEvidence(ctx context.Context, db *corrosion.Client, host, name string, b Binding, mountedAt string) (bool, string) {
	b = b.normalized()
	dir := s.poolDir(b)
	if dir == "" || !filepath.IsAbs(dir) {
		return false, "it names no directory"
	}
	if err := storage.CheckWriteRoot(dir, s.dataDir, s.pkiDir); err != nil {
		return false, err.Error()
	}
	paths, why := ownDiskPaths(ctx, db, host, name)
	if len(paths) == 0 {
		return false, why
	}
	found, err := storage.Bounded("judge a pool for upgrade adoption at", mountedAt, func() (string, error) {
		rdir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", nil
		}
		for _, p := range paths {
			p = filepath.Clean(p)
			rparent, err := filepath.EvalSymlinks(filepath.Dir(p))
			if err != nil || rparent != rdir {
				continue
			}
			if hasQcow2Magic(filepath.Join(mountedAt, filepath.Base(p))) {
				return p, nil
			}
		}
		return "", nil
	})
	if err != nil {
		return false, "its export did not answer: " + err.Error()
	}
	if found == "" {
		return false, "no disk recorded on it is a qcow2 image directly in its export"
	}
	return true, "its mounted export holds this host's disk " + found
}

// ownDiskPaths are the paths of the live disks of this host's live VMs
// recorded on pool name (at most adoptDiskRowsLimit), or why there are none.
func ownDiskPaths(ctx context.Context, db *corrosion.Client, host, name string) ([]string, string) {
	rows, err := db.Query(ctx,
		`SELECT d.path FROM vm_disks d JOIN vms v ON v.name = d.vm_name
		 WHERE d.host_name = ? AND v.host_name = ? AND d.storage_volume = ?
		   AND d.deleted_at IS NULL AND v.deleted_at IS NULL AND d.path != ''
		 LIMIT ?`, host, host, name, adoptDiskRowsLimit)
	if err != nil {
		return nil, "its disks cannot be read: " + err.Error()
	}
	var paths []string
	for _, r := range rows {
		paths = append(paths, r.String("path"))
	}
	if len(paths) == 0 {
		return nil, "no disk of this host's VMs is recorded on it"
	}
	return paths, ""
}

// poolDir is the directory a pool of binding b writes in on this host.
func (s *Store) poolDir(b Binding) string {
	switch b.Driver {
	case "local", "dir":
		if b.Target == "" && b.Driver == "local" {
			return filepath.Join(s.dataDir, "disks")
		}
		return b.Target
	case "nfs":
		return storage.NFSPoolMountDir(s.dataDir, storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target})
	case "btrfs":
		return b.Source
	}
	return ""
}

// upgradeEvidence decides whether an existing row is adopted on upgrade. A
// replicated row is evidence of nothing, and neither is a directory merely
// existing: a forged row made before the upgrade can name one that does
// (/var/lib/polkit-1/localauthority/50-local.d, say), or an ancestor of a
// real pool (/srv above /srv/vmpool). What the old build's pools leave on
// THIS host's disk is evidence, and a forged row alone did not put it there:
//
//   - a file recorded on the pool is a regular qcow2 file (not a link)
//     DIRECTLY in the pool's directory: the file's resolved parent is the
//     directory resolved. That equality is the guard: an ancestor of the
//     disk's directory, or a link inside the directory pointing elsewhere, is
//     not evidence. The rows naming the file (a live vm_disks row and a live
//     vms row of this host) are replicated, so a forger can write them too:
//     they only say which files to look at. Every file-based disk litevirt
//     creates is qcow2; or
//   - for an nfs pool whose mount point is in <data_dir>/mounts, its export
//     is mounted there now.
//
// The directory must also pass CheckWriteRoot.
func (s *Store) upgradeEvidence(ctx context.Context, db *corrosion.Client, host, name string, b Binding) (bool, string) {
	dir := s.poolDir(b)
	if dir == "" || !filepath.IsAbs(dir) {
		return false, "it names no directory"
	}
	if err := storage.CheckWriteRoot(dir, s.dataDir, s.pkiDir); err != nil {
		return false, err.Error()
	}
	if b.Driver == "nfs" {
		if in, err := storage.InDataDirPoolArea(dir, s.dataDir, s.pkiDir); err == nil && in {
			st, err := storage.CheckNFSPoolMount(s.dataDir, storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target})
			if err == nil && st.Mounted {
				return true, "its export is mounted at " + dir
			}
		}
	}
	paths, why := ownDiskPaths(ctx, db, host, name)
	if len(paths) == 0 {
		return false, why
	}
	found, err := storage.Bounded("judge a pool for upgrade adoption at", dir, func() (string, error) {
		return qcow2DiskDirectlyIn(dir, paths), nil
	})
	if err != nil {
		return false, "its directory did not answer: " + err.Error()
	}
	if found == "" {
		return false, "no disk recorded on it is a qcow2 image directly in its directory"
	}
	return true, "it holds this host's disk " + found
}

// qcow2DiskDirectlyIn returns the first of paths whose resolved parent
// directory is dir resolved, that is a regular file (opened without following
// a link) and starts with the qcow2 magic; "" when none is.
func qcow2DiskDirectlyIn(dir string, paths []string) string {
	rdir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		rparent, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil || rparent != rdir {
			continue
		}
		if hasQcow2Magic(filepath.Join(rparent, filepath.Base(p))) {
			return p
		}
	}
	return ""
}

// hasQcow2Magic opens p without following a link at its last component and
// without blocking (a FIFO), and reports whether it is a regular file that
// starts with the qcow2 magic.
func hasQcow2Magic(p string) bool {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	buf := make([]byte, len(qcow2Magic))
	if _, err := f.ReadAt(buf, 0); err != nil {
		return false
	}
	return bytes.Equal(buf, qcow2Magic)
}

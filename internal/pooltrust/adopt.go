package pooltrust

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// AdoptOnUpgrade runs once, on the first start of a build that keeps the
// ledger (no ledger file yet). Every row naming host that needs trust and is
// not already trusted (config, area) is recorded in the ledger only when the
// host's own disk shows it in use (upgradeEvidence); any other is left
// untrusted, for pool_row_untrusted to name and `lv pool trust` to confirm.
// The ledger file is then written, so this never runs again: a row arriving
// later is trusted only through a create on this host or a confirmation.
//
// A row that cannot be listed leaves the ledger unwritten, and the adoption
// runs at the next start.
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
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range rows {
		b := BindingOf(r.Driver, r.Source, r.Target)
		if v := s.Judge(r.Name, b); v.Trusted {
			continue
		}
		ok, why := s.upgradeEvidence(ctx, db, host, r.Name, b)
		if !ok {
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
	if err := s.writeLocked(next); err != nil {
		return out, err
	}
	s.entries = next
	return out, nil
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
// (/var/lib/polkit-1/localauthority/50-local.d, say). What the old build's
// pools leave on THIS host's disk is evidence, and a forged row alone did not
// put it there:
//
//   - a disk of this host's, recorded on the pool, is a regular file (not a
//     link) directly or deeper inside the pool's directory, and starts as a
//     qcow2 image does — every file-based disk litevirt creates is qcow2; or
//   - for an nfs pool whose mount point is in <data_dir>/mounts, its export
//     is mounted there now.
//
// Disk rows are replicated too, so a forged disk row can name a file; it
// still has to be a qcow2 image already in that directory, which a system
// directory does not hold. The directory must also pass CheckWriteRoot.
func (s *Store) upgradeEvidence(ctx context.Context, db *corrosion.Client, host, name string, b Binding) (bool, string) {
	dir := s.poolDir(b)
	if dir == "" || !filepath.IsAbs(dir) {
		return false, "it names no directory"
	}
	if err := storage.CheckWriteRoot(dir, s.dataDir, s.pkiDir); err != nil {
		return false, err.Error()
	}
	if b.Driver == "nfs" {
		if in, err := storage.InDataDirPoolArea(dir, s.dataDir); err == nil && in {
			st, err := storage.CheckNFSPoolMount(s.dataDir, storage.Config{Driver: b.Driver, Source: b.Source, Target: b.Target})
			if err == nil && st.Mounted {
				return true, "its export is mounted at " + dir
			}
		}
	}
	rows, err := db.Query(ctx,
		`SELECT path FROM vm_disks
		 WHERE host_name = ? AND storage_volume = ? AND deleted_at IS NULL AND path != ''
		 LIMIT ?`, host, name, adoptDiskRowsLimit)
	if err != nil {
		return false, "its disks cannot be read: " + err.Error()
	}
	var paths []string
	for _, r := range rows {
		paths = append(paths, r.String("path"))
	}
	if len(paths) == 0 {
		return false, "no disk of this host is recorded on it"
	}
	found, err := storage.Bounded("judge a pool for upgrade adoption at", dir, func() (string, error) {
		return qcow2DiskIn(dir, paths), nil
	})
	if err != nil {
		return false, "its directory did not answer: " + err.Error()
	}
	if found == "" {
		return false, "no disk recorded on it is a qcow2 image in its directory"
	}
	return true, "it holds this host's disk " + found
}

// qcow2DiskIn returns the first of paths that is a regular file inside dir,
// as written and resolved, and starts with the qcow2 magic; "" when none is.
func qcow2DiskIn(dir string, paths []string) string {
	rdir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		if !strictlyWithin(filepath.Clean(dir), p) {
			continue
		}
		rparent, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil || !(rparent == rdir || strictlyWithin(rdir, rparent)) {
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if hasQcow2Magic(p) {
			return p
		}
	}
	return ""
}

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

func strictlyWithin(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

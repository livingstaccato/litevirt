package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// keptNoteHolds reports whether path is a file this host's kept-disk notes
// name (health.KeptNotedFiles): a disk a delete kept, or a file one backs on.
// No path that removes a VM's disk files on this host may remove it. A note
// that cannot be read holds every path. why says which.
func (s *Server) keptNoteHolds(path string) (bool, string) {
	files, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return true, fmt.Sprintf("this host's notes of the disks deletes kept cannot be read (%v)", err)
	}
	for _, p := range []string{path, s.hostDiskFile(path)} {
		if vm, ok := files[filepath.Clean(p)]; ok {
			return true, fmt.Sprintf("the deleted VM %s was kept with it (%s)", vm,
				filepath.Join(s.dataDir, "kept-disks", vm+".json"))
		}
	}
	return false, ""
}

// reportKeptNoteHold logs and records, as an event of vmName, a disk file a
// removal of vmName's left because a kept-disk note holds it.
func (s *Server) reportKeptNoteHold(ctx context.Context, vmName, op, path, why string) {
	slog.Warn(op+": a disk file a kept-disk note holds is left", "vm", vmName, "path", path, "why", why)
	s.recordVMEvent(ctx, vmName, "vm.disk.kept", "ok",
		fmt.Sprintf("%s left %s on %s: %s; only an operator removes it", op, path, s.hostName, why))
}

// keptHolds reports whether path is a file no path that removes disk files on
// this host may remove: one this host's kept-disk notes name (keptNoteHolds),
// or one a kept-disks.json entry of this host names or reaches through its
// backing chain (keptRegistryChains). The registry is read too because a
// delete that kept a disk without a note (an older build's stale-record
// delete, the main delete's "whether another VM uses it cannot be told", a
// stack teardown) recorded it there only. Anything that cannot be read holds
// every path; why says which.
func (s *Server) keptHolds(ctx context.Context, path string) (bool, string) {
	if held, why := s.keptNoteHolds(path); held {
		return held, why
	}
	if held, why := s.keptNoteDotDotHeld(path); held {
		return held, why
	}
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		return true, err.Error()
	}
	for _, p := range []string{filepath.Clean(path), filepath.Clean(s.hostDiskFile(path))} {
		for _, c := range chains {
			for i, l := range c.layers {
				if l != p || (i == 0 && c.topNamed) {
					continue
				}
				what := "it is the disk " + c.rec.Disk
				if i > 0 {
					what = fmt.Sprintf("the disk %s, %s, backs on it", c.rec.Disk, c.top)
				}
				return true, fmt.Sprintf("%s the delete of VM %s kept (%s), as %s records", what, c.rec.VM, c.rec.Reason,
					filepath.Join(s.dataDir, diskKeptFile))
			}
		}
	}
	return false, ""
}

// keptRegistryChain is a kept-disks.json entry of this host and the files of
// its backing chain, top first.
type keptRegistryChain struct {
	rec    diskKeptRecord
	top    string
	layers []string
	// topNamed: a live disk row of this host names the top, so that record,
	// not this entry, holds it (layers[0]); the files under it are still
	// this entry's.
	topNamed bool
	// missing is the backing file the last layer names that does not exist
	// ("" when the chain is whole): a file written there becomes its base.
	missing string
}

// keptRegistryError is kept-disks.json, an entry's chain, or the records an
// entry is judged by, that cannot be read. Transient: storage or the
// database did not answer, and a retry may.
type keptRegistryError struct {
	msg       string
	transient bool
}

func (e *keptRegistryError) Error() string { return e.msg }

// keptRegistryChains is every kept-disks.json entry of this host, each with
// its backing chain. When a live disk row of this host names an entry's own
// file, that file is left to the record (topNamed: a delete that failed and
// keeps its record, whose retry frees it; a VM using the file again, whose
// own delete decides); the files under it stay held. A row of another host
// at the same path is another file. A chain ends at a backing file that does
// not exist (missing): nothing is there to keep, and nothing under it is
// reached; a chain that cannot be read otherwise is an error naming the entry
// and the way out, as is a registry that cannot be read.
func (s *Server) keptRegistryChains(ctx context.Context) ([]keptRegistryChain, error) {
	file := filepath.Join(s.dataDir, diskKeptFile)
	records, unreadable := s.diskKeptRecords()
	if unreadable != "" {
		return nil, &keptRegistryError{msg: fmt.Sprintf("this host's record of the disks deletes kept, %s, cannot be read (%s); "+
			"repair or remove that file (`lv health` names it under %s)", file, unreadable, condDiskLeftover)}
	}
	var out []keptRegistryChain
	for _, r := range records {
		if r.Host != s.hostName || r.Path == "" {
			continue
		}
		top := filepath.Clean(s.hostDiskFile(r.Path))
		if !filepath.IsAbs(top) {
			continue
		}
		rows, err := corrosion.DisksReferencingPath(ctx, s.db, r.Path)
		if err != nil {
			return nil, &keptRegistryError{transient: true, msg: fmt.Sprintf(
				"whether a VM's record still names %s, a disk the delete of VM %s kept (%s), cannot be read (%v); retry", top, r.VM, file, err)}
		}
		topNamed := slices.ContainsFunc(rows, func(d corrosion.DiskRecord) bool {
			return d.Path == r.Path && d.HostName == s.hostName
		})
		type walked struct {
			layers  []string
			missing string
		}
		w, err := storage.Bounded("read the backing chain of", top, func() (walked, error) {
			l, m, err := keptChainLayersToMissing(top)
			return walked{l, m}, err
		})
		if err != nil {
			return nil, &keptRegistryError{transient: storage.IsFSNoAnswer(err), msg: fmt.Sprintf(
				"the backing chain of %s, the disk %s the delete of VM %s kept, cannot be read (%v), so what it backs on is unknown; "+
					"fix that file or its storage, or, once you have checked that nothing needs that disk, move %s away or remove its entry "+
					"from %s on %s (the file is re-read within 30 s)", top, r.Disk, r.VM, err, top, file, s.hostName)}
		}
		out = append(out, keptRegistryChain{rec: r, top: top, layers: w.layers, topNamed: topNamed, missing: w.missing})
	}
	return out, nil
}

// keptDotDotHold is a file a noted file's backing chain reaches through a
// ".." reference: top is the noted file, vm the deleted VM whose note names
// it.
type keptDotDotHold struct{ vm, top string }

// what names what holds the file, for a refusal: "the disk ... backs on".
func (h keptDotDotHold) what(s *Server) string {
	return fmt.Sprintf("the disk %s the deleted VM %s was kept with (its kept-disk note %s lists it) backs on through a \"..\" reference",
		h.top, h.vm, filepath.Join(s.dataDir, "kept-disks", h.vm+".json"))
}

// keptNoteDotDotHolds is every file at or below the first layer the backing
// chain of a file this host's kept-disk notes name reaches through a ".."
// reference (keptChainWalk), by its cleaned and its resolved path. A delete
// notes nothing from that layer down (noteKeptBackingFiles): where a ".."
// leads depends on symlinked directories, so it is never the VM's own to
// release. This is what holds those files while the noted file above them is
// there. A note or a chain that cannot be read is an error.
func (s *Server) keptNoteDotDotHolds() (map[string]keptDotDotHold, error) {
	notes, err := health.KeptNotes(s.dataDir)
	if err != nil {
		return nil, fmt.Errorf("this host's notes of the disks deletes kept cannot be read (%v)", err)
	}
	out := map[string]keptDotDotHold{}
	for _, n := range notes {
		for _, p := range n.Paths {
			w, err := storage.Bounded("read the backing chain of", p, func() (keptWalked, error) {
				l, m, dd, err := keptChainWalk(p)
				return keptWalked{layers: l, missing: m, dotdot: dd}, err
			})
			if err != nil {
				return nil, fmt.Errorf("the backing chain of %s, a disk the deleted VM %s was kept with (%s), cannot be read (%w), "+
					"so what it backs on is unknown: until it can, every path that removes disk files on this host leaves them, "+
					"and lv host kept-disks --release refuses; fix that file or its storage, move %s away, or, once nothing "+
					"needs it, remove its entry from %s", p, n.VM, n.File, err, p, n.File)
			}
			if w.dotdot < 0 {
				continue
			}
			h := keptDotDotHold{vm: n.VM, top: p}
			for _, l := range w.layers[min(w.dotdot, len(w.layers)):] {
				out[filepath.Clean(l)] = h
				r, err := resolvedStrict(l)
				if err != nil {
					return nil, fmt.Errorf("%s, under %s, a disk the deleted VM %s was kept with, cannot be resolved (%w)", l, p, n.VM, err)
				}
				out[r] = h
			}
		}
	}
	return out, nil
}

// keptDotDotHeldIn reports which hold of holds, if any, path is, by its
// cleaned or its resolved form.
func keptDotDotHeldIn(holds map[string]keptDotDotHold, path string) (keptDotDotHold, bool, error) {
	if len(holds) == 0 {
		return keptDotDotHold{}, false, nil
	}
	if h, ok := holds[filepath.Clean(path)]; ok {
		return h, true, nil
	}
	r, err := resolvedStrict(path)
	if err != nil {
		return keptDotDotHold{}, false, err
	}
	h, ok := holds[r]
	return h, ok, nil
}

// keptNoteDotDotHeld reports whether path is a file a noted file's chain
// reaches through ".." (keptNoteDotDotHolds). Anything that cannot be read
// holds every path; why says which.
func (s *Server) keptNoteDotDotHeld(path string) (bool, string) {
	holds, err := s.keptNoteDotDotHolds()
	if err != nil {
		return true, err.Error()
	}
	for _, p := range uniq(path, s.hostDiskFile(path)) {
		h, ok, err := keptDotDotHeldIn(holds, p)
		if err != nil {
			return true, fmt.Sprintf("what %s is cannot be told (%v)", p, err)
		}
		if ok {
			return true, "it is the file " + h.what(s)
		}
	}
	return false, ""
}

// keptStillReached reports whether a kept chain on this host still reaches
// file, by any route: the backing chain of a file any VM's note names
// (other than file itself), or a kept-disks.json entry's chain, walked as
// the holds walk them, matched by cleaned and resolved path. Anything that
// cannot be read answers true: a note entry is forgotten only when nothing
// can still need it.
func (s *Server) keptStillReached(ctx context.Context, file string) bool {
	file = filepath.Clean(file)
	want := map[string]bool{file: true}
	r, err := resolvedStrict(file)
	if err != nil {
		return true
	}
	want[r] = true
	hit := func(l string) (bool, error) {
		if want[filepath.Clean(l)] {
			return true, nil
		}
		r, err := resolvedStrict(l)
		return err == nil && want[r], err
	}
	notes, err := health.KeptNotes(s.dataDir)
	if err != nil {
		return true
	}
	for _, n := range notes {
		for _, p := range n.Paths {
			if self, err := hit(p); err != nil || self {
				if err != nil {
					return true
				}
				continue
			}
			w, err := storage.Bounded("read the backing chain of", p, func() (keptWalked, error) {
				l, m, dd, err := keptChainWalk(p)
				return keptWalked{layers: l, missing: m, dotdot: dd}, err
			})
			if err != nil {
				return true
			}
			for _, l := range w.layers {
				if h, err := hit(l); err != nil || h {
					return true
				}
			}
		}
	}
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		return true
	}
	for _, c := range chains {
		for _, l := range c.layers {
			if h, err := hit(l); err != nil || h {
				return true
			}
		}
	}
	return false
}

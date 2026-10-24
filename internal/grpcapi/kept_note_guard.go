package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
// this host may remove: one this host's kept-disk notes name (keptNoteHolds)
// or one a noted file's backing chain reaches (keptNoteChainHolds: the base
// of a kept linked clone, which no note names), or one a kept-disks.json
// entry of this host names or reaches through its backing chain
// (keptRegistryChains). The registry is read too because a
// delete that kept a disk without a note (an older build's stale-record
// delete, the main delete's "whether another VM uses it cannot be told", a
// stack teardown) recorded it there only. Anything that cannot be read holds
// every path; why says which.
func (s *Server) keptHolds(ctx context.Context, path string) (bool, string) {
	if held, why := s.keptNoteHolds(path); held {
		return held, why
	}
	if held, why := s.keptNoteChainHeld(path); held {
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

// keptNoteChain is the backing chain of a file a kept-disk note of this host
// names, as keptChainWalk reads it: top first, missing the backing file its
// last layer names that does not exist ("" when the chain is whole), dotdot
// the index of the first layer reached through a ".." reference (-1: none).
type keptNoteChain struct {
	vm, note, top string
	layers        []string
	missing       string
	dotdot        int
}

// keptNoteChainsError is a kept-disk note, or the chain of a file one names,
// that cannot be read: what a kept disk backs on is then unknown.
type keptNoteChainsError struct{ err error }

func (e *keptNoteChainsError) Error() string { return e.err.Error() }
func (e *keptNoteChainsError) Unwrap() error { return e.err }

// keptNoteChains is the backing chain of every file this host's kept-disk
// notes name. A note names the deleted VM's own files only (noteKeptDisks,
// noteKeptBackingFiles): a kept linked clone's note names its overlay and
// not the base under it, which is another VM's disk. The chain is what
// reaches that base, so it is what holds it (keptNoteChainHolds) and what a
// create must not write under the overlay (keptNoteMissingBase). A note or a
// chain that cannot be read is a *keptNoteChainsError.
func (s *Server) keptNoteChains() ([]keptNoteChain, error) {
	notes, err := health.KeptNotes(s.dataDir)
	if err != nil {
		return nil, &keptNoteChainsError{fmt.Errorf("this host's notes of the disks deletes kept cannot be read (%w)", err)}
	}
	var out []keptNoteChain
	for _, n := range notes {
		for _, p := range n.Paths {
			w, err := storage.Bounded("read the backing chain of", p, func() (keptWalked, error) {
				l, m, dd, err := keptChainWalk(p)
				return keptWalked{layers: l, missing: m, dotdot: dd}, err
			})
			if err != nil {
				return nil, &keptNoteChainsError{fmt.Errorf("the backing chain of %s, a disk the deleted VM %s was kept with (%s), cannot be read (%w), "+
					"so what it backs on is unknown: until it can, every path that removes disk files on this host leaves them, "+
					"a create that would write a disk here is refused, and lv host kept-disks --release refuses; fix that file or its "+
					"storage, move %s away, or, once nothing needs it, remove its entry from %s", p, n.VM, n.File, err, p, n.File)}
			}
			out = append(out, keptNoteChain{vm: n.VM, note: n.File, top: filepath.Clean(p), layers: w.layers, missing: w.missing, dotdot: w.dotdot})
		}
	}
	return out, nil
}

// keptChainHold is a file below the top of a noted file's backing chain:
// top is the noted file, vm the deleted VM whose note names it, dotdot that
// the chain reaches it through a ".." reference.
type keptChainHold struct {
	vm, top string
	dotdot  bool
}

// what names what holds the file, for a refusal: "the disk ... backs on".
func (h keptChainHold) what(s *Server) string {
	how := ""
	if h.dotdot {
		how = " through a \"..\" reference"
	}
	return fmt.Sprintf("the disk %s the deleted VM %s was kept with (its kept-disk note %s lists it) backs on%s",
		h.top, h.vm, filepath.Join(s.dataDir, "kept-disks", h.vm+".json"), how)
}

// keptNoteChainHolds is every file below the top of the backing chain of a
// file this host's kept-disk notes name (keptNoteChains), by its cleaned and
// its resolved path, with each chain that reaches it. A note names only the
// deleted VM's own files: the base of a kept linked clone is another VM's
// disk, and a delete notes nothing at or below a layer reached through ".."
// (noteKeptBackingFiles), since where a ".." leads depends on symlinked
// directories. This is what holds those files while the noted file above
// them is there (rc7 lab 1 F1: a plain lv rm of the clone's source removed
// the base under the kept overlay). A note or a chain that cannot be read is
// an error.
func (s *Server) keptNoteChainHolds() (map[string][]keptChainHold, error) {
	chains, err := s.keptNoteChains()
	if err != nil {
		return nil, err
	}
	out := map[string][]keptChainHold{}
	for _, c := range chains {
		for i, l := range c.layers {
			if i == 0 {
				continue
			}
			h := keptChainHold{vm: c.vm, top: c.top, dotdot: c.dotdot >= 0 && i >= c.dotdot}
			r, err := resolvedStrict(l)
			if err != nil {
				return nil, fmt.Errorf("%s, under %s, a disk the deleted VM %s was kept with, cannot be resolved (%w)", l, c.top, c.vm, err)
			}
			for _, k := range uniq(filepath.Clean(l), r) {
				if !slices.Contains(out[k], h) {
					out[k] = append(out[k], h)
				}
			}
		}
	}
	return out, nil
}

// keptChainHeldIn is the holds of holds on path, by its cleaned or its
// resolved form.
func keptChainHeldIn(holds map[string][]keptChainHold, path string) ([]keptChainHold, error) {
	if len(holds) == 0 {
		return nil, nil
	}
	if h, ok := holds[filepath.Clean(path)]; ok {
		return h, nil
	}
	r, err := resolvedStrict(path)
	if err != nil {
		return nil, err
	}
	return holds[r], nil
}

// keptNoteChainHeld reports whether path is a file a noted file's chain
// reaches below its top (keptNoteChainHolds). Anything that cannot be read
// holds every path; why says which.
func (s *Server) keptNoteChainHeld(path string) (bool, string) {
	holds, err := s.keptNoteChainHolds()
	if err != nil {
		return true, err.Error()
	}
	for _, p := range uniq(path, s.hostDiskFile(path)) {
		h, err := keptChainHeldIn(holds, p)
		if err != nil {
			return true, fmt.Sprintf("what %s is cannot be told (%v)", p, err)
		}
		if len(h) > 0 {
			return true, "it is the file " + h[0].what(s)
		}
	}
	return false, ""
}

// keptNoteMissingBase is the refusal of a write at a path the last layer of
// a noted file's chain names as its backing file although nothing is there
// (writes.writes): the new file would become the kept disk's base, and so
// is one that cannot tell whether it writes there. unknown is set instead
// when a note or a chain cannot be read (keptNoteChains): whether the write
// is such a path cannot be told. A nil writes writes nothing.
func (s *Server) keptNoteMissingBase(writes *keptWrites) (refuse, unknown error) {
	if writes == nil {
		return nil, nil
	}
	chains, err := s.keptNoteChains()
	if err != nil {
		return nil, err
	}
	for _, c := range chains {
		if c.missing == "" {
			continue
		}
		overlay := c.layers[len(c.layers)-1]
		hit, werr := writes.writes(c.missing)
		if werr != nil {
			msg := fmt.Sprintf("whether the create writes %s, which %s backs on although it is missing (the disk %s the deleted VM %s "+
				"was kept with, as its kept-disk note %s lists it), cannot be told: %v; nothing was created", c.missing, overlay, c.top, c.vm, c.note, werr)
			if storage.IsFSNoAnswer(werr) {
				return errors.New(msg + "; retry once that storage answers, or place the VM on another host"), nil
			}
			return health.NewKeptBackingFileError(msg + ". Fix that directory, or move " + overlay + " away, or place the VM on another host"), nil
		}
		if !hit {
			continue
		}
		return health.NewKeptBackingFileError(fmt.Sprintf("the create writes %s, which %s backs on although it is missing: "+
			"%s is in the backing chain of the disk %s the deleted VM %s was kept with (its kept-disk note %s lists it), and a new "+
			"disk there would become its base; nothing was created. Put the original file back at %s, or move %s away, or release "+
			"the kept disk once nothing needs it (lv host kept-disks %s --release %s), or place the VM on another host",
			c.missing, overlay, overlay, c.top, c.vm, c.note, c.missing, overlay, s.hostName, c.vm)), nil
	}
	return nil, nil
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

// keptBaseRefusal refuses op of vmName (a delete without --keep-disks, a
// rebuild) before anything is done while a disk file of it on this host is
// one a kept disk's backing chain reaches below its top: the base of a kept
// linked clone, noted (keptNoteChainHolds) or recorded in kept-disks.json
// (keptRegistryChains). The delete of the clone dropped its disk row, so the
// linked-clone guard (linkedClonesOf) no longer sees it, and without this the
// removal leaves the file (keptHolds) only after the domain is gone. With
// freedOnly, only a disk recorded delete_with_vm counts: the delete keeps the
// others anyway. What cannot be read refuses only with failClosed; otherwise
// the removal's own holds keep every file then.
func (s *Server) keptBaseRefusal(ctx context.Context, vmName, op, wayOut string, freedOnly, failClosed bool) error {
	unknown := func(err error) error {
		if !failClosed {
			return nil
		}
		return status.Errorf(codes.FailedPrecondition,
			"cannot %s %q: whether a disk a delete kept on %s backs on its disks cannot be told (%v); nothing was done (retry once it can be read)",
			op, vmName, s.hostName, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return unknown(err)
	}
	var files []string
	for _, d := range disks {
		if d.Path == "" || d.HostName != s.hostName || strings.HasPrefix(d.Path, "rbd:") || corrosion.DiskIsShared(d) ||
			(freedOnly && !d.DeleteWithVM) {
			continue
		}
		files = append(files, filepath.Clean(s.hostDiskFile(d.Path)))
	}
	if len(files) == 0 {
		return nil
	}
	refuse := func(file, top, vm, record string) error {
		return status.Errorf(codes.FailedPrecondition,
			"cannot %s %q: its disk file %s is the backing file of %s, a disk the delete of VM %s kept on %s (%s), and removing it "+
				"would leave that kept disk without its base; %srelease the kept disk first (lv host kept-disks %s --release %s), or flatten it onto a "+
				"standalone file at its path; nothing was done",
			op, vmName, file, top, vm, s.hostName, record, wayOut, s.hostName, top)
	}
	holds, err := s.keptNoteChainHolds()
	if err != nil {
		return unknown(err)
	}
	for _, f := range files {
		hs, err := keptChainHeldIn(holds, f)
		if err != nil {
			return unknown(err)
		}
		for _, h := range hs {
			if h.top != f {
				return refuse(f, h.top, h.vm, "its kept-disk note "+filepath.Join(s.dataDir, "kept-disks", h.vm+".json")+" lists it")
			}
		}
	}
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		return unknown(err)
	}
	for _, c := range chains {
		for _, l := range c.layers[min(1, len(c.layers)):] {
			if slices.Contains(files, l) {
				return refuse(l, c.top, c.rec.VM, filepath.Join(s.dataDir, diskKeptFile)+" records it")
			}
		}
	}
	return nil
}

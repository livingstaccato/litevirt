package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// keptFileCreateRefusal refuses a create of name, before anything is moved or
// removed, while a file it would clear (files: what it removes or moves off
// its path) is one a delete kept on this host, or one a disk file beside it
// backs on. A create builds its disk exclusively (qcow2.Create* and the pool
// drivers refuse a path that is taken); what clears the path first is the
// create's own debris sweep, and this is the guard on it. Any one of these
// refuses:
//
//   - this host's kept-disk notes (health.KeptNotedFiles). With notesGovern
//     a noted file is left to health.SetAsideBeforeCreate, which moves a kept
//     disk to a .kept- name, with an event, and refuses a file one backs on;
//     without, every noted file refuses;
//   - this host's kept-disks.json (disk_kept.go): each disk a delete kept on
//     this host, and every file of its backing chain. A stale-record delete
//     recorded its kept disks there only, with no note, before rc3 lab 2 F1,
//     and a host upgraded since still holds such entries;
//   - the regular files beside it of the name (<name>-*, and everything in
//     the legacy <disks>/<name>/ directory): one whose qcow2 backing chain
//     reaches it, as a kept snapshot overlay's reaches the disk it was taken
//     of, whatever records exist.
//
// It also refuses while a kept disk's chain ends at a backing file that does
// not exist at a path the create writes (writes): the kept overlay names that
// path, and the new disk would become its base.
//
// A note, kept-disks.json or a kept disk's chain that cannot be read refuses
// too: what it would keep is then unknown (keptRegistryChains; a backing
// file that does not exist ends a chain, and holds nothing). Only storage or
// the database not answering is retryable; anything else is
// KeptBackingFileError, naming the entry and the way out.
func (s *Server) keptFileCreateRefusal(ctx context.Context, name string, files []string, writes func(string) bool, notesGovern bool) error {
	present := map[string]bool{}
	var dirs []string
	seenDir := map[string]bool{}
	for _, f := range files {
		f = filepath.Clean(f)
		fi, err := storage.Bounded("stat", f, func() (os.FileInfo, error) { return os.Lstat(f) })
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("the create clears %s, and what is there cannot be read (%v); retry once that storage answers, "+
				"or place the VM on another host", f, err)
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		present[f] = true
		if d := filepath.Dir(f); !seenDir[d] {
			seenDir[d] = true
			dirs = append(dirs, d)
		}
	}
	if len(present) == 0 {
		return s.keptMissingBaseRefusal(ctx, writes)
	}
	refuse := func(file, why string) error {
		return health.NewKeptBackingFileError(fmt.Sprintf("the create clears %s, which %s: clearing it would lose what a deleted VM "+
			"was kept with; nothing was moved or removed. Move the kept files off that path yourself (then `qemu-img rebase -u -b "+
			"<new path>` the overlay above it), or place the VM on another host", file, why))
	}

	noted, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return fmt.Errorf("the create clears a file left by an earlier VM %s, and this host's notes of the disks deletes kept "+
			"cannot be read (%v); repair or remove that file, then retry, or place the VM on another host", name, err)
	}
	if !notesGovern {
		for f := range present {
			if vm, ok := noted[f]; ok {
				return refuse(f, fmt.Sprintf("the deleted VM %s was kept with (%s)", vm,
					filepath.Join(s.dataDir, "kept-disks", vm+".json")))
			}
		}
	}

	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		var re *keptRegistryError
		if errors.As(err, &re) && re.transient {
			return fmt.Errorf("the create clears a file left by an earlier VM %s, and %v; nothing was moved or removed", name, err)
		}
		return health.NewKeptBackingFileError(fmt.Sprintf("the create clears a file left by an earlier VM %s, and %v; "+
			"nothing was moved or removed", name, err))
	}
	registry := filepath.Join(s.dataDir, diskKeptFile)
	for _, c := range chains {
		r := c.rec
		for i, l := range c.layers {
			if !present[l] || (i == 0 && c.topNamed) || (notesGovern && noted[l] != "") {
				continue
			}
			if i == 0 {
				return refuse(l, fmt.Sprintf("is the disk %s the delete of VM %s kept (%s), as %s records", r.Disk, r.VM, r.Reason, registry))
			}
			return refuse(l, fmt.Sprintf("%s backs on, the disk %s the delete of VM %s kept (%s), as %s records", c.top, r.Disk, r.VM, r.Reason, registry))
		}
		if c.missing != "" && writes(c.missing) {
			return missingBaseRefusal(c, registry)
		}
	}

	for _, dir := range dirs {
		ents, err := storage.Bounded("list", dir, func() ([]os.DirEntry, error) { return os.ReadDir(dir) })
		if err != nil {
			return fmt.Errorf("the create clears a file left by an earlier VM %s in %s, and that directory cannot be listed (%v), "+
				"so whether a file there backs on it cannot be told; retry once it answers, or place the VM on another host", name, dir, err)
		}
		legacy := filepath.Base(dir) == name
		for _, e := range ents {
			n := e.Name()
			if !e.Type().IsRegular() || strings.HasPrefix(n, ".") || (!legacy && !strings.HasPrefix(n, name+"-")) {
				continue
			}
			p := filepath.Join(dir, n)
			if present[p] {
				continue
			}
			layers, err := storage.Bounded("read the backing chain of", p, func() ([]string, error) {
				return chainLayers(os.Stat, p, ""), nil
			})
			if err != nil {
				return fmt.Errorf("the create clears a file left by an earlier VM %s, and the backing chain of %s beside it cannot be read (%v), "+
					"so whether it backs on that file cannot be told; retry once it answers, or place the VM on another host", name, p, err)
			}
			for _, l := range layers[min(1, len(layers)):] {
				if present[filepath.Clean(l)] {
					return refuse(l, fmt.Sprintf("%s beside it backs on (its qcow2 backing chain reaches it: an overlay of a deleted VM of the name, "+
						"such as a snapshot its delete kept)", p))
				}
			}
		}
	}
	return nil
}

// missingBaseRefusal refuses a create that would write the missing backing
// file of c's chain.
func missingBaseRefusal(c keptRegistryChain, registry string) error {
	overlay := c.layers[len(c.layers)-1]
	return health.NewKeptBackingFileError(fmt.Sprintf("the create writes %s, which %s backs on although it is missing: "+
		"%s is in the backing chain of the disk %s the delete of VM %s kept (%s), as %s records, and a new disk there would "+
		"become its base; nothing was created. Move %s away, or remove that entry from %s once nothing needs the disk, "+
		"or place the VM on another host", c.missing, overlay, overlay, c.rec.Disk, c.rec.VM, c.rec.Reason, registry, overlay, registry))
}

// keptMissingBaseRefusal is keptFileCreateRefusal's check of a create that
// clears nothing: one that writes the missing backing file of a kept disk's
// chain is refused. With nothing to clear, a registry that cannot be read is
// not a reason to refuse: only a write at a missing base could follow, and
// the refusals for clearing a file stay fail-closed.
func (s *Server) keptMissingBaseRefusal(ctx context.Context, writes func(string) bool) error {
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		return nil
	}
	registry := filepath.Join(s.dataDir, diskKeptFile)
	for _, c := range chains {
		if c.missing != "" && writes(c.missing) {
			return missingBaseRefusal(c, registry)
		}
	}
	return nil
}

// createDiskPathOf reports whether a create of name writes a disk at p in
// this host's disk directory: <vm>-<disk>.qcow2, a disk name without a dash
// (image.Store.VMDiskCandidates' shape).
func (s *Server) createDiskPathOf(name string) func(string) bool {
	dir := ""
	if s.images != nil {
		dir = filepath.Clean(s.images.DiskDir(name))
	}
	return func(p string) bool {
		p = filepath.Clean(p)
		if dir == "" || filepath.Dir(p) != dir {
			return false
		}
		rest, ok := strings.CutPrefix(filepath.Base(p), name+"-")
		if !ok {
			return false
		}
		disk, ok := strings.CutSuffix(rest, ".qcow2")
		return ok && disk != "" && !strings.Contains(disk, "-")
	}
}

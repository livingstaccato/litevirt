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
// A note, kept-disks.json, a kept disk's chain or the chain of a file beside
// it that cannot be read refuses a create that clears a file: what it would
// keep is then unknown (keptRegistryChains, walkKeptChain; a backing file
// that does not exist ends a chain, and holds nothing). A create that clears
// nothing is judged by the disk files on this host instead while
// kept-disks.json or a kept chain cannot be read (keptCollisionOnDisk). Only
// storage or the database not answering is retryable; anything else is
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
				return refuse(f, fmt.Sprintf("the deleted VM %s was kept with, as its kept-disk note %s lists it", vm,
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
			// Strict: a chain that cannot be read in full may reach the file.
			// A missing backing file ends it, as nothing under it is reached.
			stat := chainStat // read here: the walk may outlive this call
			layers, err := storage.Bounded("read the backing chain of", p, func() ([]string, error) {
				l, _, err := walkKeptChain(stat, p, true)
				return l, err
			})
			if err != nil {
				if storage.IsFSNoAnswer(err) {
					return fmt.Errorf("the create clears a file left by an earlier VM %s, and the backing chain of %s beside it cannot be read (%v), "+
						"so whether it backs on that file cannot be told; retry once it answers, or place the VM on another host", name, p, err)
				}
				return health.NewKeptBackingFileError(fmt.Sprintf("the create clears a file left by an earlier VM %s, and the backing chain of %s "+
					"beside it cannot be read (%v), so whether it backs on that file cannot be told; nothing was moved or removed. Fix that "+
					"file or its storage, or move it away once nothing needs it, or place the VM on another host", name, p, err))
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
// chain is refused. While the registry or a chain in it cannot be read, the
// disk files on this host are judged instead (keptCollisionOnDisk).
func (s *Server) keptMissingBaseRefusal(ctx context.Context, writes func(string) bool) error {
	registry := filepath.Join(s.dataDir, diskKeptFile)
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		return s.keptCollisionOnDisk(err, writes, registry)
	}
	for _, c := range chains {
		if c.missing != "" && writes(c.missing) {
			return missingBaseRefusal(c, registry)
		}
	}
	return nil
}

// keptCollisionOnDisk judges a create that clears nothing while the registry
// or a chain in it cannot be read (rerr), from the disk files on this host
// (keptCollisionScan): one that writes a path a file there backs on, or one
// already there, is refused, as what a delete kept cannot be told apart. Any
// other create goes ahead, with a warning naming the registry. A scan that
// cannot complete refuses: what is safe is then unknown. Retryable only when
// storage or the database did not answer.
func (s *Server) keptCollisionOnDisk(rerr error, writes func(string) bool, registry string) error {
	var re *keptRegistryError
	transient := errors.As(rerr, &re) && re.transient
	hit, err := s.keptCollisionScan(writes)
	if err != nil {
		msg := fmt.Sprintf("whether a disk a delete kept backs on a path the create writes cannot be told: %v, and %v; nothing was created", rerr, err)
		if transient || storage.IsFSNoAnswer(err) {
			return errors.New(msg)
		}
		return health.NewKeptBackingFileError(msg)
	}
	if hit != "" {
		return health.NewKeptBackingFileError(fmt.Sprintf("%s, and %v; whether that is a disk a delete kept cannot be told, "+
			"so nothing was created (or place the VM on another host)", hit, rerr))
	}
	slog.Warn("create: the record of kept disks cannot be read; the create goes ahead, as no disk file on this host backs on a path it writes. "+
		"Fix the record so that what deletes kept is judged by it again", "file", registry, "error", rerr)
	return nil
}

// keptCollisionScan reads, without kept-disks.json, every file on this host
// a kept overlay can be: each regular file at any depth under <data_dir>/disks,
// the disk store's directory and each usable file pool's directory
// (filePoolRoots), each file a kept-disk note names, and each kept-disks.json
// entry of this host still held in memory. Each one's backing chain is read
// in full (walkKeptChain). It returns how the first file that is, or backs
// on, a path the create writes collides, or "" when none does; a directory or
// a chain that cannot be read is an error.
func (s *Server) keptCollisionScan(writes func(string) bool) (string, error) {
	var files []string
	seen := map[string]bool{}
	add := func(p string) {
		if p = filepath.Clean(p); filepath.IsAbs(p) && !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	dirs := []string{filepath.Join(s.dataDir, "disks")}
	if s.images != nil {
		dirs = append(dirs, s.images.DiskDir(""))
	}
	dirs = append(dirs, s.filePoolRoots()...)
	listed := map[string]bool{}
	for len(dirs) > 0 {
		dir := filepath.Clean(dirs[len(dirs)-1])
		dirs = dirs[:len(dirs)-1]
		if listed[dir] {
			continue
		}
		listed[dir] = true
		ents, err := storage.Bounded("list", dir, func() ([]os.DirEntry, error) { return os.ReadDir(dir) })
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("the disk directory %s on this host cannot be listed (%w)", dir, err)
		}
		for _, e := range ents {
			switch p := filepath.Join(dir, e.Name()); {
			case e.IsDir():
				dirs = append(dirs, p)
			case e.Type().IsRegular():
				add(p)
			}
		}
	}
	noted, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return "", fmt.Errorf("this host's notes of the disks deletes kept cannot be read (%w)", err)
	}
	for f := range noted {
		add(f)
	}
	records, _ := s.diskKeptRecords()
	for _, r := range records {
		if r.Host == s.hostName && r.Path != "" {
			add(s.hostDiskFile(r.Path))
		}
	}
	stat := chainStat // read here: the walk may outlive this call
	for _, p := range files {
		type walked struct {
			layers  []string
			missing string
		}
		w, err := storage.Bounded("read the backing chain of", p, func() (walked, error) {
			l, m, err := walkKeptChain(stat, p, true)
			return walked{l, m}, err
		})
		if err != nil {
			return "", fmt.Errorf("the backing chain of %s on this host cannot be read (%w)", p, err)
		}
		for i, l := range w.layers {
			switch {
			case !writes(l):
			case i == 0:
				return fmt.Sprintf("the create writes %s, which is on this host already", l), nil
			default:
				return fmt.Sprintf("the create writes %s, which %s on this host backs on", l, p), nil
			}
		}
		if w.missing != "" && writes(w.missing) {
			return fmt.Sprintf("the create writes %s, which %s on this host backs on although it is missing", w.missing, p), nil
		}
	}
	return "", nil
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

package grpcapi

import (
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
// A note, kept-disks.json or a kept disk's chain that cannot be read refuses
// too: what it would keep is then unknown.
func (s *Server) keptFileCreateRefusal(name string, files []string, notesGovern bool) error {
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
		return nil
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

	records, unreadable := s.diskKeptRecords()
	registry := filepath.Join(s.dataDir, diskKeptFile)
	if unreadable != "" {
		return fmt.Errorf("the create clears a file left by an earlier VM %s, and this host's record of the disks deletes kept, %s, "+
			"cannot be read (%s); repair or remove that file, then retry, or place the VM on another host", name, registry, unreadable)
	}
	for _, r := range records {
		if r.Host != s.hostName || r.Path == "" {
			continue
		}
		top := filepath.Clean(s.hostDiskFile(r.Path))
		if !filepath.IsAbs(top) {
			continue
		}
		layers, err := storage.Bounded("read the backing chain of", top, func() ([]string, error) {
			return keptChainLayers(top)
		})
		if err != nil {
			return fmt.Errorf("the create clears a file left by an earlier VM %s, and the backing chain of %s, a disk the delete of VM %s "+
				"kept (%s), cannot be read (%v), so whether it backs on that file cannot be told; retry once it can be read, "+
				"or place the VM on another host", name, top, r.VM, registry, err)
		}
		for i, l := range layers {
			if !present[l] || (notesGovern && noted[l] != "") {
				continue
			}
			if i == 0 {
				return refuse(l, fmt.Sprintf("is the disk %s the delete of VM %s kept (%s), as %s records", r.Disk, r.VM, r.Reason, registry))
			}
			return refuse(l, fmt.Sprintf("%s backs on, the disk %s the delete of VM %s kept (%s), as %s records", top, r.Disk, r.VM, r.Reason, registry))
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

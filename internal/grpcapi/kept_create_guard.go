package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// not exist at a path the create writes (writes, keptWrites): the kept
// overlay names that path, and the new disk would become its base.
//
// A note, kept-disks.json, a kept disk's chain or the chain of a file beside
// it that cannot be read refuses too, whether or not the create clears
// anything: what it would keep is then unknown (keptRegistryChains,
// walkKeptChain; a backing file that does not exist ends a chain, and holds
// nothing). Only storage or the database not answering is retryable;
// anything else is KeptBackingFileError, naming the entry and the way out.
func (s *Server) keptFileCreateRefusal(ctx context.Context, name string, files []string, writes *keptWrites, notesGovern bool) error {
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
		return keptChainsRefusal(fmt.Sprintf("the create clears a file left by an earlier VM %s, and", name), err,
			"nothing was moved or removed")
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
		if err := writes.missingBaseRefusal(c, registry); err != nil {
			return err
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

// keptChainsUnknownError is a refusal because kept-disks.json or a kept
// disk's backing chain cannot be read (keptRegistryChains). Unlike the other
// kept-file refusals it does not depend on the name being created: until the
// file it names reads, every import, every create or clone that writes a disk
// file here, every disk attach, and every restore to a named target meets it. It wraps the error the caller maps to a code (KeptBackingFileError, or
// a plain retryable one).
type keptChainsUnknownError struct{ err error }

func (e *keptChainsUnknownError) Error() string { return e.err.Error() }
func (e *keptChainsUnknownError) Unwrap() error { return e.err }

// keptChainsRefusal is the refusal for err, a keptRegistryChains error:
// "<lead> <err>; <tail>". Storage that does not answer is retryable;
// anything else is a KeptBackingFileError.
func keptChainsRefusal(lead string, err error, tail string) error {
	msg := fmt.Sprintf("%s %v; %s", lead, err, tail)
	var re *keptRegistryError
	if errors.As(err, &re) && re.transient {
		return &keptChainsUnknownError{errors.New(msg)}
	}
	return &keptChainsUnknownError{health.NewKeptBackingFileError(msg)}
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
// chain is refused. A registry or a chain that cannot be read refuses too
// when the create writes on this host's own storage (keptWrites.local):
// whether a kept overlay names a path it writes as its missing base is then
// unknown. A nil writes is a create that writes no disk file (no disk, or
// every disk on ceph or iscsi): no kept overlay can back on what it makes.
func (s *Server) keptMissingBaseRefusal(ctx context.Context, writes *keptWrites) error {
	if writes == nil {
		return nil
	}
	chains, err := s.keptRegistryChains(ctx)
	if err != nil {
		if !writes.local {
			return nil
		}
		return keptChainsRefusal("whether a disk a delete kept backs on a path the create writes cannot be told:", err, "nothing was created")
	}
	registry := filepath.Join(s.dataDir, diskKeptFile)
	for _, c := range chains {
		if err := writes.missingBaseRefusal(c, registry); err != nil {
			return err
		}
	}
	return nil
}

// keptWrites is the files an operation writes, for the check of a kept
// overlay's missing base: each as written and as its directory resolves
// through symlinks, so an overlay that names one by another spelling of its
// directory (a pool whose target is a symlink to the disk directory, or the
// other way round) still names it. A nil *keptWrites writes nothing.
type keptWrites struct {
	files map[string]bool
	// shape: a create's disk-directory files, <vm>-<disk>.qcow2 in the disk
	// directory (createDiskPathOf); nil when it writes none there.
	shape func(string) bool
	// unknown: a file the operation writes whose path, or whose directory's
	// resolution, cannot be told. It refuses while any kept overlay is
	// missing its base.
	unknown error
	// local: it writes on this host's own storage, so a kept-disks.json or a
	// kept chain that cannot be read holds it. Not when every file it writes
	// is on shared storage elsewhere (sharedPoolElsewhere).
	local bool
}

// keptWritesOf is the keptWrites of an operation writing exactly paths
// (nil for none).
func keptWritesOf(local bool, paths ...string) *keptWrites {
	if len(paths) == 0 {
		return nil
	}
	w := &keptWrites{files: map[string]bool{}, local: local}
	for _, p := range paths {
		w.add(p)
	}
	return w
}

func (w *keptWrites) add(p string) {
	p = filepath.Clean(p)
	w.files[p] = true
	r, err := keptResolvedPath(p)
	if err != nil {
		if w.unknown == nil {
			w.unknown = err
		}
		return
	}
	w.files[r] = true
}

// writes reports whether w writes p, in either spelling of its directory.
// An error: whether it does cannot be told.
func (w *keptWrites) writes(p string) (bool, error) {
	p = filepath.Clean(p)
	r, err := keptResolvedPath(p)
	if err != nil {
		return false, err
	}
	for _, f := range []string{p, r} {
		if w.files[f] || (w.shape != nil && w.shape(f)) {
			return true, nil
		}
	}
	return false, w.unknown
}

// missingBaseRefusal refuses a write of the missing backing file of c's
// chain, and one that cannot tell whether it writes it.
func (w *keptWrites) missingBaseRefusal(c keptRegistryChain, registry string) error {
	if w == nil || c.missing == "" {
		return nil
	}
	hit, err := w.writes(c.missing)
	if err == nil && hit {
		return missingBaseRefusal(c, registry)
	}
	if err == nil {
		return nil
	}
	overlay := c.layers[len(c.layers)-1]
	msg := fmt.Sprintf("whether the create writes %s, which %s backs on although it is missing (the disk %s the delete of VM %s "+
		"kept, as %s records), cannot be told: %v; nothing was created", c.missing, overlay, c.rec.Disk, c.rec.VM, registry, err)
	if storage.IsFSNoAnswer(err) {
		return errors.New(msg + "; retry once that storage answers, or place the VM on another host")
	}
	return health.NewKeptBackingFileError(msg + ". Fix that directory, or move " + overlay + " away, or place the VM on another host")
}

// keptResolvedPath is p with its directory resolved through symlinks, as far
// as it exists (a directory not made yet is taken as written below the part
// that is); p's own name is not followed. Bounded: a pool's directory can be
// on storage that does not answer.
func keptResolvedPath(p string) (string, error) {
	dir := filepath.Dir(p)
	r, err := storage.Bounded("resolve", dir, func() (string, error) { return keptResolveDir(dir) })
	if err != nil {
		return "", fmt.Errorf("%s does not resolve (%w)", dir, err)
	}
	return filepath.Join(r, filepath.Base(p)), nil
}

// keptResolveDir resolves dir through symlinks down to its deepest part that
// exists; a part missing (or not a directory) below that is kept as written.
func keptResolveDir(dir string) (string, error) {
	cur, rest := dir, ""
	for {
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return dir, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// createKeptWrites is what a create of spec writes (cfgs: the storage the LUN
// claim resolved, by disk index): a disk with no storage named, and the
// default root disk of a create with an image and no disks, in the host's
// disk directory; one on a pool where that pool's driver puts it
// (storage.CreateDiskPath). It is local unless every disk is on shared
// storage elsewhere (createWritesHostDisk).
func (s *Server) createKeptWrites(spec *pb.VMSpec, cfgs map[int]storage.Config) *keptWrites {
	w := &keptWrites{files: map[string]bool{}, local: s.createWritesHostDisk(spec, cfgs)}
	diskDir := len(spec.Disks) == 0 && spec.Image != ""
	if diskDir && s.images != nil {
		w.add(s.images.DiskPath(spec.Name, "root"))
	}
	for i, d := range spec.Disks {
		disk := diskNameOrRoot(d.Name)
		if d.Storage == "" {
			diskDir = true
			if s.images != nil {
				w.add(s.images.DiskPath(spec.Name, disk))
			}
			continue
		}
		cfg, ok := cfgs[i]
		if !ok {
			if w.unknown == nil {
				w.unknown = fmt.Errorf("the storage %q of disk %s is not resolved", d.Storage, disk)
			}
			continue
		}
		p, writesFile, err := storage.CreateDiskPath(s.dataDir, cfg, spec.Name, disk)
		if err != nil {
			if w.unknown == nil {
				w.unknown = fmt.Errorf("where disk %s on storage %q goes cannot be told (%w)", disk, d.Storage, err)
			}
			continue
		}
		if writesFile {
			w.add(p)
		}
	}
	if diskDir {
		shape, err := s.createDiskPathOf(spec.Name)
		if err != nil && w.unknown == nil {
			w.unknown = err
		}
		w.shape = shape
	}
	if len(w.files) == 0 && w.shape == nil && w.unknown == nil {
		return nil
	}
	return w
}

// createWritesHostDisk reports whether a create of spec writes a disk on
// this host's own storage, where a kept overlay's missing base can be: a disk
// with no storage named (the host's disk directory), the default root disk of
// a create with an image and no disks, or one on a pool that is not shared
// storage elsewhere (sharedPoolElsewhere) or whose resolution is not known
// (cfgs: the storage the LUN claim resolved, by disk index). Anything it
// cannot tell counts as local.
func (s *Server) createWritesHostDisk(spec *pb.VMSpec, cfgs map[int]storage.Config) bool {
	if len(spec.Disks) == 0 {
		return spec.Image != ""
	}
	for i, d := range spec.Disks {
		if d.Storage == "" {
			return true
		}
		cfg, ok := cfgs[i]
		if !ok || !s.sharedPoolElsewhere(cfg.Driver, cfg.Target) {
			return true
		}
	}
	return false
}

// sharedPoolElsewhere reports whether a pool of driver, mounted at target
// ("" for the driver's own place), keeps its disks off this host's disk
// directory: shared storage (nfs, ceph, iscsi) whose target is not that
// directory, as written or through a symlink (storage.IsDataDirDisksErr; a
// target it cannot resolve counts as that directory).
//
// The driver and target come from the pool's replicated row (or a stack's
// volume). Until pool-row trust lands (fix/pool-row-trust), a forged row
// naming a local pool nfs, ceph or iscsi passes here: re-check this
// exemption once that branch is merged.
func (s *Server) sharedPoolElsewhere(driver, target string) bool {
	if !isSharedDriver(driver) {
		return false
	}
	if target == "" {
		return true
	}
	if s.images != nil && filepath.Clean(target) == filepath.Clean(s.images.DiskDir("")) {
		return false
	}
	is, err := isDataDirDisksErr(target, s.dataDir)
	return !is && err == nil
}

// isDataDirDisksErr is storage.IsDataDirDisksErr. A var so a test can make a
// target's resolution not answer.
var isDataDirDisksErr = storage.IsDataDirDisksErr

// keptPathRefusal is keptMissingBaseRefusal for a write of exactly the files
// writes names (a clone's disks, an attach's new disk, a restore's named
// target), as a gRPC status naming what is refused: a kept overlay whose
// missing base is one of them refuses it, and so does a kept-disks.json or
// kept chain that cannot be read when the write is local.
func (s *Server) keptPathRefusal(ctx context.Context, what string, writes *keptWrites) error {
	return keptRefusalStatus(what, s.hostName, s.keptMissingBaseRefusal(ctx, writes))
}

// keptRefusalStatus maps a kept-create refusal to a status: a file that
// stands until an operator moves it, or a record that cannot be read, is
// FailedPrecondition; storage that does not answer is Unavailable.
func keptRefusalStatus(what, host string, err error) error {
	if err == nil {
		return nil
	}
	code := codes.Unavailable
	var kb *health.KeptBackingFileError
	if errors.As(err, &kb) {
		code = codes.FailedPrecondition
	}
	return status.Errorf(code, "%s refused on %s: %v", what, host, err)
}

// createDiskPathOf reports whether a create of name writes a disk at p in
// this host's disk directory, as written or as it resolves through symlinks:
// <vm>-<disk>.qcow2, a disk name without a dash (image.Store.VMDiskCandidates'
// shape). An error: the directory does not resolve; the textual match still
// holds.
func (s *Server) createDiskPathOf(name string) (func(string) bool, error) {
	if s.images == nil {
		return func(string) bool { return false }, nil
	}
	dirs := map[string]bool{}
	dir := filepath.Clean(s.images.DiskDir(name))
	dirs[dir] = true
	var rerr error
	if r, err := keptResolvedPath(filepath.Join(dir, "x")); err == nil {
		dirs[filepath.Dir(r)] = true
	} else {
		rerr = err
	}
	return func(p string) bool {
		p = filepath.Clean(p)
		if !dirs[filepath.Dir(p)] {
			return false
		}
		rest, ok := strings.CutPrefix(filepath.Base(p), name+"-")
		if !ok {
			return false
		}
		disk, ok := strings.CutSuffix(rest, ".qcow2")
		return ok && disk != "" && !strings.Contains(disk, "-")
	}, rerr
}

// keptRefusalCause is which health.KeptRebuild* cause a
// keptMissingBaseRefusal error is: kept-disks.json or a kept chain that
// cannot be read (keptChainsUnknownError over a KeptBackingFileError), storage
// or the database that did not answer (anything that is not a
// KeptBackingFileError), or a kept overlay naming the path (the rest).
func keptRefusalCause(err error) string {
	var kb *health.KeptBackingFileError
	if !errors.As(err, &kb) {
		return health.KeptRebuildNoAnswer
	}
	var unknown *keptChainsUnknownError
	if errors.As(err, &unknown) {
		return health.KeptRebuildUnreadable
	}
	return health.KeptRebuildOverlay
}

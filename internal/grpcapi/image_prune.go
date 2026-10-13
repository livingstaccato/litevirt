package grpcapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// Pruning image versions.
//
// A refresh publishes a new file and never removes the one disks are built on
// (image/versions.go). Which file a disk is built on is in its backing header,
// not its record (backing_image holds the name), and each host's store serves
// only that host's disks, so what may be removed is decided here, per host and
// per file, from the headers of the disk files this host can see.

// imagePruneDeadline bounds a prune's scan of the disk files, the backup
// manifests and the image headers. A scan that has not finished by then —
// a hung hard-mounted share blocks a syscall nothing can interrupt — prunes
// nothing.
const imagePruneDeadline = 2 * time.Minute

// imageFilesInUse is every image-store file (resolved) the prune must keep,
// besides the files a refresh just published (keep):
//   - every layer in the backing chain of a disk file this host can see:
//     every disk row's file present here (any host's row: a disk on shared
//     storage another host runs is read here too), and every regular file in
//     <data_dir>/disks, in this host's file pool directories and in a btrfs
//     pool's per-disk subvolumes — which also covers a disk created a moment
//     ago whose row is not written yet, and leftovers no row names;
//   - every file a backup pinned on this host when it was taken on an
//     overlay of it (pinBackupBase, whatever repo or host the manifest went
//     to), and the base a backup manifest in a backup repo on this host
//     records (base_identity: a backup taken before pins), and their chains;
//   - every image's current file and every file in keep, and their chains —
//     a layered image is built on another image's version — walked until
//     nothing new is kept.
//
// The view must be whole: a directory, an nfs share, a manifest or a header
// that cannot be read is an error, and nothing is pruned on it. So is a path
// whose resolution does not answer (resolvedStrict): a file kept under one
// form and looked up under another is not kept (re-review 3, R3-I1).
//
// A deleted image (deleted: its catalog row is deleted, lv image rm) has no
// current file to keep: its current file is kept only as any other version
// is. Its files are judged by a wider view too (scanDeletedImageUse).
//
// Each kept file maps to why it is kept.
func (s *Server) imageFilesInUse(ctx context.Context, keep []string, deleted map[string]bool) (*imageUseScan, error) {
	images, err := resolvedStrict(s.imageStore().ImageDir())
	if err != nil {
		return nil, fmt.Errorf("resolve the image store: %w", err)
	}
	w := &chainWalk{images: images, inUse: map[string]string{}, walked: map[string]bool{}}
	sc := &imageUseScan{inUse: w.inUse}
	rows, err := s.db.Query(ctx, `SELECT vm_name, disk_name, host_name, path FROM vm_disks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list disk rows: %w", err)
	}
	var files []string
	for _, r := range rows {
		p := r.String("path")
		if !filepath.IsAbs(p) {
			continue
		}
		files = append(files, s.hostDiskFile(p))
		// A disk recorded on this host whose file cannot be read here might be
		// built on any image: a deleted image's files wait for it.
		if len(deleted) > 0 && sc.missingDisk == "" && r.String("host_name") == s.hostName && !strings.HasPrefix(p, "/dev/") {
			if _, err := os.Stat(s.hostDiskFile(p)); err != nil {
				sc.missingDisk = fmt.Sprintf("disk %s/%s recorded on this host cannot be read here (%v): what it is built on is unknown",
					r.String("vm_name"), r.String("disk_name"), err)
			}
		}
	}
	listed, err := s.poolDiskFiles(ctx)
	if err != nil {
		return nil, err
	}
	files = append(files, listed...)
	if len(deleted) > 0 {
		staged, err := s.stagedDiskFiles()
		if err != nil {
			sc.unscanned = fmt.Sprintf("the staging directories could not all be read (%v): a disk staged there may be built on it", err)
		}
		files = append(files, staged...)
	}
	for _, f := range files {
		if err := w.walk(f, false, "", "disk file "+f); err != nil {
			return nil, err
		}
	}
	bases, err := s.backupBaseFiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bases {
		if err := w.walk(b, true, "a backup manifest on this host records it as its base", "the base "+b+" of a backup"); err != nil {
			return nil, err
		}
	}
	// Every kept store file's own chain, to a fixed point.
	st := s.imageStore()
	for {
		grew := false
		listed, err := s.storeFiles(st)
		if err != nil {
			return nil, err
		}
		for f, n := range listed {
			r, err := resolvedStrict(f)
			if err != nil {
				return nil, err
			}
			if w.walked[r] {
				continue
			}
			why := w.inUse[r]
			switch {
			case why != "":
			case image.Pinned(f):
				why = "it is pinned: a backup was taken on it"
			case slices.Contains(keep, f):
				why = "a refresh of the image has just published or superseded it"
			case f == st.ImagePath(n) && !deleted[n]:
				why = "it is image " + n + "'s current file"
			case deleted[n]:
				// A deleted image's file may be kept for a reason only known
				// below (a VM records it, a process holds it): what it is
				// built on is kept while it is, not judged on its own.
				if err := w.walk(f, false, "", "image file "+f); err != nil {
					return nil, err
				}
				grew = true
				continue
			default:
				continue
			}
			if err := w.walk(f, true, why, "image file "+f); err != nil {
				return nil, err
			}
			grew = true
		}
		if !grew {
			break
		}
	}
	// The store's filesystem keeps every file a disk here is not built on
	// when other hosts may share it (deletedKeep, and pruneImages for the
	// versions of an image that is not deleted).
	sc.storeFS = s.imageStoreShared(st)
	if len(deleted) > 0 {
		if err := s.scanDeletedImageUse(ctx, st, deleted, sc); err != nil {
			return nil, err
		}
	}
	return sc, nil
}

// storeFiles is the image store's files (image.Store.ListStoreFiles), listed
// with the prune's directory reader under storage.Bounded: a listing that
// fails, or does not answer (a store on a network filesystem whose server
// does not, lab 2 N-6), is an error, never an empty store. What a prune
// removes and keeps is decided from what is listed.
func (s *Server) storeFiles(st *image.Store) (map[string]string, error) {
	readDir := s.imagePrune.readDirFn()
	files, err := storage.Bounded("list the image store", st.ImageDir(), func() (map[string]string, error) {
		return st.ListStoreFiles(readDir)
	})
	if err != nil {
		return nil, fmt.Errorf("list the image store %s: %w", st.ImageDir(), err)
	}
	return files, nil
}

// imageStoreShared says why the image store's files may be other hosts'
// too: it is on a network filesystem (another host's disks, which this host
// cannot see, may be built on its files), or its filesystem cannot be told.
// "" for a store on a local filesystem. The filesystem is read under a
// bound: one that does not answer cannot be told.
func (s *Server) imageStoreShared(st *image.Store) string {
	storeFS := s.imagePrune.storeFSFn()
	fsName, err := storage.Bounded("statfs (image store)", st.ImageDir(), func() (string, error) {
		return storeFS(st.ImageDir())
	})
	switch {
	case err != nil:
		return fmt.Sprintf("cannot tell whether the image store is on a filesystem other hosts share: %v", err)
	case fsName != "":
		return fmt.Sprintf("the image store is on a network filesystem (%s): another host's disks, which this host cannot see, may be built on its files", fsName)
	}
	return ""
}

// imageUseScan is what a prune's scan saw.
type imageUseScan struct {
	// inUse is every store file (resolved) kept, and why.
	inUse map[string]string
	// storeFS says why every file no disk here is built on is kept, a
	// deleted image's or not, when the image store may be shared with other
	// hosts (imageStoreShared).
	storeFS string
	// The rest is read only when a deleted image is pruned:
	// missingDisk says why every deleted image's files are kept, when a disk
	// recorded on this host cannot be read here.
	missingDisk string
	// unscanned says why, when a staging directory could not all be read.
	unscanned string
	// recorded is, per deleted image, a VM in the cluster that records it.
	recorded map[string]string
	// open is, per store file of a deleted image, the process holding it
	// open; openErr says why every one is kept when that cannot be told.
	open    map[string]string
	openErr string
}

// stagingDirs are the directories under the data dir where a disk file is
// staged on its way somewhere — a restore, an import, a replica, a recreate,
// a VM's own state — and may be an overlay on an image file.
var stagingDirs = []string{"imports", "restore-staging", "backup-staging", "replicate-scratch", "recreate-failed", "vms"}

// stagedDiskFiles is every regular file in the staging directories, at most
// four levels down. A directory on another filesystem (a mount) is not
// entered and is an error: the files on it would be unseen.
func (s *Server) stagedDiskFiles() ([]string, error) {
	readDir := s.imagePrune.boundedReadDir()
	var out []string
	var list func(d string, dev uint64, depth int) error
	list = func(d string, dev uint64, depth int) error {
		ents, err := readDir(d)
		if err != nil {
			return fmt.Errorf("list %s: %w", d, err)
		}
		// A backup repo's chunk store (a directory with repo.json, or its
		// chunks/) holds guest data, never a disk file: a chunk that begins
		// with the qcow2 magic is a guest's bytes, not an overlay.
		for _, e := range ents {
			if e.Name() == "repo.json" && e.Type().IsRegular() {
				return nil
			}
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			switch {
			case e.Type().IsRegular():
				out = append(out, p)
			case e.IsDir() && e.Name() == "chunks":
			case e.IsDir():
				if depth >= 4 {
					return fmt.Errorf("%s is nested deeper than the scan reads", p)
				}
				if sub, ok := devOf(p); !ok || sub != dev {
					return fmt.Errorf("%s is a mount: the files on it cannot be judged", p)
				}
				if err := list(p, dev, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, name := range stagingDirs {
		d := filepath.Join(s.dataDir, name)
		fi, err := os.Lstat(d)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", d, err)
		}
		if !fi.IsDir() {
			continue
		}
		dev, ok := devOf(d)
		if !ok {
			return nil, fmt.Errorf("cannot tell which filesystem %s is on", d)
		}
		if err := list(d, dev, 1); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// devOf is the device the file at p is on.
func devOf(p string) (uint64, bool) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// scanDeletedImageUse reads what keeps a deleted image's files besides the
// disk headers: the filesystem the store is on (a network one may be other
// hosts' store too, and their disks are not seen here), every VM in the
// cluster that records the image (a disk built on it, or a VM created from it:
// a failover, a recreate or a migration elsewhere may need this host's copy),
// and the processes holding a file open (a running qemu).
func (s *Server) scanDeletedImageUse(ctx context.Context, st *image.Store, deleted map[string]bool, sc *imageUseScan) error {
	recorded, err := s.imageRecordedUsers(ctx, deleted)
	if err != nil {
		return err
	}
	sc.recorded = recorded
	listed, err := s.storeFiles(st)
	if err != nil {
		return err
	}
	var files []string
	for f, n := range listed {
		if deleted[n] {
			files = append(files, f)
		}
	}
	open, err := s.imagePrune.openFilesFn()(files)
	if err != nil {
		sc.openErr = fmt.Sprintf("cannot tell which processes hold it open: %v", err)
	}
	sc.open = open
	return nil
}

// imageRecordedUsers is, for each image in names that a live VM in the
// cluster records — a disk row whose backing_image names it (by name, or by
// one of its store files), or a VM whose spec was created from it — one such
// VM, described.
//
// A row deleted within the recreate grace (imageRecreateGrace) still records
// it: a rebuild or rolling recreate tombstones the VM and then creates it
// again, possibly on another host, whose create takes its hold on the image
// only once it begins. A deleted_at that cannot be read counts as recent.
func (s *Server) imageRecordedUsers(ctx context.Context, names map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	grace := s.imagePrune.recreateGraceOr()
	recent := func(deletedAt string) (string, bool) {
		if deletedAt == "" {
			return "", true
		}
		if grace <= 0 {
			return "", false
		}
		t, err := time.Parse(time.RFC3339Nano, deletedAt)
		if err != nil || time.Since(t) < grace {
			return fmt.Sprintf(" (deleted at %s, within the %s a rebuild or recreate has to create it again)", deletedAt, grace), true
		}
		return "", false
	}
	rows, err := s.db.Query(ctx, `SELECT vm_name, disk_name, host_name, backing_image, COALESCE(deleted_at, '') AS deleted_at
		FROM vm_disks WHERE COALESCE(backing_image, '') != ''`)
	if err != nil {
		return nil, fmt.Errorf("list disk rows: %w", err)
	}
	for _, r := range rows {
		n := recordedImageName(r.String("backing_image"), names)
		if n == "" || out[n] != "" {
			continue
		}
		if when, ok := recent(r.String("deleted_at")); ok {
			out[n] = fmt.Sprintf("disk %s/%s on host %s records it as its image%s",
				r.String("vm_name"), r.String("disk_name"), r.String("host_name"), when)
		}
	}
	rows, err = s.db.Query(ctx, `SELECT name, host_name, COALESCE(deleted_at, '') AS deleted_at,
		CASE WHEN json_valid(spec) THEN json_extract(spec, '$.image') END AS image
		FROM vms`)
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}
	for _, r := range rows {
		n := r.String("image")
		if !names[n] || out[n] != "" {
			continue
		}
		if when, ok := recent(r.String("deleted_at")); ok {
			out[n] = fmt.Sprintf("VM %s on host %s was created from it%s", r.String("name"), r.String("host_name"), when)
		}
	}
	return out, nil
}

// imageRecreateGrace is how long a deleted VM row still records its image
// (imageRecordedUsers). A rebuild or rolling recreate creates the VM again
// within seconds of the tombstone, and the create holds the image from its
// start; ten minutes covers that gap, and the replication of the tombstone and
// of the new rows, many times over.
const imageRecreateGrace = 10 * time.Minute

// recordedImageName is the image in names a disk row's backing_image names:
// the image's name, or a path to one of its files in an image store.
func recordedImageName(backing string, names map[string]bool) string {
	if names[backing] {
		return backing
	}
	if filepath.IsAbs(backing) && filepath.Base(filepath.Dir(backing)) == "images" {
		if n, ok := image.ImageNameOfFile(backing); ok && names[n] {
			return n
		}
	}
	return ""
}

// deletedImages is the images (name's alone, when set) whose catalog row is
// deleted on this host. With wait, it waits — up to deletedImageWait — for
// the row of name to read deleted here: lv image rm deletes it on the host it
// asks, and asks every host at once.
func (s *Server) deletedImages(ctx context.Context, name string, wait bool) (map[string]bool, error) {
	deadline := time.Now().Add(s.imagePrune.deleteWaitOr())
	for {
		rows, err := s.db.Query(ctx, `SELECT name FROM images WHERE deleted_at IS NOT NULL`)
		if err != nil {
			return nil, fmt.Errorf("read the image catalog: %w", err)
		}
		out := map[string]bool{}
		for _, r := range rows {
			if n := r.String("name"); name == "" || n == name {
				out[n] = true
			}
		}
		if !wait || name == "" || out[name] || !time.Now().Before(deadline) {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return out, nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// poolDiskFiles is every regular file in <data_dir>/disks and in this host's
// file pool directories, and in the subdirectories of a btrfs pool (each disk
// is a subvolume of its own). An nfs pool must be mounted: an unmounted share
// reads as an empty directory, and the disks on it would be unseen.
func (s *Server) poolDiskFiles(ctx context.Context) ([]string, error) {
	type dir struct {
		path         string
		nfs, perDisk bool
	}
	dirs := []dir{{path: filepath.Join(s.dataDir, "disks")}}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return nil, fmt.Errorf("list pools: %w", err)
	}
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		if d, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target}); err == nil {
			drv := strings.ToLower(p.Driver)
			dirs = append(dirs, dir{path: d, nfs: drv == "nfs", perDisk: drv == "btrfs"})
		}
	}
	readDir := s.imagePrune.boundedReadDir()
	var out []string
	var list func(d string, sub, top bool) error
	list = func(d string, sub, top bool) error {
		ents, err := readDir(d)
		if top && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("list %s: %w", d, err)
		}
		for _, e := range ents {
			switch {
			case e.Type().IsRegular():
				out = append(out, filepath.Join(d, e.Name()))
			case sub && e.IsDir():
				if err := list(filepath.Join(d, e.Name()), false, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, d := range dirs {
		if d.nfs {
			if err := s.nfsPoolDirMounted(d.path); err != nil {
				return nil, err
			}
		}
		// A directory that does not exist holds no disk.
		if err := list(d.path, d.perDisk, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// nfsPoolDirMounted refuses an nfs pool directory that is not mounted: an
// unmounted share reads as an empty directory, and the disks on it would be
// unseen. A directory the mount table has as a mount point is mounted, with
// no call on it (on a mount whose server does not answer, a stat would wait
// as long, lab 2); any other is judged by stat, under a bound.
func (s *Server) nfsPoolDirMounted(dir string) error {
	if storage.IsMountPoint(dir) {
		return nil
	}
	mountedFn := s.imagePrune.mountedFn()
	mounted, err := storage.Bounded("judge whether it is mounted", dir, func() (bool, error) { return mountedFn(dir) })
	if err != nil || !mounted {
		return fmt.Errorf("nfs pool directory %s is not mounted (%v): the disks on the share cannot be seen", dir, err)
	}
	return nil
}

// backupBaseFiles is the base every backup manifest in a backup repo on this
// host records it was taken on (base_identity): the configured repos and the
// cluster-registered ones. A repo whose directory is not here is another
// host's; one that is here and cannot be read is an error.
func (s *Server) backupBaseFiles(ctx context.Context) ([]string, error) {
	roots := map[string]bool{}
	for _, p := range s.backupRepos {
		roots[p] = true
	}
	if repos, err := corrosion.ListBackupRepos(ctx, s.db); err != nil {
		return nil, fmt.Errorf("list backup repos: %w", err)
	} else {
		for _, r := range repos {
			roots[r.Path] = true
		}
	}
	var out []string
	for _, root := range slices.Sorted(maps.Keys(roots)) {
		if !filepath.IsAbs(root) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "repo.json")); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		repo, err := pbsstore.Open(root)
		if err != nil {
			return nil, fmt.Errorf("backup repo %s: %w", root, err)
		}
		ms, err := repo.ListParsedManifests()
		if err != nil {
			return nil, fmt.Errorf("backup repo %s: %w", root, err)
		}
		for _, m := range ms {
			if m.BaseIdentity != nil && filepath.IsAbs(m.BaseIdentity.Path) {
				out = append(out, m.BaseIdentity.Path)
			}
		}
	}
	return out, nil
}

// chainWalk collects the image-store files (resolved) in backing chains.
type chainWalk struct {
	images string
	inUse  map[string]string // image-store files kept, and why
	walked map[string]bool   // files whose chain is walked
}

// walk adds every image-store layer below path to inUse — and path itself
// with self, kept for why — following qcow2 backings (a raw backing is kept
// but not read); a layer below is kept because who is built on it. A missing
// file names nothing; a header that cannot be read is an error.
func (w *chainWalk) walk(path string, self bool, why, who string) error {
	path, err := resolvedStrict(path)
	if err != nil {
		return err
	}
	if self && w.inImages(path) && w.inUse[path] == "" {
		w.inUse[path] = why
	}
	for depth := 0; ; depth++ {
		if w.walked[path] {
			return nil
		}
		w.walked[path] = true
		if depth > maxBackingDepth {
			return fmt.Errorf("%s: backing chain deeper than %d", path, maxBackingDepth)
		}
		backing, qcow, err := layerBacking(path)
		if err != nil || backing == "" {
			return err
		}
		if w.inImages(backing) && w.inUse[backing] == "" {
			w.inUse[backing] = who + " is built on it"
		}
		if !qcow {
			return nil
		}
		path = backing
	}
}

func (w *chainWalk) inImages(p string) bool {
	return p != w.images && safename.Contains(w.images, p)
}

// layerBacking is the backing (resolved) the qcow2 file at path declares,
// and whether it is declared qcow2. A file that is missing, not regular or
// not a qcow2, or a qcow2 with no local backing (none, a protocol, a file
// that does not exist), names none. A file with the qcow2 magic whose header
// does not parse is an error: what it names is unknown.
func layerBacking(path string) (string, bool, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !fi.Mode().IsRegular() {
		return "", false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	var magic [4]byte
	_, err = io.ReadFull(f, magic[:])
	f.Close()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || (err == nil && binary.BigEndian.Uint32(magic[:]) != qcow2.Magic) {
		return "", false, nil // not a qcow2
	}
	if err != nil {
		return "", false, err
	}
	info, err := qcow2.Info(path)
	if err != nil {
		return "", false, fmt.Errorf("read the qcow2 header of %s: %w", path, err)
	}
	if info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
		return "", false, nil
	}
	b := info.BackingFile
	if !filepath.IsAbs(b) {
		b = filepath.Join(filepath.Dir(path), b)
	}
	resolved, err := filepath.EvalSymlinks(b)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("resolve the backing of %s: %w", path, err)
	}
	return resolved, info.BackingFormat == "qcow2", nil
}

// imageFilesInUseBounded is imageFilesInUse within imagePruneDeadline. One
// scan runs at a time; a scan that outlives its deadline keeps that slot
// until its blocked syscall returns, so a hung share costs one goroutine, not
// one per refresh.
func (s *Server) imageFilesInUseBounded(ctx context.Context, keep []string, deleted map[string]bool) (*imageUseScan, error) {
	deadline := s.imagePrune.deadlineOr()
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	slot := s.imagePrune.scanSlot()
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("an earlier scan of the disk files has not finished within %s (a hung mount?): nothing is pruned", deadline)
	}
	type result struct {
		sc  *imageUseScan
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-slot }()
		sc, err := s.imageFilesInUse(ctx, keep, deleted)
		done <- result{sc, err}
	}()
	select {
	case r := <-done:
		if storage.IsFSNoAnswer(r.err) {
			return nil, fmt.Errorf("the scan of the disk files: %w: nothing is pruned", r.err)
		}
		return r.sc, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("the scan of the disk files did not finish within %s (a hung mount?): nothing is pruned", deadline)
	}
}

// pruneOutcome is what a prune did (or, dry, would do) on this host.
type pruneOutcome struct {
	removed []string
	freed   int64
	kept    []*pb.KeptImageFile // the files of a deleted image kept, and why
}

// pruneImageVersions removes, on this host, the files of image name (every
// image when name is "") that the prune need not keep (pruneImages). It
// returns the files it removed (or, with dryRun, would remove) and their
// bytes.
func (s *Server) pruneImageVersions(ctx context.Context, name string, dryRun bool, keep ...string) ([]string, int64, error) {
	out, err := s.pruneImages(ctx, name, dryRun, false, keep...)
	return out.removed, out.freed, err
}

// pruneImages removes, on this host, the files of image name (every image
// when name is "") that the prune need not keep (imageFilesInUse) and that no
// in-flight disk create holds (holdImage). On an image store other hosts may
// share (a network filesystem, or one whose filesystem cannot be told) no
// version is removed: another host's disk may be built on it, and this host
// cannot see that disk (lab 2 N-7). Each is reported kept, with the reason.
// Nothing is removed unless the store, and every directory the scan reads,
// can be listed within the bound (storeFiles, boundedReadDir).
//
// The files of a deleted image (its catalog row is deleted: lv image rm) are
// all candidates, its current file too, and each is removed only when none of
// these keeps it, else it is kept and the reason reported:
//   - a disk file, staged file, backup base or kept image file this host can
//     see is built on it, or it is pinned (imageFilesInUse);
//   - a live VM anywhere in the cluster records the image (a disk built on it,
//     or a VM created from it): a failover, recreate or migration onto this
//     host may need this copy;
//   - a disk recorded on this host cannot be read here, a staging directory
//     cannot be read, or the store is on a network filesystem other hosts may
//     share: what is built on it cannot all be seen;
//   - a process holds it open (a running qemu), or that cannot be told;
//   - a disk create, pull or import of the image was in flight when the scan
//     began, or began before the removal: its disk may not have been seen.
//
// The last check and the removal are one step under the prune's lock, which
// every create, pull and import of the image takes to begin (holdImage,
// holdImagePublish): a create that begins after the removal finds no file.
//
// justDeleted (deleted_image): the caller has just deleted name's row, and
// this host waits for its catalog to show it (deletedImages); if it never
// does, name's current file is kept and that reported.
func (s *Server) pruneImages(ctx context.Context, name string, dryRun, justDeleted bool, keep ...string) (pruneOutcome, error) {
	var out pruneOutcome
	st := s.imageStore()
	// The snapshot comes first: a pull or import that completes after it —
	// reviving the catalog row this prune may already have read as deleted —
	// has moved the image's generation, and its file is not removed.
	snap := s.imagePrune.snapshot()
	// Only the deleted images with files here are this prune's: a host with
	// no file of name does not wait for its delete.
	present := map[string]bool{}
	listed, err := s.storeFiles(st)
	if err != nil {
		return out, fmt.Errorf("%w: nothing is pruned", err)
	}
	for _, n := range listed {
		present[n] = true
	}
	deleted, err := s.deletedImages(ctx, name, justDeleted && present[name])
	if err != nil {
		return out, err
	}
	for n := range deleted {
		if !present[n] {
			delete(deleted, n)
		}
	}
	if hook := s.imagePrune.afterCatalog; hook != nil {
		hook()
	}
	sc, err := s.imageFilesInUseBounded(ctx, keep, deleted)
	if err != nil {
		return out, err
	}
	if hook := s.imagePrune.afterScan; hook != nil {
		hook()
	}
	// Every candidate's resolved form first, before anything is removed: the
	// scan's keeps are by that form, and one that cannot be had is not
	// guessed (resolvedStrict).
	files, err := s.storeFiles(st)
	if err != nil {
		return out, fmt.Errorf("%w: nothing is pruned", err)
	}
	resolved := map[string]string{}
	for f, n := range files {
		if name != "" && n != name {
			continue
		}
		r, err := resolvedStrict(f)
		if err != nil {
			return out, fmt.Errorf("resolve %s: %w: nothing is pruned", f, err)
		}
		resolved[f] = r
	}
	for f, n := range files {
		if name != "" && n != name {
			continue
		}
		r := resolved[f]
		if !deleted[n] {
			if f == st.ImagePath(n) || slices.Contains(keep, f) || sc.inUse[r] != "" {
				if justDeleted && n == name && f == st.ImagePath(n) {
					out.kept = append(out.kept, &pb.KeptImageFile{Path: f, Reason: fmt.Sprintf(
						"the image's catalog record is not deleted on %s (the delete has not replicated here yet, or the image was pulled again): lv image prune %s --host %s removes it once it is",
						s.hostName, n, s.hostName)})
				}
				continue
			}
			// A version no disk here is built on may still be another
			// host's base when the store is shared (lab 2 N-7): kept, as a
			// deleted image's files are (deletedKeep).
			if sc.storeFS != "" {
				out.kept = append(out.kept, &pb.KeptImageFile{Path: f, Reason: sc.storeFS})
				continue
			}
		} else if why := sc.deletedKeep(f, r, n, snap[n]); why != "" {
			out.kept = append(out.kept, &pb.KeptImageFile{Path: f, Reason: why})
			continue
		}
		fi, err := os.Lstat(f)
		if err != nil {
			continue
		}
		if !dryRun {
			if err := s.removeUnheldImageFile(st, n, f, snap[n], deleted[n]); err != nil {
				if deleted[n] {
					out.kept = append(out.kept, &pb.KeptImageFile{Path: f, Reason: err.Error()})
				}
				slog.Warn("image: prune of an unused file skipped", "image", n, "file", f, "error", err)
				continue
			}
			if deleted[n] {
				slog.Info("image: removed a file of a deleted image nothing uses", "image", n, "file", f)
			} else {
				slog.Info("image: removed a version no disk on this host is built on", "image", n, "file", f)
			}
		}
		out.removed = append(out.removed, f)
		out.freed += fi.Size()
	}
	slices.Sort(out.removed)
	slices.SortFunc(out.kept, func(a, b *pb.KeptImageFile) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// deletedKeep is why the scan keeps f, a file of deleted image n resolved to
// r ("" when nothing does).
func (sc *imageUseScan) deletedKeep(f, r, n string, held holdSnap) string {
	switch {
	case sc.inUse[r] != "":
		return sc.inUse[r]
	case sc.recorded[n] != "":
		return sc.recorded[n]
	case held.held:
		return fmt.Sprintf("a disk create, pull or import of image %q was in flight when the scan began", n)
	case sc.missingDisk != "":
		return sc.missingDisk
	case sc.unscanned != "":
		return sc.unscanned
	case sc.storeFS != "":
		return sc.storeFS
	case sc.open[f] != "":
		return sc.open[f] + " holds it open"
	case sc.openErr != "":
		return sc.openErr
	}
	return ""
}

// removeUnheldImageFile removes file f of image n unless a disk create on n
// is in flight (it may be building on f) or f became n's current file since
// the scan. A file of a deleted image (deleted) is removed, its current file
// too, only if no create, pull or import of n is in flight or began since the
// scan's snapshot (held).
func (s *Server) removeUnheldImageFile(st *image.Store, n, f string, held holdSnap, deleted bool) error {
	p := &s.imagePrune
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.holds[n] > 0 {
		return fmt.Errorf("a disk create on image %q is in flight", n)
	}
	if !deleted {
		if f == st.ImagePath(n) {
			return fmt.Errorf("it is the current version now")
		}
		return st.RemoveImageFile(n, f)
	}
	if p.pubs[n] > 0 {
		return fmt.Errorf("a pull or import of image %q is in flight", n)
	}
	if p.gens[n] != held.gen {
		return fmt.Errorf("a disk create, pull or import of image %q started during the scan; the next prune decides", n)
	}
	return st.RemoveDeletedImageFile(n, f)
}

// holdImage marks a disk create on image name in flight until release is
// called: from before the image's file is resolved until the disk's row is
// written (or the create fails), no prune removes a file of name.
func (s *Server) holdImage(name string) (release func()) {
	return s.imagePrune.hold(name, false)
}

// holdImagePublish marks a pull, import or build of image name in flight
// until release is called: from before its content is published until its
// catalog row is written, no file of name is removed as a deleted image's.
// Unlike a create's hold it does not stop a prune of unused versions: a
// refresh starts one itself.
func (s *Server) holdImagePublish(name string) (release func()) {
	return s.imagePrune.hold(name, true)
}

func (p *imagePruneState) hold(name string, publish bool) (release func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.holds == nil {
		p.holds, p.pubs, p.gens = map[string]int{}, map[string]int{}, map[string]uint64{}
	}
	m := p.holds
	if publish {
		m = p.pubs
	}
	m[name]++
	p.gens[name]++
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if m[name]--; m[name] <= 0 {
				delete(m, name)
			}
		})
	}
}

// holdSnap is an image's holds as a prune's scan began.
type holdSnap struct {
	gen  uint64 // holds ever taken on the image
	held bool   // one was in flight
}

func (p *imagePruneState) snapshot() map[string]holdSnap {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]holdSnap{}
	for n, g := range p.gens {
		out[n] = holdSnap{gen: g, held: p.holds[n] > 0 || p.pubs[n] > 0}
	}
	return out
}

// pruneAfterRefresh prunes image name's unused versions in the background,
// keeping keep: a refresh never waits on the scan (a hung share would hang
// it), and the scan is bounded (imagePruneDeadline).
func (s *Server) pruneAfterRefresh(name string, keep ...string) {
	s.imagePrune.bg.Add(1)
	go func() {
		defer s.imagePrune.bg.Done()
		if _, _, err := s.pruneImageVersions(context.Background(), name, false, keep...); err != nil {
			slog.Warn("image: pruning unused versions after a refresh skipped", "image", name, "error", err)
		}
	}()
}

// PruneImages removes the image-store files no disk on the host is built on
// (except each image's current file, unless the image is deleted): lv image
// prune, and each host's part of lv image rm (deleted_image).
func (s *Server) PruneImages(ctx context.Context, req *pb.PruneImagesRequest) (*pb.PruneImagesResponse, error) {
	if err := s.RequirePerm(ctx, "/", "image.import", "operator"); err != nil {
		return nil, err
	}
	if req.Name != "" {
		if err := safename.ValidateImageName(req.Name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	if req.DeletedImage && req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "deleted_image needs the image's name")
	}
	if req.HostName != "" && req.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.HostName, err)
		}
		defer conn.Close()
		return client.PruneImages(ctx, req)
	}
	out, err := s.pruneImages(ctx, req.Name, req.DryRun, req.DeletedImage)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "prune images: %v", err)
	}
	return &pb.PruneImagesResponse{HostName: s.hostName, Removed: out.removed, FreedBytes: out.freed,
		Kept: out.kept, RemovesDeletedImages: true}, nil
}

// imageRemoveTimeout bounds one host's part of lv image rm: the wait for its
// catalog to show the delete, then its bounded scan.
func imageRemoveTimeout(p *imagePruneState) time.Duration {
	return p.deleteWaitOr() + p.deadlineOr() + 30*time.Second
}

// RemoveImage deletes image name's catalog row (DeleteImage), then asks every
// host to remove its files of the image where nothing uses them (PruneImages
// with deleted_image), and reports each host's outcome: lv image rm. A host
// that cannot be asked, or runs an older build, keeps its files; lv image
// prune on it removes them later.
//
// It is gated exactly as DeleteImage (the operator role): removing the files
// is part of the delete, which DeleteImage performs too, so no caller main let
// delete an image is refused here. Each host's part runs as that host — this
// one directly, a peer through its PruneImages with this host's certificate —
// for RemoveImage and DeleteImage alike, never as the caller.
func (s *Server) RemoveImage(ctx context.Context, req *pb.RemoveImageRequest) (*pb.RemoveImageResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := safename.ValidateImageName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := corrosion.DeleteImage(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete image: %v", err)
	}
	return s.removeImageFiles(ctx, req.Name), nil
}

// removeImageFiles asks every host in the cluster (this one too) to remove
// its files of deleted image name (PruneImages, deleted_image), at once,
// each bounded (imageRemoveTimeout).
func (s *Server) removeImageFiles(ctx context.Context, name string) *pb.RemoveImageResponse {
	hosts := []string{s.hostName}
	resp := &pb.RemoveImageResponse{}
	if hs, err := corrosion.ListHosts(ctx, s.db); err != nil {
		resp.Failed = append(resp.Failed, &pb.RemoveImageHostError{HostName: "*",
			Error: fmt.Sprintf("list the cluster's hosts: %v; only %s was asked", err, s.hostName)})
	} else {
		for _, h := range hs {
			if h.Name != s.hostName {
				hosts = append(hosts, h.Name)
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hctx, cancel := context.WithTimeout(ctx, imageRemoveTimeout(&s.imagePrune))
			defer cancel()
			r, err := s.removeImageFilesOn(hctx, h, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Failed = append(resp.Failed, &pb.RemoveImageHostError{HostName: h, Error: err.Error()})
				return
			}
			resp.Hosts = append(resp.Hosts, r)
		}()
	}
	wg.Wait()
	slices.SortFunc(resp.Hosts, func(a, b *pb.PruneImagesResponse) int { return strings.Compare(a.HostName, b.HostName) })
	slices.SortFunc(resp.Failed, func(a, b *pb.RemoveImageHostError) int { return strings.Compare(a.HostName, b.HostName) })
	for _, r := range resp.Hosts {
		for _, f := range r.Removed {
			slog.Info("image rm: removed a file", "image", name, "host", r.HostName, "file", f)
		}
		for _, k := range r.Kept {
			slog.Warn("image rm: kept a file", "image", name, "host", r.HostName, "file", k.Path, "reason", k.Reason)
		}
		if !r.RemovesDeletedImages {
			slog.Warn("image rm: the host runs an older build that keeps a deleted image's current file", "image", name, "host", r.HostName)
		}
	}
	for _, f := range resp.Failed {
		slog.Warn("image rm: a host's files were not removed", "image", name, "host", f.HostName, "error", f.Error)
	}
	return resp
}

// removeImageFilesOn is host's part of removeImageFiles.
func (s *Server) removeImageFilesOn(ctx context.Context, host, name string) (*pb.PruneImagesResponse, error) {
	if host == s.hostName {
		out, err := s.pruneImages(ctx, name, false, true)
		if err != nil {
			return nil, err
		}
		return &pb.PruneImagesResponse{HostName: s.hostName, Removed: out.removed, FreedBytes: out.freed,
			Kept: out.kept, RemovesDeletedImages: true}, nil
	}
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot reach host %s: %w; its files are kept: lv image prune %s --host %s removes them later", host, err, name, host)
	}
	defer conn.Close()
	r, err := client.PruneImages(ctx, &pb.PruneImagesRequest{Name: name, DeletedImage: true})
	if status.Code(err) == codes.Unimplemented {
		return nil, fmt.Errorf("host %s runs an older build with no image prune; its files are kept", host)
	}
	if err != nil {
		return nil, fmt.Errorf("%w; its files are kept: lv image prune %s --host %s removes them later", err, name, host)
	}
	if r.HostName == "" {
		r.HostName = host
	}
	return r, nil
}

// imagePruneState is the prune's per-server state.
type imagePruneState struct {
	mu    sync.Mutex
	scan  chan struct{}     // the one scan slot (scanSlot)
	holds map[string]int    // image → in-flight disk creates (holdImage)
	pubs  map[string]int    // image → in-flight pulls, imports, builds (holdImagePublish)
	gens  map[string]uint64 // image → holds ever taken, either kind
	bg    sync.WaitGroup    // background prunes after a refresh, and after DeleteImage

	readDir  func(string) ([]os.DirEntry, error) // test seam; os.ReadDir when nil
	mounted  func(string) (bool, error)          // test seam; isMountpoint when nil
	deadline atomic.Int64                        // test seam (ns); imagePruneDeadline when 0

	openFiles    func([]string) (map[string]string, error) // test seam; processesHolding when nil
	storeFS      func(string) (string, error)              // test seam; networkFilesystem when nil
	afterScan    func()                                    // test seam: runs between the scan and the removals
	afterCatalog func()                                    // test seam: runs after the catalog is read
	deleteWait   atomic.Int64                              // test seam (ns); deletedImageWait when 0
	recentGrace  atomic.Int64                              // test seam (ns); imageRecreateGrace when 0, none when < 0
}

func (p *imagePruneState) recreateGraceOr() time.Duration {
	switch d := p.recentGrace.Load(); {
	case d < 0:
		return 0
	case d > 0:
		return time.Duration(d)
	}
	return imageRecreateGrace
}

// deletedImageWait bounds how long a host told an image was just deleted
// waits for its own catalog to show the delete (deletedImages).
const deletedImageWait = 15 * time.Second

func (p *imagePruneState) deadlineOr() time.Duration {
	if d := p.deadline.Load(); d > 0 {
		return time.Duration(d)
	}
	return imagePruneDeadline
}

func (p *imagePruneState) deleteWaitOr() time.Duration {
	if d := p.deleteWait.Load(); d > 0 {
		return time.Duration(d)
	}
	return deletedImageWait
}

func (p *imagePruneState) scanSlot() chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scan == nil {
		p.scan = make(chan struct{}, 1)
	}
	return p.scan
}

func (p *imagePruneState) readDirFn() func(string) ([]os.DirEntry, error) {
	if p.readDir != nil {
		return p.readDir
	}
	return os.ReadDir
}

// boundedReadDir is readDirFn under storage.Bounded: a directory whose
// listing does not answer (a network filesystem whose server does not)
// fails the scan within the bound, with an *storage.FSNoAnswerError, instead
// of holding it to its deadline.
func (p *imagePruneState) boundedReadDir() func(string) ([]os.DirEntry, error) {
	readDir := p.readDirFn()
	return func(d string) ([]os.DirEntry, error) {
		return storage.Bounded("list", d, func() ([]os.DirEntry, error) { return readDir(d) })
	}
}

func (p *imagePruneState) mountedFn() func(string) (bool, error) {
	if p.mounted != nil {
		return p.mounted
	}
	return isMountpoint
}

func (p *imagePruneState) openFilesFn() func([]string) (map[string]string, error) {
	if p.openFiles != nil {
		return p.openFiles
	}
	return processesHolding
}

func (p *imagePruneState) storeFSFn() func(string) (string, error) {
	if p.storeFS != nil {
		return p.storeFS
	}
	return networkFilesystem
}

// isMountpoint reports whether dir is the root of a mount: it is on another
// device than its parent (or is /).
func isMountpoint(dir string) (bool, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	pi, err := os.Stat(filepath.Dir(filepath.Clean(dir)))
	if err != nil {
		return false, err
	}
	a, ok1 := fi.Sys().(*syscall.Stat_t)
	b, ok2 := pi.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("cannot tell whether %s is a mountpoint", dir)
	}
	return a.Dev != b.Dev || a.Ino == b.Ino, nil
}

// pinBackupBase pins, on this host — the VM's, which holds the base — the
// image-store file a disk-file backup of an overlay was taken on (id), so no
// prune removes it, whatever repo or host the manifest lands in (a sink host,
// an absolute repo path). A base outside the image store is not the prune's.
func (s *Server) pinBackupBase(id *pbsstore.BaseIdentity) error {
	if id == nil || !filepath.IsAbs(id.Path) {
		return nil
	}
	// Whether the base is the store's is not answered on a guess: a store
	// whose resolution does not answer is an error, and the backup warns
	// that its base is unpinned (pinBackupBaseOrWarn).
	images, err := resolvedStrict(s.imageStore().ImageDir())
	if err != nil {
		return fmt.Errorf("resolve the image store: %w", err)
	}
	if filepath.Dir(id.Path) != images {
		return nil
	}
	if _, ok := image.ImageNameOfFile(id.Path); !ok {
		return nil
	}
	return s.imageStore().Pin(id.Path)
}

// pinBackupBaseOrWarn pins the backup's base (pinBackupBase). A pin that
// cannot be written never fails the backup — the backup is still whole —
// but the base is then unprotected from a prune, so it is said loudly: a
// WARN log, a warning in the backup's progress, and a VM event.
func (s *Server) pinBackupBaseOrWarn(ctx context.Context, vm string, id *pbsstore.BaseIdentity, send func(*pb.BackupSnapshotProgress) error) {
	err := s.pinBackupBase(id)
	if err == nil {
		return
	}
	msg := fmt.Sprintf("warning: could not pin the base %s this backup was taken on (%v); a prune of the image's unused versions on this host may remove it, and a restore of this backup would then have no base", id.Path, err)
	slog.Warn("backup: pinning the base the backup is taken on failed", "vm", vm, "base", id.Path, "error", err)
	_ = send(&pb.BackupSnapshotProgress{Phase: pb.BackupSnapshotProgress_SNAPSHOT, Status: msg})
	s.recordVMEvent(ctx, vm, "backup.base_unpinned", "warning", msg)
}

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
// that cannot be read is an error, and nothing is pruned on it.
func (s *Server) imageFilesInUse(ctx context.Context, keep []string) (map[string]bool, error) {
	w := &chainWalk{images: resolvedOr(s.imageStore().ImageDir()), inUse: map[string]bool{}, walked: map[string]bool{}}
	rows, err := s.db.Query(ctx, `SELECT path FROM vm_disks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list disk rows: %w", err)
	}
	var files []string
	for _, r := range rows {
		if p := r.String("path"); filepath.IsAbs(p) {
			files = append(files, s.hostDiskFile(p))
		}
	}
	listed, err := s.poolDiskFiles(ctx)
	if err != nil {
		return nil, err
	}
	files = append(files, listed...)
	for _, f := range files {
		if err := w.walk(f, false); err != nil {
			return nil, err
		}
	}
	bases, err := s.backupBaseFiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bases {
		if err := w.walk(b, true); err != nil {
			return nil, err
		}
	}
	// Every kept store file's own chain, to a fixed point.
	st := s.imageStore()
	for {
		grew := false
		for f, n := range st.StoreFiles() {
			r := resolvedOr(f)
			if w.walked[r] || !(f == st.ImagePath(n) || slices.Contains(keep, f) || w.inUse[r] || image.Pinned(f)) {
				continue
			}
			if err := w.walk(f, true); err != nil {
				return nil, err
			}
			grew = true
		}
		if !grew {
			return w.inUse, nil
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
	readDir := s.imagePrune.readDirFn()
	var out []string
	var list func(d string, sub bool) error
	list = func(d string, sub bool) error {
		ents, err := readDir(d)
		if err != nil {
			return fmt.Errorf("list %s: %w", d, err)
		}
		for _, e := range ents {
			switch {
			case e.Type().IsRegular():
				out = append(out, filepath.Join(d, e.Name()))
			case sub && e.IsDir():
				if err := list(filepath.Join(d, e.Name()), false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, d := range dirs {
		if d.nfs {
			mounted, err := s.imagePrune.mountedFn()(d.path)
			if err != nil || !mounted {
				return nil, fmt.Errorf("nfs pool directory %s is not mounted (%v): the disks on the share cannot be seen", d.path, err)
			}
		}
		if _, err := os.Lstat(d.path); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := list(d.path, d.perDisk); err != nil {
			return nil, err
		}
	}
	return out, nil
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
	inUse  map[string]bool // image-store files kept
	walked map[string]bool // files whose chain is walked
}

// walk adds every image-store layer below path to inUse — and path itself
// with self — following qcow2 backings (a raw backing is kept but not read).
// A missing file names nothing; a header that cannot be read is an error.
func (w *chainWalk) walk(path string, self bool) error {
	path = resolvedOr(path)
	if self && w.inImages(path) {
		w.inUse[path] = true
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
		if w.inImages(backing) {
			w.inUse[backing] = true
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
func (s *Server) imageFilesInUseBounded(ctx context.Context, keep []string) (map[string]bool, error) {
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
		inUse map[string]bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-slot }()
		inUse, err := s.imageFilesInUse(ctx, keep)
		done <- result{inUse, err}
	}()
	select {
	case r := <-done:
		return r.inUse, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("the scan of the disk files did not finish within %s (a hung mount?): nothing is pruned", deadline)
	}
}

// pruneImageVersions removes, on this host, the files of image name (every
// image when name is "") that the prune need not keep (imageFilesInUse) and
// that no in-flight disk create holds (holdImage). It returns the files it
// removed (or, with dryRun, would remove) and their bytes.
func (s *Server) pruneImageVersions(ctx context.Context, name string, dryRun bool, keep ...string) ([]string, int64, error) {
	st := s.imageStore()
	inUse, err := s.imageFilesInUseBounded(ctx, keep)
	if err != nil {
		return nil, 0, err
	}
	var removed []string
	var freed int64
	for f, n := range st.StoreFiles() {
		if name != "" && n != name {
			continue
		}
		if f == st.ImagePath(n) || slices.Contains(keep, f) || inUse[resolvedOr(f)] {
			continue
		}
		fi, err := os.Lstat(f)
		if err != nil {
			continue
		}
		if !dryRun {
			if err := s.removeUnheldImageFile(st, n, f); err != nil {
				slog.Warn("image: prune of an unused version skipped", "image", n, "file", f, "error", err)
				continue
			}
			slog.Info("image: removed a version no disk on this host is built on", "image", n, "file", f)
		}
		removed = append(removed, f)
		freed += fi.Size()
	}
	slices.Sort(removed)
	return removed, freed, nil
}

// removeUnheldImageFile removes file f of image n unless a disk create on n
// is in flight (it may be building on f) or f became n's current file since
// the scan.
func (s *Server) removeUnheldImageFile(st *image.Store, n, f string) error {
	p := &s.imagePrune
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.holds[n] > 0 {
		return fmt.Errorf("a disk create on image %q is in flight", n)
	}
	if f == st.ImagePath(n) {
		return fmt.Errorf("it is the current version now")
	}
	return st.RemoveImageFile(n, f)
}

// holdImage marks a disk create on image name in flight until release is
// called: from before the image's file is resolved until the disk's row is
// written (or the create fails), no prune removes a file of name.
func (s *Server) holdImage(name string) (release func()) {
	p := &s.imagePrune
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.holds == nil {
		p.holds = map[string]int{}
	}
	p.holds[name]++
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.holds[name]--; p.holds[name] <= 0 {
				delete(p.holds, name)
			}
		})
	}
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
// (except each image's current file): lv image prune.
func (s *Server) PruneImages(ctx context.Context, req *pb.PruneImagesRequest) (*pb.PruneImagesResponse, error) {
	if err := s.RequirePerm(ctx, "/", "image.import", "operator"); err != nil {
		return nil, err
	}
	if req.Name != "" {
		if err := safename.ValidateImageName(req.Name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	if req.HostName != "" && req.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.HostName, err)
		}
		defer conn.Close()
		return client.PruneImages(ctx, req)
	}
	removed, freed, err := s.pruneImageVersions(ctx, req.Name, req.DryRun)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "prune images: %v", err)
	}
	return &pb.PruneImagesResponse{HostName: s.hostName, Removed: removed, FreedBytes: freed}, nil
}

// imagePruneState is the prune's per-server state.
type imagePruneState struct {
	mu    sync.Mutex
	scan  chan struct{}  // the one scan slot (scanSlot)
	holds map[string]int // image → in-flight disk creates (holdImage)
	bg    sync.WaitGroup // background prunes after a refresh

	readDir  func(string) ([]os.DirEntry, error) // test seam; os.ReadDir when nil
	mounted  func(string) (bool, error)          // test seam; isMountpoint when nil
	deadline atomic.Int64                        // test seam (ns); imagePruneDeadline when 0
}

func (p *imagePruneState) deadlineOr() time.Duration {
	if d := p.deadline.Load(); d > 0 {
		return time.Duration(d)
	}
	return imagePruneDeadline
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

func (p *imagePruneState) mountedFn() func(string) (bool, error) {
	if p.mounted != nil {
		return p.mounted
	}
	return isMountpoint
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
	if filepath.Dir(id.Path) != resolvedOr(s.imageStore().ImageDir()) {
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

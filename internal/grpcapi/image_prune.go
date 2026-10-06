package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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

// imageFilesInUse is every image-store file (resolved) named in the backing
// chain of a disk file this host can see: every disk row's file present here
// (any host's row: a disk on shared storage another host runs is read here
// too), and every regular file in <data_dir>/disks and in this host's file
// pool directories — which also covers a disk created a moment ago whose row
// is not written yet, and leftovers no row names. Any failure to list is an
// error: nothing is pruned on a partial view.
func (s *Server) imageFilesInUse(ctx context.Context) (map[string]bool, error) {
	files := map[string]bool{}
	rows, err := s.db.Query(ctx, `SELECT path FROM vm_disks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list disk rows: %w", err)
	}
	for _, r := range rows {
		if p := r.String("path"); filepath.IsAbs(p) {
			files[s.hostDiskFile(p)] = true
		}
	}
	dirs := []string{filepath.Join(s.dataDir, "disks")}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return nil, fmt.Errorf("list pools: %w", err)
	}
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		if dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target}); err == nil {
			dirs = append(dirs, dir)
		}
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("list %s: %w", d, err)
		}
		for _, e := range ents {
			if e.Type().IsRegular() {
				files[filepath.Join(d, e.Name())] = true
			}
		}
	}
	images := resolvedOr(s.imageStore().ImageDir())
	inUse := map[string]bool{}
	for f := range files {
		chainImageFiles(f, images, inUse)
	}
	return inUse, nil
}

// chainImageFiles walks the qcow2 backing chain of path (each layer a regular
// file, judged by stat before it is opened; a raw backing ends it) and adds
// every layer inside images to inUse. A file that is not a readable qcow2 ends
// the walk: what it would name is unknown, and the files it can keep are only
// ones some other header names.
func chainImageFiles(path, images string, inUse map[string]bool) {
	for depth := 0; depth <= maxBackingDepth; depth++ {
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return
		}
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		resolved, err := filepath.EvalSymlinks(b)
		if err != nil {
			return
		}
		if safename.Contains(images, resolved) && resolved != images {
			inUse[resolved] = true
		}
		if info.BackingFormat != "qcow2" {
			return
		}
		path = resolved
	}
}

// pruneImageVersions removes, on this host, the files of image name (every
// image when name is "") that are not the image's current file, not in keep,
// and not named by any disk's backing chain here (imageFilesInUse). It returns
// the files it removed (or, with dryRun, would remove) and their bytes.
func (s *Server) pruneImageVersions(ctx context.Context, name string, dryRun bool, keep ...string) ([]string, int64, error) {
	st := s.imageStore()
	inUse, err := s.imageFilesInUse(ctx)
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
			if err := st.RemoveImageFile(n, f); err != nil {
				slog.Warn("image: prune of an unused version failed", "image", n, "file", f, "error", err)
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

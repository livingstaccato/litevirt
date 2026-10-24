package grpcapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keepDisksSnapshotRefusal refuses `lv rm --keep-disks` of a VM that has
// snapshot records, before anything is done. A kept disk with snapshots is a
// backing chain whose base sits at the path a later VM of the same name
// creates its disk at, and the kept snapshots' records, memory images and
// firmware bundles are keyed by the VM's name, so that later VM would list
// them and remove or overwrite them. Removing the snapshots first (`lv
// snapshot rm`, which merges each into its disk) or deleting without
// --keep-disks leaves nothing of the kind. Records that cannot be read
// refuse too. A snapshot libvirt holds with no record here is refused by
// libvirt itself: the keep-state undefine passes no SNAPSHOTS_METADATA.
func (s *Server) keepDisksSnapshotRefusal(ctx context.Context, req *pb.DeleteVMRequest) error {
	if !req.KeepDisks {
		return nil
	}
	snaps, err := corrosion.ListSnapshots(ctx, s.db, req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot delete VM %q with --keep-disks: its snapshot records cannot be read (%v); nothing was done (retry is safe)", req.Name, err)
	}
	if len(snaps) == 0 {
		return nil
	}
	names := make([]string, 0, len(snaps))
	for _, sn := range snaps {
		names = append(names, sn.Name)
	}
	return status.Errorf(codes.FailedPrecondition,
		"cannot delete VM %q with --keep-disks: it has %d snapshot(s) (%s), and a later VM of the name could overwrite the "+
			"kept disks' snapshot chain and remove the snapshots' memory images and firmware bundles; remove them first "+
			"(`lv snapshot rm %s <snapshot>`), or delete without --keep-disks; nothing was done",
		req.Name, len(snaps), strings.Join(names, ", "), req.Name)
}

// keptDiskChains is, for each host-local disk of req.Name recorded here that
// the delete keeps (every one with --keep-disks, and one recorded
// delete_with_vm=false), its file and the files of its backing chain below
// it, top first. A chain that cannot be read in full is an error naming the
// file: what the kept disk is built on is then unknown, and a file under it
// would be left unprotected. dotdots[i] is the index in chains[i] of the
// first layer reached through a ".." reference, -1 when none
// (keptChainWalk).
func (s *Server) keptDiskChains(ctx context.Context, name string, keepDisks bool) (kept []corrosion.DiskRecord, chains [][]string, dotdots []int, err error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, name)
	if err != nil {
		return nil, nil, nil, &diskRecordsReadError{err}
	}
	for _, d := range disks {
		if !s.keptHere(d, keepDisks) {
			continue
		}
		top := filepath.Clean(s.hostDiskFile(d.Path))
		w, err := storage.Bounded("read the backing chain of", top, func() (keptWalked, error) {
			l, _, dd, err := walkKeptChain(os.Stat, top, false)
			return keptWalked{layers: l, dotdot: dd}, err
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the backing chain of its disk %s cannot be read (%w)", d.DiskName, err)
		}
		kept = append(kept, d)
		chains = append(chains, w.layers)
		dotdots = append(dotdots, w.dotdot)
	}
	return kept, chains, dotdots, nil
}

// keptWalked is one walk of a kept file's backing chain (walkKeptChain).
type keptWalked struct {
	layers  []string
	missing string
	dotdot  int
}

// aboveDotDot is layers down to, and not including, the first one reached
// through a ".." reference (dotdot, -1 when none): what a note may name as
// the VM's own. Where a ".." leads depends on symlinked directories, so that
// layer and everything below it are listed only, never noted.
func aboveDotDot(layers []string, dotdot int) []string {
	if dotdot >= 0 && dotdot < len(layers) {
		return layers[:dotdot]
	}
	return layers
}

// diskRecordsReadError is a VM's disk records that cannot be read.
type diskRecordsReadError struct{ err error }

func (e *diskRecordsReadError) Error() string {
	return "its disk records cannot be read: " + e.err.Error()
}
func (e *diskRecordsReadError) Unwrap() error { return e.err }

// keptHere reports whether d is a host-local file of this host that a delete
// keeps: every one with keepDisks, and one recorded delete_with_vm=false.
func (s *Server) keptHere(d corrosion.DiskRecord, keepDisks bool) bool {
	if d.Path == "" || d.HostName != s.hostName || corrosion.DiskIsShared(d) || strings.HasPrefix(d.Path, "rbd:") ||
		!isHostLocalDiskDriver(d.StorageType) {
		return false
	}
	return keepDisks || !d.DeleteWithVM
}

// keptChainLayers is file and each file of its backing chain, top first. It
// ends at a file without the qcow2 magic (raw, or a block device), which
// names no file under it, unless the overlay above it declares it qcow2
// (backing_fmt): that one has lost its header, and may have hidden a file
// under it. A raw backing file, declared raw or with no format declared,
// ends the chain. It also ends at a backing reference that is a protocol URI.
// A file that cannot be stated (the top only when it is missing, which keeps
// nothing), a file with the qcow2 magic whose header cannot be read, a
// declared qcow2 backing file without the magic, and a chain deeper than
// maxBackingDepth are errors naming the file.
func keptChainLayers(file string) ([]string, error) {
	layers, _, _, err := walkKeptChain(os.Stat, file, false)
	return layers, err
}

// keptChainLayersToMissing is keptChainLayers, except that a backing file
// below the top that does not exist ends the chain, with the layers above it,
// and is returned as missing: nothing is at that path to keep, and nothing
// below it is reached, but the last layer still names it, so a file written
// there becomes that layer's base. Any other error is still one.
func keptChainLayersToMissing(file string) (layers []string, missing string, err error) {
	layers, missing, _, err = walkKeptChain(os.Stat, file, true)
	return layers, missing, err
}

// keptChainWalk is keptChainLayersToMissing, and also the index of the first
// layer reached through a backing reference with a ".." element (-1 when
// none): that layer's path depends on where symlinked directories lead, so a
// caller that removes files treats it, and everything below it, as listed
// only (keptBackingPath).
func keptChainWalk(file string) (layers []string, missing string, dotdot int, err error) {
	return walkKeptChain(os.Stat, file, true)
}

// keptBackingPath is the file an overlay at overlay names as its backing
// file b, as the kernel finds it: a relative b is joined to the overlay's
// directory, and a ".." element is taken physically, after the symlinked
// directories before it, not by cleaning the text (qemu passes the joined
// path to open(2) as it is). dotdot reports a ".." element. A directory on
// the way that does not exist (or a dangling link) leaves the joined path as
// it is, uncleaned: a stat of it then fails as the kernel's open does, even
// when a file sits at the path its text cleans to.
func keptBackingPath(overlay, b string) (path string, dotdot bool, err error) {
	raw := b
	if !filepath.IsAbs(b) {
		raw = filepath.Dir(overlay) + string(filepath.Separator) + b
	}
	if !slices.Contains(strings.Split(raw, string(filepath.Separator)), "..") {
		return filepath.Clean(raw), false, nil
	}
	i := strings.LastIndex(raw, string(filepath.Separator))
	dir, base := raw[:i], raw[i+1:]
	if base == ".." || base == "." || base == "" {
		dir, base = raw, ""
	}
	real, err := filepath.EvalSymlinks(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return raw, true, nil
	}
	if err != nil {
		return "", true, fmt.Errorf("%s: resolve its backing file %s: %w", overlay, b, err)
	}
	return filepath.Join(real, base), true, nil
}

// walkKeptChain reads file's chain for keptChainLayers,
// keptChainLayersToMissing and keptChainWalk, statting each layer with stat.
func walkKeptChain(stat func(string) (os.FileInfo, error), file string, stopAtMissing bool) ([]string, string, int, error) {
	return walkKeptChainIn(nil, stat, file, stopAtMissing)
}

// walkKeptChainIn is walkKeptChain, with each layer's header read within b
// when b is not nil (keptCollisionScan): opened by b.open, which opens only
// a regular file on no pseudo-filesystem and never blocks, read through
// that one open file, and charged to b.
func walkKeptChainIn(b *keptScanBudget, stat func(string) (os.FileInfo, error), file string, stopAtMissing bool) ([]string, string, int, error) {
	var out []string
	path, declaredQcow2 := file, false
	dotdot := -1
	for depth := 0; depth <= maxBackingDepth; depth++ {
		fi, err := stat(path)
		if err != nil {
			if depth == 0 && errors.Is(err, fs.ErrNotExist) {
				return nil, "", -1, nil
			}
			if stopAtMissing && errors.Is(err, fs.ErrNotExist) {
				return out, path, dotdot, nil
			}
			return nil, "", -1, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, path)
		if !fi.Mode().IsRegular() {
			return out, "", dotdot, nil
		}
		isQ, info, err := keptLayerHeader(b, path)
		if errors.Is(err, errKeptScanPseudoLayer) {
			// On a pseudo-filesystem: no kept overlay backs on it, and it is
			// never opened. The chain ends here, as at a non-regular layer.
			return out, "", dotdot, nil
		}
		if err != nil {
			return nil, "", -1, fmt.Errorf("%s: %w", path, err)
		}
		if !isQ {
			if declaredQcow2 {
				return nil, "", -1, fmt.Errorf("%s: the overlay above it declares it qcow2, and it has no qcow2 header", path)
			}
			return out, "", dotdot, nil
		}
		if info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return out, "", dotdot, nil
		}
		next, dd, err := keptBackingPath(path, info.BackingFile)
		if err != nil {
			return nil, "", -1, err
		}
		if dd && dotdot < 0 {
			dotdot = len(out)
		}
		path, declaredQcow2 = next, info.BackingFormat == "qcow2"
	}
	return nil, "", -1, fmt.Errorf("%s: backing chain deeper than %d", file, maxBackingDepth)
}

// keptLayerHeader reads whether the layer at path is qcow2 and, when it
// is, its image info: by name with a nil b, as before; within b otherwise.
func keptLayerHeader(b *keptScanBudget, path string) (bool, *qcow2.ImageInfo, error) {
	if b == nil {
		isQ, err := hasQcow2Magic(path)
		if err != nil || !isQ {
			return false, nil, err
		}
		info, err := qcow2.Info(path)
		return err == nil, info, err
	}
	f, err := b.open(path)
	if err != nil {
		return false, nil, err
	}
	defer f.Close()
	var m [4]byte
	_, err = f.ReadAt(m[:], 0)
	if cerr := b.charge(int64(len(m))); cerr != nil {
		return false, nil, cerr
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if binary.BigEndian.Uint32(m[:]) != qcow2.Magic {
		return false, nil, nil
	}
	info, err := qcow2.InfoFile(f)
	if err != nil {
		return false, nil, err
	}
	// What InfoFile read: the header, its extensions and the backing file's
	// name, far under keptScanLayerBytes (not the cluster size, which a 2M
	// cluster image would make 2 MiB a layer).
	if err := b.charge(keptScanLayerBytes); err != nil {
		return false, nil, err
	}
	return true, info, nil
}

// hasQcow2Magic reports whether path starts with the qcow2 magic.
func hasQcow2Magic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	return binary.BigEndian.Uint32(b[:]) == qcow2.Magic, nil
}

// keptChainRefusal refuses a delete, before anything is done, when a disk
// it keeps has a backing chain that cannot be read in full (the files under
// it could not be protected), and, with --keep-disks, when one is an overlay
// on another of the VM's own disk files (<vm>-<disk>.qcow2), as a restore or
// a metadata-only snapshot delete leaves it. A plain delete notes such a
// file as one a kept disk backs on (noteKeptDisks), and a create of the name
// refuses while it is there.
func (s *Server) keptChainRefusal(ctx context.Context, req *pb.DeleteVMRequest) error {
	_, chains, _, err := s.keptDiskChains(ctx, req.Name, req.KeepDisks)
	var rerr *diskRecordsReadError
	if errors.As(err, &rerr) {
		return status.Errorf(codes.Internal,
			"cannot delete VM %q: %v; nothing was done (retry is safe)", req.Name, err)
	}
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot delete VM %q: %v, so what a disk it keeps is built on cannot be protected; nothing was done "+
				"(retry once it can be read)", req.Name, err)
	}
	if !req.KeepDisks || s.images == nil || len(chains) == 0 {
		return nil
	}
	taken, err := s.vmDiskCandidateSet(req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot delete VM %q with --keep-disks: the disk files a later VM of the name would take cannot be listed (%v); nothing was done (retry is safe)", req.Name, err)
	}
	for _, layers := range chains {
		for _, under := range layers[min(1, len(layers)):] {
			if taken[under] {
				return status.Errorf(codes.FailedPrecondition,
					"cannot delete VM %q with --keep-disks: its disk %s is an overlay on %s, which a later VM of the name would set "+
						"aside or write over, leaving the kept overlay on that VM's disk; copy the disk out to a standalone image, "+
						"then delete without --keep-disks; nothing was done",
					req.Name, layers[0], under)
			}
		}
	}
	return nil
}

// vmDiskCandidateSet is the set of name's <vm>-<disk>.qcow2 files, cleaned,
// that a create of the name clears (image.Store.VMDiskCandidates).
func (s *Server) vmDiskCandidateSet(name string) (map[string]bool, error) {
	candidates, err := s.images.VMDiskCandidates(name)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, c := range candidates {
		set[filepath.Clean(c)] = true
	}
	return set, nil
}

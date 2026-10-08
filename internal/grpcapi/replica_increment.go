package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PushReplicaIncrement receives an incremental (or full) replica into a
// file-based pool. The first message is the header (pool/host/filename/base/
// total_size); the rest carry (offset,data) dirty extents. The new replica is a
// sparse RAW file: when base is set it is forked from that previous replica
// (server-side, no network) and only the streamed extents are patched in, so a
// plain WriteAt suffices — no qcow2 writer needed. base="" makes it a full push.
func (s *Server) PushReplicaIncrement(stream pb.LiteVirt_PushReplicaIncrementServer) error {
	ctx := stream.Context()
	// Peer-only: dirty-extent replica pushes come from a peer over host mTLS
	// (no direct operator caller). Tighter than the old RequireRole("operator").
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no header: %v", err)
	}
	if first.PoolName == "" || first.Filename == "" {
		return status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	if !isBaseName(first.Filename) || (first.Base != "" && !isBaseName(first.Base)) {
		return status.Error(codes.InvalidArgument, "filename and base must be base names")
	}
	// A replica carries its record: the receiver writes it into that VM's
	// own directory of the replica area, never a bare name into the pool. A
	// sender on an older build sends none (rolling upgrade): its push is
	// taken as main took it, at the pool's top level, only under a VM disk's
	// exact runner name (receiveLegacyIncrement).
	legacy := first.GetReplica() == nil
	var rec replicaRecord
	if !legacy {
		rec, err = replicaRecordFromPB(first.GetReplica())
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if first.Filename != rec.File {
			return status.Errorf(codes.InvalidArgument, "filename %q is not the record's file %q", first.Filename, rec.File)
		}
	}
	if first.TotalSize <= 0 {
		return status.Error(codes.InvalidArgument, "total_size must be > 0")
	}
	host := first.Host
	if host == "" {
		host = s.hostName
	}
	pool, ok, err := corrosion.GetStoragePool(ctx, s.db, host, first.PoolName)
	if err != nil {
		return status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return status.Errorf(codes.NotFound, "pool %q not on host %q", first.PoolName, host)
	}

	// Remote pool: proxy the whole stream to the owning host.
	if host != s.hostName {
		client, conn, perr := s.peerClient(ctx, host)
		if perr != nil {
			return status.Errorf(codes.Unavailable, "reach host %q: %v", host, perr)
		}
		defer conn.Close()
		fctx, ferr := s.forwardContentCall(ctx)
		if ferr != nil {
			return ferr
		}
		up, perr := client.PushReplicaIncrement(fctx)
		if perr != nil {
			return status.Errorf(codes.Unavailable, "open push to %q: %v", host, perr)
		}
		if err := up.Send(first); err != nil {
			return err
		}
		for {
			msg, rerr := stream.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
			if err := up.Send(msg); err != nil {
				return err
			}
		}
		resp, rerr := up.CloseAndRecv()
		if rerr != nil {
			return rerr
		}
		return stream.SendAndClose(resp)
	}

	if !isFileBasedDriver(pool.Driver) {
		return status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", first.PoolName)
	}

	var written int64
	apply := func(f *os.File) error {
		// The header may itself carry a first extent (offset/data).
		if len(first.Data) > 0 {
			if _, err := f.WriteAt(first.Data, first.Offset); err != nil {
				return err
			}
			written += int64(len(first.Data))
		}
		for {
			msg, rerr := stream.Recv()
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
			if len(msg.Data) == 0 {
				continue
			}
			if msg.Offset < 0 || msg.Offset+int64(len(msg.Data)) > first.TotalSize {
				return status.Errorf(codes.InvalidArgument, "extent [%d,%d) out of bounds (size %d)", msg.Offset, msg.Offset+int64(len(msg.Data)), first.TotalSize)
			}
			if _, err := f.WriteAt(msg.Data, msg.Offset); err != nil {
				return err
			}
			written += int64(len(msg.Data))
		}
	}
	if legacy {
		dest, ferr := s.receiveLegacyIncrement(ctx, first.PoolName, first.Filename, first.Base, first.TotalSize, apply)
		if ferr != nil {
			if _, isStatus := status.FromError(ferr); isStatus {
				return ferr
			}
			return status.Errorf(codes.Internal, "apply replica: %v", ferr)
		}
		return stream.SendAndClose(&pb.PushReplicaIncrementResponse{Path: dest, BytesWritten: written})
	}
	dest, ferr := s.receiveRawReplica(ctx, first.PoolName, rec, first.Base, first.TotalSize, apply)
	if ferr != nil {
		if _, isStatus := status.FromError(ferr); isStatus {
			return ferr
		}
		return status.Errorf(codes.Internal, "apply replica: %v", ferr)
	}
	return stream.SendAndClose(&pb.PushReplicaIncrementResponse{Path: dest, BytesWritten: written, ReplicaRecorded: true})
}

// receiveLegacyIncrement takes an older build's incremental replica push
// (no record) as main took it: a new raw file named name at pool's top
// level, forked from base, recorded as a peer's upload. Only when name is
// exactly a runner name of one VM disk here (<vm>-<disk>-<stamp>.raw, not
// one another project's VM could have written), and base, when set, is a
// top-level raw replica of that same disk; a promotion then matches the
// file by that name, as main did.
func (s *Server) receiveLegacyIncrement(ctx context.Context, pool, name, base string, totalSize int64, apply func(*os.File) error) (string, error) {
	k, ok := s.legacyReplicaKey(ctx, name)
	if !ok || !strings.HasSuffix(name, ".raw") {
		return "", status.Errorf(codes.InvalidArgument,
			"%q is not a replica name of one VM disk on this cluster; a push without a replica record names one", name)
	}
	poolDir, err := s.replicaPoolDir(ctx, pool)
	if err != nil {
		return "", err
	}
	if base != "" && (!strings.HasSuffix(base, ".raw") || !slices.Contains(s.localReplicaNames(ctx, poolDir, k, "", false), base)) {
		return "", status.Errorf(codes.FailedPrecondition,
			"base %q is not a raw replica of vm %q disk %q in pool %q", base, k.VM, k.Disk, pool)
	}
	dest, err := forkRawAndApply(poolDir, name, base, totalSize, apply)
	if err != nil {
		return "", err
	}
	if err := s.recordPeerUpload(ctx, pool, dest); err != nil {
		slog.Warn("replica push from an older build not recorded; it is matched by its name", "path", dest, "error", err)
	}
	return dest, nil
}

// legacyReplicaKey is the VM disk whose exact runner name name is: the one
// split of its <vm>-<disk> stem that names a live VM with that disk, which
// no VM of another project could have written. ok is false for any other.
func (s *Server) legacyReplicaKey(ctx context.Context, name string) (replicaKey, bool) {
	stem, ok := replicaNamePrefix(name)
	if !ok {
		return replicaKey{}, false
	}
	var found []replicaKey
	for i := 1; i < len(stem)-1; i++ {
		if stem[i] != '-' {
			continue
		}
		vm, err := corrosion.GetVM(ctx, s.db, stem[:i])
		if err != nil || vm == nil {
			continue
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if err != nil {
			continue
		}
		for _, d := range disks {
			if d.DiskName == stem[i+1:] {
				found = append(found, replicaKeyOf(vm, d.DiskName))
			}
		}
	}
	if len(found) != 1 || !replicaNameIs(name, found[0]) || s.replicaNameClaimedElsewhere(ctx, name, found[0]) {
		return replicaKey{}, false
	}
	return found[0], true
}

// isBaseName rejects path separators / traversal so a streamed filename can't
// escape the pool directory.
func isBaseName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.Contains(name, "/") && name != ".."
}

// forkRawAndApply materializes a new sparse RAW replica at dir/name of
// total_size bytes: when base is set it copies that previous replica forward
// (sparse, skipping zero runs) then runs apply to patch the dirty extents;
// base="" starts from an all-zero sparse file. Written atomically via a temp +
// rename so a partial transfer never leaves a half-written replica in place.
func forkRawAndApply(dir, name, base string, totalSize int64, apply func(*os.File) error) (string, error) {
	if totalSize <= 0 {
		return "", fmt.Errorf("total_size must be > 0")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := storage.CreatePoolTemp(dir, ".repl-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close() // idempotent enough: a second Close just errors, which we ignore
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Truncate(totalSize); err != nil {
		return "", err
	}
	if base != "" {
		if err := sparseCopyInto(tmp, filepath.Join(dir, base)); err != nil {
			return "", err
		}
	}
	if err := apply(tmp); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, name)
	// Never over a file already there (RENAME_NOREPLACE).
	if err := placeNoClobber(tmpName, dest); err != nil {
		return "", err
	}
	committed = true
	return dest, nil
}

// sparseCopyInto copies srcPath into dst at matching offsets, skipping all-zero
// 1 MiB chunks so holes in the source stay holes in the destination (dst is
// pre-truncated to size). Pure file I/O — no network.
func sparseCopyInto(dst *os.File, srcPath string) error {
	src, err := storage.OpenPoolFile(srcPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	buf := make([]byte, 1<<20)
	var off int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if !allZero(buf[:n]) {
				if _, err := dst.WriteAt(buf[:n], off); err != nil {
					return err
				}
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

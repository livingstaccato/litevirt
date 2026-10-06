package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// maxPoolUploadBytes caps a single pool-content upload stream so a client can't
// fill the host disk. Generous (matches the restore ceiling) since legitimate
// ISOs/images are large.
const maxPoolUploadBytes int64 = 2 << 40 // 2 TiB

// Storage-pool CONTENT RPCs authorize against the pool's OWNING project
// (poolRBACPathFor on the STORED rec.Project), the same boundary pool CRUD uses —
// resolve the pool first, then authorize, then forward. A cluster PEER call (an
// entry-node forward, cross-host replication, or auto-promote — see requirePeerCert)
// skips tenant RBAC: the user was already authorized on the entry node, or it's a
// system flow. The peer bypass skips ONLY tenant RBAC — pool-name/filename validation
// and SafeJoin still run for both peer and user calls.
//
// TRUST BOUNDARY: any known cluster host cert can reach pool contents via these RPCs.
// This is a deliberate bypass of project RBAC, consistent with the peer-RPC model.

// ListStoragePoolContents lists the files in a file-based storage pool (used by
// the UI content browser to pick ISOs). Block-backed pools (ceph/iscsi/zfs/
// lvm-thin) return empty — they have no plain-file directory. Forwards to the
// pool's owning host, since the files live on that host's filesystem.
func (s *Server) ListStoragePoolContents(ctx context.Context, req *pb.ListStoragePoolContentsRequest) (*pb.ListStoragePoolContentsResponse, error) {
	if req.PoolName == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name required")
	}
	if err := safename.ValidatePoolName(req.PoolName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.PoolName, host)
	}
	// Peer calls (forward / replication / auto-promote) skip tenant RBAC; user calls
	// authorize against the pool's owning project.
	if s.requirePeerCert(ctx) != nil {
		if err := s.authorizeResourceRead(ctx, rec.Project, poolRBACPathFor(rec.Project, req.PoolName), "storage.content.read"); err != nil {
			return nil, err
		}
	}

	// Files live on the owning host — forward there if it isn't us. A user's
	// listing then gains the replicas of the VMs that user may read, decided
	// here where the user is known (the owner sees only this host's cert).
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		resp, err := client.ListStoragePoolContents(ctx, req)
		if err != nil {
			return nil, err
		}
		if s.requirePeerCert(ctx) != nil {
			s.appendReadableReplicas(ctx, resp, req.PoolName, host)
		}
		return resp, nil
	}

	if !isFileBasedDriver(rec.Driver) {
		// Block-backed pool: no browsable file directory.
		return &pb.ListStoragePoolContentsResponse{}, nil
	}
	ref := StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}
	// A refused pool — a directory no pool may use, one shared with another
	// pool, a weak NFS mount — is not even listed: its directory may be
	// /root/.ssh, the daemon's state, or another project's disks.
	if err := s.checkPoolForWrite(ctx, rec.Name, ref); err != nil {
		return nil, err
	}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.ListStoragePoolContentsResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "read pool dir: %v", err)
	}

	resp := &pb.ListStoragePoolContentsResponse{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		name := e.Name()
		// A file a live disk of another pool (or of no pool) uses is not this
		// pool's content: a legacy target-less local pool shares <data_dir>/disks
		// with every local VM disk on the host. Unknown ownership hides it.
		owners, oerr := s.liveDiskOwners(ctx, s.hostName, filepath.Join(dir, name))
		if oerr != nil || slices.ContainsFunc(owners, func(d corrosion.DiskRecord) bool { return d.StorageVolume != req.PoolName }) {
			continue
		}
		resp.Contents = append(resp.Contents, &pb.StoragePoolContent{
			Name:       name,
			Path:       filepath.Join(dir, name),
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
			IsIso:      strings.HasSuffix(strings.ToLower(name), ".iso"),
		})
	}
	sort.Slice(resp.Contents, func(i, j int) bool { return resp.Contents[i].Name < resp.Contents[j].Name })
	if s.requirePeerCert(ctx) != nil {
		s.appendReadableReplicas(ctx, resp, req.PoolName, host)
	}
	return resp, nil
}

// appendReadableReplicas adds to a user's pool listing the replicas of every
// VM the user may read (canReadVMRecord), each from its records in the pool's
// replica area on host — never another project's, never a file by name.
func (s *Server) appendReadableReplicas(ctx context.Context, resp *pb.ListStoragePoolContentsResponse, pool, host string) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return
	}
	for i := range vms {
		vm := &vms[i]
		if !s.canReadVMRecord(ctx, vm) {
			continue
		}
		for _, r := range s.replicaRecordsOn(ctx, pool, host, vm.Project, vm.Name) {
			resp.Contents = append(resp.Contents, &pb.StoragePoolContent{
				Name: r.File, SizeBytes: r.SizeBytes,
				ReplicaVm: vm.Name, ReplicaDisk: r.Disk, ReplicaTaken: r.Taken,
			})
		}
	}
}

// DeleteStoragePoolContent removes one file from a file-based pool (forwarded
// to the pool's owning host). Replication no longer uses it: replicas are
// pruned through the peer-only PruneReplicas, by record.
func (s *Server) DeleteStoragePoolContent(ctx context.Context, req *pb.DeleteStoragePoolContentRequest) (*emptypb.Empty, error) {
	if req.PoolName == "" || req.Filename == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	if err := safename.ValidatePoolName(req.PoolName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := safename.ValidateName(req.Filename); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "filename: %v", err)
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.PoolName, host)
	}
	if s.requirePeerCert(ctx) != nil {
		if err := s.RequirePerm(ctx, poolRBACPathFor(rec.Project, req.PoolName), "storage.content.write", "operator"); err != nil {
			return nil, err
		}
	}
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.DeleteStoragePoolContent(ctx, req)
	}
	if !isFileBasedDriver(rec.Driver) {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", req.PoolName)
	}
	dir, err := s.poolWriteDir(ctx, rec)
	if err != nil {
		return nil, err
	}
	target, err := safename.SafeJoin(dir, req.Filename)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Never a file a live disk uses — this pool's or, in a directory shared
	// with other disks, anyone's, on any host (a pool on shared storage).
	owners, err := s.diskReferencesAnyHost(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check disk use: %v", err)
	}
	if len(owners) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%q is in use by VM %q disk %q; it is not pool content to delete", req.Filename, owners[0].VMName, owners[0].DiskName)
	}
	// os.Remove deletes a symlink itself (not its target), so this can't be
	// redirected to delete an arbitrary file outside the pool.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// UploadStoragePoolContent streams a file into a file-based pool. The first
// message carries pool_name/host/filename; the rest carry chunks. Forwards the
// whole stream to the pool's owning host when it isn't local.
func (s *Server) UploadStoragePoolContent(stream pb.LiteVirt_UploadStoragePoolContentServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no data: %v", err)
	}
	// Nothing this build does not know rides on an upload. Field 5 used to
	// carry a replica record; an entry node on a build that has it, or one
	// that does not know it, forwards it as it came — under its own host
	// certificate. Replicas now travel only on the peer-only PushReplica, which
	// no entry node forwards for a user, so any unknown field is refused here.
	if len(first.ProtoReflect().GetUnknown()) != 0 {
		return status.Error(codes.InvalidArgument,
			"upload header carries fields this daemon does not accept (a replica is sent with PushReplica, never as an upload)")
	}
	if first.PoolName == "" || first.Filename == "" {
		return status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	// The first frame is a header only — pool/host/filename, no payload — so
	// authorization always precedes any byte hitting disk. Reject a bundled chunk.
	if len(first.Chunk) != 0 {
		return status.Error(codes.InvalidArgument, "first message must carry only pool_name/host/filename (no chunk data)")
	}
	if err := safename.ValidatePoolName(first.PoolName); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := validatePoolUploadName(first.Filename); err != nil {
		return status.Errorf(codes.InvalidArgument, "filename: %v", err)
	}
	host := first.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, first.PoolName)
	if err != nil {
		return status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return status.Errorf(codes.NotFound, "pool %q not on host %q", first.PoolName, host)
	}
	// Authorize BEFORE creating a temp file or reading any further frame (peer calls
	// skip tenant RBAC). A denied upload writes nothing and drains no chunks.
	if s.requirePeerCert(ctx) != nil {
		if err := s.RequirePerm(ctx, poolRBACPathFor(rec.Project, first.PoolName), "storage.content.write", "operator"); err != nil {
			return err
		}
	}

	// Remote pool: proxy the stream to the owning host.
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		up, err := client.UploadStoragePoolContent(ctx)
		if err != nil {
			return status.Errorf(codes.Unavailable, "open upload to %q: %v", host, err)
		}
		if err := up.Send(first); err != nil {
			return err
		}
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := up.Send(msg); err != nil {
				return err
			}
		}
		resp, err := up.CloseAndRecv()
		if err != nil {
			return err
		}
		return stream.SendAndClose(resp)
	}

	if !isFileBasedDriver(rec.Driver) {
		return status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", first.PoolName)
	}
	dir, err := s.poolWriteDir(ctx, rec)
	if err != nil {
		return err
	}
	dest, total, err := receiveFileNoClobber(dir, 0o755, first.Filename, func() ([]byte, error) {
		msg, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return msg.Chunk, nil
	})
	if err != nil {
		return err
	}
	return stream.SendAndClose(&pb.UploadStoragePoolContentResponse{Path: dest, SizeBytes: total})
}

// receiveFileNoClobber streams chunks (next returns io.EOF at the end) into a
// NEW file dir/filename: a temp, synced, published with no clobber, the
// directory synced after it. An existing name — a file, a directory, a
// symlink — is refused before anything is written and again atomically at the
// publish.
func receiveFileNoClobber(dir string, dirMode os.FileMode, filename string, next func() ([]byte, error)) (string, int64, error) {
	dest, err := safename.SafeJoin(dir, filename)
	if err != nil {
		return "", 0, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := refuseExistingDest(dest, filename); err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", 0, status.Errorf(codes.Internal, "mkdir: %v", err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*.tmp")
	if err != nil {
		return "", 0, status.Errorf(codes.Internal, "create temp: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // after a publish, drops the temp's second link
	defer tmp.Close()

	var total int64
	for {
		b, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, err
		}
		if len(b) == 0 {
			continue
		}
		if total+int64(len(b)) > maxPoolUploadBytes {
			return "", 0, status.Errorf(codes.InvalidArgument, "upload exceeds %d-byte ceiling", maxPoolUploadBytes)
		}
		n, werr := tmp.Write(b)
		total += int64(n)
		if werr != nil {
			return "", 0, werr
		}
	}
	if err := tmp.Close(); err != nil {
		return "", 0, status.Errorf(codes.Internal, "close: %v", err)
	}
	// Durable before visible: data synced before the publish, the directory
	// after it, or a power loss can leave the final name on a file whose bytes
	// never reached the disk.
	if err := syncPath(tmpName); err != nil {
		return "", 0, status.Errorf(codes.Internal, "sync: %v", err)
	}
	// Never replace what is there — a file, or a symlink planted at the name —
	// and never write through one.
	if err := publishNoClobber(tmpName, dest, filename); err != nil {
		return "", 0, err
	}
	if err := syncPath(dir); err != nil {
		// The publish may not survive a crash; withdraw it rather than leave a
		// name the storage will not vouch for.
		_ = os.Remove(dest)
		return "", 0, status.Errorf(codes.Internal, "sync directory: %v", err)
	}
	return dest, total, nil
}

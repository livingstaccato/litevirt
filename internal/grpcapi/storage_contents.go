package grpcapi

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

	// Files live on the owning host — forward there if it isn't us.
	if host != s.hostName {
		fctx, err := s.forwardContentCall(ctx)
		if err != nil {
			return nil, err
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.ListStoragePoolContents(fctx, req)
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
	// A directory that is not the pool's own shows a caller only its
	// project's files — the caller who made the call, on whichever node.
	caller, err := s.poolContentCallerOf(ctx)
	if err != nil {
		return nil, err
	}
	conf, err := s.poolConfinementFor(ctx, rec, caller)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pool content owners: %v", err)
	}
	if caller.view == viewReplicas {
		// Tell the daemon asking that these are matched by record; an older
		// host lists every file and the caller matches by name.
		_ = grpc.SetHeader(ctx, metadata.Pairs(replicaListingMDKey, "matched"))
	}
	resp := &pb.ListStoragePoolContentsResponse{}
	seen := map[string]bool{}
	for _, d := range s.poolContentDirs(dir) {
		entries, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, status.Errorf(codes.Internal, "read pool dir: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			name := e.Name()
			path := filepath.Join(d, name)
			// A file a live disk of another pool (or of no pool) uses is not this
			// pool's content: a legacy target-less local pool shares <data_dir>/disks
			// with every local VM disk on the host. Unknown ownership hides it.
			owners, oerr := s.liveDiskOwners(ctx, s.hostName, path)
			if oerr != nil || slices.ContainsFunc(owners, func(d corrosion.DiskRecord) bool { return d.StorageVolume != req.PoolName }) {
				continue
			}
			if !conf.visible(ctx, path) {
				continue
			}
			seen[name] = true
			resp.Contents = append(resp.Contents, &pb.StoragePoolContent{
				Name:       name,
				Path:       path,
				SizeBytes:  info.Size(),
				ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
				IsIso:      strings.HasSuffix(strings.ToLower(name), ".iso"),
			})
		}
	}
	sort.Slice(resp.Contents, func(i, j int) bool { return resp.Contents[i].Name < resp.Contents[j].Name })
	return resp, nil
}

// DeleteStoragePoolContent removes one file from a file-based pool (forwarded
// to the pool's owning host). Used by cross-host replication pruning.
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
		fctx, err := s.forwardContentCall(ctx)
		if err != nil {
			return nil, err
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.DeleteStoragePoolContent(fctx, req)
	}
	if !isFileBasedDriver(rec.Driver) {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", req.PoolName)
	}
	dir, err := s.poolWriteDir(ctx, rec)
	if err != nil {
		return nil, err
	}
	// In a directory that is not the pool's own, only the caller's project's
	// files — the caller who made the call, on whichever node; another's is
	// reported as absent, not as someone else's.
	caller, err := s.poolContentCallerOf(ctx)
	if err != nil {
		return nil, err
	}
	conf, err := s.poolConfinementFor(ctx, rec, caller)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pool content owners: %v", err)
	}
	// The file is in the pool's directory, or (a pool on <data_dir>/disks) in
	// disks/uploads, where users' uploads land. The name is the file the
	// listing shows the caller under it: the first, in poolContentDirs order,
	// that is there and that the caller sees. Otherwise it is the first that
	// is there (refused below as not the caller's), or the first path.
	var target, existing, first string
	for _, d := range s.poolContentDirs(dir) {
		p, err := safename.SafeJoin(d, req.Filename)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if first == "" {
			first = p
		}
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if existing == "" {
			existing = p
		}
		if target == "" && conf.visible(ctx, p) {
			target = p
		}
	}
	if target == "" {
		target = existing
	}
	if target == "" {
		target = first
	}
	if !conf.visible(ctx, target) {
		return nil, status.Errorf(codes.NotFound, "%q is not in pool %q", req.Filename, req.PoolName)
	}
	// Never a file a live disk uses — this pool's or, in a directory shared
	// with other disks, anyone's; and for the daemon's pruning on shared
	// storage, any host's (a promotion there may keep it as a backing file).
	owners, err := s.liveDiskOwners(ctx, s.hostName, target)
	if caller.view == viewReplicas {
		owners, err = s.replicaUsers(ctx, target)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check disk use: %v", err)
	}
	if len(owners) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%q is in use by VM %q disk %q; it is not pool content to delete", req.Filename, owners[0].VMName, owners[0].DiskName)
	}
	// Only the caller's own upload or replica; library content no record
	// refers to is shared by everyone who reads the pool, and only an admin
	// deletes it.
	if !conf.deletable(ctx, target) {
		return nil, status.Errorf(codes.PermissionDenied,
			"%q is shared library content, not the caller's own; deleting it needs %s at the cluster root", req.Filename, verbStorageHostPath)
	}
	// os.Remove deletes a symlink itself (not its target), so this can't be
	// redirected to delete an arbitrary file outside the pool.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	if err := s.forgetPoolUpload(ctx, target); err != nil {
		slog.Warn("pool content deleted but its upload record was not dropped", "pool", req.PoolName, "file", req.Filename, "error", err)
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
		fctx, err := s.forwardContentCall(ctx)
		if err != nil {
			return err
		}
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		up, err := client.UploadStoragePoolContent(fctx)
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
	poolDir, err := s.poolWriteDir(ctx, rec)
	if err != nil {
		return err
	}
	// Who the upload is for: the caller who made it, on whichever node. A
	// user's upload is recorded as its pool's project's; the daemon's replica
	// as its VM's; an older node's (no marker) is not recorded.
	caller, err := s.poolContentCallerOf(ctx)
	if err != nil {
		return err
	}
	// Into a pool on <data_dir>/disks a user's upload lands in disks/uploads,
	// out of the VM disks' namespace. The daemon's replica lands in the pool
	// directory, where promotion reads it.
	dir := poolDir
	if caller.record {
		dir = s.poolUploadDir(poolDir)
	}
	if caller.view == viewReplicas && !replicaNameIs(first.Filename, caller.replica) {
		return notAReplicaName(first.Filename, caller.replica)
	}
	dest, err := safename.SafeJoin(dir, first.Filename)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Refuse a taken name — in any of the pool's content directories —
	// before streaming anything; publishNoClobber below refuses it again
	// atomically.
	for _, d := range s.poolContentDirs(poolDir) {
		p, err := safename.SafeJoin(d, first.Filename)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if err := refuseExistingDest(p, first.Filename); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir: %v", err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*.tmp")
	if err != nil {
		return status.Errorf(codes.Internal, "create temp: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // after a publish, drops the temp's second link
	defer tmp.Close()

	var total int64
	writeChunk := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		if total+int64(len(b)) > maxPoolUploadBytes {
			return status.Errorf(codes.InvalidArgument, "upload exceeds %d-byte ceiling", maxPoolUploadBytes)
		}
		n, err := tmp.Write(b)
		total += int64(n)
		return err
	}
	if err := writeChunk(first.Chunk); err != nil {
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
		if err := writeChunk(msg.Chunk); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close: %v", err)
	}
	// Durable before visible. This receiver carries cross-host replicas into
	// their promotable name, so it follows publishReplica: data synced before
	// the rename, the directory after it, or a power loss can leave the final
	// name on a file whose bytes never reached the disk.
	if err := syncPath(tmpName); err != nil {
		return status.Errorf(codes.Internal, "sync: %v", err)
	}
	// Never replace what is there — a file, or a symlink planted at the name —
	// and never write through one.
	if err := publishNoClobber(tmpName, dest, first.Filename); err != nil {
		return err
	}
	if err := syncPath(dir); err != nil {
		// The rename may not survive a crash; withdraw it rather than leave a
		// name the storage will not vouch for.
		_ = os.Remove(dest)
		return status.Errorf(codes.Internal, "sync directory: %v", err)
	}
	// A caller's upload is recorded as its pool's project's: in a directory
	// that is not the pool's own, the record is what makes it theirs. A
	// replica's record says whose VM's disk it is, which is what promotion
	// and pruning match it by.
	var recErr error
	switch {
	case caller.view == viewReplicas:
		recErr = s.recordPoolReplica(ctx, rec.Name, caller.replica, dest)
	case caller.record:
		recErr = s.recordPoolUpload(ctx, rec.Name, rec.Project, callerUsername(caller.ctx)+"@"+callerRealm(caller.ctx), dest)
	default:
		recErr = s.recordPeerUpload(ctx, rec.Name, dest)
	}
	if recErr != nil {
		_ = os.Remove(dest)
		return status.Errorf(codes.Internal, "record upload: %v", recErr)
	}
	return stream.SendAndClose(&pb.UploadStoragePoolContentResponse{Path: dest, SizeBytes: total})
}

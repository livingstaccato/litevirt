package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// containerSnapshotDir is the per-host subdir of dataDir holding container
// snapshot tars: {dataDir}/ct-snapshots/<container>/<snapshot>.tar.
const containerSnapshotDir = "ct-snapshots"

func ctSnapshotPath(dataDir, ctName, snap string) string {
	return filepath.Join(dataDir, containerSnapshotDir, ctName, snap+".tar")
}

// A snapshot tar is the container's whole rootfs, /etc/shadow included, so it
// is readable by root alone: 0600 in 0700 directories. An earlier build wrote
// 0644 in 0755 directories; makeSnapshotPrivate tightens one the next time it
// is used (create, list, revert) — nothing sweeps the rest.

// makeSnapshotPrivate sets the snapshot directories under dataDir for ctName
// to 0700 and, when path is set and exists, the tar to 0600. A path outside
// this container's snapshot directory (a hand-edited record) is left alone.
func makeSnapshotPrivate(dataDir, ctName, path string) {
	top := filepath.Join(dataDir, containerSnapshotDir)
	dir := filepath.Join(top, ctName)
	for _, d := range []string{top, dir} {
		if fi, err := os.Lstat(d); err == nil && fi.IsDir() && fi.Mode().Perm() != 0o700 {
			_ = os.Chmod(d, 0o700)
		}
	}
	if path == "" || filepath.Dir(path) != dir {
		return
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm() != 0o600 {
		_ = os.Chmod(path, 0o600)
	}
}

// SnapshotContainer takes a point-in-time snapshot of a container: freeze (if
// running) → tar the on-disk dir → store host-local under dataDir, recording it
// in container_snapshots. Runs on the owning host (forwards there if the
// container lives elsewhere, mirroring VM CreateSnapshot).
func (s *Server) SnapshotContainer(ctx context.Context, req *pb.SnapshotContainerRequest) (_ *pb.ContainerSnapshot, retErr error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	// Both names are joined into ctSnapshotPath and the daemon runs as root, so
	// both are validated here — before any path is built from them. Without this
	// a `../` in the snapshot name escapes the snapshot directory: create
	// truncates whatever it lands on, delete removes it. The VM twin validates
	// its snapshot name for the same reason (snapshot.go). The container name is
	// additionally protected in practice by the record lookup below failing, but
	// that is incidental to another function's behaviour, so it is checked here
	// too rather than relied upon.
	if !validRestoreName(req.Name) || !validRestoreName(req.Snapshot) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid container/snapshot name: allowed [A-Za-z0-9_.-], not '.' or '..'")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "snapshot.create", "operator", containerWhat(req.Name)); err != nil {
		s.audit(ctx, "ct.snapshot.create", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward snapshot: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.SnapshotContainer(ctx, req)
	}
	op := s.startContainerOp("snapshot", req.Name, "snapshot", req.Snapshot)
	defer func() { op.done(retErr) }()
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	if existing, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "snapshot %q already exists for container %q", req.Snapshot, req.Name)
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	path := ctSnapshotPath(s.dataDir, req.Name, req.Snapshot)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "prepare snapshot dir: %v", err)
	}
	makeSnapshotPrivate(s.dataDir, req.Name, "")

	// Quiesce a running container so the tar is a consistent point-in-time;
	// always unfreeze, even on failure.
	if rec.State == "running" {
		if ferr := s.containerRuntime.FreezeContainer(ctx, req.Name); ferr == nil {
			defer func() { _ = s.containerRuntime.UnfreezeContainer(context.Background(), req.Name) }()
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create snapshot file: %v", err)
	}
	if err := f.Chmod(0o600); err != nil { // the umask never widens it, and an old file is narrowed
		_ = f.Close()
		_ = os.Remove(path)
		return nil, status.Errorf(codes.Internal, "create snapshot file: %v", err)
	}
	exportErr := s.containerRuntime.ExportContainer(ctx, req.Name, f)
	closeErr := f.Close()
	if exportErr != nil || closeErr != nil {
		_ = os.Remove(path)
		s.audit(ctx, "ct.snapshot.create", req.Name, "project="+project, "error")
		if exportErr != nil {
			return nil, status.Errorf(codes.Internal, "snapshot export: %v", exportErr)
		}
		return nil, status.Errorf(codes.Internal, "snapshot close: %v", closeErr)
	}
	var size int64
	if st, serr := os.Stat(path); serr == nil {
		size = st.Size()
	}
	// The owner record: which container (project and lineage) the snapshot is
	// of, so a later container reusing the name is not handed it.
	if err := writeSnapshotOwner(path, rec); err != nil {
		_ = os.Remove(path)
		return nil, status.Errorf(codes.Internal, "record snapshot owner: %v", err)
	}

	srec := corrosion.ContainerSnapshotRecord{
		CtName: req.Name, HostName: host, Name: req.Snapshot,
		State: "ok", SizeBytes: size, Type: "tar", Path: path,
	}
	if err := corrosion.InsertContainerSnapshot(ctx, s.db, srec); err != nil {
		_ = os.Remove(path)
		return nil, status.Errorf(codes.Internal, "record snapshot: %v", err)
	}
	s.audit(ctx, "ct.snapshot.create", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &pb.ContainerSnapshot{
		CtName: req.Name, HostName: host, Name: req.Snapshot,
		State: "ok", SizeBytes: size, Type: "tar",
	}, nil
}

// ListContainerSnapshots returns a container's snapshots. Forwards to the
// owning host for an immediately-consistent view.
func (s *Server) ListContainerSnapshots(ctx context.Context, req *pb.ListContainerSnapshotsRequest) (*pb.ListContainerSnapshotsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// ct.read OR snapshot.read on the container's own path (same shape
	// authorizeSchedule and the other container RPCs use, extended to admit
	// either verb per review ruling): ListContainerSnapshots used to check
	// only the cluster-wide viewer floor above, so a caller scoped to one
	// project could list every container's snapshots. ct.read alone also
	// excluded BackupOperator (snapshot.*, no ct.read), which can otherwise
	// fully create/restore/delete a container's snapshots — snapshot.read
	// admits the one role that fully manages this resource, while still
	// scoping per container and still hiding existence identically either
	// way (requirePermResolvedAny).
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolvedAny(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name),
		[]string{"ct.read", "snapshot.read"}, "viewer", containerWhat(req.Name)); err != nil {
		return nil, err
	}
	host, listRec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		if c, conn, derr := s.peerClient(ctx, host); derr == nil {
			defer conn.Close()
			req.HostName = host
			return c.ListContainerSnapshots(s.ownerStrictOutgoing(ctx), req)
		}
		// Fall through to the local (possibly stale) view if the peer is down.
	}
	snaps, err := corrosion.ListContainerSnapshots(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list snapshots: %v", err)
	}
	resp := &pb.ListContainerSnapshotsResponse{}
	for _, sn := range snaps {
		if host == s.hostName {
			makeSnapshotPrivate(s.dataDir, req.Name, sn.Path)
			// Another project's earlier container took it: not listed to a
			// caller the owner rules bind.
			if s.refuseForeignSnapshot(ctx, sn.Path, sn.Name, listRec) != nil {
				continue
			}
		}
		resp.Snapshots = append(resp.Snapshots, &pb.ContainerSnapshot{
			Id: sn.ID, CtName: sn.CtName, HostName: sn.HostName, Name: sn.Name,
			State: sn.State, SizeBytes: sn.SizeBytes, Type: sn.Type, CreatedAt: sn.CreatedAt,
		})
	}
	return resp, nil
}

// RevertContainerSnapshot rolls a container back to a snapshot: stop (revert
// replaces the rootfs) → restore the snapshot tar in place → restart if it had
// been running. The runtime's RevertContainer is crash-safe (sets the live dir
// aside and restores it if the extract fails).
func (s *Server) RevertContainerSnapshot(ctx context.Context, req *pb.RevertContainerSnapshotRequest) (_ *emptypb.Empty, retErr error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	if !validRestoreName(req.Name) || !validRestoreName(req.Snapshot) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid container/snapshot name: allowed [A-Za-z0-9_.-], not '.' or '..'")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "snapshot.restore", "operator", containerWhat(req.Name)); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward revert: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.RevertContainerSnapshot(s.ownerStrictOutgoing(ctx), req)
	}
	op := s.startContainerOp("snapshot revert", req.Name, "snapshot", req.Snapshot)
	defer func() { op.done(retErr) }()
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	snap, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot)
	if snap == nil {
		return nil, status.Errorf(codes.NotFound, "snapshot %q not found for container %q", req.Snapshot, req.Name)
	}

	if err := s.refuseForeignSnapshot(ctx, snap.Path, req.Snapshot, rec); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project+" foreign snapshot", "denied")
		return nil, err
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	makeSnapshotPrivate(s.dataDir, req.Name, snap.Path)
	f, err := os.Open(snap.Path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open snapshot data (%s): %v", snap.Path, err)
	}
	defer f.Close()

	// Revert replaces the rootfs, so the container must be stopped. Remember
	// whether it was running to bring it back up afterward.
	wasRunning := rec.State == "running"
	if wasRunning {
		if err := s.containerRuntime.StopContainer(ctx, req.Name, 30); err != nil {
			return nil, status.Errorf(codes.Internal, "stop for revert: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, host, req.Name, "stopped", "snapshot-revert"); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
	}
	if err := s.revertKeepingSecurity(ctx, rec, f); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "revert: %v", err)
	}
	s.reportDroppedAttrs(ctx, req.Name, "snapshot.revert")
	// The snapshot's config carries the privilege mode and range it was taken
	// with; the container keeps the ones it has now (the row's).
	if err := s.keepRecordedSecurity(ctx, rec); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project, "error")
		return nil, err
	}
	if wasRunning {
		if err := s.refuseOverlappingRange(ctx, req.Name); err != nil {
			s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project+" (restart refused: id range overlap)", "error")
			return nil, err
		}
		if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
			s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project+" (restart failed)", "error")
			return nil, status.Errorf(codes.Internal, "reverted but restart failed: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, host, req.Name, "running", ""); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
	}
	s.audit(ctx, "ct.snapshot.revert", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &emptypb.Empty{}, nil
}

// DeleteContainerSnapshot removes a snapshot's tar and tombstones its record.
func (s *Server) DeleteContainerSnapshot(ctx context.Context, req *pb.DeleteContainerSnapshotRequest) (_ *emptypb.Empty, retErr error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	if !validRestoreName(req.Name) || !validRestoreName(req.Snapshot) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid container/snapshot name: allowed [A-Za-z0-9_.-], not '.' or '..'")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "snapshot.delete", "operator", containerWhat(req.Name)); err != nil {
		s.audit(ctx, "ct.snapshot.delete", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, delRec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward delete: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.DeleteContainerSnapshot(s.ownerStrictOutgoing(ctx), req)
	}
	op := s.startContainerOp("snapshot delete", req.Name, "snapshot", req.Snapshot)
	defer func() { op.done(retErr) }()
	snap, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot)
	if snap != nil && snap.Path != "" {
		if err := s.refuseForeignSnapshot(ctx, snap.Path, req.Snapshot, delRec); err != nil {
			s.audit(ctx, "ct.snapshot.delete", req.Name, "project="+project+" foreign snapshot", "denied")
			return nil, err
		}
		if rmErr := os.Remove(snap.Path); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, status.Errorf(codes.Internal, "remove snapshot file: %v", rmErr)
		}
		_ = os.Remove(snapshotOwnerPath(snap.Path))
	}
	if err := corrosion.DeleteContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot); err != nil {
		return nil, status.Errorf(codes.Internal, "tombstone snapshot: %v", err)
	}
	// The last snapshot gone, its directory goes too. os.Remove only removes
	// an empty directory, so one still holding a snapshot is kept.
	if s.dataDir != "" {
		_ = os.Remove(filepath.Join(s.dataDir, containerSnapshotDir, req.Name))
	}
	s.audit(ctx, "ct.snapshot.delete", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &emptypb.Empty{}, nil
}

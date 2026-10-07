package grpcapi

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/nbd"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// RestoreLive spawns a localhost NBD server over a manifest's chunk
// reader and creates a qcow2 overlay backed by it. The server stays
// up until the client closes the stream, so an operator can boot a
// VM against target_path immediately and the NBD source vanishes only
// when the operator signals they're done (typically after a successful
// `virsh blockpull` migration).
//
// see service.proto for the rationale and the operator
// follow-up steps. With auto_start the handler also reconstructs the
// domain (from the manifest's embedded VMSpec or an operator-supplied
// one) and boots it against the overlay; without it the behavior is the
// original NBD + overlay only.
func (s *Server) RestoreLive(req *pb.RestoreLiveRequest, stream grpc.ServerStreamingServer[pb.RestoreLiveProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.RepoPath == "" || req.VmName == "" || req.DiskName == "" || req.Timestamp == "" {
		return status.Error(codes.InvalidArgument,
			"repo_path, vm_name, disk_name, timestamp all required")
	}
	// The overlay becomes a VM's disk. It is a fresh file the daemon names, or
	// one an admin names that does not exist yet — never a file already there
	// (restore_dest.go).
	disksDir := filepath.Join(s.dataDir, "disks")
	var target string
	if req.TargetPath != "" {
		var err error
		if target, err = s.resolveAdminTarget(ctx, req.TargetPath, disksDir); err != nil {
			return err
		}
	} else {
		name := req.NewName
		if name == "" {
			name = req.VmName
		}
		var err error
		if target, err = derivedDiskFile(disksDir, name, req.DiskName, "live", ".qcow2"); err != nil {
			return err
		}
	}
	// repo_path: registered repo name (any operator) or admin-only absolute path.
	repoPath, err := s.resolveBackupRepoPath(ctx, req.RepoPath)
	if err != nil {
		return err
	}

	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo: %v", err)
	}
	manifest, err := repo.GetManifest(req.VmName, req.Timestamp, req.DiskName)
	if err != nil {
		return status.Errorf(codes.NotFound, "manifest: %v", err)
	}
	// Authorize against the project the backup belongs to (its manifest spec,
	// authoritative; a name-reuse mismatch with a live row, or an undeterminable
	// project, requires admin) — never a _default fallback that would let a
	// default-scoped operator restore/read another project's backup by name.
	authProject, err := s.authorizeVMRestore(ctx, req.VmName, manifest)
	if err != nil {
		return err
	}

	reader, err := pbsstore.NewManifestReader(repo, manifest)
	if err != nil {
		return status.Errorf(codes.Internal, "manifest reader: %v", err)
	}
	defer reader.Close()

	exportName := fmt.Sprintf("%s-%s", req.VmName, req.DiskName)
	srv := &nbd.Server{ExportName: exportName, Dev: reader}

	bindAddr := req.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}
	addr, err := srv.Listen(bindAddr)
	if err != nil {
		return status.Errorf(codes.Internal, "nbd listen: %v", err)
	}
	nbdURL := fmt.Sprintf("nbd://%s/%s", addr.String(), exportName)

	// Spin the NBD server up on a separate goroutine so we can stream
	// progress without blocking. The server returns when ctx cancels
	// or Stop is called.
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(ctx)
	}()
	// Tear-down is deferred so a panic, a cancel, or a normal return
	// all release the listener.
	defer func() {
		srv.Stop()
		<-serveDone
	}()

	if err := stream.Send(&pb.RestoreLiveProgress{
		Phase:      pb.RestoreLiveProgress_STARTING_NBD,
		NbdUrl:     nbdURL,
		TargetPath: target,
		Status:     fmt.Sprintf("NBD server listening on %s (export=%s, size=%d bytes)", addr.String(), exportName, manifest.TotalSize),
	}); err != nil {
		return err
	}

	// Create the overlay BEFORE the domain is defined/started against it.
	// qcow2 publishes it exclusively: anything already at the target — a
	// file, a symlink, a disk a VM runs on — is refused, never replaced.
	if err := qcow2.CreateWithBackingURI(target, nbdURL, uint64(manifest.TotalSize), nil); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return existAsAlreadyExists(err)
		}
		return status.Errorf(codes.Internal, "create overlay qcow2: %v", err)
	}

	if err := stream.Send(&pb.RestoreLiveProgress{
		Phase:      pb.RestoreLiveProgress_READY,
		NbdUrl:     nbdURL,
		TargetPath: target,
		Status: fmt.Sprintf("qcow2 overlay at %s — point qemu/libvirt at it; "+
			"`virsh blockpull` will migrate data off the NBD source", target),
	}); err != nil {
		return err
	}

	// Auto-define-and-start (opt-in). Reconstruct the domain from the
	// resolved spec and boot it against the overlay so the operator
	// needn't run virsh by hand.
	if req.AutoStart {
		name, rootDev, err := s.autoDefineRestoredVM(ctx, req, repo, manifest, target, authProject, stream.Send)
		if err != nil {
			return err
		}
		if req.Blockpull {
			// Daemon drives the localize, then self-terminates so the
			// deferred Stop tears the NBD server down. A failed/partial
			// pull falls through to the operator-driven keep-open path
			// rather than bricking a half-pulled disk.
			if s.driveBlockpull(ctx, name, rootDev, stream.Send) {
				return nil
			}
		}
		// No blockpull (or it didn't complete): keep the NBD source up
		// until the operator localizes the disk and closes the stream.
		<-ctx.Done()
		_ = stream.Send(&pb.RestoreLiveProgress{
			Phase: pb.RestoreLiveProgress_DONE, VmName: name,
			Status: "operator closed the stream — NBD server stopping",
		})
		return nil
	}

	// Block until the operator closes the stream. ctx.Done() fires
	// when the client disconnects or hits its deadline; we then drop
	// out of the deferred Stop above and unwind cleanly.
	<-ctx.Done()
	_ = stream.Send(&pb.RestoreLiveProgress{
		Phase:  pb.RestoreLiveProgress_DONE,
		Status: "operator closed the stream — NBD server stopping",
	})
	return nil
}

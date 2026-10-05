package grpcapi

// The disk copy of a STOPPED VM's cold migration (coldMigrateStoppedVM).
//
// A running VM's host-local disks travel in libvirt's storage copy (QEMU's NBD
// mirror, --with-storage). A stopped VM has no QEMU to mirror from, so its
// disk files are streamed over the peer connection instead: the source reads
// each one and the target writes it at the disk's recorded path. The peer
// connection is the cluster's mTLS, so unlike the NBD mirror this copy is never
// plaintext.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// coldDiskChunk is the most file data one ReceiveMigrationDisk frame carries.
const coldDiskChunk = 1 << 20

// hostDiskFile is where the host-local disk file recorded at path lives on
// this host. It is path, except under the hostDiskRoot test seam.
func (s *Server) hostDiskFile(path string) string {
	if s.hostDiskRoot == "" {
		return path
	}
	return filepath.Join(s.hostDiskRoot, path)
}

// SetHostDiskRootForTest gives this server its own filesystem root for the
// host-local disk files a cold migration copies, removes or cleans up
// (hostDiskFile). The fleet runs every node in one process on one filesystem,
// where a disk's recorded path names the same file on both hosts; rooting each
// node apart is what lets a copy between them move bytes at all. Never set in
// production.
func (s *Server) SetHostDiskRootForTest(root string) { s.hostDiskRoot = root }

// coldDiskFrameDigest folds one data frame into the digest both ends of a disk
// copy compute: its offset, its length and its bytes, in stream order.
func coldDiskFrameDigest(h hash.Hash, offset int64, data []byte) {
	var hdr [16]byte
	binary.BigEndian.PutUint64(hdr[:8], uint64(offset))
	binary.BigEndian.PutUint64(hdr[8:], uint64(len(data)))
	h.Write(hdr[:])
	h.Write(data)
}

// copyColdDisksToTarget streams every host-local disk file of a stopped VM to
// targetHost and returns the disks it copied. A shared disk (nfs, ceph, a
// volume manager) is the same disk on the target already and is not copied.
//
// Each path is recorded in abort.createdStubs BEFORE its copy is sent, so a
// failure — a cancelled request included — has the cleanup ask the target for
// it. The target removes a file only if it recorded writing it for this VM, so
// naming one it never wrote removes nothing.
func (s *Server) copyColdDisksToTarget(ctx context.Context, targetHost, vmName string, disks []corrosion.DiskRecord, abort *migrationAbort, send func(pb.MigratePhase, float32, float32) error) ([]corrosion.DiskRecord, error) {
	var toCopy []corrosion.DiskRecord
	for _, d := range disks {
		if copiedByStorageMigration(d) {
			toCopy = append(toCopy, d)
		}
	}
	if len(toCopy) == 0 {
		return nil, nil
	}
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot reach %s to copy the disks of VM %q: %v", targetHost, vmName, err)
	}
	defer closeConn()
	for i, d := range toCopy {
		abort.createdStubs = append(abort.createdStubs, d.Path)
		if err := s.streamColdDisk(ctx, client, vmName, d); err != nil {
			code := status.Code(err)
			switch code {
			case codes.Unimplemented:
				return nil, status.Errorf(codes.FailedPrecondition,
					"%s cannot take the disks of a stopped VM (it is a build from before cold migration copied them); "+
						"upgrade it, or start VM %q and migrate it live with --with-storage", targetHost, vmName)
			case codes.Unknown:
				code = codes.Internal
			}
			return nil, status.Errorf(code, "copy disk %q of VM %q to %s: %s",
				d.DiskName, vmName, targetHost, status.Convert(err).Message())
		}
		_ = send(pb.MigratePhase_MIGRATE_COPYING, 0, float32(100*(i+1)/len(toCopy)))
	}
	return toCopy, nil
}

// streamColdDisk sends one disk file to the target's ReceiveMigrationDisk.
//
// A qcow2 overlay is flattened first, into a scratch file beside it: its
// backing file (the image it was created from, a linked clone's base) is not
// part of the copy, and the target may not hold it at the same path — or at
// all. The target then gets a standalone image of the same content, which is
// what libvirt's storage copy of a running VM leaves there too.
func (s *Server) streamColdDisk(ctx context.Context, client pb.LiteVirtClient, vmName string, d corrosion.DiskRecord) error {
	src := s.hostDiskFile(d.Path)
	fi, err := os.Lstat(src)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "disk file %s: %v", d.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return status.Errorf(codes.FailedPrecondition, "disk file %s is not a regular file", d.Path)
	}
	readPath := src
	if info, ierr := qcow2.Info(src); ierr == nil && info.BackingFile != "" {
		flat := filepath.Join(filepath.Dir(src), "."+filepath.Base(src)+".coldmig-"+uuid.NewString())
		defer os.Remove(flat)
		if err := qcow2.Convert(ctx, src, flat, &qcow2.Options{Uncompressed: true}); err != nil {
			return status.Errorf(codes.Internal, "flatten disk %s (backed by %s) for the copy: %v", d.Path, info.BackingFile, err)
		}
		readPath = flat
	}
	f, err := os.Open(readPath)
	if err != nil {
		return status.Errorf(codes.Internal, "open disk %s: %v", d.Path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return status.Errorf(codes.Internal, "stat disk %s: %v", d.Path, err)
	}
	size := st.Size()

	up, err := client.ReceiveMigrationDisk(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{VmName: vmName, Path: d.Path, SizeBytes: size}); err != nil {
		return coldDiskSendErr(up, err)
	}
	h := sha256.New()
	buf := make([]byte, coldDiskChunk)
	for off := int64(0); off < size; {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			// A range no frame covers reads as zeros on the target, so an
			// all-zero chunk is not sent.
			if !allZero(buf[:n]) {
				coldDiskFrameDigest(h, off, buf[:n])
				// Send serializes the frame before it returns, so buf can be reused.
				if err := up.Send(&pb.ReceiveMigrationDiskRequest{Offset: off, Data: buf[:n]}); err != nil {
					return coldDiskSendErr(up, err)
				}
			}
			off += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			if off != size {
				return status.Errorf(codes.Internal, "disk %s changed size during the copy (%d of %d bytes)", d.Path, off, size)
			}
			break
		}
		if rerr != nil {
			return status.Errorf(codes.Internal, "read disk %s: %v", d.Path, rerr)
		}
	}
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{Sha256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return coldDiskSendErr(up, err)
	}
	resp, err := up.CloseAndRecv()
	if err != nil {
		return err
	}
	if resp.GetSizeBytes() != size {
		return status.Errorf(codes.Internal, "target holds %d bytes of disk %s, want %d", resp.GetSizeBytes(), d.Path, size)
	}
	return nil
}

// coldDiskSendErr is the error to return for a failed Send: io.EOF means the
// target ended the stream, and its own error says why.
func coldDiskSendErr(up grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], err error) error {
	if errors.Is(err, io.EOF) {
		if _, rerr := up.CloseAndRecv(); rerr != nil {
			return rerr
		}
	}
	return err
}

// ReceiveMigrationDisk writes one host-local disk file of a stopped VM being
// cold-migrated to this host (see ReceiveMigrationDiskRequest).
//
// Peer-only, and vm.migrate on the VM. It writes only a disk of a VM that does
// not live here — its row names another host and no domain of that name is
// defined here — that is recorded stopped, at that disk's recorded path, inside
// a disk-artifact root. The path must hold no file, or one this host created
// for the same VM's migration (EnsureDisks' rule: a file found here may be the
// VM's disk from an earlier stay). The data goes to a scratch file first and
// takes the path only once the digest matches, and the file is recorded as this
// attempt's (migrationStubs), so a failed attempt's cleanup removes it and
// nothing else.
func (s *Server) ReceiveMigrationDisk(stream grpc.ClientStreamingServer[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse]) error {
	ctx := stream.Context()
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	hdr, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no header: %v", err)
	}
	if hdr.VmName == "" || hdr.Path == "" || hdr.SizeBytes < 0 {
		return status.Error(codes.InvalidArgument, "vm_name, path and a size are required")
	}
	if len(hdr.Data) != 0 || hdr.Offset != 0 || hdr.Sha256 != "" {
		return status.Error(codes.InvalidArgument, "the first frame carries only vm_name, path and size_bytes")
	}
	vm, err := s.authorizeMigrationHelper(ctx, hdr.VmName)
	if err != nil {
		return err
	}
	if vm.HostName == s.hostName || (s.virt != nil && s.virt.DomainExists(vm.Name)) {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q lives on %s; its disks are not overwritten by a migration to it", vm.Name, s.hostName)
	}
	if vm.State != "stopped" {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q is %s; only a stopped VM's disks are copied this way", vm.Name, vm.State)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read the disks of VM %q: %v", vm.Name, err)
	}
	known := false
	for _, d := range disks {
		if d.Path == hdr.Path && copiedByStorageMigration(d) {
			known = true
			break
		}
	}
	if !known {
		return status.Errorf(codes.InvalidArgument, "%s is not a host-local disk of VM %q", hdr.Path, vm.Name)
	}
	if !s.withinDiskArtifactRoot(hdr.Path) {
		return status.Errorf(codes.InvalidArgument, "disk path %q is not in a disk-artifact root", hdr.Path)
	}
	dst := s.hostDiskFile(hdr.Path)
	if _, err := os.Lstat(dst); err == nil {
		if !s.migrationStubs.owns(vm.Name, hdr.Path) {
			return status.Errorf(codes.FailedPrecondition,
				"disk %s of VM %q already exists on %s, and this migration did not create it. "+
					"It may be the VM's disk from an earlier stay on %s, and the copy would overwrite it. "+
					"Check whether it is still needed, move it aside or remove it on %s, then migrate again",
				hdr.Path, vm.Name, s.hostName, s.hostName, s.hostName)
		}
	} else if !os.IsNotExist(err) {
		return status.Errorf(codes.Internal, "stat %s: %v", hdr.Path, err)
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "create disk dir %s: %v", filepath.Dir(hdr.Path), err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".receiving-*")
	if err != nil {
		return status.Errorf(codes.Internal, "create scratch file for %s: %v", hdr.Path, err)
	}
	placed := false
	defer func() {
		if !placed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Truncate(hdr.SizeBytes); err != nil {
		return status.Errorf(codes.Internal, "size scratch file for %s: %v", hdr.Path, err)
	}

	h := sha256.New()
	var next int64
	var digest string
	for digest == "" {
		msg, err := stream.Recv()
		if err == io.EOF {
			return status.Errorf(codes.InvalidArgument, "the copy of %s ended without its digest", hdr.Path)
		}
		if err != nil {
			return err
		}
		if msg.Sha256 != "" {
			if len(msg.Data) != 0 {
				return status.Error(codes.InvalidArgument, "the digest frame carries no data")
			}
			digest = msg.Sha256
			continue
		}
		end := msg.Offset + int64(len(msg.Data))
		if msg.Offset < next || end > hdr.SizeBytes || len(msg.Data) == 0 {
			return status.Errorf(codes.InvalidArgument,
				"frame [%d,%d) of %s is out of order or outside its %d bytes", msg.Offset, end, hdr.Path, hdr.SizeBytes)
		}
		if _, err := tmp.WriteAt(msg.Data, msg.Offset); err != nil {
			return status.Errorf(codes.Internal, "write %s: %v", hdr.Path, err)
		}
		coldDiskFrameDigest(h, msg.Offset, msg.Data)
		next = end
	}
	if _, err := stream.Recv(); err != io.EOF {
		return status.Errorf(codes.InvalidArgument, "the copy of %s continued past its digest", hdr.Path)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digest {
		return status.Errorf(codes.DataLoss, "the copy of %s does not match the source (digest %s, want %s)", hdr.Path, got, digest)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return status.Errorf(codes.Internal, "chmod %s: %v", hdr.Path, err)
	}
	if err := tmp.Sync(); err != nil {
		return status.Errorf(codes.Internal, "sync %s: %v", hdr.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close %s: %v", hdr.Path, err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return status.Errorf(codes.Internal, "place %s: %v", hdr.Path, err)
	}
	placed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	s.migrationStubs.add(vm.Name, hdr.Path)
	slog.Info("cold migration: disk received", "vm", vm.Name, "path", hdr.Path, "bytes", hdr.SizeBytes)
	return stream.SendAndClose(&pb.ReceiveMigrationDiskResponse{SizeBytes: hdr.SizeBytes})
}

// removeColdMigratedSourceDisks removes this host's copy of each disk a cold
// migration copied to the target, once the handoff has committed and the
// target's copy is the VM's disk. A disk still referenced here — a linked
// clone's backing, another VM's disk — is left, as after a storage migration
// (finalizeMigrationOwnership). Best effort: a file that cannot be removed is
// a leftover, not a failed migration.
func (s *Server) removeColdMigratedSourceDisks(ctx context.Context, vmName string, copied []corrosion.DiskRecord) {
	for _, d := range copied {
		if referenced, reason, _ := s.pathStillReferenced(ctx, d.Path, vmName, d.DiskName); referenced {
			slog.Warn("cold migration: source disk still referenced — NOT deleting",
				"vm", vmName, "path", d.Path, "referenced_by", reason)
			continue
		}
		if err := os.Remove(s.hostDiskFile(d.Path)); err != nil && !os.IsNotExist(err) {
			slog.Warn("cold migration: could not remove the source copy of a migrated disk",
				"vm", vmName, "path", d.Path, "error", err)
			s.recordVMEvent(ctx, vmName, "vm.migrated", "warn",
				fmt.Sprintf("migrated, but the source copy of disk %s could not be removed: %v", d.Path, err))
			continue
		}
		slog.Info("cold migration: removed the source copy of a migrated disk", "vm", vmName, "path", d.Path)
	}
}

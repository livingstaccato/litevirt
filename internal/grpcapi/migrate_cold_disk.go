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
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

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
func (s *Server) copyColdDisksToTarget(ctx context.Context, targetHost, vmName string, disks []corrosion.DiskRecord, formats map[string]string, abort *migrationAbort, send func(pb.MigratePhase, float32, float32) error) ([]corrosion.DiskRecord, error) {
	var toCopy []corrosion.DiskRecord
	for _, d := range disks {
		if copiedByStorageMigration(d) {
			toCopy = append(toCopy, d)
		}
	}
	if len(toCopy) == 0 {
		return nil, nil
	}
	// The format of each disk is the domain's, never the file's: a raw disk
	// holds guest data, and a guest can write a qcow2 header into it that names
	// any host file as its backing.
	for _, d := range toCopy {
		if formats[d.Path] == "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disk %q of VM %q (%s) is not in its domain definition on %s, so its format is unknown; "+
					"repair the VM's disks before migrating it", d.DiskName, vmName, d.Path, s.hostName)
		}
	}
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot reach %s to copy the disks of VM %q: %v", targetHost, vmName, err)
	}
	defer closeConn()
	for i, d := range toCopy {
		abort.createdStubs = append(abort.createdStubs, d.Path)
		if err := s.streamColdDisk(ctx, client, vmName, d, formats[d.Path]); err != nil {
			code := status.Code(err)
			switch code {
			case codes.Unimplemented:
				return nil, targetTooOldForColdMigration(targetHost, vmName)
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
func (s *Server) streamColdDisk(ctx context.Context, client pb.LiteVirtClient, vmName string, d corrosion.DiskRecord, format string) error {
	src := s.hostDiskFile(d.Path)
	info, err := s.coldDiskSourceCheck(d, format)
	if err != nil {
		return err
	}
	readPath := src
	if info != nil {
		flat := filepath.Join(filepath.Dir(src), "."+filepath.Base(src)+coldMigScratch+uuid.NewString())
		defer os.Remove(flat)
		defer os.Remove(flat + ".tmp")
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
	allocated := size
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Blocks*512 < size {
		allocated = sys.Blocks * 512
	}

	up, err := client.ReceiveMigrationDisk(ctx)
	if err != nil {
		return err
	}
	// The caller (coldMigrateStoppedVM) confirmed the domain shut off before
	// the first disk, and holds the VM's lock until the handoff.
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{
		VmName: vmName, Path: d.Path, SizeBytes: size, AllocatedBytes: allocated,
		OwnerDomainShutOff: true,
	}); err != nil {
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

// coldDiskSourceCheck is everything this host checks about one disk before
// copying it: the file is a regular file, a qcow2 disk's image can be read,
// and an overlay's backing chain can be flattened — every image in it is a
// readable qcow2, and the flatten fits in the disk's directory with headroom.
// It returns the overlay's image info when the disk must be flattened for the
// copy, and nil when it is copied as it is. It writes nothing, so a drain runs
// it while the VM is still running (coldMovePreflight).
func (s *Server) coldDiskSourceCheck(d corrosion.DiskRecord, format string) (*qcow2.ImageInfo, error) {
	src := s.hostDiskFile(d.Path)
	fi, err := os.Lstat(src)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "disk file %s: %v", d.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, status.Errorf(codes.FailedPrecondition, "disk file %s is not a regular file", d.Path)
	}
	if format != "qcow2" {
		// Copied as it is, whatever its bytes look like (see copyColdDisksToTarget).
		return nil, nil
	}
	info, ierr := qcow2.Info(src)
	if ierr != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "disk %s is qcow2 in its domain definition, but its image cannot be read: %v", d.Path, ierr)
	}
	if info.BackingFile == "" {
		return nil, nil
	}
	// The flatten reads the chain with this package's qcow2 reader, which reads
	// only qcow2 images: a raw backing (a promoted replica's overlay) cannot be
	// flattened, and saying so here beats failing part-way through the copy.
	if err := flattenableChain(src); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"disk %s cannot be flattened for the copy: %v; move the VM to shared storage, or rebase the disk onto a qcow2 image or none, then migrate again", d.Path, err)
	}
	// The flatten writes a copy of the chain's allocated clusters beside
	// the disk (Convert's .tmp, renamed in place): refuse rather than fill
	// the filesystem the VM's neighbours' thin-provisioned disks live on.
	alloc, aerr := chainAllocated(src)
	if aerr != nil {
		return nil, status.Errorf(codes.Internal, "measure disk %s and its backing chain: %v", d.Path, aerr)
	}
	if err := s.requireDiskSpace(filepath.Dir(src), filepath.Dir(d.Path),
		"flattening disk "+d.Path+" for the copy", coldFlattenEstimate(alloc, info.VirtualSize)); err != nil {
		return nil, err
	}
	return info, nil
}

// flattenableChain reports why the backing chain under the qcow2 image at
// path cannot be read by qcow2.Convert, or nil when every image in it is a
// readable qcow2 file. Relative backing names resolve as chainAllocated does.
func flattenableChain(path string) error {
	for i := 0; i < 64; i++ {
		info, err := qcow2.Info(path)
		if err != nil {
			return fmt.Errorf("its backing image %s is not a qcow2 image (%v)", path, err)
		}
		if info.BackingFile == "" {
			return nil
		}
		next := info.BackingFile
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		path = next
	}
	return fmt.Errorf("its backing chain is longer than 64 images")
}

// checkColdDiskOnTarget asks targetHost whether it would take disk d of the
// VM (ReceiveMigrationDisk with check_only): the path, the record, a file
// already there and its free space, with nothing written. It sends what a copy
// would send: the file's size and allocation, or, for an overlay flattened for
// the copy (flatten non-nil), the flatten's estimate of the data it writes.
func (s *Server) checkColdDiskOnTarget(ctx context.Context, client pb.LiteVirtClient, vmName string, d corrosion.DiskRecord, flatten *qcow2.ImageInfo) error {
	src := s.hostDiskFile(d.Path)
	var size, allocated int64
	if flatten != nil {
		alloc, err := chainAllocated(src)
		if err != nil {
			return status.Errorf(codes.Internal, "measure disk %s and its backing chain: %v", d.Path, err)
		}
		size = int64(coldFlattenEstimate(alloc, flatten.VirtualSize))
		allocated = size
	} else {
		st, err := os.Stat(src)
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "disk file %s: %v", d.Path, err)
		}
		size, allocated = st.Size(), st.Size()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Blocks*512 < size {
			allocated = sys.Blocks * 512
		}
	}
	up, err := client.ReceiveMigrationDisk(ctx)
	if err != nil {
		return err
	}
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{
		VmName: vmName, Path: d.Path, SizeBytes: size, AllocatedBytes: allocated, CheckOnly: true,
	}); err != nil {
		return coldDiskSendErr(up, err)
	}
	_, err = up.CloseAndRecv()
	return err
}

// nearestExistingDir is dir, or its closest ancestor that exists.
func nearestExistingDir(dir string) string {
	for {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
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
// defined here — that is recorded stopped, or whose owner says in the header
// that its domain is shut off, at that disk's recorded path, inside a
// disk-artifact root. A check_only header runs these checks and free space,
// and writes nothing. The path must hold no file, or one this host created
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
	// The copy reads a disk no guest may be writing. A stopped row says so;
	// so does the owner, which checked its own domain, and whose word is the
	// fresher: this host's copy of the row lags the owner's stopped write (a
	// drain stops a running VM moments before its copy). Only the host the row
	// names as the owner can vouch for it — ownership does not change until the
	// copy is done — and a check-only call writes nothing, so it needs neither.
	ownerShutOff := hdr.OwnerDomainShutOff && callerMTLSCommonName(ctx) == vm.HostName
	if !hdr.CheckOnly && vm.State != "stopped" && !ownerShutOff {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q is %s; only a stopped VM's disks are copied this way", vm.Name, vm.State)
	}
	if !hdr.CheckOnly && vm.State != "stopped" {
		slog.Info("receive migration disk: this host's row lags; the owner says the domain is shut off",
			"vm", vm.Name, "row_state", vm.State, "owner", vm.HostName, "path", hdr.Path)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read the disks of VM %q: %v", vm.Name, err)
	}
	var rec *corrosion.DiskRecord
	for i, d := range disks {
		if d.Path == hdr.Path && copiedByStorageMigration(d) {
			rec = &disks[i]
			break
		}
	}
	if rec == nil {
		return status.Errorf(codes.InvalidArgument, "%s is not a host-local disk of VM %q", hdr.Path, vm.Name)
	}
	if rec.SizeBytes > 0 && hdr.SizeBytes > coldDiskSizeLimit(rec.SizeBytes) {
		return status.Errorf(codes.FailedPrecondition,
			"disk %s of VM %q is %d bytes on the source, more than its record of %d bytes allows (at most %d with image metadata); "+
				"make the disk and its record agree, then migrate again",
			hdr.Path, vm.Name, hdr.SizeBytes, rec.SizeBytes, coldDiskSizeLimit(rec.SizeBytes))
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
	// A check-only call writes nothing, not even the directory: its free space
	// is that of the nearest directory that exists, which is the filesystem
	// the copy's MkdirAll would create it on.
	spaceDir := dir
	if hdr.CheckOnly {
		spaceDir = nearestExistingDir(dir)
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "create disk dir %s: %v", filepath.Dir(hdr.Path), err)
	}
	// The data the copy writes, not the file's apparent size: the receive
	// writes only non-zero pages, so a sparse disk stays sparse. The figure is
	// the source's estimate, so the free space is checked again as the data
	// arrives (coldDiskRecheckEvery).
	need := hdr.SizeBytes
	if hdr.AllocatedBytes > 0 && hdr.AllocatedBytes < need {
		need = hdr.AllocatedBytes
	}
	if err := s.requireDiskSpace(spaceDir, filepath.Dir(hdr.Path), "receiving disk "+hdr.Path, uint64(need)); err != nil {
		return err
	}
	if hdr.CheckOnly {
		// Every check a copy would meet before writing has passed.
		return stream.SendAndClose(&pb.ReceiveMigrationDiskResponse{})
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+coldRecvScratch+"*")
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
	var next, sinceCheck int64
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
		n, err := writeNonZeroPages(tmp, msg.Data, msg.Offset)
		if err != nil {
			return status.Errorf(codes.Internal, "write %s: %v", hdr.Path, err)
		}
		if sinceCheck += n; sinceCheck >= coldDiskRecheckEvery {
			sinceCheck = 0
			if err := s.requireDiskSpace(dir, filepath.Dir(hdr.Path), "receiving disk "+hdr.Path, 0); err != nil {
				return err
			}
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
	// A stub this host made for the VM's migration is the one file the copy may
	// take the place of (checked above); anything else at the path — even one
	// that appeared since the check — makes the placement fail.
	if s.migrationStubs.owns(vm.Name, hdr.Path) {
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return status.Errorf(codes.Internal, "replace this host's stub %s: %v", hdr.Path, err)
		}
	}
	if err := placeColdDisk(tmp.Name(), dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return status.Errorf(codes.FailedPrecondition,
				"disk %s of VM %q appeared on %s during the copy, and this migration did not create it; it is left as it is",
				hdr.Path, vm.Name, s.hostName)
		}
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

// Scratch-file markers. A cold copy's scratch files are hidden (a leading dot)
// and carry one of these after the disk's name: coldRecvScratch on the target
// while a copy is received, coldMigScratch on the source while an overlay is
// flattened (qcow2.Convert adds ".tmp" to that). SweepColdMigrationScratch
// recognises them by the same markers.
const (
	coldRecvScratch = ".receiving-"
	coldMigScratch  = ".coldmig-"
)

// coldDiskSizeLimit is the most bytes a disk file recorded at recorded bytes
// may hold: its virtual size plus qcow2 metadata (L1/L2 and refcount tables,
// well under 1/32 of the image) and a fixed allowance for a small image.
func coldDiskSizeLimit(recorded int64) int64 { return recorded + recorded/32 + 64<<20 }

// coldDiskHeadroom is the free space a cold copy leaves on a filesystem:
// 5% of it, but at least 1 GiB and at most 64 GiB. The disks on a host's
// filesystem are thin-provisioned, and when it fills every guest writing to
// one pauses; past 64 GiB a percentage only refuses copies that fit.
func coldDiskHeadroom(total uint64) uint64 {
	const floor, ceiling = 1 << 30, 64 << 30
	return max(floor, min(total/20, ceiling))
}

// coldFlattenEstimate is what flattening a qcow2 chain with alloc allocated
// bytes and the given virtual size writes: the data (never more than the
// virtual size) plus the new image's tables.
func coldFlattenEstimate(alloc, virtual uint64) uint64 {
	data := min(alloc, virtual)
	return data + data/32 + 16<<20
}

// fileAllocated is the bytes a file occupies on disk.
func fileAllocated(p string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Blocks) * 512, nil
}

// chainAllocated is the allocated bytes of a qcow2 image and of every image
// in its backing chain: what qcow2.Convert can read clusters from.
func chainAllocated(path string) (uint64, error) {
	top := path
	var total uint64
	for i := 0; i < 64; i++ {
		a, err := fileAllocated(path)
		if err != nil {
			return 0, err
		}
		total += a
		info, err := qcow2.Info(path)
		if err != nil || info.BackingFile == "" {
			return total, nil // the end of the chain (a raw backing ends it too)
		}
		next := info.BackingFile
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		path = next
	}
	return 0, fmt.Errorf("backing chain of %s is longer than 64 images", top)
}

// writeNonZeroPages writes data at off into f, skipping every all-zero 4 KiB
// page, so a range of zeros inside a frame allocates nothing. It returns the
// bytes it wrote. The scratch file was truncated to size, so skipped pages read
// as zeros.
func writeNonZeroPages(f *os.File, data []byte, off int64) (int64, error) {
	const page = 4096
	var written int64
	for i := 0; i < len(data); {
		end := min(i+page, len(data))
		if allZero(data[i:end]) {
			i = end
			continue
		}
		j := end
		for j < len(data) {
			e := min(j+page, len(data))
			if allZero(data[j:e]) {
				break
			}
			j = e
		}
		if _, err := f.WriteAt(data[i:j], off+int64(i)); err != nil {
			return written, err
		}
		written += int64(j - i)
		i = j
	}
	return written, nil
}

// diskSpace reports the bytes available to the daemon, and the total, on the
// filesystem holding dir.
func (s *Server) diskSpace(dir string) (avail, total uint64, err error) {
	if s.diskSpaceOverride != nil {
		return s.diskSpaceOverride(dir)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

// requireDiskSpace refuses a write of need bytes into dir (shown as shownDir,
// the recorded path) that would leave less than coldDiskHeadroom free.
func (s *Server) requireDiskSpace(dir, shownDir, what string, need uint64) error {
	avail, total, err := s.diskSpace(dir)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s: cannot read the free space of %s on %s: %v", what, shownDir, s.hostName, err)
	}
	headroom := coldDiskHeadroom(total)
	if avail < need || avail-need < headroom {
		return status.Errorf(codes.FailedPrecondition,
			"%s needs %d MiB on %s, where %s has %d MiB free; a cold migration leaves at least %d MiB free there, "+
				"because the thin-provisioned disks on that filesystem pause their guests when it fills. "+
				"Free space in %s on %s, or move the disk to shared storage, then migrate again",
			what, need>>20, s.hostName, shownDir, avail>>20, headroom>>20, shownDir, s.hostName)
	}
	return nil
}

// placeColdDisk gives the received file at tmp the name dst, failing with an
// error satisfying errors.Is(err, os.ErrExist) if dst exists: a hard link, not
// a rename, so a file at dst is never replaced. The scratch name is removed.
//
// A filesystem that cannot hard-link (EPERM, EXDEV, ENOTSUP from link) gets a
// renameat2(RENAME_NOREPLACE), which never replaces dst either. One that can
// do neither is refused: there is no rename there that cannot replace a file.
//
// Once the link has given the copy its name, the copy is placed: if the
// scratch name then cannot be removed it is only logged — the startup sweep
// takes it — so a retry is not refused over a file that is the copy itself.
func placeColdDisk(tmp, dst string) error {
	err := coldLink(tmp, dst)
	if err == nil {
		if rerr := coldRemove(tmp); rerr != nil {
			slog.Warn("cold migration: placed the received disk but could not remove its scratch name",
				"scratch", tmp, "path", dst, "error", rerr)
		}
		return nil
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EXDEV) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	rerr := coldRenameNoReplace(tmp, dst)
	if rerr == nil || errors.Is(rerr, os.ErrExist) {
		return rerr
	}
	return fmt.Errorf("the filesystem holding %s supports neither hard links (%v) nor a rename that cannot replace a file (%v); "+
		"a received disk is never placed with a rename that could overwrite one", filepath.Dir(dst), err, rerr)
}

// coldDiskRecheckEvery is how many bytes a receive writes between re-checks
// of the target's free space.
var coldDiskRecheckEvery int64 = 256 << 20

// The filesystem calls placeColdDisk makes, as variables so a test can fail
// each one.
var (
	coldLink            = os.Link
	coldRemove          = os.Remove
	coldRenameNoReplace = renameNoReplace
)

// domainDiskFormats maps the source file of each file-backed disk in a domain
// definition to its driver type (qcow2, raw, ...).
func domainDiskFormats(domXML string) (map[string]string, error) {
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Driver struct {
				Type string `xml:"type,attr"`
			} `xml:"driver"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, d := range dom.Disks {
		if d.Source.File == "" || (d.Device != "" && d.Device != "disk") {
			continue
		}
		f := d.Driver.Type
		if f == "" {
			f = "raw" // libvirt's default, and the one that never reads a backing file
		}
		out[d.Source.File] = f
	}
	return out, nil
}

// isColdMigrationScratch reports whether a file name is a cold copy's scratch
// file (see coldRecvScratch, coldMigScratch).
func isColdMigrationScratch(name string) bool {
	return coldScratchName.MatchString(name)
}

// coldScratchName is the exact shape of the names the copy generates:
// os.CreateTemp's decimal suffix after coldRecvScratch, and a uuid after
// coldMigScratch with Convert's optional ".tmp". A file that only resembles
// one — an operator's upload, say — never matches.
var coldScratchName = regexp.MustCompile(`^\..+(` + regexp.QuoteMeta(coldRecvScratch) + `[0-9]+|` +
	regexp.QuoteMeta(coldMigScratch) + `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\.tmp)?)$`)

// SweepColdMigrationScratch removes the scratch files a cold migration left
// in this host's disk-artifact roots when the daemon stopped mid-copy: a
// partial receive, a partial flatten and its convert temp. Run once at
// startup, before this daemon serves, when no copy can be in flight. Only the
// host-local roots are swept — the disks dir and local/dir pools — never a
// shared (nfs) pool, where another host's copy may be running.
func (s *Server) SweepColdMigrationScratch() {
	roots := []string{filepath.Join(s.dataDir, "disks")}
	s.storagePoolsMu.RLock()
	pools := make(map[string]StoragePoolRef, len(s.storagePools))
	for n, pr := range s.storagePools {
		pools[n] = pr
	}
	s.storagePoolsMu.RUnlock()
	for n, pr := range pools {
		if !isHostLocalDiskDriver(strings.ToLower(pr.Driver)) && pr.Driver != "" {
			continue
		}
		if !s.poolUsableForWrite(context.Background(), n, pr) {
			continue
		}
		if dir, err := fileBasedPoolDir(s.dataDir, pr); err == nil {
			roots = append(roots, dir)
		}
	}
	seen := map[string]bool{}
	for _, root := range roots {
		root = s.hostDiskFile(root)
		if seen[root] {
			continue
		}
		seen[root] = true
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.Type().IsRegular() || !isColdMigrationScratch(e.Name()) {
				continue
			}
			p := filepath.Join(root, e.Name())
			if err := os.Remove(p); err != nil {
				slog.Warn("cold migration: could not remove a scratch file left by an interrupted copy", "path", p, "error", err)
				continue
			}
			slog.Info("cold migration: removed a scratch file left by an interrupted copy", "path", p)
		}
	}
}

// oldTargetBundleRequired is how a target built before stopped-VM cold
// migration refuses a domain definition sent without a firmware bundle: the
// first check of its EnsureFirmwareState, verbatim.
const oldTargetBundleRequired = "vm_name and a non-empty firmware bundle are required"

// targetTooOldForColdMigration is the refusal for a target whose build cannot
// take a stopped VM's cold migration — it lacks ReceiveMigrationDisk, or
// requires a firmware bundle to define a domain.
func targetTooOldForColdMigration(targetHost, vmName string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s is a build from before cold migration of stopped VMs and cannot take VM %q; nothing was changed. "+
			"To migrate it, upgrade %s, or start the VM and migrate it live (with --with-storage for a host-local disk)",
		targetHost, vmName, targetHost)
}

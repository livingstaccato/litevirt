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
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
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
	s.endMoveRecords(vmName)
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
		// The file is read here and removed after the commit: its recorded
		// path must be one of this host's own disk places (coldSourcePathCheck).
		if err := s.coldSourcePathCheck(d.Path); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disk %q of VM %q: %v; nothing was copied or changed", d.DiskName, vmName, err)
		}
	}
	for i, d := range toCopy {
		// One connection per disk: each disk's stream is the only RPC on its
		// connection. A renewal of either host's certificate mid-copy drains
		// the connections made with the replaced one — the stream in flight
		// finishes (pki.ConnTracker), but no new RPC starts on them — so the
		// next disk must not reuse one; a fresh dial presents and sees the
		// renewed certificates. Each dial goes to the migration network when
		// one is configured (dialColdPeer), as the whole copy did.
		client, closeConn, err := s.dialColdPeer(ctx, targetHost, vmName, abort.diskAddr)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach %s to copy the disks of VM %q: %v", targetHost, vmName, err)
		}
		abort.createdStubs = append(abort.createdStubs, d.Path)
		abort.copyStarted = true
		err = s.streamColdDisk(ctx, client, vmName, d, formats[d.Path])
		closeConn()
		if err != nil {
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
		if err := s.flattenColdDisk(ctx, d, src, flat); err != nil {
			return err
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

	// The copy is bounded by its progress, not by the request: a drain's
	// move runs detached from its client, and a target that is alive but
	// wedged (a hung write) takes no frame and never fails the stream. A copy
	// with no accepted frame (or no answer after the last) for the stall
	// bound is aborted, and the move rolls back as on any failed copy.
	// After the last frame the target verifies, syncs and places the disk
	// before it answers. It syncs as it writes (defaultColdDiskSyncEvery), so
	// that final sync is no larger than one it made mid-copy, and the same
	// bound covers it.
	stall := s.coldDiskStallBound()
	sctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	progressed := make(chan struct{}, 1)
	tick := func() {
		select {
		case progressed <- struct{}{}:
		default:
		}
	}
	go func() {
		t := time.NewTimer(stall)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-progressed:
				if !t.Stop() {
					<-t.C
				}
				t.Reset(stall)
			case <-t.C:
				cancel(errColdCopyStalled)
				return
			}
		}
	}()
	stalled := func(err error) error {
		if errors.Is(context.Cause(sctx), errColdCopyStalled) {
			return status.Errorf(codes.DeadlineExceeded, "the copy of disk %s to the target made no progress for %s, so it was aborted: %v",
				d.Path, stall, err)
		}
		return err
	}
	up, err := client.ReceiveMigrationDisk(sctx)
	if err != nil {
		return stalled(err)
	}
	// The caller (coldMigrateStoppedVM) confirmed the domain shut off before
	// the first disk, and holds the VM's lock until the handoff.
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{
		VmName: vmName, Path: d.Path, SizeBytes: size, AllocatedBytes: allocated,
		OwnerDomainShutOff: true,
	}); err != nil {
		return stalled(coldDiskSendErr(up, err))
	}
	tick()
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
					return stalled(coldDiskSendErr(up, err))
				}
				tick()
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
		return stalled(coldDiskSendErr(up, err))
	}
	tick()
	resp, err := up.CloseAndRecv()
	if err != nil {
		return stalled(err)
	}
	if resp.GetSizeBytes() != size {
		return status.Errorf(codes.Internal, "target holds %d bytes of disk %s, want %d", resp.GetSizeBytes(), d.Path, size)
	}
	return nil
}

// errColdCopyStalled is the cause of a cold disk copy cancelled for making no
// progress (streamColdDisk).
var errColdCopyStalled = errors.New("the cold disk copy made no progress")

// defaultColdDiskStall bounds how long a cold disk copy may go without the
// target taking a frame (or answering after the last) before it is aborted.
const defaultColdDiskStall = 5 * time.Minute

func (s *Server) coldDiskStallBound() time.Duration {
	if s.coldDiskStall > 0 {
		return s.coldDiskStall
	}
	return defaultColdDiskStall
}

// SetColdDiskStallForTest shortens the cold disk copy's stall bound.
func (s *Server) SetColdDiskStallForTest(d time.Duration) { s.coldDiskStall = d }

// defaultColdDiskSyncEvery is how many bytes a receive writes between syncs
// of the scratch file: the final sync then flushes at most this much, a slow
// target's storage shows in the sender's progress as it writes, and the
// stall bound that covers each sync mid-copy covers the final one too.
const defaultColdDiskSyncEvery = 64 << 20

// SetColdDiskSyncEveryForTest shortens the interval between a receive's syncs.
func (s *Server) SetColdDiskSyncEveryForTest(n int64) { s.coldDiskSyncEvery = n }

// SetColdDiskPlacedHookForTest runs fn after a received disk is placed,
// before its directory is synced. Tests only.
func (s *Server) SetColdDiskPlacedHookForTest(fn func()) { s.coldDiskPlacedHook = fn }

// SetColdDiskSyncHookForTest runs fn before each sync of a received disk
// (final: the one before it is placed). Tests only.
func (s *Server) SetColdDiskSyncHookForTest(fn func(final bool)) { s.coldDiskSyncHook = fn }

// syncReceivedDisk syncs a receive's scratch file (final: before placing it).
func (s *Server) syncReceivedDisk(f *os.File, final bool) error {
	if s.coldDiskSyncHook != nil {
		s.coldDiskSyncHook(final)
	}
	return f.Sync()
}

// flattenColdDisk writes a standalone copy of disk d's chain (its file src) to
// flat with this package's qcow2 reader: every backing judged by
// diskChainRule first, the reader confined to exactly the files that accepted,
// each read by the format the layer above declares (a raw backing as raw).
func (s *Server) flattenColdDisk(ctx context.Context, d corrosion.DiskRecord, src, flat string) error {
	accepted, err := precheckChain(src, s.diskChainRule(ctx, d))
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "disk %s cannot be flattened for the copy: %v", d.Path, err)
	}
	if err := qcow2.ConvertConfined(ctx, src, flat, &qcow2.Options{Uncompressed: true}, onlyAccepted(accepted)); err != nil {
		return status.Errorf(codes.Internal, "flatten disk %s for the copy: %v", d.Path, err)
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
	// The flatten reads the chain with this package's qcow2 reader, by each
	// layer's DECLARED backing format, every backing judged by diskChainRule.
	// A raw backing — a promoted replica, guest content — is read as raw and
	// accepted only as the backing_disk recorded on the layer naming it.
	if _, err := precheckChain(src, s.diskChainRule(context.Background(), d)); err != nil {
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
	// One question and its answer, bounded like a copy's progress: a target
	// that is alive but wedged would otherwise hold the move here forever.
	stall := s.coldDiskStallBound()
	cctx, cancel := context.WithTimeout(ctx, stall)
	defer cancel()
	unanswered := func(err error) error {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return status.Errorf(codes.DeadlineExceeded, "%s did not answer whether it would take disk %s within %s: %v",
				"the target", d.Path, stall, err)
		}
		return err
	}
	up, err := client.ReceiveMigrationDisk(cctx)
	if err != nil {
		return unanswered(err)
	}
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{
		VmName: vmName, Path: d.Path, SizeBytes: size, AllocatedBytes: allocated, CheckOnly: true,
	}); err != nil {
		return unanswered(coldDiskSendErr(up, err))
	}
	_, err = up.CloseAndRecv()
	return unanswered(err)
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
	vm, err := s.authorizeMigrationTarget(ctx, hdr.VmName)
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
	if !s.withinMigrationDiskRoot(ctx, hdr.Path, vm.HostName) {
		return status.Errorf(codes.InvalidArgument, "disk path %q is not in a disk-artifact root", hdr.Path)
	}
	dst := s.hostDiskFile(hdr.Path)
	// A path accepted only as the source's own pool directory is written
	// through its resolved parent, so a symlink below the pool directory is
	// never followed to somewhere the check did not judge.
	foreign := !s.withinDiskArtifactRoot(hdr.Path)
	if foreign {
		rd, rerr := resolveDeepest(filepath.Dir(dst))
		if rerr != nil {
			return status.Errorf(codes.Internal, "resolve the directory of %s: %v", hdr.Path, rerr)
		}
		dst = filepath.Join(rd, filepath.Base(dst))
	}
	if _, err := os.Lstat(dst); err == nil {
		if !s.madeHere(ctx, &s.migrationStubs, vm.Name, hdr.Path) {
			return status.Errorf(codes.FailedPrecondition,
				"disk %s of VM %q already exists on %s, and this migration did not create it. "+
					"It may be the VM's disk from an earlier stay on %s, or a copy a move that was rolled back placed "+
					"after it gave up, and the copy would overwrite it. "+
					"It may be the only copy of the VM's data from before a failover: do not delete it. %s, "+
					"then migrate again",
				hdr.Path, vm.Name, s.hostName, s.hostName, moveAsideAdvice(s.hostName, dst))
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
	} else if err := diskmode.MkdirAll(dir); err != nil {
		return status.Errorf(codes.Internal, "create disk dir %s: %v", filepath.Dir(hdr.Path), err)
	} else if foreign {
		// Made, and still where it was judged: nothing swapped a link in.
		if again, rerr := resolveDeepest(dir); rerr != nil || again != dir {
			return status.Errorf(codes.FailedPrecondition, "disk dir %s changed while it was made; nothing was written", filepath.Dir(hdr.Path))
		}
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
	var next, sinceCheck, sinceSync int64
	syncEvery := int64(defaultColdDiskSyncEvery)
	if s.coldDiskSyncEvery > 0 {
		syncEvery = s.coldDiskSyncEvery
	}
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
		if sinceSync += n; sinceSync >= syncEvery {
			sinceSync = 0
			if err := s.syncReceivedDisk(tmp, false); err != nil {
				return status.Errorf(codes.Internal, "sync %s: %v", hdr.Path, err)
			}
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
	// The copy is a new file: owner-only, whatever the source's mode was
	// (internal/diskmode).
	// Best effort: a filesystem that refuses chmod never fails the copy.
	diskmode.Restrict(tmp, diskmode.File)
	if err := s.syncReceivedDisk(tmp, true); err != nil {
		return status.Errorf(codes.Internal, "sync %s: %v", hdr.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close %s: %v", hdr.Path, err)
	}
	// A source that gave up on the copy (its stall bound, an abort) has
	// rolled the move back: the copy is not placed, and the scratch file goes.
	if err := stream.Context().Err(); err != nil {
		return status.Errorf(codes.Canceled, "the source gave up on the copy of %s before it was placed: %v", hdr.Path, err)
	}
	// The file this receive places: what a re-check below may take back, and
	// nothing else. It is held open until the receive returns (pinnedFile):
	// while the directory sync below stalls, the placed copy may be removed
	// and a retried receive place its own at the path, and only a held
	// file's inode cannot be given to that copy, which would then read as
	// this receive's own. After the retry commits it is the VM's only copy.
	// Pinned before the stub below is replaced, so a copy refused here
	// leaves the target as it was.
	ours, perr := pinFile(tmp.Name())
	if perr != nil {
		return status.Errorf(codes.Internal,
			"could not hold the copy of %s open to tell it apart from another file at its path (%v); it is not placed",
			hdr.Path, perr)
	}
	defer ours.release()
	// A stub this host made for the VM's migration is the one file the copy may
	// take the place of (checked above); anything else at the path — even one
	// that appeared since the check — makes the placement fail.
	if s.madeHere(ctx, &s.migrationStubs, vm.Name, hdr.Path) {
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return status.Errorf(codes.Internal, "replace this host's stub %s: %v", hdr.Path, err)
		}
		// The stub is gone, and the copy placed at its path is not this
		// host's stub until the source is known to be there (the add below):
		// nothing may reuse a file the take-back below may still unlink.
		s.migrationStubs.forget(hdr.Path)
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
	if s.coldDiskPlacedHook != nil {
		s.coldDiskPlacedHook()
	}
	syncDir := func() {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	syncDir()
	// A source that gave up while the disk was placed (the directory sync can
	// stall on storage that just wedged) has had no answer, so it rolled the
	// move back and keeps the VM's disk: the file this receive just placed is
	// taken back, and only that file (the same inode at the same path).
	if err := stream.Context().Err(); err != nil {
		if ours.stillAt(dst) {
			if rerr := os.Remove(dst); rerr != nil {
				slog.Warn("cold migration: could not take back a disk placed after the source gave up",
					"vm", vm.Name, "path", hdr.Path, "error", rerr)
			} else {
				ours.release()
				if s.cleanedUpHook != nil {
					s.cleanedUpHook()
				}
				syncDir()
			}
		}
		return status.Errorf(codes.Canceled, "the source gave up on the copy of %s as it was placed: %v", hdr.Path, err)
	}
	s.recordMade(ctx, &s.migrationStubs, vm.Name, hdr.Path)
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
		if err := s.coldSourcePathCheck(d.Path); err != nil {
			slog.Warn("cold migration: the source copy of a migrated disk is outside this host's disk places — NOT deleting",
				"vm", vmName, "path", d.Path, "error", err)
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

// moveAsideAdvice is the way out of a disk file at path on host that a copy
// would overwrite: the exact rename that sets it aside where
// `lv host superseded-disks` lists and keeps it. Nothing deletes it.
func moveAsideAdvice(host, path string) string {
	return fmt.Sprintf("Move it aside on %s with `mv %s %s` (`lv host superseded-disks %s` then lists and keeps it)",
		host, path, health.SupersededName(path, time.Now()), host)
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
// in its backing chain: what qcow2.Convert can read clusters from. Each
// layer's backing is followed by its DECLARED format: a raw backing ends the
// chain (it is never parsed), and an undeclared one ends it too (the flatten
// refuses it, precheckChain).
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
			return total, nil
		}
		next := info.BackingFile
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		switch info.BackingFormat {
		case "qcow2":
			path = next
		case "raw":
			ra, err := fileAllocated(next)
			if err != nil {
				return 0, err
			}
			return total + ra, nil
		default:
			return total, nil
		}
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
// A filesystem that cannot hard-link gets a renameat2(RENAME_NOREPLACE),
// which never replaces dst either. One that can do neither is refused: there
// is no rename there that cannot replace a file (noReplacePlace, link first).
//
// Once the link has given the copy its name, the copy is placed: if the
// scratch name then cannot be removed it is only logged — the startup sweep
// takes it — so a retry is not refused over a file that is the copy itself.
func placeColdDisk(tmp, dst string) error {
	unsupported, err := noReplacePlace(tmp, dst, true, "cold migration: placed the received disk but could not remove its scratch name")
	if unsupported {
		return fmt.Errorf("%v; a received disk is never placed with a rename that could overwrite one", err)
	}
	return err
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
//
// Each root is judged and listed under a bound (storage.Bounded): a local or
// dir pool whose directory is on an NFS mount (fstab) whose server does not
// answer would block its check or listing in the kernel, and this runs
// before the daemon serves gRPC. Such a root is skipped. Nothing is removed
// from it later: only a listing that finished here is acted on, and its
// scratch names are unique to the copy that made them, so a removal that
// completes late cannot reach a copy started after the daemon serves.
func (s *Server) SweepColdMigrationScratch() {
	type root struct {
		dir  string
		pool string // "" for <data_dir>/disks
		ref  StoragePoolRef
	}
	roots := []root{{dir: filepath.Join(s.dataDir, "disks")}}
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
		if dir, err := fileBasedPoolDir(s.dataDir, pr); err == nil {
			roots = append(roots, root{dir: dir, pool: n, ref: pr})
		}
	}
	readDir := coldScratchReadDir
	seen := map[string]bool{}
	for _, r := range roots {
		dir := s.hostDiskFile(r.dir)
		if seen[dir] {
			continue
		}
		scratch, err := storage.Bounded("list cold migration scratch in", dir, func() ([]string, error) {
			if r.pool != "" && !s.poolUsableForWrite(context.Background(), r.pool, r.ref) {
				return nil, errColdScratchPoolUnusable
			}
			ents, err := readDir(dir)
			if err != nil {
				return nil, nil
			}
			var out []string
			for _, e := range ents {
				if e.Type().IsRegular() && isColdMigrationScratch(e.Name()) {
					out = append(out, filepath.Join(dir, e.Name()))
				}
			}
			return out, nil
		})
		if errors.Is(err, errColdScratchPoolUnusable) {
			continue // another pool on the same directory may still sweep it
		}
		seen[dir] = true
		if err != nil {
			slog.Warn("cold migration: scratch files not swept from a directory that does not answer", "dir", dir, "error", err)
			continue
		}
		for _, p := range scratch {
			if _, err := storage.Bounded("remove", p, func() (struct{}, error) { return struct{}{}, os.Remove(p) }); err != nil {
				slog.Warn("cold migration: could not remove a scratch file left by an interrupted copy", "path", p, "error", err)
				continue
			}
			slog.Info("cold migration: removed a scratch file left by an interrupted copy", "path", p)
		}
	}
}

// coldScratchReadDir lists a root SweepColdMigrationScratch sweeps; tests
// replace it.
var coldScratchReadDir = os.ReadDir

// errColdScratchPoolUnusable: a pool SweepColdMigrationScratch does not sweep
// (its check refuses it).
var errColdScratchPoolUnusable = errors.New("pool refused by its check")

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

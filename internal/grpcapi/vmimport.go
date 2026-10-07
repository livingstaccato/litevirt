package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/uuid"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
	"github.com/litevirt/litevirt/internal/vmimport"
	"log/slog"
)

// ImportVM ingests a foreign VM (VMware OVA/OVF, Proxmox .conf or vzdump/.vma),
// converts its disks to qcow2, and defines it as a STOPPED VM (optionally
// started). The RPC is wire-level bidi: the client streams the source artifact
// (first frame carries metadata); the server streams unpack/convert/define
// progress. See internal/vmimport for the source adapters.
func (s *Server) ImportVM(stream pb.LiteVirt_ImportVMServer) error {
	ctx := stream.Context()

	// First frame carries metadata (+ possibly the first upload chunk).
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no import metadata received: %v", err)
	}

	// ── RBAC BEFORE anything else, including the forward ──
	//
	// The forward below hands the request to a peer, and the peer leg
	// authenticates as admin unless forwarded identity is BOTH configured and
	// latched (default-off for each). Authorizing after it would therefore let
	// an unauthorized caller reach the target host with the second leg's
	// privileges — including resolveStagedPath's admin-only arbitrary-path read.
	// Every other forwarding handler here (MigrateVM, MoveVolume,
	// CreateSnapshot) authorizes first; this one did not.
	//
	// The name is validated here too, because vmRBACPathFor is built from it and
	// an unvalidated name must not shape the path a permission is checked
	// against.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	name := first.Name
	if name == "" || !validRestoreName(name) {
		return status.Errorf(codes.InvalidArgument,
			"invalid vm name %q: allowed [A-Za-z0-9_.-], not '.' or '..'", name)
	}
	project := tenancy.NormalizeProject(first.Project)
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, name), "vm.create", "operator"); err != nil {
		return err
	}

	// Forward to the destination host without consuming more of the stream, so
	// bytes land directly on the host that will own the VM (a concurrent stream
	// proxy). The target re-runs the checks below for itself, but it sees this
	// node as an admin peer, not as the caller: so a forwarded import never
	// names a host path outside the staging root (resolveStagedPath).
	if first.TargetHost != "" && first.TargetHost != s.hostName {
		return s.proxyImportVM(ctx, stream, first)
	}

	if project != tenancy.Default {
		if p, perr := corrosion.GetProject(ctx, s.db, project); perr != nil || p == nil {
			return status.Errorf(codes.NotFound, "project %q not found", project)
		}
	}
	if existing, _ := corrosion.GetVM(ctx, s.db, name); existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"VM %q already exists (on host %s) — choose a different --name or remove it first", name, existing.HostName)
	}
	// ── Stage the source into a temp import dir (always cleaned up) ──
	if err := os.MkdirAll(filepath.Join(s.dataDir, "imports"), 0o755); err != nil {
		return status.Errorf(codes.Internal, "prepare import dir: %v", err)
	}
	importDir, err := os.MkdirTemp(filepath.Join(s.dataDir, "imports"), name+"-*")
	if err != nil {
		return status.Errorf(codes.Internal, "create import dir: %v", err)
	}
	// From the upload to the last converted disk the import writes, alongside
	// any other import on the host: each write reserves its bytes first, and
	// every other import's check on the same filesystem counts what this one
	// has reserved and not yet written. The reservation is released before
	// anything waits on the client, so a client that stops reading holds no
	// other import's room. (While the upload waits for its next chunk it
	// holds only what it has written and not yet flushed.)
	space := s.reserveImportSpace(importDir)
	defer space.release()
	defer os.RemoveAll(importDir)

	srcPath, err := s.stageImportSource(ctx, stream, first, importDir, space)
	if err != nil {
		return err
	}
	space.begin()

	// ── Parse via the source adapter → ForeignVM ──
	fv, err := s.parseImportSource(ctx, first.SourceFormat, srcPath, importDir, space.totals(importDir, "unpacking the source"))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "parse source: %v", err)
	}
	fv.Name = name
	// What the extraction reserved and left sparse it never writes.
	space.begin()

	// Resolve foreign networks → bridges + MAC policy (also surfaced by --inspect).
	if err := s.applyImportNetworks(fv, first); err != nil {
		return err
	}

	if first.Inspect {
		// Nothing unpacked is needed to describe the source; free it before
		// waiting on the client.
		space.release()
		_ = os.RemoveAll(importDir)
		return s.sendImportInspect(stream, fv, project)
	}

	// The row is written only at the end; until then the name is held here,
	// or two imports of one name would write the same files into the pool.
	// (An --inspect writes nothing there, and does not take it.)
	importID := randid.New()
	releaseName, err := s.claimImportNameAs(name, importID)
	if err != nil {
		return err
	}
	defer releaseName()
	// Each file the import writes into the pool is measured, and recorded as
	// its own, from before its first byte (importWritesFor). The records go
	// when the import ends, either way: by then its disks are a row's, or
	// removed. Only a crash leaves them, to show its leftovers dead.
	writes, forgetWrites := s.importWritesFor(importID, space)
	defer forgetWrites()

	// An import does not claim. importRecords builds the NIC rows straight from
	// the foreign hypervisor's NICs, so importing onto a NetBox-bound network
	// would bring in an address the external IPAM never issued to this cluster.
	// Run AFTER --inspect (which writes nothing and should still describe what
	// the source contains) and before the disk conversion, the quota admission
	// and the define, so a refusal leaves no converted disk and no reservation.
	names := make([]string, 0, len(fv.NICs))
	for _, n := range fv.NICs {
		names = append(names, n.Network)
	}
	if err := s.refuseIfBound(ctx, "import", names); err != nil {
		return err
	}
	// Project isolation: an import names its networks (through --net-map or
	// --network) the way a create does, so each takes create admission.
	for _, name := range names {
		if err := s.admitNetworkAttach(ctx, project, name); err != nil {
			return err
		}
	}

	// Resolve disk files (Proxmox .conf disks need --disk-map) + safety checks.
	if err := s.applyImportDiskMap(ctx, fv, first, importDir); err != nil {
		return err
	}

	// Charge what will be copied, not only what the descriptor declares.
	if err := bindImportDiskSizes(fv); err != nil {
		return err
	}
	// Quota estimate from declared sizes (re-checked post-convert with real sizes).
	if err := s.admitImport(ctx, project, fv); err != nil {
		return err
	}

	// Project isolation: the imported VM's project may land in a global pool or one
	// it owns. The import converts disks into first.TargetPool on this host.
	if err := s.admitPoolAttach(ctx, project, s.hostName, first.TargetPool); err != nil {
		return err
	}

	// ── Convert each data disk → qcow2 in the target pool ──
	poolDir, err := s.importPoolDir(ctx, first.TargetPool)
	if err != nil {
		return err
	}
	// Records of earlier daemons' imports into this pool that nothing is left
	// for go, off this import's path (a hung pool stalls only the prune).
	s.startImportPlacementPrune(poolDir)
	// A pool that can place a disk only by copying it holds it twice for a
	// moment: the second copy is reserved like the first, once the
	// conversion's own unwritten reservation is dropped.
	writes.copying = func(n uint64) error {
		space.begin()
		return space.reserve(poolDir, n, "copying a converted disk into place (the pool has neither link() nor RENAME_NOREPLACE)")
	}
	var convertedPaths []string
	cleanupDisks := func() {
		for _, p := range convertedPaths {
			_ = os.Remove(p)
		}
	}
	// Convert progress goes to the client from its own goroutine, and is
	// dropped while a send is still pending: the conversion never waits on the
	// client while it holds a reservation.
	progress := make(chan *pb.ImportVMProgress, 1)
	progressSent := make(chan struct{})
	go func() {
		defer close(progressSent)
		for p := range progress {
			_ = stream.Send(p)
		}
	}()
	stopProgress := sync.OnceFunc(func() { close(progress) })
	defer stopProgress()
	for i := range fv.Disks {
		d := &fv.Disks[i]
		if d.IsCDROM {
			continue
		}
		if !fileExists(d.LocalPath) {
			cleanupDisks()
			return status.Errorf(codes.FailedPrecondition,
				"disk %q (source %q) has no staged file — pass --disk-map %s=/path", d.Name, d.SourceID, d.SourceID)
		}
		dst := lv.DiskPath(poolDir, name, d.Name) // poolDir/<vm>-<disk>.qcow2 (poolDir already the disks dir)
		dst = filepath.Join(poolDir, name+"-"+d.Name+".qcow2")
		curDisk := d.Name
		// A file already at the name is never replaced. One that something
		// records is refused; an orphan (a crashed import's output) is moved
		// aside and kept.
		if err := s.clearImportDiskName(ctx, first.TargetPool, name, importID, d.Name, dst); err != nil {
			cleanupDisks()
			return status.Error(codes.FailedPrecondition, err.Error())
		}
		// What the import writes is reserved, not what the disk declares: a
		// disk from outside the import directory is first copied privately,
		// sparse, so it is charged the source's allocated blocks; the
		// conversion is charged what qemu-img measures it will write (a thin
		// 1 TiB disk holding 40 GiB writes about 40 GiB). Each is reserved on
		// its own filesystem, just before it is written; on a shared one the
		// two add up. The declared capacity stays the quota's bound only.
		diskName := d.Name
		writes.privateCopy = func(n uint64) error {
			return space.reserve(importDir, n, "a private copy of disk "+diskName)
		}
		writes.converting = func(n uint64) error {
			return space.reserve(poolDir, n, "converting disk "+diskName)
		}
		if err := convertForeignDisk(ctx, d.LocalPath, d.Format, dst, importDir, importSourceLimit(d.CapacityBytes), func(pct float32) {
			select {
			case progress <- &pb.ImportVMProgress{Phase: "convert", ConvertPct: pct, CurrentDisk: curDisk}:
			default:
			}
		}, writes); err != nil {
			cleanupDisks()
			if status.Code(err) == codes.AlreadyExists {
				return err
			}
			if errors.Is(err, os.ErrExist) {
				return status.Errorf(codes.FailedPrecondition,
					"disk %q: %s appeared in the pool during the conversion; an import never replaces a file there", d.Name, dst)
			}
			// A refused reservation (the copy a pool without link() needs)
			// keeps its code.
			var st interface{ GRPCStatus() *status.Status }
			if errors.As(err, &st) && st.GRPCStatus().Code() == codes.FailedPrecondition {
				return status.Errorf(codes.FailedPrecondition, "convert disk %q: %v", d.Name, err)
			}
			return status.Errorf(codes.Internal, "convert disk %q: %v", d.Name, err)
		}
		convertedPaths = append(convertedPaths, dst)
		// The disk is written and flushed; what it reserved and left sparse
		// it never writes.
		space.begin()
		d.LocalPath = dst
		// Authoritative size from the converted qcow2.
		if info, e := qcow2.Info(dst); e == nil && info.VirtualSize > 0 {
			if d.CapacityBytes != 0 && info.VirtualSize != d.CapacityBytes {
				fv.Warnf("disk %q declared %d bytes but converted image is %d bytes", d.Name, d.CapacityBytes, info.VirtualSize)
			}
			d.CapacityBytes = info.VirtualSize
		}
	}
	// The writes are done; drop what is left of the reservation, and free the
	// unpacked source, before anything here waits on this one's client again.
	space.release()
	_ = os.RemoveAll(importDir)

	// Re-check quota against the real converted sizes before committing.
	if err := s.admitImport(ctx, project, fv); err != nil {
		cleanupDisks()
		return err
	}

	// Reserve-then-verify admission across ALL FOUR quota dimensions, with
	// residency safety and the commit fence — the same contract every other path
	// that lands a VM carries. admitImport above stays as the cheap pre-convert
	// fail-fast, but a glance cannot see in-flight reservations, holds nothing
	// across the commit below, and never consulted host capacity or host safety
	// at all.
	//
	// Disk and NIC are reserved here rather than left to that glance. Leaving
	// them there made those two limits enforceable one request at a time: two
	// imports (or an import racing a create) each read a view without the
	// other's claim, each fit the remaining disk or NIC budget, and both
	// committed — over the limit, with neither request having done anything
	// wrong. The converted sizes are authoritative by this point, so the
	// reservation charges what the row will actually contribute.
	//
	// Quota is charged for stopped AND started imports alike — the row written
	// below counts toward project usage the moment it lands. HOST capacity and
	// residency safety apply only to --start: a stopped import is a durable
	// record, not runtime residency, and its host charge is StartVM's job.
	importIntent := intentResourceGrow
	if first.Start {
		importIntent = intentVMResident
	}
	// A create's absolute contribution IS its delta — the VM does not exist yet.
	importAmount := importQuotaAmount(fv)
	importQuotaLease, qerr := s.admitQuotaWithReservation(ctx, "ImportVM", s.hostName, project,
		corrosion.WorkloadVM, name, importAmount, importAmount, importIntent)
	if qerr != nil {
		cleanupDisks()
		return qerr
	}
	defer importQuotaLease.release(ctx)
	if first.Start {
		hostLease, herr := s.admitHostWithReservation(ctx, "ImportVM", s.hostName, project,
			"vm:"+name, fv.CPUs, fv.MemoryMiB, intentVMResident)
		if herr != nil {
			cleanupDisks()
			return herr
		}
		defer hostLease.release(ctx)
	}

	// ── Define → persist stopped → optional start, with full rollback ──
	cfg := fv.ToVMConfig()
	spec := fv.ToVMSpec(project)

	// An import DEFINES a brand-new domain, so it takes the node's cpu_mode
	// default like any other create. The foreign source carries no litevirt
	// cpu_mode, and leaving it empty would define the guest with no <cpu> element
	// — QEMU's qemu64, with no SSE4.2/AVX/AVX2. That is strictly further from the
	// hardware the guest was installed on than the host-derived default is.
	if spec.CpuMode == "" {
		spec.CpuMode = s.effectiveDefaultCPUMode()
	}
	cfg.CPUMode, cfg.CPUModel = spec.CpuMode, spec.CpuModel

	// Firmware (G1): a source that had Secure Boot / a vTPM is imported WITH them,
	// but under a FRESH identity — the source's TPM secret is NOT carried, so a
	// BitLocker guest will need its recovery key (the new TPM can't unseal the old
	// volume). applyFirmwareConfig resolves the host OVMF paths, mints the NVRAM
	// location, and preflights host capability (fails clearly on a non-capable host).
	fwImport := spec.SecureBoot || spec.Tpm
	if fwImport {
		spec.Uuid = uuid.NewString()
		if err := s.applyFirmwareConfig(&cfg, spec); err != nil {
			cleanupDisks()
			return err
		}
		cfg.UUID = spec.Uuid
		if spec.Tpm {
			fv.Warnf("imported with a FRESH vTPM — the source's TPM secret was not carried, so a BitLocker guest needs its recovery key (the new TPM cannot unseal the old volume)")
		}
	}

	domXML, err := lv.GenerateDomainXML(cfg)
	if err != nil {
		cleanupDisks()
		return status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	// Conditional orphan guard: never undefine a RUNNING same-name domain that
	// has no DB row — fail clearly instead (cf. vm.go orphan handling).
	if s.virt.DomainExists(name) {
		if st, _ := s.virt.DomainState(name); st == "running" {
			cleanupDisks()
			return status.Errorf(codes.FailedPrecondition,
				"a running libvirt domain %q already exists with no cluster record; resolve it before importing", name)
		}
		_ = s.virt.UndefineDomain(name, false)
	}
	if err := s.virt.DefineDomain(domXML); err != nil {
		cleanupDisks()
		if fwImport {
			lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
		}
		return status.Errorf(codes.Internal, "define domain: %v", err)
	}
	s.ensureSparePCIeRootPorts(name)

	// The define above resolved any machine alias against this host's qemu;
	// persist the concrete value so the imported VM's guest ABI travels with it.
	s.pinMachineFromDomain(spec)
	specJSON, _ := json.Marshal(spec)
	diskRecords, ifaceRecords, nicRecords := importRecords(fv, name, s.hostName)
	// pciIntents: the mapped spec's Devices, if the source format ever declares
	// any (none do today — ForeignVM carries no PCI passthrough — but this keeps
	// import on the same canonicalized-BDF path as every other producer with a
	// spec.Devices list, per the shared buildPCIIntents helper).
	pciIntents := s.buildPCIIntents(name, spec.Devices)

	// The quota-authority commit fence, immediately before the durable write.
	// Unwind mirrors the insert-failure rollback below: nothing was persisted.
	if err := importQuotaLease.allowCommit(ctx); err != nil {
		_ = s.virt.UndefineDomain(name, false)
		if fwImport {
			lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
		}
		cleanupDisks()
		return err
	}

	// adopt=false: best-effort-populate vm_nics/vm_pci_intent, but don't
	// self-certify adoption — the Phase-6 backfill audit confirms/reconciles
	// against the just-defined inactive domain.
	//
	// An import that will be started is inserted "creating", not "stopped":
	// assignOwnerEpochAtCreate publishes it running only once it holds a
	// positive epoch and a marker names it.
	insertState := "stopped"
	if first.Start {
		insertState = "creating"
	}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{
		Name:      name,
		HostName:  s.hostName,
		Spec:      string(specJSON),
		State:     insertState,
		CPUActual: fv.CPUs,
		MemActual: fv.MemoryMiB,
		Project:   project,
	}, ifaceRecords, diskRecords, nicRecords, pciIntents, false); err != nil {
		_ = s.virt.UndefineDomain(name, false)
		if fwImport {
			lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
		}
		cleanupDisks()
		return status.Errorf(codes.Internal, "record imported VM: %v", err)
	}

	stateMsg := "imported (stopped)"
	if first.Start {
		if err := s.virt.StartDomain(name); err != nil {
			// Roll back fully: remove DB row, undefine, delete disks. The
			// tombstone is best-effort inside a rollback that already fails the
			// RPC — but a decline must at least be visible, since it leaves a
			// live row for a VM whose disks the lines below delete.
			if derr := corrosion.DeleteVM(ctx, s.db, name); derr != nil {
				slog.Warn("import rollback: could not tombstone the just-created row — it stays live until a retry or delete",
					"vm", name, "error", derr)
			}
			_ = s.virt.UndefineDomain(name, false)
			if fwImport {
				lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
			}
			cleanupDisks()
			return status.Errorf(codes.Internal, "imported but failed to start: %v", err)
		}
		// Graduates, marks, and only then publishes running. A failure leaves the
		// row "creating" for the reconciler to finish, never running at epoch 0.
		s.assignOwnerEpochAtCreate(ctx, name, true)
		if vm, _ := corrosion.GetVM(ctx, s.db, name); vm != nil {
			s.reapplyVLANTaps(ctx, vm) // best-effort
		}
		stateMsg = "imported + started"
	} else {
		// A stopped import is graduated too, or it starts later at epoch 0.
		s.assignOwnerEpochAtCreate(ctx, name, false)
	}

	s.recordVMEvent(ctx, name, "vm.imported", "ok", fmt.Sprintf("format=%s disks=%d", first.SourceFormat, len(convertedPaths)))
	slog.Info("VM imported", "name", name, "host", s.hostName, "disks", len(convertedPaths), "started", first.Start, "warnings", len(fv.Warnings))

	// Every progress frame is out before the final one: one sender at a
	// time on the stream. The converted disks are charged to the project by
	// now, so a client that stops reading pins nothing uncharged.
	stopProgress()
	<-progressSent
	return stream.Send(&pb.ImportVMProgress{
		Phase:          "done",
		MappedSpecJson: string(specJSON),
		Warnings:       append(fv.Warnings, stateMsg),
	})
}

// proxyImportVM relays the import stream to the destination host. It is a
// concurrent proxy (client→peer chunks in one goroutine, peer→client progress in
// this one) so bytes never buffer locally first. The forwarded first frame keeps
// TargetHost set to the peer's name, so the peer treats it as a local import.
func (s *Server) proxyImportVM(ctx context.Context, stream pb.LiteVirt_ImportVMServer, first *pb.ImportVMRequest) error {
	client, conn, err := s.peerClient(ctx, first.TargetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", first.TargetHost, err)
	}
	defer conn.Close()

	up, err := client.ImportVM(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "open import on %s: %v", first.TargetHost, err)
	}
	if err := up.Send(first); err != nil {
		return err
	}

	relayErr := make(chan error, 1)
	go func() {
		for {
			req, rerr := stream.Recv()
			if rerr == io.EOF {
				relayErr <- up.CloseSend()
				return
			}
			if rerr != nil {
				relayErr <- rerr
				return
			}
			if serr := up.Send(req); serr != nil {
				relayErr <- serr
				return
			}
		}
	}()

	for {
		prog, rerr := up.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if serr := stream.Send(prog); serr != nil {
			return serr
		}
	}
	select {
	case e := <-relayErr:
		if e != nil && e != io.EOF {
			return e
		}
	default:
	}
	return nil
}

// stageImportSource lands the source artifact under importDir and returns its
// path. source_path (a file/dir already on THIS host) skips the upload; otherwise
// the streamed chunks are written to importDir/source.
//
// Each chunk is reserved before it is written, so an upload larger than the
// room left is refused as it arrives.
func (s *Server) stageImportSource(ctx context.Context, stream pb.LiteVirt_ImportVMServer, first *pb.ImportVMRequest, importDir string, space *importReservation) (string, error) {
	if first.SourcePath != "" {
		return s.resolveStagedPath(ctx, first.SourcePath)
	}

	path := filepath.Join(importDir, "source")
	f, err := os.Create(path)
	if err != nil {
		return "", status.Errorf(codes.Internal, "create upload file: %v", err)
	}
	defer f.Close()

	var total int64
	var reserved uint64
	write := func(chunk []byte) error {
		if len(chunk) == 0 {
			return nil
		}
		if total+int64(len(chunk)) > maxRestoreBytes {
			return status.Errorf(codes.ResourceExhausted, "import upload exceeded the %d-byte ceiling", maxRestoreBytes)
		}
		// Reserved a step at a time, so no more than a step is held
		// unwritten while the client sends the next chunk.
		for uint64(total)+uint64(len(chunk)) > reserved {
			if err := space.reserve(importDir, importUploadStep, "uploading the source"); err != nil {
				return err
			}
			reserved += importUploadStep
		}
		n, werr := f.Write(chunk)
		if werr != nil {
			return status.Errorf(codes.Internal, "write upload: %v", werr)
		}
		total += int64(n)
		if total > maxRestoreBytes {
			return status.Errorf(codes.ResourceExhausted, "import upload exceeded the %d-byte ceiling", maxRestoreBytes)
		}
		return nil
	}
	if err := write(first.Chunk); err != nil {
		return "", err
	}
	for {
		req, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
		if err := write(req.Chunk); err != nil {
			return "", err
		}
	}
	if total == 0 {
		return "", status.Error(codes.InvalidArgument, "no source data received (and no --server-path)")
	}
	if err := f.Sync(); err != nil {
		return "", status.Errorf(codes.Internal, "sync upload: %v", err)
	}
	return path, nil
}

// resolveStagedPath validates a destination-host path used for --server-path or
// --disk-map: it must resolve (symlinks included) under the import staging root,
// or the caller must be admin.
func (s *Server) resolveStagedPath(ctx context.Context, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", status.Errorf(codes.InvalidArgument, "staged path %q must be absolute", p)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "staged path %q: %v", p, err)
	}
	stagingRoot := filepath.Join(s.dataDir, "imports", "staging")
	if root, e := filepath.EvalSymlinks(stagingRoot); e == nil {
		stagingRoot = root
	}
	if !safename.Contains(stagingRoot, resolved) {
		// Outside the staging root → privileged. A request that reached this
		// host from a peer is a forwarded import (--target-host): the peer
		// authenticates as admin here whoever called the entry node, so a
		// forwarded import never names a host path. An admin connects to the
		// target host itself for that.
		if callerPrincipalKind(ctx) == principalKindPeer {
			return "", status.Errorf(codes.PermissionDenied,
				"path %q is outside the import staging root (%s); a forwarded import may not name a host path — "+
					"stage the file under %s, or run the import against %s directly as an admin", p, stagingRoot, stagingRoot, s.hostName)
		}
		// The storage host-path verb, as every host path in storage; the
		// admin role keeps it, as on main.
		if s.RequirePerm(ctx, "/", verbStorageHostPath, "admin") != nil && RequireRole(ctx, "admin") != nil {
			return "", status.Errorf(codes.PermissionDenied,
				"path %q is outside the import staging root (%s); reading an arbitrary host path needs %s at the cluster root (the Admin role on /)", p, stagingRoot, verbStorageHostPath)
		}
	}
	return resolved, nil
}

// parseImportSource dispatches to the right adapter. auto sniffs by content.
// An archive reserves what it unpacks into importDir through reserve.
func (s *Server) parseImportSource(ctx context.Context, format, srcPath, importDir string, reserve vmimport.Reserve) (*vmimport.ForeignVM, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		format = sniffImportFormat(srcPath)
	}
	switch format {
	case "ova", "ovf":
		// Directory (server-path OVF dir): find the .ovf inside.
		if fi, err := os.Stat(srcPath); err == nil && fi.IsDir() {
			ovf, e := findByExt(srcPath, ".ovf")
			if e != nil {
				return nil, e
			}
			return vmimport.ParseOVF(ovf)
		}
		// A bare .ovf file (server-path) → parse directly.
		if strings.EqualFold(filepath.Ext(srcPath), ".ovf") {
			return vmimport.ParseOVF(srcPath)
		}
		// Otherwise a tar (.ova or an OVF-dir tar) → unpack then parse.
		f, err := os.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		ovfPath, err := vmimport.UnpackOVA(f, importDir, reserve)
		if err != nil {
			return nil, err
		}
		return vmimport.ParseOVF(ovfPath)
	case "proxmox":
		// A .conf file (disks resolved via --disk-map), or a dir holding one.
		if fi, err := os.Stat(srcPath); err == nil && fi.IsDir() {
			conf, e := findByExt(srcPath, ".conf")
			if e != nil {
				return nil, e
			}
			return vmimport.ParseProxmoxConf(conf)
		}
		return vmimport.ParseProxmoxConf(srcPath)
	case "vma":
		f, err := os.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return vmimport.ParseVMA(ctx, f, importDir, reserve)
	default:
		return nil, fmt.Errorf("unrecognized source format (use --from ova|ovf|proxmox|vma)")
	}
}

// applyImportNetworks resolves each foreign network to a bridge (via --net-map,
// the "*" wildcard from --network, or the name as-is) and applies the MAC policy.
// Two NICs on the same resolved bridge collide on vm_interfaces (vm_name,
// network_name) — rejected here (v1 limitation).
func (s *Server) applyImportNetworks(fv *vmimport.ForeignVM, meta *pb.ImportVMRequest) error {
	seen := map[string]bool{}
	for i := range fv.NICs {
		n := &fv.NICs[i]
		bridge := meta.NetMap[n.Network]
		if bridge == "" {
			bridge = meta.NetMap["*"]
		}
		if bridge == "" {
			bridge = n.Network
			fv.Warnf("network %q not mapped (--net-map); attaching to a bridge named %q", n.Network, n.Network)
		}
		if bridge == "" {
			return status.Errorf(codes.InvalidArgument, "NIC %d has no network; pass --network <bridge> or --net-map", i)
		}
		if seen[bridge] {
			return status.Errorf(codes.InvalidArgument,
				"two NICs map to the same network/bridge %q — litevirt v1 allows one NIC per network per VM; use distinct bridges or --net-map", bridge)
		}
		seen[bridge] = true
		n.Network = bridge
		if !meta.PreserveMac || n.MAC == "" {
			n.MAC = lv.GenerateMAC()
		}
	}
	return nil
}

// applyImportDiskMap resolves disks that have no staged file yet (Proxmox .conf
// references a storage volume) via --disk-map, with the same path safety as
// --server-path.
//
// A disk the source adapter unpacked into importDir needs no map. Any other
// existing file is a path the source named — a Proxmox .conf keeps its volume
// reference verbatim, so it can name any file on this host — and it takes the
// same staging check as --disk-map; otherwise an operator could have a host
// file converted into their VM's disk and read it from the guest.
func (s *Server) applyImportDiskMap(ctx context.Context, fv *vmimport.ForeignVM, meta *pb.ImportVMRequest, importDir string) error {
	for i := range fv.Disks {
		d := &fv.Disks[i]
		if d.IsCDROM {
			continue
		}
		mapped := meta.DiskMap[d.SourceID]
		if mapped == "" && fileExists(d.LocalPath) {
			if inImportDir(importDir, d.LocalPath) {
				continue
			}
			mapped = d.LocalPath
		}
		if mapped == "" {
			return status.Errorf(codes.FailedPrecondition,
				"disk %q (source %q, ref %q) is not a local file — pass --disk-map %s=/staged/path", d.Name, d.SourceID, d.LocalPath, d.SourceID)
		}
		resolved, err := s.resolveStagedPath(ctx, mapped)
		if err != nil {
			return err
		}
		d.LocalPath = resolved
	}
	return nil
}

// inImportDir reports whether p, with symlinks resolved, lies inside importDir.
func inImportDir(importDir, p string) bool {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	root, err := filepath.EvalSymlinks(importDir)
	if err != nil {
		return false
	}
	return safename.Contains(root, resolved)
}

// importQuotaAmount is what an import will charge the project, in every
// dimension the quota bounds. One derivation feeds BOTH the cheap pre-convert
// fail-fast and the serialized reservation, so the two can never disagree about
// what the import costs. Disk goes through corrosion.DiskQuotaGiB, the same rule
// committed usage and the settle contribution use, so the charge is a number the
// accounting can actually observe as paid.
func importQuotaAmount(fv *vmimport.ForeignVM) corrosion.QuotaAmount {
	diskGiB := 0
	for _, d := range fv.Disks {
		if d.IsCDROM {
			continue
		}
		// A parsed foreign descriptor is untrusted input; clamp rather than let
		// an absurd declared size wrap negative and charge nothing.
		size := d.CapacityBytes
		if size > math.MaxInt64 {
			size = math.MaxInt64
		}
		diskGiB += corrosion.DiskQuotaGiB(int64(size))
	}
	return corrosion.QuotaAmount{VCPU: fv.CPUs, MemMiB: fv.MemoryMiB, DiskGiB: diskGiB, NIC: len(fv.NICs)}
}

func (s *Server) admitImport(ctx context.Context, project string, fv *vmimport.ForeignVM) error {
	amt := importQuotaAmount(fv)
	qreq := tenancy.QuotaRequest{VCPU: amt.VCPU, MemMiB: amt.MemMiB, DiskGiB: amt.DiskGiB, NIC: amt.NIC}
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, project, qreq); err != nil {
			return status.Errorf(codes.ResourceExhausted, "%v", err)
		}
		return nil
	}
	if err := corrosion.CheckProjectQuota(ctx, s.db, project, corrosion.QuotaCheck{
		VCPU: qreq.VCPU, MemMiB: qreq.MemMiB, DiskGiB: qreq.DiskGiB, NIC: qreq.NIC,
	}); err != nil {
		return status.Errorf(codes.ResourceExhausted, "%v", err)
	}
	return nil
}

// importPoolDir resolves the target pool to a file-based directory. Empty pool =
// local {dataDir}/disks. Block-backed pools (ceph/iscsi/lvm-thin/zfs) are
// rejected for import in v1 — the converted artifact is a qcow2 file.
func (s *Server) importPoolDir(ctx context.Context, pool string) (string, error) {
	if pool == "" {
		dir := filepath.Join(s.dataDir, "disks")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", status.Errorf(codes.Internal, "prepare disks dir: %v", err)
		}
		return dir, nil
	}
	ref, ok := s.resolvePool(ctx, pool)
	if !ok {
		return "", status.Errorf(codes.NotFound, "storage pool %q not found", pool)
	}
	if !isFileBasedDriver(ref.Driver) {
		return "", status.Errorf(codes.FailedPrecondition,
			"pool %q (driver %q) is not file-backed; VM import targets file pools (local/dir/nfs/btrfs) only", pool, ref.Driver)
	}
	// The same write check as every other write into a pool, and an NFS
	// export mounted (hardened) first — never a bare mount point.
	dir, err := s.poolDirForWrite(ctx, pool, ref)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", status.Errorf(codes.Internal, "prepare pool dir: %v", err)
	}
	return dir, nil
}

func (s *Server) sendImportInspect(stream pb.LiteVirt_ImportVMServer, fv *vmimport.ForeignVM, project string) error {
	spec := fv.ToVMSpec(project)
	j, _ := json.Marshal(spec)
	return stream.Send(&pb.ImportVMProgress{
		Phase:          "done",
		MappedSpecJson: string(j),
		Warnings:       fv.Warnings,
	})
}

// importRecords builds the disk/interface/NIC rows ImportVM persists via
// corrosion.InsertVMWithHardware. A vm_nics row is built alongside each legacy
// vm_interfaces row (v42 dual-write, mirroring CreateVM/task 7.1), carrying
// the foreign NIC's tracked model (ForeignVM.Normalize defaults an unset one
// to "virtio" before this runs) and the deterministic (vmName, mac) id so it
// converges with what the Phase-6 backfill audit would derive for the same
// legacy NIC. TapDevice stays empty — tap assignment is a start-time fact, not
// an import-time one.
func importRecords(fv *vmimport.ForeignVM, name, host string) ([]corrosion.DiskRecord, []corrosion.InterfaceRecord, []corrosion.NICRecord) {
	var disks []corrosion.DiskRecord
	di := 0
	for _, d := range fv.Disks {
		if d.IsCDROM {
			continue
		}
		disks = append(disks, corrosion.DiskRecord{
			VMName:      name,
			DiskName:    d.Name,
			HostName:    host,
			Path:        d.LocalPath,
			SizeBytes:   int64(d.CapacityBytes),
			StorageType: "local",
			TargetDev:   lv.DiskDevName(d.Bus, di),
			Bus:         d.Bus,
		})
		di++
	}
	var ifaces []corrosion.InterfaceRecord
	var nics []corrosion.NICRecord
	for i, n := range fv.NICs {
		ifaces = append(ifaces, corrosion.InterfaceRecord{
			VMName:      name,
			NetworkName: n.Network,
			Ordinal:     i,
			MAC:         n.MAC,
		})
		nics = append(nics, corrosion.NICRecord{
			VMName:      name,
			ID:          corrosion.DeterministicNICID(name, n.MAC),
			NetworkName: n.Network,
			Model:       n.Model,
			MAC:         n.MAC,
			Ordinal:     i,
			TapDevice:   "",
		})
	}
	return disks, ifaces, nics
}

// ── disk conversion ──

// importDiskWrites is told of the files a disk conversion writes in the pool,
// so its import can measure them and record them as its own. Every field is
// optional, and a nil *importDiskWrites is told nothing.
type importDiskWrites struct {
	// created is a file the import just created in the pool — a conversion's
	// scratch file, or a copy on its way to its name — before its first byte.
	created func(p string)
	// placing is the finished, flushed file fi describes about to take
	// dst's name.
	placing func(dst string, fi os.FileInfo)
	// placed is tmp's disk now placed at dst: dst is the import's file.
	placed func(tmp, dst string)
	// copying is a placement that has to copy n bytes (a pool with neither
	// link() nor RENAME_NOREPLACE): an error refuses it.
	copying func(n uint64) error
	// privateCopy reserves n bytes in the import directory for the private
	// copy of a disk from outside it (the source's allocated blocks), before
	// the copy begins: an error refuses it.
	privateCopy func(n uint64) error
	// converting reserves n bytes in the pool for the conversion (what
	// qemu-img measure says it writes), before it begins: an error refuses
	// it.
	converting func(n uint64) error
	// discarded is a file it created that is gone, or no longer its own.
	discarded func(p string)
}

func (w *importDiskWrites) reservePrivateCopy(n uint64) error {
	if w != nil && w.privateCopy != nil {
		return w.privateCopy(n)
	}
	return nil
}

func (w *importDiskWrites) reserveConversion(n uint64) error {
	if w != nil && w.converting != nil {
		return w.converting(n)
	}
	return nil
}

func (w *importDiskWrites) didCreate(p string) {
	if w != nil && w.created != nil {
		w.created(p)
	}
}

func (w *importDiskWrites) willPlace(dst string, fi os.FileInfo) {
	if w != nil && w.placing != nil {
		w.placing(dst, fi)
	}
}

func (w *importDiskWrites) didPlace(tmp, dst string) {
	if w != nil && w.placed != nil {
		w.placed(tmp, dst)
	}
}

func (w *importDiskWrites) copy(n uint64) error {
	if w != nil && w.copying != nil {
		return w.copying(n)
	}
	return nil
}

func (w *importDiskWrites) discard(p string) {
	if w != nil && w.discarded != nil {
		w.discarded(p)
	}
}

// importWritesFor is what the import importID does with each file it writes
// into a pool: measures it in space, sets its origin xattr where the pool
// keeps one, and records it in this host's placement record (see
// vmimport_placement.go). A scratch file or a copy on its way to its name is
// recorded when it is created; a placed disk is recorded before it takes its
// name, in the state it is placed in, so a crash at any point leaves no
// unrecorded file of the import, and again once placed, its change time
// bound too. forget drops every record the import wrote. The caller sets
// copying.
func (s *Server) importWritesFor(importID string, space *importReservation) (w *importDiskWrites, forget func()) {
	origin := s.importOriginFor(importID)
	var recorded []string
	record := func(p string, fi os.FileInfo, scratch, withCtime bool) {
		if err := s.recordImportPlacementBound(p, fi, importID, scratch, withCtime); err != nil {
			slog.Warn("import: could not record a file it writes; a leftover of it is judged by age", "path", p, "error", err)
			return
		}
		recorded = append(recorded, p)
	}
	w = &importDiskWrites{
		created: func(p string) {
			space.track(p)
			_ = setImportOrigin(p, origin)
			if fi, err := os.Lstat(p); err == nil {
				record(p, fi, true, false)
			}
		},
		placing: func(dst string, fi os.FileInfo) { record(dst, fi, false, false) },
		placed: func(tmp, dst string) {
			space.track(dst)
			s.forgetImportPlacement(tmp, importID)
			if fi, err := os.Lstat(dst); err == nil {
				record(dst, fi, false, true)
			}
		},
		discarded: func(p string) { s.forgetImportPlacement(p, importID) },
	}
	return w, func() {
		for _, p := range recorded {
			s.forgetImportPlacement(p, importID)
		}
	}
}

// convertForeignDisk converts a foreign-format disk to qcow2 at dst using
// qemu-img. It HARD-FAILS if qemu-img is absent (the byte-copy fallback used
// elsewhere would dump foreign bytes into a qcow2-named file and corrupt it) and
// rejects any external backing-file / out-of-dir extent reference BEFORE invoking
// qemu-img (a malicious descriptor would otherwise make qemu-img read host files).
//
// w, when set, is told of each file the conversion writes in dst's directory
// (see importDiskWrites).
func convertForeignDisk(ctx context.Context, src, srcFormat, dst, allowedDir string, maxSrcBytes int64, emit func(pct float32), w *importDiskWrites) error {
	if !qemuImgAvailable() {
		return fmt.Errorf("qemu-img not found on PATH (required to import/convert foreign disks)")
	}
	// Only a file nobody else can write is checked and converted; otherwise
	// what was checked need not be what qemu-img opens.
	// A new file only. Without a pool the destination is <data_dir>/disks,
	// which holds every project's pool-less disks, and "<vm>-<disk>.qcow2" can
	// be another VM's disk (VM "a" disk "b-root" against VM "a-b" disk
	// "root"): an existing file is refused, never replaced.
	if err := refuseExistingFile(dst); err != nil {
		return err
	}
	private, err := privateImportDisk(ctx, src, allowedDir, maxSrcBytes, w.reservePrivateCopy)
	if err != nil {
		return err
	}
	if private != src {
		defer os.Remove(private)
	}
	src = private
	// One format for the check and the conversion: a disk judged as one
	// format but converted as another can name files the check never saw.
	if srcFormat == "" {
		if srcFormat, err = staticDiskFormat(src); err != nil {
			return err
		}
	}
	if err := assertNoExternalDiskRefsAs(ctx, src, srcFormat, allowedDir); err != nil {
		return err
	}
	// The conversion writes up to the image's virtual size, which a
	// compressed image can make far larger than its file.
	vs, err := qemuVirtualSize(ctx, src, srcFormat)
	if err != nil {
		return err
	}
	if vs > uint64(maxSrcBytes) {
		return fmt.Errorf("disk's virtual size is %d bytes, more than the %d bytes the import was admitted for", vs, maxSrcBytes)
	}
	// Reserve what the conversion will write, judged on the checked private
	// copy in the format it is converted from.
	if err := w.reserveConversion(importConvertNeed(ctx, src, srcFormat, vs)); err != nil {
		return err
	}

	// A fresh name of its own, never a fixed "<dst>.tmp" another writer to
	// the pool directory could plant first.
	tf, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".convert-*")
	if err != nil {
		return fmt.Errorf("create conversion target: %w", err)
	}
	tmp := tf.Name()
	tf.Close()
	w.didCreate(tmp)
	finished := false
	defer func() {
		if !finished {
			_ = os.Remove(tmp)
		}
	}()
	args := []string{"convert", "-p", "-O", "qcow2", "-f", srcFormat, src, tmp}

	cmd := exec.CommandContext(ctx, "qemu-img", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 256)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 && emit != nil {
			if pct := parseQemuImgProgress(string(buf[:n])); pct >= 0 {
				emit(pct)
			}
		}
		if rerr != nil {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("qemu-img convert: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Defense-in-depth: the produced qcow2 must be standalone.
	if err := assertNoExternalDiskRefsAs(ctx, tmp, "qcow2", allowedDir); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Flushed before it is placed: the import's reservation stops counting
	// it once it has its name, so its bytes must be gone from the free space
	// by then.
	if err := syncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("flush converted disk: %w", err)
	}
	if fi, err := os.Lstat(tmp); err == nil {
		w.willPlace(dst, fi)
	}
	// Never over a file already there: another VM's disk keeps its bytes.
	if err := placeNoReplace(ctx, tmp, dst, w); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize converted disk: %w", err)
	}
	finished = true
	// The disk is the import's own file under its new name, and stays
	// measured as such.
	w.didPlace(tmp, dst)
	return nil
}

type qemuImgInfo struct {
	Filename              string `json:"filename"`
	VirtualSize           uint64 `json:"virtual-size"`
	Format                string `json:"format"`
	BackingFilenameFormat string `json:"backing-filename-format"`
	BackingFilename       string `json:"backing-filename"`
	FullBackingFilename   string `json:"full-backing-filename"`
	FormatSpecific        struct {
		Data struct {
			DataFile string `json:"data-file"`
			Extents  []struct {
				Filename string `json:"filename"`
			} `json:"extents"`
		} `json:"data"`
	} `json:"format-specific"`
	Children []struct {
		Name string      `json:"name"`
		Info qemuImgInfo `json:"info"`
	} `json:"children"`
}

// openedFiles is every file qemu-img reported opening for this image: the
// image, its children (extents, data file, the protocol layer) and the
// format-specific extent list. Judging these, rather than parsing VMDK text,
// covers every way a format can name another file.
func (i *qemuImgInfo) openedFiles() []string {
	var out []string
	if i.Filename != "" {
		out = append(out, i.Filename)
	}
	for _, e := range i.FormatSpecific.Data.Extents {
		if e.Filename != "" {
			out = append(out, e.Filename)
		}
	}
	for c := range i.Children {
		out = append(out, i.Children[c].Info.openedFiles()...)
	}
	return out
}

// assertNoExternalDiskRefs rejects a disk that would make qemu-img open a file
// outside allowedDir: a VMDK extent, a backing file anywhere in the chain, or
// a qcow2 external data file (a host-file-read escape via a crafted header).
// A backing name that is not a plain path (json:{...}, nbd:, a URL) is refused
// outright: joined to a directory it would look contained while naming
// anything. The chain is walked one image at a time, and nothing outside
// allowedDir is ever opened.
func assertNoExternalDiskRefs(ctx context.Context, file, allowedDir string) error {
	return assertNoExternalDiskRefsAs(ctx, file, "", allowedDir)
}

// assertNoExternalDiskRefsAs judges file opened as format — the format qemu
// will be told, not the one it would probe: a VMDK descriptor can probe as
// raw yet be opened as vmdk. An empty format is read from the header
// (staticDiskFormat), never probed by qemu-img. Every file the disk names must
// lie in allowedDir, which the daemon alone writes: a disk from anywhere else
// is copied there first (privateImportDisk), and what it named beside it is
// not.
func assertNoExternalDiskRefsAs(ctx context.Context, file, format, allowedDir string) error {
	if format == "" {
		f, err := staticDiskFormat(file)
		if err != nil {
			return err
		}
		format = f
	}
	roots := []string{allowedDir}
	if real, err := filepath.EvalSymlinks(allowedDir); err == nil {
		roots = append(roots, real)
	}
	return assertNoExternalDiskRefsDepth(ctx, file, format, roots, 0)
}

func withinAnyRoot(roots []string, p string) bool {
	for _, r := range roots {
		if safename.Contains(r, p) {
			return true
		}
	}
	return false
}

func assertNoExternalDiskRefsDepth(ctx context.Context, file, format string, roots []string, depth int) error {
	if depth > maxBackingDepth {
		return fmt.Errorf("backing chain deeper than %d images", maxBackingDepth)
	}
	// Nothing the header names may be opened before it is judged: refuse
	// what qemu-img info itself would open (extents, a data file).
	if err := precheckDiskHeader(file, format); err != nil {
		return err
	}
	// qemu-img info on this one image only (no --backing-chain: that would
	// open the backing file before it is judged).
	out, err := exec.CommandContext(ctx, "qemu-img", "info", "-U", "--output=json", "-f", format, "--", file).Output()
	if err != nil {
		// info failure is not itself an escape; surface it as a convert-time error.
		return fmt.Errorf("inspect %s: %w", filepath.Base(file), err)
	}
	var info qemuImgInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("inspect %s: unreadable qemu-img info: %w", filepath.Base(file), err)
	}
	self := file
	if real, err := filepath.EvalSymlinks(file); err == nil {
		self = real
	}
	for _, f := range info.openedFiles() {
		if f == file || f == self {
			continue // the disk itself, which its caller chose
		}
		if !plainBackingPath(f) {
			return fmt.Errorf("disk makes qemu open %q, which is not a plain path", f)
		}
		resolved := f
		if !filepath.IsAbs(f) {
			resolved = filepath.Join(filepath.Dir(file), f)
		}
		if real, err := filepath.EvalSymlinks(resolved); err == nil {
			resolved = real
		}
		if !withinAnyRoot(roots, resolved) {
			return fmt.Errorf("disk makes qemu open %q, outside the import directory", f)
		}
	}
	if df := info.FormatSpecific.Data.DataFile; df != "" {
		return fmt.Errorf("disk keeps its data in an external file %q; only standalone disks are imported", df)
	}
	backing := info.BackingFilename
	if backing == "" {
		backing = info.FullBackingFilename
	}
	if backing == "" {
		return nil
	}
	if !plainBackingPath(backing) {
		return fmt.Errorf("disk names a backing file %q that is not a plain path", backing)
	}
	resolved := backing
	if !filepath.IsAbs(backing) {
		resolved = filepath.Join(filepath.Dir(file), backing)
	}
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = real
	}
	if !withinAnyRoot(roots, resolved) {
		return fmt.Errorf("disk has an external backing file %q outside the import directory", backing)
	}
	// Walk the backing file in the format the image records for it; qemu
	// opens it that way. With none recorded qemu would probe, so refuse.
	if info.BackingFilenameFormat == "" {
		return fmt.Errorf("disk names a backing file %q without its format", backing)
	}
	return assertNoExternalDiskRefsDepth(ctx, resolved, info.BackingFilenameFormat, roots, depth+1)
}

// plainBackingPath reports whether a backing name is a filesystem path rather
// than a json: spec or a protocol (nbd:, http:, file:, ...). qemu treats a
// leading "<word>:" as a protocol prefix.
func plainBackingPath(name string) bool {
	if strings.HasPrefix(name, "json:") {
		return false
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		if j := strings.IndexByte(name, '/'); j < 0 || i < j {
			return false
		}
	}
	return true
}

// ── small helpers ──

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	r, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:r], nil
}

func findByExt(dir, ext string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ext) {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no %s file found in %s", ext, dir)
}

// sniffImportFormat guesses the source format from the file's leading bytes.
func sniffImportFormat(path string) string {
	head, err := readHead(path, 512)
	if err != nil || len(head) == 0 {
		return ""
	}
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{'V', 'M', 'A', 0}):
		return "vma"
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x28, 0xB5, 0x2F, 0xFD}): // zstd
		return "vma"
	case len(head) >= 2 && head[0] == 0x1F && head[1] == 0x8B: // gzip
		return "vma"
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")): // tar
		return "ova"
	case bytes.Contains(head, []byte("<Envelope")) || bytes.Contains(head, []byte("<?xml")):
		return "ovf"
	case bytes.Contains(head, []byte("scsihw:")) || bytes.Contains(head, []byte("bootdisk:")) ||
		bytes.Contains(head, []byte("boot:")) || bytes.Contains(head, []byte("ostype:")):
		return "proxmox"
	default:
		return ""
	}
}

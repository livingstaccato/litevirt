package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Containers gRPC service.
//
// Routing model:
//   - Every request carries a host_name. If empty or matches s.hostName,
//     the local containerRuntime executes.
//   - Otherwise the call forwards to the named host via peerClient
//     (existing pattern in server.go).
//   - Cluster-state side-effects (containers table) are written by
//     the host that performed the action so the row reflects truth.

// CreateContainer creates an LXC/OCI container on the named host.
// containerProject resolves a container's tenancy project for RBAC/audit.
// known is false when no row was found here (or the read failed): the project
// is then unknown, NOT "_default", and the caller must authorize through
// requirePermResolved, which refuses to guess. The "_default" returned
// alongside known=false is only for audit text and the admission a root caller
// reaches. When host is empty it scans by name (lifecycle RPCs usually carry
// the owning host).
func (s *Server) containerProject(ctx context.Context, host, name string) (project string, known bool) {
	if host != "" {
		ct, err := corrosion.GetContainer(ctx, s.db, host, name)
		if err != nil || ct == nil {
			return tenancy.Default, false
		}
		return tenancy.NormalizeProject(ct.Project), true
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return tenancy.Default, false
	}
	for _, ct := range cts {
		if ct.Name == name {
			return tenancy.NormalizeProject(ct.Project), true
		}
	}
	return tenancy.Default, false
}

// containerWhat names a container in requirePermResolved's NotFound.
func containerWhat(name string) string { return "container " + strconv.Quote(name) }

// authorizeContainerCreate is a create's caller-side checks, judged where the
// caller is real: ct.create on the container, the host-path authority for a
// template that names a host path, and the Admin's security opt-outs
// (privileged, legacy confinement). A compose recreate runs it before its
// delete half (judgeContainerRecreate), so none of them refuses after the
// member is gone; there the template the member already uses is granted
// (recreateTemplateGranted), as on main, and the reading host still refuses
// a protected place (checkContainerTemplate).
func (s *Server) authorizeContainerCreate(ctx context.Context, req *pb.CreateContainerRequest) error {
	if err := s.RequirePerm(ctx, ctRBACPathFor(req.Project, req.Name), "ct.create", "operator"); err != nil {
		s.audit(ctx, "ct.create", req.Name, "project="+tenancy.NormalizeProject(req.Project), "denied")
		return err
	}
	if !recreateTemplateGranted(ctx, req.Template) {
		if err := s.authorizeContainerTemplate(ctx, req.Template); err != nil {
			s.audit(ctx, "ct.create", req.Name, "template="+req.Template, "denied")
			return err
		}
	}
	if err := containerSecurityRequest(ctx, req.Privileged, req.Confinement); err != nil {
		s.audit(ctx, "ct.create", req.Name, fmt.Sprintf("privileged=%v confinement=%s", req.Privileged, req.Confinement), "denied")
		return err
	}
	if err := s.containerHostAccessRequest(ctx, req.HostName, req.Mounts, req.Devices); err != nil {
		s.audit(ctx, "ct.create", req.Name, hostAccessAudit(req.Mounts, req.Devices), "denied")
		return err
	}
	return nil
}

func (s *Server) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (resp *pb.Container, retErr error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// Validate the name + project BEFORE the permission check (so a path-like
	// name never participates in the auth path) and before they reach the LXC
	// runtime (which builds <lxcpath>/<name>) or the stored row used for RBAC.
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.Project != "" {
		if _, err := safename.CanonicalProjectName(req.Project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	// A forwarded compose recreate's decision, judged on the entry host:
	// honoured from a peer, for the create it is bound to only.
	ctx = s.acceptRecreateInherit(ctx, req)
	if err := s.authorizeContainerCreate(ctx, req); err != nil {
		return nil, err
	}
	// Idempotency: replay a completed create on a lost-response retry (see CreateVM).
	// Placed before the forward so a retry replays without re-forwarding; recorded
	// on success across all return paths.
	if req.IdempotencyKey != "" {
		reqHash := idempotencyRequestHash(req)
		replay, claimID, ierr := s.idempotencyBegin(ctx, req.IdempotencyKey, "CreateContainer", reqHash)
		if ierr != nil {
			return nil, ierr
		}
		if replay != nil {
			out := &pb.Container{}
			if proto.Unmarshal(replay, out) != nil {
				return nil, status.Error(codes.Internal, "corrupt idempotency record")
			}
			return out, nil
		}
		stopHB := s.startIdempotencyHeartbeat(ctx, req.IdempotencyKey, claimID)
		defer func() {
			stopHB()
			// Fail closed: if a successful create's result couldn't be durably
			// recorded, surface that as the RPC error rather than a success we
			// can't replay.
			if ferr := s.idempotencyFinish(ctx, req.IdempotencyKey, claimID, resp, retErr); ferr != nil && retErr == nil {
				resp, retErr = nil, ferr
			}
		}()
	}
	if forwarded, err := s.forwardCreateContainer(ctx, req); err != nil || forwarded != nil {
		if err == nil {
			// Report the create once this node lists the row (see
			// awaitForwardedContainer).
			s.awaitForwardedContainer(ctx, forwarded.GetHostName(), forwarded.GetName(), "created", containerRowPresent)
		}
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	if err := s.refuseNoContainerRuntime(ctx, s.hostName); err != nil {
		return nil, err
	}
	if err := s.checkContainerTemplate(req.Template, req.Name); err != nil {
		s.audit(ctx, "ct.create", req.Name, "template="+req.Template, "denied")
		return nil, err
	}
	// A library item another project pulled is that project's image, for
	// every create (a compose recreate's judgment runs this same check before
	// its delete when the member is on this host).
	// A recreate built from the copy its member's host took before the
	// delete was judged where the copy was taken (recreateFetchImage); the
	// item's owner now is not that copy's, and the runtime judges the item
	// again (createItemCheck) if it copies the item instead.
	if p, isPath, _ := lxc.TemplatePath(req.Template); isPath && !recreateBound(ctx, req.Template) {
		if err := s.refuseForeignOCIItem(ctx, ociLibraryName(p, s.dataDir), req.Project, "be created from"); err != nil {
			s.audit(ctx, "ct.create", req.Name, "template="+req.Template, "denied")
			return nil, err
		}
	}

	// Serialize same-name creates on this host, and reject a duplicate BEFORE
	// allocating any IPAM lease. Without this, a duplicate / concurrent create that
	// later fails would run the lease-cleanup path (keyed on host+name) and tombstone
	// the EXISTING container's leases + interface rows. The lock + preflight make the
	// failure cleanup safe (this is the only live container of this name on the host).
	unlock := s.lockVMAs("ct/"+req.Name, "container create")
	defer unlock()
	// Fail CLOSED on a read error: if we can't prove the name is free, a later
	// cleanup keyed on (host, name) could release an existing container's managed
	// NIC state — so never proceed to allocate leases / touch the runtime on a
	// read we couldn't complete.
	existing, gerr := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if gerr != nil {
		return nil, status.Errorf(codes.Internal, "check existing container: %v", gerr)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "container %q already exists on host %q", req.Name, s.hostName)
	}
	// Host mounts and devices are written by THIS node, so the feature's gate
	// runs here, after the cheap local refusals (template, image ownership, a
	// duplicate name) and before anything is admitted or created: the entry
	// check (containerHostAccessRequest) only fails fast, and a forwarded
	// create is gated on the owner. A create without them takes no grant.
	//
	// The grant records the use before the tenancy check and the host
	// admission below, so a create those refuse leaves the feature recorded
	// as used with nothing set (n3). That errs only toward "used", which
	// changes nothing for this release (release_2026_11_v1 blocks rollback
	// whether or not it was used), and taking the grant after the admission
	// would hold the host reservation through a first use's ack wait (up to
	// 30s).
	var hostAccessG capabilities.FeatureGrant
	if len(req.Mounts) > 0 || len(req.Devices) > 0 {
		g, gerr := s.passthroughGrant(ctx)
		if gerr != nil {
			return nil, gerr
		}
		hostAccessG = g
	}

	// Tenancy admission — containers draw down the SAME project vCPU/Mem budget
	// as VMs (mirrors CreateVM). Runs on the owning host (post-forward) so the
	// check happens once against the cluster-wide usage view.
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, tenancy.NormalizeProject(req.Project),
			tenancy.QuotaRequest{VCPU: int(req.Cpu), MemMiB: int(req.MemoryMib)}); err != nil {
			return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
		}
	}

	// Admission. Two different scopes, deliberately split:
	//
	//   HOST capacity — MEMORY only. A container's cpu_limit is a CAP in cores (a
	//   ceiling the cgroup enforces), not a vCPU reservation, so it is not added
	//   to a host's vCPU total; only its memory cap is comparable to a VM's. An
	//   UNCAPPED container (memory 0) reserves nothing, matching how it is
	//   accounted, and never pays the qemu overhead (newVMOnHost=false).
	//
	//   PROJECT quota — CPU **and** memory. SumProjectUsage counts a container's
	//   cpu_limit against the project's vCPU budget, so admission has to charge it
	//   or the limit is unenforceable. It previously passed 0 for CPU and ran only
	//   when memory was non-zero, so concurrent containers could exceed the
	//   project vCPU limit, and a CPU-limited container with unlimited memory
	//   skipped serialized admission entirely.
	//
	// Reserved (not just checked) because this host commits the container below —
	// otherwise a concurrent create for a different name sees the same headroom
	// and both pass. Placed after tenancy and before any runtime or IPAM work, so
	// a refusal leaves no partial state to unwind.
	// The host admission is UNCONDITIONAL — a fully uncapped container reserves
	// nothing but still becomes resident, and residency is a safety decision
	// (incomplete inventory, active ownership conditions) the container cannot
	// opt out of by declining limits. The zero-delta case returns an empty lease
	// after safety passes.
	var ctLease *reservationLease
	{
		lease, aerr := s.admitHostWithReservation(ctx, "CreateContainer", s.hostName, tenancy.NormalizeProject(req.Project), "ct:"+req.Name, 0, int(req.MemoryMib), intentContainerResident)
		if aerr != nil {
			return nil, aerr
		}
		defer lease.release(ctx)
	}

	// Resolve the requested NICs into runtime attachments + managed-interface rows
	// + create-spec intent, ALLOCATING each managed NIC's IPAM lease as it goes
	// (managed network vs legacy raw bridge). On any later failure we release this
	// container's leases (s.releaseContainerNICs) to undo partial allocation.
	//
	// This runs BEFORE the quota reservation, and the order is load-bearing: only
	// a MANAGED NIC becomes a container_interfaces row, and only those rows count
	// toward the project's NIC budget. Charging len(req.Networks) up front would
	// refuse creates for raw-bridge attachments that contribute nothing, so the
	// charge waits until the persisted set is known. Residency safety is already
	// settled by the host admission above, so nothing unsafe has been done by the
	// time we get here, and a refusal below unwinds the allocation.
	plan, err := s.resolveContainerNICs(ctx, req.Project, req.Name, req.Networks)
	if err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name) // undo any leases taken before the error
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, err
	}

	// PROJECT quota — cpu, memory and the NICs about to be persisted. The NIC
	// charge was missing entirely: SumProjectUsage counts container_interfaces
	// rows against the project's NIC budget, so a container could walk straight
	// past the limit without any concurrency at all.
	if ctQuota := (corrosion.QuotaAmount{
		VCPU: int(req.Cpu), MemMiB: int(req.MemoryMib), NIC: len(plan.ifaces),
	}); !ctQuota.IsZero() {
		// Normalize before admission. project_quotas is keyed "_default", and
		// UpsertContainer normalizes the stored row the same way — so passing the
		// raw "" that `lv ct create` sends without --project found no quota row,
		// skipped quotaVerdict entirely, and then counted the container against a
		// budget that had never admitted it. It also wrote the reservation with
		// Project "", where a concurrent VM create in _default cannot see it.
		lease, aerr := s.admitQuotaWithReservation(ctx, "CreateContainer", s.hostName, tenancy.NormalizeProject(req.Project),
			corrosion.WorkloadContainer, req.Name, ctQuota, ctQuota, intentContainerResident)
		if aerr != nil {
			_ = s.releaseContainerNICs(ctx, req.Name)
			s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
			return nil, aerr
		}
		defer lease.release(ctx)
		ctLease = lease
	}
	// Unprivileged by default, in a range no other container uses.
	confinement := req.Confinement
	if confinement == "" {
		confinement = lxc.ConfinementDefault
	}
	var idmapBase int64
	if !req.Privileged {
		b, aerr := s.allocateIDMapBase(ctx, req.Name)
		if aerr != nil {
			_ = s.releaseContainerNICs(ctx, req.Name)
			return nil, aerr
		}
		idmapBase = b
	}
	// A container's managed NICs are new NICs: guarded by default, held to the
	// exact address IPAM gave them. Recorded — and put in force, from the
	// NICs planned here, since its rows do not exist yet — before the runtime
	// brings its veth up (re-review m-f, m10); a failure fails the create.
	// Before failover_scope_v1 has latched nothing can be recorded and the
	// NICs are unguarded, as every container NIC was.
	ctOwner := corrosion.ContainerGuardOwner(s.hostName, req.Name)
	var ctGuards []corrosion.NICGuardRecord
	for _, ifc := range plan.ifaces {
		ctGuards = append(ctGuards, corrosion.NICGuardRecord{
			VMName: ctOwner, MAC: ifc.MAC, Mode: corrosion.NICGuardOn,
			Network: ifc.NetworkName, Ordinal: ifc.Ordinal})
	}
	if err := s.writeNewNICGuards(ctx, ctGuards); err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name)
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, err
	}
	if pa, ok := s.fwRec().(pendingContainerArmer); ok && len(plan.ifaces) > 0 {
		pa.SetPendingContainer(req.Name, plan.ifaces)
		defer pa.ClearPendingContainer(req.Name)
	}
	if err := s.armWorkload(ctx, req.Name, func() ([]string, error) { return s.containerGuardedMACs(ctx, req.Name) }); err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name)
		s.retireNICGuards(ctx, ctOwner)
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	specMounts, specDevices := hostAccessSpec(req.Mounts, req.Devices)
	optMounts, optDevices := hostAccessOpts(corrosion.ContainerCreateSpec{Mounts: specMounts, Devices: specDevices})
	checkItem, pinned, pinnedGen, anyGen := s.createItemCheck(ctx, req)
	info, err := s.containerRuntime.CreateContainer(ctx, CreateContainerOpts{
		Name: req.Name, Template: req.Template,
		Distro: req.Distro, Release: req.Release, Arch: req.Arch,
		CPULimit: int(req.Cpu), MemoryMiB: int(req.MemoryMib),
		Networks: plan.lxcNics, Labels: req.Labels,
		Confinement: confinement, IDMapBase: idmapBase,
		Mounts: optMounts, Devices: optDevices,
		CheckItem: checkItem, Pinned: pinned, PinnedGen: pinnedGen, PinAnyGen: anyGen,
	})
	if err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name)
		s.retireNICGuards(ctx, ctOwner)
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied {
			return nil, st.Err()
		}
		if errors.Is(err, lxc.ErrImageReplaced) {
			return nil, status.Errorf(codes.PermissionDenied,
				"recreating container %q: it is privileged or legacy-confined, and the image under %q was replaced after the recreate was judged, "+
					"with no copy of the judged image kept for it, so the create would run another image as root on the host; "+
					"that needs the Admin role or the ContainerRoot role on it (lv role grant ContainerRoot <principal> --path %s)",
				req.Name, req.Template, ctRBACPathFor(req.Project, req.Name))
		}
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}

	// Persist the create-time intent (incl. networking) so host-loss relocation /
	// restore can rebuild this container faithfully, not as a bare image recreate.
	createSpec := corrosion.ContainerCreateSpec{
		Template: req.Template, Distro: req.Distro, Release: req.Release, Arch: req.Arch,
		TemplateGen: info.ImageGen,
		Networks:    plan.specNets,
		// A new lineage: the owner record its files are matched by.
		OwnerID:     randid.New(),
		IDMapBase:   idmapBase,
		Confinement: confinement,
		Mounts:      specMounts,
		Devices:     specDevices,
	}
	s.stampContainerOwner(info.Name, req.Project, corrosion.EncodeCreateSpec(createSpec))

	// CreatedAt is left empty ON PURPOSE: the corrosion writer stamps it with
	// nanosecond precision, and that stamp is the row's INCARNATION identity —
	// anti-entropy uses it to tell a genuine recreate from a stale pre-delete
	// copy. Pre-filling a bare-second stamp here (as this site used to) would
	// make a same-second delete+recreate indistinguishable from the incarnation
	// the delete killed.
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: info.Name,
		State: info.State, Image: chooseImage(req.Image, info.Image),
		CPULimit: int(req.Cpu), MemMiB: int(req.MemoryMib),
		Labels: req.Labels, RestartPolicy: encodeRestartPolicy(req.Restart),
		Project:       req.Project, // UpsertContainer normalizes "" → "_default"
		OnHostFailure: req.OnHostFailure,
		CreateSpec:    corrosion.EncodeCreateSpec(createSpec),
		// Never started: the checker leaves it to the operator's start.
		StateDetail: corrosion.ContainerCreatedDetail,
	}
	rec.CreateSpec, _ = corrosion.WithNewPlacement(rec.CreateSpec) // its first placement
	// FENCE before the durable write; see CreateVM. The cleanup mirrors the
	// failed-write path below: the runtime container exists but must not be
	// recorded under an authority that no longer covers its admission.
	if ferr := ctLease.allowCommit(ctx); ferr != nil {
		_ = s.releaseContainerNICs(ctx, info.Name)
		if delErr := s.containerRuntime.DeleteContainer(ctx, info.Name); delErr != nil {
			slog.Warn("container create: cleanup after an aborted admission also failed",
				"name", info.Name, "error", delErr)
		}
		return nil, ferr
	}
	// Write the container row + managed interface rows in ONE atomic batch. Fail
	// closed: the runtime container exists but the DB write failed → delete the
	// just-created container and release its leases, so no partial tracked state
	// and no leaked lease.
	writeRow := corrosion.CreateContainerAtomic
	if len(createSpec.Mounts) > 0 || len(createSpec.Devices) > 0 {
		writeRow = func(ctx context.Context, c *corrosion.Client, rec corrosion.ContainerRecord, ifaces []corrosion.ContainerInterfaceRecord) error {
			return corrosion.CreateContainerAtomicWithHostAccess(ctx, c, hostAccessG, rec, ifaces)
		}
	}
	if err := writeRow(ctx, s.db, rec, plan.ifaces); err != nil {
		_ = s.releaseContainerNICs(ctx, info.Name)
		if delErr := s.containerRuntime.DeleteContainer(ctx, info.Name); delErr != nil {
			slog.Warn("container create: cleanup after cluster-state-write failure also failed",
				"name", info.Name, "error", delErr)
		}
		s.audit(ctx, "ct.create", info.Name, "image="+rec.Image, "error")
		return nil, status.Errorf(codes.Internal, "create: record cluster state: %v", err)
	}
	if len(ctGuards) > 0 {
		s.reconcileLocal(ctx)
	}
	auditDetail := "project=" + tenancy.NormalizeProject(req.Project) + " image=" + rec.Image
	if ha := hostAccessAudit(req.Mounts, req.Devices); ha != "" {
		auditDetail += " " + ha
	}
	s.audit(ctx, "ct.create", info.Name, auditDetail, "ok")
	slog.Info("container created", "name", info.Name, "host", s.hostName)
	return toPbContainer(rec), nil
}

func (s *Server) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "ct.start", "operator", containerWhat(req.Name)); err != nil {
		return nil, err
	}
	// Resolve the OWNER when no host was named (same shape as DeleteContainer):
	// the daemon knows exactly where the container lives, so a host-less start
	// from a non-owning node forwards there instead of failing "not found on
	// host <local>". A name that exists nowhere is NotFound.
	startHost := req.HostName
	if startHost == "" {
		h, _, rerr := s.resolveContainerHost(ctx, "", req.Name)
		if rerr != nil {
			return nil, rerr
		}
		startHost = h
	}
	if forwarded, err := s.forwardSimpleCT(ctx, startHost, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.StartContainer(ctx, &pb.StartContainerRequest{Name: req.Name, HostName: startHost})
	}); err != nil || forwarded != nil {
		if err == nil {
			// Report the start once this node lists it running (see
			// awaitForwardedContainer).
			s.awaitForwardedContainer(ctx, startHost, req.Name, "running", containerRunning)
		}
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	// Serialize with a concurrent start/create of the SAME container before reading
	// the row. Without this, two starts both read state != "running", both admit
	// and both reserve its memory — so the second is refused for capacity the first
	// is already accounting for. The row read has to be under the lock for the
	// admission below to be based on a state that can't change underneath it.
	unlock := s.lockVMAs("ct/"+req.Name, "container start")
	defer unlock()
	// Preflight the cluster row BEFORE touching the runtime: a missing/soft-deleted
	// row means we'd start an UNTRACKED container, so refuse. (Also folds in the
	// template check — a frozen clone source can't be started.)
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if err != nil {
		// A state-read failure is not the same as "not found" — surface it as
		// Internal rather than masking a storage problem behind FailedPrecondition.
		return nil, status.Errorf(codes.Internal, "start: read container row: %v", err)
	}
	if rec == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "container %q not found on host %q", req.Name, s.hostName)
	}
	if rec.IsTemplate {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is a template and cannot be started; clone it instead", req.Name)
	}
	// A forced stop made under write quarantine holds the container until it
	// is recorded: refused while the quarantine holds, replayed first once it
	// has lifted (container_operator_stop_marker.go).
	if replayed, err := s.containerOperatorStopStartRefusal(ctx, rec); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project+" held by an operator-stop marker", "denied")
		return nil, err
	} else if replayed {
		if rec, err = corrosion.GetContainer(ctx, s.db, s.hostName, req.Name); err != nil || rec == nil {
			return nil, status.Errorf(codes.Unavailable, "start: read the container row again after recording its stop: %v; retry `lv ct start %s`", err, req.Name)
		}
	}
	// Host capacity admission — memory only (see CreateContainer). Starting is when
	// the memory is actually taken: a stopped container is accounted as nothing, so
	// checking only at create would be sidestepped by creating several that each fit
	// and starting them all. Skipped when already running (adds nothing). An
	// UNCAPPED container reserves nothing but is still admitted: the start makes it
	// resident, and residency is the safety decision — a host with incomplete
	// inventory or an active ownership condition refuses it even at zero delta.
	// Reserved, not just checked, so the memory stays accounted for across the
	// runtime start and the "running" state write below.
	if rec.State != "running" {
		lease, aerr := s.admitHostWithReservation(ctx, "StartContainer", s.hostName, tenancy.NormalizeProject(rec.Project), "ct:"+req.Name, 0, rec.MemMiB, intentContainerResident)
		if aerr != nil {
			return nil, aerr
		}
		defer lease.release(ctx)
	}
	if err := s.refuseOverlappingRange(ctx, req.Name); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project+" id range overlap", "denied")
		return nil, err
	}
	if err := s.startContainerArmed(ctx, req.Name); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project, "error")
		if status.Code(err) == codes.FailedPrecondition {
			return nil, err
		}
		return nil, status.Errorf(hostAccessBusyCode(err, codes.Internal), "start: %v", err)
	}
	// Clear any prior stop intent ('operator-stop') so a later unexpected stop is
	// judged fresh. Strict: if the row vanished mid-flight the container is now
	// untracked → stop it and error; a transient DB error leaves it running + errors.
	if err := corrosion.SetContainerStateDetailStrict(ctx, s.db, s.hostName, req.Name, "running", ""); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project, "error")
		if errors.Is(err, corrosion.ErrNoRowsAffected) {
			if stopErr := s.containerRuntime.StopContainer(ctx, req.Name, 0); stopErr != nil {
				slog.Warn("container start: failed to stop now-untracked container after its row vanished",
					"name", req.Name, "error", stopErr)
			}
			return nil, status.Errorf(codes.FailedPrecondition, "container %q row vanished during start; stopped to avoid an untracked container", req.Name)
		}
		return nil, status.Errorf(codes.Internal, "start: clear stop intent: %v", err)
	}
	s.audit(ctx, "ct.start", req.Name, "project="+project, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "ct.stop", "operator", containerWhat(req.Name)); err != nil {
		return nil, err
	}
	// Owner resolution, same as StartContainer/DeleteContainer.
	stopHost := req.HostName
	if stopHost == "" {
		h, _, rerr := s.resolveContainerHost(ctx, "", req.Name)
		if rerr != nil {
			return nil, rerr
		}
		stopHost = h
	}
	var hdr metadata.MD
	if forwarded, err := s.forwardSimpleCT(ctx, stopHost, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.StopContainer(ctx, &pb.StopContainerRequest{Name: req.Name, HostName: stopHost, TimeoutSec: req.TimeoutSec, Force: req.Force}, grpc.Header(&hdr))
	}); err != nil || forwarded != nil {
		// Report the stop once this node no longer lists it running (see
		// awaitForwardedContainer); a stop the owner recorded only on itself
		// (write quarantine) leaves the row as it was.
		if err == nil && len(hdr.Get(ctStopLocalOnlyHeader)) == 0 {
			s.awaitForwardedContainer(ctx, stopHost, req.Name, "not running", containerNotRunning)
		}
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	// Serialize with the other operations on this container and with the
	// container checker's sweep (LockContainer): a sweep that read the row as
	// running and then saw this stop in the runtime would take it for an
	// unexpected stop and restart the container.
	unlock := s.LockContainer(req.Name)
	defer unlock()
	// Under write quarantine the stop below cannot be recorded, and an
	// unrecorded stop is undone by the restart policy: refused before the
	// runtime is touched, unless forced, which records it on this host first
	// (container_operator_stop_marker.go).
	if reason := s.stopQuarantineReason(); reason != "" {
		if !req.Force {
			s.audit(ctx, "ct.stop", req.Name, "project="+project+" write quarantine", "denied")
			return nil, s.quarantinedContainerStopRefusal(req.Name, reason)
		}
		return s.quarantinedForceStopContainerLocked(ctx, req, project, reason)
	}
	noop := false
	if err := s.containerRuntime.StopContainer(ctx, req.Name, int(req.TimeoutSec)); err != nil {
		// A container that is already stopped is stopped (lxc-stop answers
		// "is not running"), as StopVM treats a domain that is not running:
		// the stop is recorded below. Anything else is still an error.
		if st, serr := s.containerRuntime.StateContainer(ctx, req.Name); serr != nil || st != "stopped" {
			s.audit(ctx, "ct.stop", req.Name, "project="+project, "error")
			return nil, status.Errorf(codes.Internal, "stop: %v", err)
		}
		slog.Info("container stop: already stopped; recording the stop", "name", req.Name, "error", err)
		noop = true
	}
	// Record operator intent so the container reconciler leaves it stopped (the
	// container analogue of StopVM's vms.state_detail='operator-stop'). Strict:
	// this marker is load-bearing — without it the reconciler auto-restarts the
	// container — so a missing-row / failed write must surface, not silently pass.
	if err := corrosion.SetContainerStateDetailStrict(ctx, s.db, s.hostName, req.Name, "stopped", "operator-stop"); err != nil {
		s.audit(ctx, "ct.stop", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "stop: record operator-stop intent: %v", err)
	}
	// The row now says what a forced stop's marker held (or a marker that
	// cannot be read meant to): the recorded stop is its remedy.
	s.clearContainerOperatorStopMarker(req.Name)
	detail := "project=" + project
	if noop {
		detail += " already stopped: nothing was running; the operator's stop is recorded"
	}
	s.audit(ctx, "ct.stop", req.Name, detail, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// A plain delete ends the container's own schedules (deleteContainerSchedules),
	// by the entry host only, as DeleteVM's: never on a host a peer called (the
	// owner of a forward, an older entry's unmarked compose re-create), and
	// never for a delete that keeps them (withSchedulesKept).
	dropSchedules := false
	var dropProject, dropHost string
	if !schedulesKept(ctx) && !s.forwardedByEntry(ctx) && !s.isRemotePeer(ctx) {
		dropProject, dropSchedules = s.containerProject(ctx, req.HostName, req.Name)
		dropHost = s.deletedContainerHost(ctx, req.HostName, req.Name)
	}
	out, err := s.deleteContainer(ctx, req)
	if err == nil && dropSchedules {
		s.deleteContainerSchedules(context.WithoutCancel(ctx), dropHost, dropProject, req.Name)
	}
	return out, err
}

func (s *Server) deleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error) {
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "ct.delete", "operator", containerWhat(req.Name)); err != nil {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "denied")
		return nil, err
	}
	// Resolve the OWNER when no host was named. Without this a host-less delete
	// executed "locally" on whichever node the client happened to dial, where
	// the runtime not-found AND the zero-row tombstone are both idempotent
	// successes — rc=0, nothing deleted anywhere, an operator typo
	// indistinguishable from a clean delete. Resolution is scoped to the
	// name-only form: an EXPLICIT-host delete keeps its full retry idempotency
	// (failover/relocation re-issue those), and a name that exists nowhere now
	// surfaces as NotFound instead of a silent ok.
	targetHost := req.HostName
	if targetHost == "" {
		h, _, rerr := s.resolveContainerHost(ctx, "", req.Name)
		if rerr != nil {
			return nil, rerr
		}
		targetHost = h
	}
	// A delete ends the container's firewall identity, so its tags row is
	// cleared once the delete succeeds (spec §4.3), by the entry host only:
	// a forward to the owner says so (entryForwardCtx). Moves and
	// relocations retire their source row without this RPC.
	var fwID string
	if !s.forwardedByEntry(ctx) {
		if rec, _ := corrosion.GetContainer(ctx, s.db, targetHost, req.Name); rec != nil {
			fwID = corrosion.FirewallIDOf(corrosion.TagMemberCT, rec.CreateSpec)
		}
	}
	// A removed host is not dialled: its rows are deleted here
	// (removed_host_delete.go).
	if removed, err := s.workloadHostRemoved(ctx, targetHost); err != nil {
		return nil, err
	} else if removed {
		out, err := s.deleteContainerOnRemovedHost(ctx, targetHost, req.Name, project)
		if err == nil {
			// The delete has happened: its tags go whatever becomes of the
			// caller.
			pctx, pcancel := context.WithTimeout(context.WithoutCancel(ctx), deletePostStepsTimeout)
			s.clearDeletedFirewallTags(pctx, corrosion.TagMemberCT, targetHost, req.Name, fwID)
			pcancel()
		}
		return out, err
	}
	// A running container is deleted only with force (see refuseDeleteRunning).
	// Judged here from the row when the owner is remote — the owner then trusts
	// a peer's forward — and on the owner from its runtime.
	if !req.Force && targetHost != s.hostName {
		if rec, _ := corrosion.GetContainer(ctx, s.db, targetHost, req.Name); rec != nil && rec.State == "running" {
			return nil, refuseDeleteRunning(req.Name, targetHost)
		}
	}
	if forwarded, err := s.forwardSimpleCT(ctx, targetHost, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.DeleteContainer(entryForwardCtx(s.recreatePreflightOutgoing(ctx)), &pb.DeleteContainerRequest{Name: req.Name, HostName: targetHost, Force: req.Force})
	}); err != nil || forwarded != nil {
		if err == nil {
			// Report the delete once this node no longer lists the row (see
			// awaitForwardedContainer).
			s.awaitForwardedContainer(ctx, targetHost, req.Name, "deleted", containerRowGone)
			s.clearDeletedFirewallTags(ctx, corrosion.TagMemberCT, targetHost, req.Name, fwID)
		}
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	// A compose recreate's delete forwarded from another entry host: the
	// create that follows it is judged on this host first, its image
	// fetched included, so a recreate refused there keeps its member
	// (recreate_preflight.go). Before the container's lock: a fetch can take
	// minutes, and judges nothing about the container itself.
	if err := s.recreateDeleteCheck(ctx, req.Name); err != nil {
		return nil, err
	}
	// Serialize with the other operations on this container and with the
	// container checker's sweep (LockContainer), so a sweep never reconciles a
	// container that is half deleted.
	unlock := s.LockContainer(req.Name)
	defer unlock()
	// The admission inventory cache (localInventoryTTL) would otherwise list
	// the deleted container for up to 10 s with no row here to account for
	// it: an uncapped one then refuses every create on this host as a rogue
	// (lab 2 run c2, P-3). Dropping the cache only makes the next admission
	// read the runtime afresh; it never admits anything unread.
	defer s.invalidateInventoryCache()
	// The runtime delete is lxc-destroy -f, which stops a running container
	// first, so without force a running one is refused. A remote peer's call is
	// exempt: a current entry node judged it before forwarding, and an older
	// one (a rolling upgrade) drives compose and relocation deletes that never
	// carried the flag.
	if !req.Force && !s.isRemotePeer(ctx) {
		if st, serr := s.containerRuntime.StateContainer(ctx, req.Name); serr == nil && strings.EqualFold(st, "running") {
			s.audit(ctx, "ct.delete", req.Name, "project="+project+" running", "denied")
			return nil, refuseDeleteRunning(req.Name, s.hostName)
		}
	}
	// Capture the stack label NOW (for the DNS-record name) — the row is about to be
	// tombstoned. Best-effort: if the row is already gone, the reaper backstops.
	dnsStack := ""
	if rec, _ := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name); rec != nil {
		dnsStack = containerStackLabel(*rec)
	}
	// Its NICs' MACs, for retiring their guard records below: the tombstone
	// takes the NIC rows with it.
	ctMACs := s.containerNICMACs(ctx, req.Name)
	// From the runtime delete on, the delete runs to its tombstone whatever
	// becomes of its caller: a client gone between the two would leave a live
	// row over a container that no longer exists (detachDelete). A caller
	// already gone refuses it with nothing done.
	if err := refuseIfCancelled(ctx); err != nil {
		return nil, err
	}
	ctx, cancelFinish := s.detachDelete(ctx)
	defer cancelFinish()
	// A runtime "not found" is acceptable (idempotent) — proceed to the row
	// tombstone so a retry after "runtime gone but DB write failed" can clear the
	// ghost row. A real runtime failure still aborts.
	if err := s.containerRuntime.DeleteContainer(ctx, req.Name); err != nil && !errors.Is(err, lxc.ErrContainerNotFound) {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	// Mandatory tombstone: a ghost (stale-live) row skews quota + makes failover
	// chase a container that no longer exists. Delete is intentionally IDEMPOTENT
	// (the documented exception to the strict "zero-row = failure" rule that
	// governs start/stop): retry-safety matters for the failover/relocation paths
	// that re-issue deletes. So an already-gone row (ErrNoRowsAffected) is a
	// success — but audited distinctly (not a silent "ok") so an operator typo
	// isn't invisible. A REAL DB error — or ErrDeleteContended, a row still LIVE
	// after the guarded CAS retried (its authority kept moving) — surfaces as
	// Internal: the runtime container is gone by this point, and OK-with-a-live-
	// row would be exactly the ghost this tombstone is mandatory to prevent.
	derr := corrosion.DeleteContainerStrict(ctx, s.db, s.hostName, req.Name)
	if derr != nil && !errors.Is(derr, corrosion.ErrNoRowsAffected) {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: remove cluster row: %v", derr)
	}
	// Cascade the managed network state (IPAM leases + container_interfaces rows)
	// and clear restart state, on BOTH the normal and already-absent paths — a
	// prior delete may have tombstoned the container row but failed these, so a
	// retry (now zero-row) must still clean them up, else a later same-host/name
	// recreate inherits stale leases/rows.
	s.retireContainerGuards(ctx, req.Name, ctMACs)
	nicErr := s.releaseContainerNICs(ctx, req.Name)
	// Remove the auto DNS record (prompt — a lingering record could resolve to a now
	// freed/reassigned IP). Best-effort; the reaper backstops.
	s.deleteContainerDNS(ctx, req.Name, dnsStack)
	if err := corrosion.DeleteContainerRestartState(ctx, s.db, s.hostName, req.Name); err != nil {
		slog.Warn("container delete: failed to clear restart state (harmless, GC'able)", "name", req.Name, "error", err)
	}
	// The managed-NIC cascade is part of the CT network invariant: a stale lease or
	// interface row would be inherited by a later same-host/same-name recreate —
	// which makes the name live again and so hides the orphan from the lease GC.
	// Surface a cascade failure so the caller retries; the whole delete is
	// idempotent (runtime not-found OK, row tombstone zero-row OK, cascade re-runs).
	if nicErr != nil {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: release managed NICs: %v", nicErr)
	}
	s.clearDeletedFirewallTags(ctx, corrosion.TagMemberCT, targetHost, req.Name, fwID)
	if errors.Is(derr, corrosion.ErrNoRowsAffected) {
		// Idempotent: the row was already gone. Audited distinctly, not a silent "ok".
		s.audit(ctx, "ct.delete", req.Name, "project="+project+" already-absent", "ok")
		slog.Info("container delete: cluster row already absent (idempotent no-op)", "name", req.Name, "host", s.hostName)
		return &emptypb.Empty{}, nil
	}
	s.audit(ctx, "ct.delete", req.Name, "project="+project, "ok")
	slog.Info("container deleted", "name", req.Name, "host", s.hostName)
	return &emptypb.Empty{}, nil
}

func (s *Server) ExecContainer(ctx context.Context, req *pb.ExecContainerRequest) (*pb.ExecContainerResponse, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Operator role floor BEFORE the lookup, so a caller who holds nothing
	// cannot probe container existence through the resolution outcome.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		s.audit(ctx, "ct.exec", req.Name, "permission denied: "+strings.Join(req.Argv, " "), "denied")
		return nil, err
	}
	// Resolve the container the way every other lifecycle RPC does, and
	// authorize against the row that resolution actually returned.
	//
	// This used to be containerProject(ctx, req.HostName, req.Name), which on an
	// empty host scans the cluster and returns the FIRST name match — while the
	// forward below only fires when host_name is non-empty. Authorization read
	// one host's row and execution used a different host's container: an
	// attacker owning a same-named container on a host that sorts earlier
	// (ORDER BY host_name, name) got ct.exec inside the victim's. With no
	// matching row at all the fallback was "_default", so ct.exec on _default
	// authorized an exec against any local container of that name.
	//
	// resolveContainerHost refuses an ambiguous name and is NotFound on an
	// unknown one, which is why the siblings do not have this hole.
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		s.audit(ctx, "ct.exec", req.Name, "unresolved: "+strings.Join(req.Argv, " "), "error")
		return nil, err
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(rec.Project, req.Name), "ct.exec", "operator"); err != nil {
		s.audit(ctx, "ct.exec", req.Name, "permission denied: "+strings.Join(req.Argv, " "), "denied")
		return nil, err
	}
	// In a privileged or legacy-confined container, exec is a host-level
	// grant (requireContainerRoot), judged here from the resolved row, and
	// again on the owner from its own row for a forward (execRootRefused):
	// an entry whose replica lags may not know the container became one.
	if err := s.judgeExecMode(ctx, *rec, rootContainerMode(*rec), req.Argv); err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward exec: %v", err)
		}
		defer conn.Close()
		// Pin the resolved host on the forwarded request so the peer does not
		// re-run the cluster-wide name resolution (same as StartContainer).
		return c.ExecContainer(s.execRootOutgoing(ctx, *rec), &pb.ExecContainerRequest{
			Name: req.Name, HostName: host, Argv: req.Argv,
		})
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	execAfterJudge()
	// Judge again where the exec attaches, from the row read under the
	// container's lock, which lv ct stop, start and convert hold: the row
	// judged above may be stale by now.
	//
	// The lock is held until the exec is attached, not for the session: a
	// mode change needs the container stopped (lv ct convert), and the stop
	// ends what is attached. A runtime that cannot tell when it is attached
	// keeps the lock for the whole exec.
	var once sync.Once
	unlockContainer := s.LockContainer(req.Name)
	unlock := func() { once.Do(unlockContainer) }
	defer unlock()
	cur, err := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "exec: read container: %v", err)
	}
	if cur == nil {
		return nil, status.Errorf(codes.NotFound, "container %q not found on %s", req.Name, s.hostName)
	}
	if err := s.judgeExecMode(ctx, *cur, rootContainerMode(*cur), req.Argv); err != nil {
		return nil, err
	}
	var res ContainerExecResult
	if es, ok := s.containerRuntime.(containerExecStarter); ok {
		res, err = es.ExecContainerStarted(ctx, req.Name, req.Argv, unlock)
	} else {
		res, err = s.containerRuntime.ExecContainer(ctx, req.Name, req.Argv)
	}
	if err != nil {
		s.audit(ctx, "ct.exec", req.Name, strings.Join(req.Argv, " "), "error")
		return nil, status.Errorf(codes.Internal, "exec: %v", err)
	}
	s.audit(ctx, "ct.exec", req.Name, strings.Join(req.Argv, " "), "ok")
	return &pb.ExecContainerResponse{
		Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: int32(res.ExitCode),
	}, nil
}

// ListContainers returns containers across the cluster (or just one
// host when host_name is set). Reads from the containers table —
// authoritative since each host upserts on every lifecycle change.
func (s *Server) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	if err := s.RequirePerm(ctx, "/", "ct.read", "viewer"); err != nil {
		return nil, err
	}
	resp := &pb.ListContainersResponse{}
	pageSize, err := normalizePageSize(req.PageSize)
	if err != nil {
		return nil, err
	}
	var rows []corrosion.ContainerRecord
	if pageSize > 0 {
		// Composite (host_name, name) keyset cursor — containers are keyed by that
		// pair, so name alone isn't unique across hosts. Fetch one extra to detect
		// a next page.
		parts, cerr := pageCursor(req.PageToken, 2)
		if cerr != nil {
			return nil, cerr
		}
		afterHost, afterName := "", ""
		if len(parts) == 2 {
			afterHost, afterName = parts[0], parts[1]
		}
		rows, err = corrosion.ListContainersPage(ctx, s.db, req.HostName, afterHost, afterName, pageSize+1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list: %v", err)
		}
		if len(rows) > pageSize {
			rows = rows[:pageSize]
			last := rows[len(rows)-1]
			resp.NextPageToken = encodePageToken(last.HostName, last.Name)
		}
	} else if rows, err = corrosion.ListContainers(ctx, s.db, req.HostName); err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	for _, r := range rows {
		resp.Containers = append(resp.Containers, toPbContainer(r))
	}
	return resp, nil
}

func (s *Server) PullOCIImage(ctx context.Context, req *pb.PullOCIImageRequest) (*emptypb.Empty, error) {
	if err := s.RequirePerm(ctx, "/", "image.pull", "operator"); err != nil {
		return nil, err
	}
	if req.Project != "" {
		if _, err := safename.CanonicalProjectName(req.Project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		// --project makes the image that project's, and is the project the
		// pull-over rule checks: it must be one the caller may create
		// containers in, judged here where the caller is real.
		if err := s.RequirePerm(ctx, projectRBACBase(req.Project)+"/containers", "ct.create", "operator"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied,
				"--project %q: you cannot create containers in that project, so you cannot pull an image for it", req.Project)
		}
	}
	// Dest is where umoci unpacks the (untrusted) image rootfs as root, and a
	// local source (oci:, dir:, oci-archive:, docker-archive:) is read as
	// root — both are host-path primitives. A bare Dest name is contained
	// under the daemon OCI staging dir; an absolute Dest or a local source
	// requires admin (registry pulls stay operator), and any other transport
	// is refused (lxc.ParseOCISource reads the source as skopeo does). The
	// check binds the real caller on the entry node; a forwarded peer call
	// runs as admin (daemon mTLS) so it isn't re-denied, and the host that
	// reads the source judges its path (checkOCIPullPaths).
	src, err := lxc.ParseOCISource(req.Image)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if src.Local {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied,
				"pulling from a local %s: source reads this host as root, which requires the admin role", src.Transport)
		}
	}
	if filepath.IsAbs(req.Dest) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Error(codes.PermissionDenied,
				"an absolute --dest requires the admin role; use a bare name to stage under the daemon OCI directory")
		}
	} else if req.Dest != "" {
		// A bare Dest must be a single safe name (no nested path); it is resolved
		// to a staging path on the host that actually unpacks it (below, after the
		// forward), so the raw name — not the entry host's dataDir path — crosses
		// the wire.
		if err := safename.ValidateName(req.Dest); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid --dest (use a bare name): %v", err)
		}
	}
	// Resolve registry credentials on the ENTRY node — only here is
	// callerUsername(ctx) meaningful (a forwarded peer runs under the daemon's
	// mTLS identity). Skip if the request already carries inline creds (ad-hoc
	// `lv ct pull --username`, or a secret an entry node already resolved and
	// forwarded) or the image is a local oci: layout (RegistryHost == "").
	if req.Username == "" && req.Password == "" && s.db != nil {
		if reg := lxc.RegistryHost(req.Image); reg != "" {
			if rc, err := corrosion.ResolveRegistryCredential(ctx, s.db, callerUsername(ctx), reg); err != nil {
				slog.Warn("registry credential resolve failed; pulling anonymously",
					"registry", reg, "error", err)
			} else if rc != nil {
				req.Username, req.Password = rc.Username, rc.Secret
			}
		}
	}
	// Forward AFTER resolution so req carries the resolved secret to the host
	// that actually runs skopeo (it cannot resolve per-user creds itself).
	if forwarded, err := s.forwardSimpleCT(ctx, req.HostName, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.PullOCIImage(s.ociReplaceOutgoing(ctx, req), req)
	}); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	// Resolve a bare Dest name to a staging path on THIS (the unpacking) host,
	// so it lands under this host's OCI dir regardless of where the request
	// entered the cluster.
	if req.Dest != "" && !filepath.IsAbs(req.Dest) {
		resolved, err := safename.SafeJoin(filepath.Join(s.dataDir, "oci"), req.Dest)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid --dest: %v", err)
		}
		req.Dest = resolved
	}
	if err := s.checkOCIPullPaths(req.Image, req.Dest); err != nil {
		return nil, err
	}
	// A library item belongs to the project that pulled it; another project's
	// caller may not pull over it.
	item := ociLibraryName(req.Dest, s.dataDir)
	if err := s.refuseForeignOCIItem(ctx, item, req.Project, "pull over"); err != nil {
		return nil, err
	}
	if err := s.refuseClaimingOwnerlessItem(ctx, item, req.Dest, req.Project); err != nil {
		return nil, err
	}
	replace, err := s.judgeOCIReplace(ctx, req)
	if err != nil {
		return nil, err
	}
	// Only an explicit --project makes the image a project's; without one it
	// is everyone's, as on main. The owner is recorded in the bundle with
	// the content (lxc.OwnerFile), so the one rename that publishes the
	// content publishes its owner; then, under the item's locks, in
	// <data_dir>/oci-owners too, which an earlier build reads.
	//
	// Until the image is in place, that copy holds ociOwnerPending, which
	// matches no project: an earlier build, rolled back to after a claim was
	// cut short, refuses the item to every project rather than give the new
	// image to the old owner. A pull that fails before then puts the copy
	// back as it was.
	var owner string
	var publish func() error
	restore := func() {}
	published := false
	if item != "" && s.dataDir != "" && req.Project != "" {
		owner = tenancy.NormalizeProject(req.Project)
		restore = s.markOCIOwnerPending(item)
		publish = func() error {
			published = true
			ociOwnerWriteHook(item, owner)
			if err := s.writeOCIOwner(item, owner); err != nil {
				slog.Warn("oci pull: the image's owner is recorded with it, but its copy for earlier builds could not be written", "image", item, "project", owner, "error", err)
			}
			return nil
		}
	}
	if err := s.containerRuntime.PullOCIImage(ctx, req.Image, req.Dest, req.Tag, req.Username, req.Password, replace, s.checkPullSource, owner, publish); err != nil {
		if !published {
			restore()
		}
		switch {
		case errors.Is(err, lxc.ErrOCIItemExists):
			return nil, ociItemExistsErr(req.Dest, s.hostName)
		case errors.Is(err, lxc.ErrSourceRefused):
			return nil, status.Errorf(codes.InvalidArgument, "pull oci: %v", err)
		case errors.Is(err, lxc.ErrStagingSpace):
			return nil, status.Errorf(codes.ResourceExhausted, "pull oci: %v", err)
		}
		// The source check, run by the runtime on the object it opened,
		// answers with its own code.
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown && st.Code() != codes.OK {
			return nil, st.Err()
		}
		return nil, status.Errorf(codes.Internal, "pull oci: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// ── helpers ──

// refuseDeleteRunning is the refusal for a delete of a running container
// without force.
func refuseDeleteRunning(name, host string) error {
	return status.Errorf(codes.FailedPrecondition,
		"container %q is running on host %q; stop it first (lv ct stop %s), or delete it running with --force", name, host, name)
}

// isRemotePeer reports whether the caller is another cluster node's daemon
// (peer mTLS from a trusted host, not this host's own local-root CLI).
func (s *Server) isRemotePeer(ctx context.Context) bool {
	return callerPrincipalKind(ctx) == principalKindPeer && s.requirePeerCert(ctx) == nil
}

// forwardCreateContainer routes the request to the owning host when
// host_name names a remote. Returns (resp, err) — both nil means
// "execute locally".
func (s *Server) forwardCreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.Container, error) {
	if req.HostName == "" || req.HostName == s.hostName {
		return nil, nil
	}
	c, closer, err := s.dialPeer(ctx, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "forward create: %v", err)
	}
	defer closer()
	// The entry node owns the idempotency claim; strip the key from the forwarded
	// copy so the executor doesn't re-run the idempotency path and self-conflict on
	// the same key (abort the forward, or race a duplicate claim on the same row).
	fwd := req
	if req.IdempotencyKey != "" {
		fwd = proto.Clone(req).(*pb.CreateContainerRequest)
		fwd.IdempotencyKey = ""
	}
	// A compose recreate's create carries its decision, bound to it, to the
	// member's host (recreate_inherit.go).
	return c.CreateContainer(recreateInheritOutgoing(ctx, s.ownerStrictOutgoing(ctx), req), fwd)
}

// forwardSimpleCT is the empty-result version: returns (resp, err)
// where (nil, nil) means "execute locally" so the caller proceeds.
func (s *Server) forwardSimpleCT(
	ctx context.Context, hostName string,
	dial func(pb.LiteVirtClient) (*emptypb.Empty, error),
) (*emptypb.Empty, error) {
	if hostName == "" || hostName == s.hostName {
		return nil, nil
	}
	c, closer, err := s.dialPeer(ctx, hostName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "forward: %v", err)
	}
	defer closer()
	return dial(c)
}

func toPbContainer(r corrosion.ContainerRecord) *pb.Container {
	privileged, confinement, base := containerSecurityOf(r)
	mounts, devices := pbHostAccess(corrosion.DecodeCreateSpec(r.CreateSpec))
	return &pb.Container{
		Mounts: mounts, Devices: devices,
		Privileged: privileged, Confinement: confinement, IdmapBase: base,
		HostName: r.HostName, Name: r.Name, State: r.State,
		Image: r.Image, CpuLimit: int32(r.CPULimit), MemoryMib: int32(r.MemMiB),
		Restart: decodeRestartPolicy(r.RestartPolicy), StateDetail: r.StateDetail,
		Project:   r.Project,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func chooseImage(req, info string) string {
	if req != "" {
		return req
	}
	return info
}

// encodeRestartPolicy serializes a container's restart policy for the
// containers.restart_policy column. A nil or none-condition policy stores an
// empty string so the common (opt-out) case carries no JSON. Round-trips via
// decodeRestartPolicy.
func encodeRestartPolicy(rp *pb.RestartPolicy) string {
	if rp == nil || rp.Condition == "" || rp.Condition == "none" {
		return ""
	}
	b, err := json.Marshal(rp)
	if err != nil {
		return ""
	}
	return string(b)
}

// decodeRestartPolicy parses the stored restart_policy JSON; an empty string (or
// garbage) yields nil (treated as "none").
func decodeRestartPolicy(s string) *pb.RestartPolicy {
	if s == "" {
		return nil
	}
	rp := &pb.RestartPolicy{}
	if err := json.Unmarshal([]byte(s), rp); err != nil {
		return nil
	}
	return rp
}

// keep errors imported in case we add typed-error returns later
var _ = errors.New

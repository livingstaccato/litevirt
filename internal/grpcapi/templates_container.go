package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// ConvertContainerToTemplate marks a stopped container as a template (a
// clone source that can't start), or with revert turns it back into a normal
// container. Mirrors ConvertToTemplate for VMs. Container clones are always
// full copies (no qcow2 backing), so a template has no linked-clone
// dependencies — revert is always safe.
func (s *Server) ConvertContainerToTemplate(ctx context.Context, req *pb.ConvertContainerToTemplateRequest) (*pb.Container, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "ct.update", "operator", containerWhat(req.Name)); err != nil {
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward convert-template: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.ConvertContainerToTemplate(ctx, req)
	}

	if req.Revert {
		if !rec.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is not a template", req.Name)
		}
		if err := corrosion.SetContainerTemplate(ctx, s.db, host, req.Name, false); err != nil {
			return nil, status.Errorf(codes.Internal, "revert template: %v", err)
		}
		s.audit(ctx, "ct.template.revert", req.Name, "project="+project, "ok")
	} else {
		if rec.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is already a template", req.Name)
		}
		if rec.State != "stopped" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"container %q must be stopped to convert to a template (current: %s)", req.Name, rec.State)
		}
		if err := corrosion.SetContainerTemplate(ctx, s.db, host, req.Name, true); err != nil {
			return nil, status.Errorf(codes.Internal, "convert to template: %v", err)
		}
		s.audit(ctx, "ct.template.convert", req.Name, "project="+project, "ok")
	}
	rec.IsTemplate = !req.Revert
	return toPbContainer(*rec), nil
}

// CloneContainer creates a new container as a full copy of a template or
// stopped source, with a fresh identity (new hostname/MAC/machine-id). The
// clone is created on the source's host (its rootfs lives there) and admitted
// against the project quota. Mirrors CloneVM (full-copy only — no linked
// clones for containers).
func (s *Server) CloneContainer(ctx context.Context, req *pb.CloneContainerRequest) (*pb.Container, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Source == "" || req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "source and target required")
	}
	if !validResourceName(req.Target) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target name %q", req.Target)
	}
	// Authorize the SOURCE as well as the destination — see CloneVM. A container
	// clone copies the source rootfs, so the destination check alone leaves the
	// read of another tenant's filesystem unguarded.
	//
	// Authorized BEFORE the source is resolved, through requirePermResolved, so
	// a caller without rights on it gets one answer whether it exists or not —
	// resolving first returned NotFound for a free name and a PermissionDenied
	// naming the owner's project for a foreign one (see CloneVM).
	srcProject, known := s.containerProject(ctx, req.HostName, req.Source)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(srcProject, req.Source), ctRBACPathFor("", req.Source),
		"backup.create", "operator", containerWhat(req.Source)); err != nil {
		detail := "source project=" + srcProject
		if !known {
			detail = "source project=unresolved"
		}
		s.audit(ctx, "ct.clone", req.Source, detail, "denied")
		return nil, err
	}
	host, src, err := s.resolveContainerHost(ctx, req.HostName, req.Source)
	if err != nil {
		return nil, err
	}
	project := tenancy.NormalizeProject(req.Project)
	if req.Project == "" {
		project = tenancy.NormalizeProject(src.Project)
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Target), "ct.create", "operator"); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project, "denied")
		return nil, err
	}
	// The clone holds its source's host mounts and devices, which only the
	// admin role grants. Judged HERE, as the caller, before the forward: the
	// source's host runs a forwarded call as the peer, which must never be
	// what grants it. That host strips any host access the clone's
	// authorized spec does not carry (rebuildContainerConfig).
	if err := cloneHostAccessAllowed(ctx, *src); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "source="+req.Source+" host mounts/devices", "denied")
		return nil, err
	}
	// A privileged mode and legacy confinement are the same host-escalation
	// class as a host mount, but a clone is never refused for them: a
	// non-admin's clone lands unprivileged, with default confinement. Ruled
	// HERE, as the caller, and carried: the source's host sees only the peer.
	if RequireRole(ctx, "admin") != nil {
		req.Unprivileged = true
	}
	// The clone is created where the source's rootfs lives.
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward clone: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.CloneContainer(ctx, req)
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	// Consistent rootfs: clone a template or a stopped container (a running
	// container's rootfs isn't quiescent). Mirrors CloneVM.
	if !src.IsTemplate && src.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"source %q must be a template or stopped to clone (current: %s)", req.Source, src.State)
	}
	// A source with an unfinished conversion is not cloned: the copy would
	// carry its marker, which names the SOURCE's target range, so finishing
	// the clone's conversion would move it into that range too — a range two
	// containers then share. (On main such a clone could start once its own
	// conversion finished, sharing the range; a confinement-only conversion
	// shares none.) Finishing the source's conversion first, then cloning,
	// loses nothing. Security that cannot be read is refused rather than read
	// as "not converting".
	if sc, ok := s.containerRuntime.(containerSecurer); ok {
		sec, serr := sc.ContainerSecurity(req.Source)
		switch {
		case errors.Is(serr, errRuntimeKeepsNoSecurity):
			// Nothing to convert on such a runtime.
		case serr != nil:
			return nil, status.Errorf(codes.Unavailable,
				"read source %q's security settings (a source mid-conversion is not cloned): %v", req.Source, serr)
		case sec.Converting:
			return nil, status.Errorf(codes.FailedPrecondition,
				"source %q has an unfinished conversion; finish it with lv ct convert %s, then clone it", req.Source, req.Source)
		}
	}
	// Fail CLOSED on a read error — never clone onto a name we couldn't prove free
	// (a later cleanup keyed on (host, name) could release an existing CT's NICs).
	if existing, gerr := corrosion.GetContainer(ctx, s.db, s.hostName, req.Target); gerr != nil {
		return nil, status.Errorf(codes.Internal, "check existing container: %v", gerr)
	} else if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "container %q already exists on host %q", req.Target, s.hostName)
	}

	// Project isolation: the clone's NICs land in the TARGET project, which may
	// differ from the source's. Refused before admission and the rootfs copy.
	// A raw bridge is judged as what it now is: one that renders a managed
	// network is that network's NIC (m-7).
	cloneNets, cerr := s.classifiedNetworkNames(ctx, corrosion.DecodeCreateSpec(src.CreateSpec))
	if cerr != nil {
		return nil, status.Errorf(codes.Unavailable, "clone: read the networks (what decides whether the source's raw bridges are managed networks): %v", cerr)
	}
	if err := s.admitCopiedNetworks(ctx, "clone", project, src.Project, cloneNets); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project, "denied")
		return nil, err
	}
	var cloneSGs []string
	for _, n := range corrosion.DecodeCreateSpec(src.CreateSpec).Networks {
		cloneSGs = append(cloneSGs, n.SecurityGroups...)
	}
	if err := s.admitSecurityGroupRefs(ctx, project, cloneSGs); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project, "denied")
		return nil, status.Errorf(status.Code(err), "clone: %s", status.Convert(err).Message())
	}

	unlock := s.lockVMAs("ct/"+req.Target, "container clone")
	defer unlock()

	// Quota fail-fast: the clone draws down the project's vCPU/Mem budget (like
	// CreateContainer). The real decision is the serialized admission below —
	// this read-only glance cannot see in-flight reservations and was the ONLY
	// gate this path had (nothing at all with tenancy unwired).
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, project, tenancy.QuotaRequest{VCPU: src.CPULimit, MemMiB: src.MemMiB}); err != nil {
			return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
		}
	}

	// Admission, mirroring CreateContainer exactly: the host half is
	// UNCONDITIONAL — a zero-limit clone still becomes resident here, and
	// residency (incomplete inventory, active ownership conditions) is a safety
	// decision the clone cannot opt out of by inheriting no limits. The quota
	// half is serialized reserve-then-verify and carries the commit fence.
	var cloneQuotaLease *reservationLease
	{
		lease, aerr := s.admitHostWithReservation(ctx, "CloneContainer", s.hostName, project,
			"ct:"+req.Target, 0, src.MemMiB, intentContainerResident)
		if aerr != nil {
			return nil, aerr
		}
		defer lease.release(ctx)
	}
	// The clone rebuilds the source's MANAGED NICs (below), and those rows count
	// toward the project's NIC budget — so the charge includes them, derived from
	// the same spec the rebuild reads.
	if cloneQuota := (corrosion.QuotaAmount{
		VCPU: src.CPULimit, MemMiB: src.MemMiB,
		NIC: managedNICCount(corrosion.DecodeCreateSpec(src.CreateSpec)),
	}); !cloneQuota.IsZero() {
		lease, aerr := s.admitQuotaWithReservation(ctx, "CloneContainer", s.hostName, project,
			corrosion.WorkloadContainer, req.Target, cloneQuota, cloneQuota, intentContainerResident)
		if aerr != nil {
			return nil, aerr
		}
		defer lease.release(ctx)
		cloneQuotaLease = lease
	}

	if err := s.containerRuntime.CloneContainer(ctx, req.Source, req.Target); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project+" source="+req.Source, "error")
		return nil, status.Errorf(codes.Internal, "clone: %v", err)
	}
	cloneBase, strippedSec, err := s.secureClone(ctx, req, corrosion.DecodeCreateSpec(src.CreateSpec))
	if err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after the range move failed also failed", "name", req.Target, "error", delErr)
		}
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	// Rebuild the clone's MANAGED NIC identity (fresh deterministic MAC+veth, a
	// dynamic IP — a clone must not reuse the source's address) from the source's
	// create spec, and rewrite the spec to match. The runtime clone
	// (cloneFreshIdentity) stamps the SAME deterministic MAC/veth on-disk and drops
	// the source's static IP, so the clone's DB state and on-disk config agree.
	cloneSpec := corrosion.DecodeCreateSpec(src.CreateSpec)
	ifaces, specNets, redrawnMACs, merr := s.cloneContainerNICs(ctx, req.Target, cloneSpec)
	if merr != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after the MAC draw failed also failed", "name", req.Target, "error", delErr)
		}
		return nil, merr
	}
	cloneSpec.Networks = specNets
	// A clone is a new lineage, with its own owner record (the copied
	// directory carried the source's).
	cloneSpec.OwnerID = randid.New()
	cloneSpec.RestoredFromOwnerID, cloneSpec.RestoredFromTS = "", ""
	cloneSpec.IDMapBase = cloneBase
	if strippedSec != "" {
		cloneSpec.Confinement = lxc.ConfinementDefault
	}
	// The copied config is rendered again from the clone's spec: host access
	// the source's spec records (judged admin-only before the forward) is
	// carried; a managed block the spec does not record — a restored or
	// earlier container's — is not.
	if err := s.rebuildContainerConfig(ctx, req.Target, cloneSpec); err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after the config rebuild failed also failed", "name", req.Target, "error", delErr)
		}
		return nil, err
	}
	// A derived MAC another NIC holds was drawn afresh: the clone's config
	// takes the drawn one, never the duplicate the runtime clone wrote.
	if err := s.setContainerNICMACs(ctx, req.Target, redrawnMACs); err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after the MAC rewrite failed also failed", "name", req.Target, "error", delErr)
		}
		return nil, err
	}
	s.noteStrippedHostAccess(ctx, "ct.clone", req.Target, strippedSec)
	s.stampContainerOwner(req.Target, project, corrosion.EncodeCreateSpec(cloneSpec))
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: req.Target, State: "stopped",
		// Never started yet: the restart policy copied from the source must not
		// start it (the container checker leaves a "created" container alone).
		// A start below clears it.
		StateDetail: corrosion.ContainerCreatedDetail,
		Image:       src.Image, CPULimit: src.CPULimit, MemMiB: src.MemMiB,
		Labels: src.Labels, RestartPolicy: src.RestartPolicy,
		Project: project, OnHostFailure: src.OnHostFailure,
		CreateSpec: corrosion.EncodeCreateSpec(cloneSpec), CreatedAt: now,
		// A clone is a normal container, never a template.
	}
	rec.CreateSpec, _ = corrosion.WithNewPlacement(rec.CreateSpec) // a new container's first placement
	// The quota-authority commit fence, immediately before the durable write.
	// A refusal deletes the just-cloned runtime container, same as a persist
	// failure below: nothing was persisted, nothing is left untracked.
	if err := cloneQuotaLease.allowCommit(ctx); err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after fence refusal also failed", "name", req.Target, "error", delErr)
		}
		return nil, err
	}

	// Atomic: the container row + the clone's interface rows in one batch (no IPAM
	// lease — clone NICs are dynamic). Fail closed: if persistence fails, delete the
	// just-cloned runtime container so we don't strand an untracked clone (same rule
	// as CreateContainer).
	if err := corrosion.CreateContainerAtomic(ctx, s.db, rec, ifaces); err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Target); delErr != nil {
			slog.Warn("container clone: cleanup after persist failure also failed", "name", req.Target, "error", delErr)
		}
		s.audit(ctx, "ct.clone", req.Target, "project="+project+" source="+req.Source, "error")
		return nil, status.Errorf(codes.Internal, "persist clone: %v", err)
	}

	if req.Start {
		if err := s.startContainerArmed(ctx, req.Target); err != nil {
			s.audit(ctx, "ct.clone", req.Target, "project="+project+" (start failed)", "error")
			return nil, status.Errorf(codes.Internal, "cloned but start failed: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Target, "running", ""); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
		rec.State = "running"
	}
	s.audit(ctx, "ct.clone", req.Target, fmt.Sprintf("project=%s source=%s", project, req.Source), "ok")
	slog.Info("container cloned", "source", req.Source, "target", req.Target, "host", s.hostName)
	return toPbContainer(rec), nil
}

// secureClone gives a fresh copy of a container (still stopped) its security:
// an unprivileged copy moves out of its source's id range into one of its
// own; a privileged one stays privileged only when the caller may hold it
// (an admin), else it moves into a range of its own, its files shifted. A
// non-admin's clone also drops legacy confinement. It returns the clone's
// range base (0: privileged) and what was not carried.
func (s *Server) secureClone(ctx context.Context, req *pb.CloneContainerRequest, srcSpec corrosion.ContainerCreateSpec) (int64, string, error) {
	drop := req.Unprivileged || RequireRole(ctx, "admin") != nil
	sc, ok := s.containerRuntime.(containerSecurer)
	if !ok {
		switch {
		case drop && escalatedSecurity(srcSpec):
			return 0, "", status.Error(codes.Unavailable, "this host cannot move a clone of a privileged container into an id range of its own")
		case srcSpec.IDMapBase != 0:
			return 0, "", status.Error(codes.Internal, "clone: this host cannot move the clone to its own id range")
		}
		return 0, "", nil
	}
	cur, err := sc.ContainerSecurity(req.Target)
	if err != nil {
		return 0, "", status.Errorf(codes.Internal, "clone: read the copy's security: %v", err)
	}
	// The source's row is the record; a row an earlier build wrote records
	// neither, and the copy's config says.
	conf := srcSpec.Confinement
	if conf == "" {
		conf = cur.Confinement
	}
	legacy := drop && conf != lxc.ConfinementDefault
	var what []string
	var base int64
	switch {
	case srcSpec.IDMapBase != 0 || cur.IDMap != nil:
		// The copy carries its source's range; the clone is another container.
		b, aerr := s.allocateIDMapBase(ctx, req.Target)
		if aerr == nil {
			to := lxc.ConvertOpts{IDMap: &lxc.IDMap{Base: b, Size: lxc.IDMapSize}}
			if legacy {
				to.Confinement = lxc.ConfinementDefault
			}
			aerr = sc.ConvertContainerSecurity(ctx, req.Target, to)
		}
		if aerr != nil {
			return 0, "", status.Errorf(codes.Internal, "clone: move the clone to its own id range: %v", aerr)
		}
		base = b
	case drop:
		b, aerr := s.unprivilegeContainer(ctx, sc, req.Target)
		if aerr != nil {
			return 0, "", status.Errorf(codes.Internal, "clone: move the clone of a privileged container into an id range of its own: %v", aerr)
		}
		base = b
		what = append(what, "privileged")
	}
	if legacy {
		what = append(what, "confinement=legacy")
	}
	return base, strings.Join(what, " "), nil
}

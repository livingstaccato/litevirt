package grpcapi

// Project isolation model (v37).
//
// The isolation guarantee is enforced at ATTACH TIME, not in the dataplane: a
// workload may bind a NIC / place a disk only on a network/pool that is GLOBAL
// (empty project — the deliberate admin escape hatch) or OWNED by its own project.
// This is the privilege boundary. admitPoolAttach gates every create and day-2
// pool path (move, replicate, import, schedule, runner). Network admission gates
// every path that attaches a network: admitNetworkAttach where the caller names
// the network (CreateVM, container create, AttachDevice NIC, ImportVM, a
// live-restore given --spec), and admitCopiedNetworks where a path copies an
// existing workload's NICs (CloneVM, CloneContainer, promote, live-restore from
// the backed-up spec, container restore, a stack NIC retarget). A named-project
// workload may not use a raw/unmanaged bridge at all.
//
// There is intentionally NO dataplane cross-project L2 firewall deny. Admission
// already makes its firing condition unreachable: two DIFFERENT named projects can
// never share a non-global L2 (neither can attach to the other's owned network,
// and a named project can't use a raw bridge), and a GLOBAL network is shared by
// design (two tenants placed there CAN talk unless an SG/default-deny says
// otherwise — the operator's choice, not an isolation failure). A per-NIC
// cross-project nftables synthesis would be redundant defense-in-depth for an
// admission bypass; it's a deliberate non-goal here, a clean follow-up if wanted.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// admitNetworkAttach is the attach-time enforcement of project network isolation:
// a workload in wlProject may attach to a network that is GLOBAL (empty project)
// or OWNED by its own project, never another project's. Fail closed: a lookup
// error denies.
//
// A name with NO managed network record is a raw/unmanaged bridge — outside
// isolation entirely (no project, SGs, IPAM, or firewall bindings). A NAMED-project
// workload may NOT use one (hard tenant isolation requires a managed network); the
// default project / root keeps the legacy raw-bridge escape hatch.
func (s *Server) admitNetworkAttach(ctx context.Context, wlProject, networkName string) error {
	if networkName == "" {
		return nil
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil {
		return status.Errorf(codes.Internal, "network admission lookup %q: %v", networkName, err)
	}
	if nr == nil {
		return s.admitRawBridge(ctx, networkName)
	}
	return refuseForeignNetwork(wlProject, nr)
}

// admitCopiedNetworks is network admission for a path that COPIES an existing
// workload's NICs into a new or re-homed workload in targetProject: clone,
// promote, restore, live-restore from a backed-up spec, and a stack NIC
// retarget. The managed-network rule is the same as admitNetworkAttach
// (tenancy.AdmitAttach against the network's owner) and always applies, so a
// copy can never carry a NIC onto a network the target project may not use —
// whatever let the source hold it. A global network is shared and passes.
//
// A raw/unmanaged bridge differs by whether the copy changes project. Into the
// SAME project it is carried: the source's create already passed the
// raw-bridge gate, and the automated paths (failover promote, container
// relocation) have no caller whose authority could be checked again. Into a
// DIFFERENT project it is a new attachment, so it takes the caller-authority
// gate admitNetworkAttach applies to a create.
//
// op names the path in the refusal ("clone", "promote", ...), so the error says
// which operation, which network and why. Fail closed on a lookup error.
func (s *Server) admitCopiedNetworks(ctx context.Context, op, targetProject, sourceProject string, networkNames []string) error {
	crossProject := tenancy.NormalizeProject(targetProject) != tenancy.NormalizeProject(sourceProject)
	for _, name := range networkNames {
		if name == "" {
			continue
		}
		var err error
		if crossProject {
			err = s.admitNetworkAttach(ctx, targetProject, name)
		} else {
			err = s.admitManagedNetwork(ctx, targetProject, name)
		}
		if err != nil {
			return status.Errorf(status.Code(err), "%s: %s", op, status.Convert(err).Message())
		}
	}
	return nil
}

// admitManagedNetwork is the managed-network half of admitNetworkAttach: a name
// with a managed network record must be global or owned by wlProject. A name with
// no record (a raw bridge) is not judged here.
func (s *Server) admitManagedNetwork(ctx context.Context, wlProject, networkName string) error {
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil {
		return status.Errorf(codes.Internal, "network admission lookup %q: %v", networkName, err)
	}
	if nr == nil {
		return nil
	}
	return refuseForeignNetwork(wlProject, nr)
}

// refuseForeignNetwork applies tenancy.AdmitAttach to a resolved network record.
func refuseForeignNetwork(wlProject string, nr *corrosion.NetworkRecord) error {
	if !tenancy.AdmitAttach(wlProject, nr.Project) {
		return status.Errorf(codes.PermissionDenied,
			"network %q is owned by project %q; a workload in project %q may not attach",
			nr.Name, nr.Project, tenancy.NormalizeProject(wlProject))
	}
	return nil
}

// admitRawBridge gates a raw/unmanaged bridge attachment (a name with no managed
// network row). A raw bridge is OUTSIDE isolation (no project / SG / IPAM / firewall
// bindings) and a name can collide with another project's RENDERED bridge, so it's
// the ADMIN escape hatch — gated on the CALLER's cluster-root network authority,
// NOT on the workload's project (_default is a tenant, not root, so a _default
// workload could otherwise reach an owned network's bridge by raw name). A
// cluster/root operator (or a legacy cluster-wide operator via the role fallback)
// passes; a project-scoped caller must use a managed network.
func (s *Server) admitRawBridge(ctx context.Context, ref string) error {
	if err := s.RequirePerm(ctx, "/", "network.create", "operator"); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"attaching to a raw/unmanaged bridge %q requires cluster-root network authority; use a managed network", ref)
	}
	return nil
}

// authorizeResourceRead authorizes VIEWING a project-owned-or-global resource. A
// GLOBAL (empty-project) resource is shared infrastructure, visible to any viewer;
// an OWNED one requires read access to its project path (so a project-scoped caller
// can read its own + global, never another project's). Returned by Get* and used
// as a per-row filter by List* (skip rows where it's non-nil). A legacy cluster
// viewer (no binding) passes via the role fallback → unchanged broad visibility.
func (s *Server) authorizeResourceRead(ctx context.Context, project, rbacPath, verb string) error {
	if project == "" {
		return RequireRole(ctx, "viewer")
	}
	return s.RequirePerm(ctx, rbacPath, verb, "viewer")
}

// admitVMPoolUse is the centralized day-2 storage-pool admission: a VM's project
// may place/move/copy/import onto a target pool only if that pool is global or
// owned by the VM's own project. host is where the target pool lives ("" ⇒ the
// VM's own host). Used by create, move, replicate, import, replication-schedule
// creation, and the replication runner so every path that targets a pool enforces
// the same rule. Fail closed on a lookup error.
func (s *Server) admitVMPoolUse(ctx context.Context, vm *corrosion.VMRecord, host, poolName string) error {
	if host == "" {
		host = vm.HostName
	}
	return s.admitPoolAttach(ctx, vm.Project, host, poolName)
}

// admitPoolAttach is the attach-time enforcement of project storage isolation: a
// workload in wlProject may place a disk on a pool that is GLOBAL or OWNED by its
// own project, never another project's. A name that doesn't resolve to a managed
// pool on host (e.g. a stack volume) carries no pool ownership, so is allowed
// (dedicated volume-project admission is a follow-up). Fail closed on a lookup error.
func (s *Server) admitPoolAttach(ctx context.Context, wlProject, host, poolName string) error {
	if poolName == "" {
		return nil
	}
	pool, ok, err := corrosion.GetStoragePool(ctx, s.db, host, poolName)
	if err != nil {
		return status.Errorf(codes.Internal, "pool admission lookup %q: %v", poolName, err)
	}
	if !ok {
		return nil // not a managed pool on this host ⇒ no pool ownership to enforce
	}
	if !tenancy.AdmitAttach(wlProject, pool.Project) {
		return status.Errorf(codes.PermissionDenied,
			"storage pool %q is owned by project %q; a workload in project %q may not use it",
			poolName, pool.Project, tenancy.NormalizeProject(wlProject))
	}
	return nil
}

// admitPoolCapacity refuses a disk that will not fit its storage pool.
//
// Pool-level, not host-level, and that is the whole point. hosts.disk_total is
// the wrong denominator for anything shared — a Ceph or NFS pool's capacity has
// nothing to do with the host's local disk — while every managed pool carries its
// own statfs-sampled total/used. Comparing against the pool answers the question
// that actually matters for both local and shared storage.
//
// Charged against ACTUAL free space, with the declared size divided by the
// thin-provisioning ratio first. Admitting a declared 100 GiB qcow2 against real
// free space at 1:1 would refuse ordinary practice, since it may occupy 2 GiB.
//
// Skips silently when the pool is unmanaged or carries no capacity sample.
// Missing telemetry means UNKNOWN, never full: refusing there would break every
// cluster whose pools have not been sampled, which is the opposite of safe.
func (s *Server) admitPoolCapacity(ctx context.Context, host, poolName string, declaredBytes int64) error {
	if declaredBytes <= 0 {
		return nil
	}
	// An UNNAMED disk is the primary path — `lv run --disk 20G` sets no storage at
	// all — and it lands in the host's default pool (the same "" → "default"
	// mapping poolLabel already uses). Skipping empty made this check dead for
	// every ordinary create: a 200 GiB disk was accepted onto a 38 GiB filesystem
	// on real hardware, because qcow2 is sparse and nothing objected until the
	// guest eventually hit ENOSPC.
	if poolName == "" {
		poolName = "default"
	}
	pool, ok, err := corrosion.GetStoragePool(ctx, s.db, host, poolName)
	if err != nil {
		return status.Errorf(codes.Internal, "pool capacity lookup %q: %v", poolName, err)
	}
	if !ok {
		return nil // not a managed pool here — nothing to admit against
	}
	free, known := corrosion.PoolFreeBytes(pool.TotalBytes, pool.UsedBytes, s.capacity)
	if !known {
		return nil // never sampled — unknown, not full
	}
	need := corrosion.DiskNeedBytes(declaredBytes, s.capacity)
	if need > free {
		return status.Errorf(codes.ResourceExhausted,
			"storage pool %q on %s has insufficient free space for a %d GiB disk (needs ~%d GiB after thin-provisioning, %d GiB free after reserve)",
			poolName, host, declaredBytes>>30, need>>30, free>>30)
	}
	return nil
}

package grpcapi

import (
	"context"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// A rebuild (RebuildVM) and a rolling recreate (serverOps.recreateAs) tear a
// VM down and create it again from a spec. The create judges the spec afresh
// — the installer ISO included — so a refusal there, after the teardown,
// would lose the VM: its row, its MACs and addresses, everything the rebuild
// meant to keep. Two things prevent that:
//
//   - recreatePreflight runs, before anything is torn down, the create's
//     refusals that do not depend on the teardown (authority, names, project,
//     hooks, network and pool admission, and the ISO, judged on the VM's host
//     as the create there will judge it), so a refusal leaves the VM as it
//     was;
//   - a recreateISOGrant carries the VM's own installer ISO, as it was
//     classified at its create, into that create. A VM whose ISO is a host
//     path — an Admin's, or one stored before iso_scope existed, which its
//     starts keep honouring (resolveHostISO) — is created again with that
//     classification and the same full host judgement a start gives it,
//     rather than refused because the rebuilding caller is not an Admin. The
//     VM already reads that file; re-creating it gives nothing new. A pool
//     ISO is judged again, held to the kind recorded at its create.

//
// The grant lives in this process only: a create that placement sent to
// another host would arrive there without it, and an owner judging the
// relayed caller (auth.forwarded_identity) would refuse the ISO after the
// teardown. So a VM re-created with an installer ISO is re-created on this
// host — the one whose preflight judged the ISO, and whose file a host path
// names (recreatePinnedHere) — or refused before anything is torn down.

// recreateISOGrantKey carries a recreateISOGrant in a context. Only this
// process sets it, so a caller cannot.
type recreateISOGrantKey struct{}

// recreateISOGrant is the installer ISO a VM being re-created already has.
type recreateISOGrant struct {
	iso, scope, project string
}

// withRecreateISOGrant returns ctx carrying the installer ISO of the VM row
// vm (when it has one) into a create that re-creates it.
func withRecreateISOGrant(ctx context.Context, vm *corrosion.VMRecord) context.Context {
	spec := vmSpecFor(vm)
	if spec.GetIso() == "" {
		return ctx
	}
	return context.WithValue(ctx, recreateISOGrantKey{},
		recreateISOGrant{iso: spec.GetIso(), scope: spec.GetIsoScope(), project: tenancy.NormalizeProject(vm.Project)})
}

// recreateISOGrantFor returns the grant in ctx when it is for this ISO, as
// the spec names it, in this project.
func recreateISOGrantFor(ctx context.Context, iso, project string) (recreateISOGrant, bool) {
	g, ok := ctx.Value(recreateISOGrantKey{}).(recreateISOGrant)
	if !ok || iso == "" || g.iso != iso || g.project != tenancy.NormalizeProject(project) {
		return recreateISOGrant{}, false
	}
	return g, true
}

// hostPath reports whether the grant is a host path ISO: an
// Admin's, or one stored before iso_scope was recorded.
func (g recreateISOGrant) hostPath() bool {
	return filepath.IsAbs(g.iso) && (g.scope == "" || g.scope == isoScopeHostPath)
}

// recreatePreflight runs, before a VM is torn down to be created again from
// in on host (the host it is on now), the create's refusals that the teardown
// does not change. Quota and placement are not among them: the VM being torn
// down still holds its share of both until it is gone.
func (s *Server) recreatePreflight(ctx context.Context, in *pb.VMSpec, host string) error {
	spec, err := normalizeCreateVMSpec(in, s.defaultCPUModeCfg)
	if err != nil {
		return err
	}
	// The create mints a fresh uuid, so its ISO identity record (the key a
	// shared directory's file is admitted by) is a new one: judge under a
	// fresh one too, and drop what the judgement records.
	spec.Uuid = uuid.NewString()
	defer s.forgetISOIdentity(isoIdentityKey(spec.Name, spec))
	if spec.Name == "" {
		return status.Error(codes.InvalidArgument, "VM name required")
	}
	if err := validateSpecNames(spec); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(spec.Project, spec.Name), "vm.create", "operator"); err != nil {
		return err
	}
	if hooksDefined(spec.Hooks) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return status.Error(codes.PermissionDenied,
				"defining VM lifecycle hooks requires the admin role (hooks execute as root on the target host)")
		}
	}
	project := tenancy.NormalizeProject(spec.Project)
	if project != tenancy.Default {
		if p, err := corrosion.GetProject(ctx, s.db, project); err != nil || p == nil {
			return status.Errorf(codes.NotFound, "project %q not found", project)
		}
	}
	for _, n := range spec.Network {
		if err := s.admitNetworkAttach(ctx, project, n.Name); err != nil {
			return err
		}
	}
	for _, d := range spec.Disks {
		if err := s.admitPoolAttach(ctx, project, host, d.Storage); err != nil {
			return err
		}
	}
	if err := s.authorizeVMISO(ctx, project, host, spec); err != nil {
		return err
	}
	if host == s.hostName && spec.GetIso() != "" {
		if _, err := s.resolveVMISO(ctx, project, spec); err != nil {
			return err
		}
	}
	return nil
}

// recreatePinnedHere reports whether the create that re-creates cur (nil: a
// new VM, nothing torn down) from in must run on this host, and refuses —
// before any teardown — one that placement would not admit here.
//
// It must when in names an installer ISO: the preflight judged that ISO here
// (a host path names this host's file, and this process holds the grant that
// carries its classification into the create), and a judgement made here
// says nothing about another host. A pool (library) ISO is pinned the same
// way, rather than placed freely and judged against rows of a host the
// preflight did not see: one judgement, by the host that creates the VM, is
// the one that cannot be refused after the teardown.
//
// Placement is checked as the create's own pinned check (ValidatePinned),
// with what cur holds here released (it is torn down first). The devices,
// the per-node limit and anti-affinity with itself are left out while cur is
// on this host: until the teardown they count cur itself, which the create
// replaces. A spec pinned to another host is refused: it cannot be re-created
// where its ISO was judged.
func (s *Server) recreatePinnedHere(ctx context.Context, in *pb.VMSpec, cur *corrosion.VMRecord) (bool, error) {
	if in.GetIso() == "" {
		return false, nil
	}
	spec, err := normalizeCreateVMSpec(in, s.defaultCPUModeCfg)
	if err != nil {
		return false, err
	}
	compose.NormalizeVMSpecResources(spec)
	if pin := spec.GetPlacement().GetHost(); pin != "" && pin != s.hostName {
		return true, status.Errorf(codes.FailedPrecondition,
			"its spec pins it to %s, but its installer ISO %q was judged here, on %s; migrate it to %s first",
			pin, spec.GetIso(), s.hostName, pin)
	}
	req := s.createVMPlacementRequest(ctx, spec, false)
	if cur != nil && cur.HostName == s.hostName {
		req.Replaces = placement.VMAllocation(*cur)
		req.Devices, req.MaxPerNode = nil, 0
		req.AntiAffinity = slices.DeleteFunc(slices.Clone(req.AntiAffinity), func(n string) bool { return n == spec.Name || n == cur.Name })
	}
	if err := placement.ValidatePinned(ctx, s.db, req, s.hostName); err != nil {
		return true, status.Errorf(codes.FailedPrecondition,
			"it must be re-created on %s, where its installer ISO %q was judged, and placement does not admit it there: %v",
			s.hostName, spec.GetIso(), err)
	}
	return true, nil
}

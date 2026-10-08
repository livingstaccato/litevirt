package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

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
// A VM re-created with an installer ISO is placed BEFORE the teardown, by the
// cluster's placement rules as main placed it after the teardown, with what
// the VM holds released (placeRecreate). The host chosen judges the spec as
// its create there will — as the caller the forward relays, holding the
// grant — and only then is the VM torn down and created there
// (judgeRecreateOn). The grant reaches that host with the forward, in
// metadata it honours only from a peer host (recreateISOGrantMD), never as
// a value of this process that the forward would drop.

// recreateISOGrantKey carries a recreateISOGrant in a context. This process
// sets it from the row of the VM it re-creates, or from what a peer host
// handed over (acceptRecreateISOGrantMD); a caller cannot.
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
// in on host, the create's refusals that the teardown does not change. Quota
// and placement are not among them: the VM being torn down still holds its
// share of both until it is gone.
func (s *Server) recreatePreflight(ctx context.Context, in *pb.VMSpec, host string) error {
	_, err := s.recreatePreflightSpec(ctx, in, host)
	return err
}

// recreatePreflightSpec is recreatePreflight returning the spec as the create
// would forward it to host: normalized, with the installer ISO's
// classification (iso_scope) set.
func (s *Server) recreatePreflightSpec(ctx context.Context, in *pb.VMSpec, host string) (*pb.VMSpec, error) {
	spec, err := normalizeCreateVMSpec(in, s.defaultCPUModeCfg)
	if err != nil {
		return nil, err
	}
	// As createVM: iso_scope is server-owned, carried only by a peer's leg.
	if sc := in.GetIsoScope(); sc != "" && s.requirePeerCert(ctx) == nil {
		spec.IsoScope = sc
	}
	// The create mints a fresh uuid, so its ISO identity record (the key a
	// shared directory's file is admitted by) is a new one: judge under a
	// fresh one too, and drop what the judgement records.
	spec.Uuid = uuid.NewString()
	defer s.forgetISOIdentity(isoIdentityKey(spec.Name, spec))
	if spec.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}
	if err := validateSpecNames(spec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(spec.Project, spec.Name), "vm.create", "operator"); err != nil {
		return nil, err
	}
	if hooksDefined(spec.Hooks) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Error(codes.PermissionDenied,
				"defining VM lifecycle hooks requires the admin role (hooks execute as root on the target host)")
		}
	}
	project := tenancy.NormalizeProject(spec.Project)
	if project != tenancy.Default {
		if p, err := corrosion.GetProject(ctx, s.db, project); err != nil || p == nil {
			return nil, status.Errorf(codes.NotFound, "project %q not found", project)
		}
	}
	for _, n := range spec.Network {
		if err := s.admitNetworkAttach(ctx, project, n.Name); err != nil {
			return nil, err
		}
	}
	for _, d := range spec.Disks {
		if err := s.admitPoolAttach(ctx, project, host, d.Storage); err != nil {
			return nil, err
		}
	}
	if err := s.authorizeVMISO(ctx, project, host, spec); err != nil {
		return nil, err
	}
	if host == s.hostName && spec.GetIso() != "" {
		if _, err := s.resolveVMISO(ctx, project, spec); err != nil {
			return nil, err
		}
	}
	spec.Uuid = ""
	return spec, nil
}

// placeRecreate chooses, before cur is torn down, the host that re-creates it
// from in: placement.Select with the request createVM builds, as main chose
// it after the teardown (vm.go:207-212 at 3e4ba50b). A spec pin restricts it
// exactly as there. What cur holds is released first (Replaces: its CPU,
// memory, VM slot and replica count), and cur is not its own (anti-)affinity
// peer — after the teardown it is gone, and main's Select did not see it.
// No host is preferred for being this one.
func (s *Server) placeRecreate(ctx context.Context, in *pb.VMSpec, cur *corrosion.VMRecord) (string, error) {
	spec, err := normalizeCreateVMSpec(in, s.defaultCPUModeCfg)
	if err != nil {
		return "", err
	}
	compose.NormalizeVMSpecResources(spec)
	req := s.createVMPlacementRequest(ctx, spec, false)
	if cur != nil {
		req.Replaces = placement.VMAllocation(*cur)
		self := func(n string) bool { return n == spec.Name || n == cur.Name }
		req.AntiAffinity = slices.DeleteFunc(slices.Clone(req.AntiAffinity), self)
		req.Affinity = slices.DeleteFunc(slices.Clone(req.Affinity), self)
	}
	host, err := placement.Select(ctx, s.db, req)
	if err != nil {
		return "", placementSelectionError(err)
	}
	return host, nil
}

// judgeRecreateOn runs, before the teardown, every judgement the create on
// host will make that the teardown does not change: this node's own, as the
// entry of that create (recreatePreflightSpec), and, when host is another
// one, host's — asked with PreflightRecreateVM through the same peer path the
// create is forwarded on, so it judges the same caller with the same grant.
//
// A host on an older build has no PreflightRecreateVM; its create judges no
// installer ISO (main had no ISO gate), so it is not asked further.
func (s *Server) judgeRecreateOn(ctx context.Context, in *pb.VMSpec, host string) error {
	spec, err := s.recreatePreflightSpec(ctx, in, host)
	if err != nil || host == s.hostName {
		return err
	}
	client, done, err := s.dialPeer(ctx, host)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach %s, where placement puts the VM, to have it judged: %v", host, err)
	}
	defer done()
	_, err = client.PreflightRecreateVM(withRecreateISOGrantMD(ctx, spec), &pb.PreflightRecreateVMRequest{Spec: spec})
	if status.Code(err) == codes.Unimplemented {
		slog.Info("re-create: the chosen host is on an older build and judges no installer ISO at its create",
			"vm", spec.GetName(), "host", host)
		return nil
	}
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "%s, where placement puts it, would refuse its create: %s", host, st.Message())
	}
	return nil
}

// PreflightRecreateVM is judgeRecreateOn's question to the host placement
// chose: this host judges the spec as its create of it will, with the VM
// still in place elsewhere. Peer-only; the caller it judges is the one the
// peer relays, holding the grant the peer hands over (recreateISOGrantMD).
func (s *Server) PreflightRecreateVM(ctx context.Context, req *pb.PreflightRecreateVMRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetSpec() == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}
	if _, err := s.recreatePreflightSpec(s.acceptRecreateISOGrantMD(ctx), req.GetSpec(), s.hostName); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// recreateISOGrantMD is the metadata key that hands a recreateISOGrant to the
// host a re-create is forwarded to (or asked to judge it). That host honours
// it only from a peer host (acceptRecreateISOGrantMD): a peer already acts as
// an Admin wherever forwarded identity is off, and hands one over only for a
// VM it is re-creating, whose row it read the grant from.
const recreateISOGrantMD = "x-litevirt-recreate-iso-grant"

// withRecreateISOGrantMD returns ctx with the grant ctx holds for spec's ISO
// added to its outgoing metadata, or ctx unchanged when it holds none.
func withRecreateISOGrantMD(ctx context.Context, spec *pb.VMSpec) context.Context {
	g, ok := recreateISOGrantFor(ctx, spec.GetIso(), spec.GetProject())
	if !ok {
		return ctx
	}
	b, err := json.Marshal(recreateISOGrantWire{ISO: g.iso, Scope: g.scope, Project: g.project})
	if err != nil {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, recreateISOGrantMD, string(b))
}

// acceptRecreateISOGrantMD returns ctx holding the grant a peer host handed
// over in its metadata, or ctx unchanged: no grant, several, a malformed one,
// or a caller that is not a peer host.
func (s *Server) acceptRecreateISOGrantMD(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	vals := md.Get(recreateISOGrantMD)
	if len(vals) != 1 || s.requirePeerCert(ctx) != nil {
		return ctx
	}
	var w recreateISOGrantWire
	if err := json.Unmarshal([]byte(vals[0]), &w); err != nil || w.ISO == "" {
		return ctx
	}
	return context.WithValue(ctx, recreateISOGrantKey{},
		recreateISOGrant{iso: w.ISO, scope: w.Scope, project: tenancy.NormalizeProject(w.Project)})
}

type recreateISOGrantWire struct {
	ISO     string `json:"iso"`
	Scope   string `json:"scope,omitempty"`
	Project string `json:"project,omitempty"`
}

package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/network"
)

// Container host bind mounts and device nodes (Proxmox mpN / devN).
//
// A host path inside a container is host access, so it is the admin role's
// to grant, as a privileged container is — and, unlike that opt-out, never
// inherited by a compose recreate. The host that creates (or recreates, or
// starts) the container then judges every path against its own
// containers.bind_mount_paths / containers.device_paths (internal/lxc
// mounts.go): resolved there, symlinks followed, read-only by default, nosuid
// and nodev. Unprivileged containers keep their id map.

// hostAccessDenied is the refusal for a non-admin caller.
const hostAccessDenied = "bind-mounting a host path or passing a host device into a container requires the admin role (a host path inside a container is access to the host)"

// containerHostAccessRequest is a create's check of the mounts and devices it
// asks for: the admin role, the release gate of the usb_mounts_memory feature
// (a fail-fast here; the owner that writes the row takes the grant), and paths
// that can be judged at all. The owning host judges them against its allowed
// prefixes.
func (s *Server) containerHostAccessRequest(ctx context.Context, host string, mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) error {
	if len(mounts) == 0 && len(devices) == 0 {
		return nil
	}
	if err := RequireRole(ctx, "admin"); err != nil {
		return status.Error(codes.PermissionDenied, hostAccessDenied)
	}
	if err := s.passthroughFeatureGate(ctx); err != nil {
		return err
	}
	if err := lxc.CheckHostAccessShape(lxcMountsFromPb(mounts), lxcDevicesFromPb(devices)); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Nothing litevirt already uses on the target host — a VM disk, a pool's
	// device or directory — is handed to a container as well.
	if host == "" {
		host = s.hostName
	}
	var paths []string
	for _, m := range mounts {
		paths = append(paths, m.GetHostPath())
	}
	for _, d := range devices {
		paths = append(paths, d.GetHostPath())
	}
	for _, p := range paths {
		user, err := corrosion.HostPathInUse(ctx, s.db, host, filepath.Clean(p))
		if err != nil {
			return status.Errorf(codes.Internal, "check what uses %s on %s: %v", p, host, err)
		}
		if user != "" {
			return status.Errorf(codes.FailedPrecondition, "%s on %s is %s; it is never also passed into a container", p, host, user)
		}
	}
	return nil
}

func lxcMountsFromPb(in []*pb.ContainerMount) []lxc.Mount {
	out := make([]lxc.Mount, 0, len(in))
	for _, m := range in {
		out = append(out, lxc.Mount{HostPath: m.GetHostPath(), ContainerPath: m.GetContainerPath(), ReadWrite: m.GetReadWrite()})
	}
	return out
}

func lxcDevicesFromPb(in []*pb.ContainerDevice) []lxc.Device {
	out := make([]lxc.Device, 0, len(in))
	for _, d := range in {
		out = append(out, lxc.Device{HostPath: d.GetHostPath(), ContainerPath: d.GetContainerPath()})
	}
	return out
}

// hostAccessSpec converts a create's mounts and devices into the create
// spec's record of them.
func hostAccessSpec(mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) ([]corrosion.ContainerHostMount, []corrosion.ContainerHostDevice) {
	var ms []corrosion.ContainerHostMount
	for _, m := range mounts {
		ms = append(ms, corrosion.ContainerHostMount{HostPath: m.GetHostPath(), ContainerPath: m.GetContainerPath(), ReadWrite: m.GetReadWrite()})
	}
	var ds []corrosion.ContainerHostDevice
	for _, d := range devices {
		ds = append(ds, corrosion.ContainerHostDevice{HostPath: d.GetHostPath(), ContainerPath: d.GetContainerPath()})
	}
	return ms, ds
}

// hostAccessOpts is the create spec's mounts and devices as runtime options.
func hostAccessOpts(spec corrosion.ContainerCreateSpec) ([]ContainerMountOpt, []ContainerDeviceOpt) {
	var ms []ContainerMountOpt
	for _, m := range spec.Mounts {
		ms = append(ms, ContainerMountOpt{HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadWrite: m.ReadWrite})
	}
	var ds []ContainerDeviceOpt
	for _, d := range spec.Devices {
		ds = append(ds, ContainerDeviceOpt{HostPath: d.HostPath, ContainerPath: d.ContainerPath})
	}
	return ms, ds
}

// pbHostAccess is a container record's mounts and devices for the API.
func pbHostAccess(spec corrosion.ContainerCreateSpec) ([]*pb.ContainerMount, []*pb.ContainerDevice) {
	var ms []*pb.ContainerMount
	for _, m := range spec.Mounts {
		ms = append(ms, &pb.ContainerMount{HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadWrite: m.ReadWrite})
	}
	var ds []*pb.ContainerDevice
	for _, d := range spec.Devices {
		ds = append(ds, &pb.ContainerDevice{HostPath: d.HostPath, ContainerPath: d.ContainerPath})
	}
	return ms, ds
}

// hostAccessAudit renders mounts and devices for an audit row.
func hostAccessAudit(mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) string {
	var parts []string
	for _, m := range mounts {
		mode := "ro"
		if m.GetReadWrite() {
			mode = "rw"
		}
		parts = append(parts, "mount="+m.GetHostPath()+":"+m.GetContainerPath()+":"+mode)
	}
	for _, d := range devices {
		parts = append(parts, "device="+d.GetHostPath())
	}
	return strings.Join(parts, " ")
}

// hostAccessRebuilder is the runtime half that makes a container's config
// litevirt's own again from what was authorized (lxc.LxcRunner.RebuildConfig
// through the adapter): security rendered from the confinement and id range,
// host access from the mounts and devices, nothing kept from an archive.
type hostAccessRebuilder interface {
	// RebuildContainerConfig returns what of the config it dropped.
	RebuildContainerConfig(ctx context.Context, name string, cfg AuthorizedContainerConfig) ([]string, error)
}

// AuthorizedContainerConfig is what a rebuilt container config is rendered from.
type AuthorizedContainerConfig struct {
	Confinement string
	IDMapBase   int64
	Mounts      []ContainerMountOpt
	Devices     []ContainerDeviceOpt
	// RenderNetwork renders lxc.net.* from Networks alone (none: create's
	// default), dropping every network line the config holds — a restore,
	// whose config an archive wrote. Unset, the network is kept as it is (a
	// revert or a clone of a config this host wrote).
	RenderNetwork bool
	Networks      []ContainerNICOpt
}

// networkMode is what a config rebuild does with the container's network.
type networkMode int

const (
	// networkKeep keeps the config's network as it is: a revert, or a clone
	// of a config this host wrote.
	networkKeep networkMode = iota
	// networkRender renders lxc.net.* from the authorized spec's NICs alone
	// (none: create's default), dropping every network line the config
	// holds: a restore, whose config an archive wrote.
	networkRender
	// networkKeepBridgeNICs keeps the veth-on-bridge NICs the config holds
	// (lxc.BridgeNICs) and drops every other NIC: a peer move of a container
	// whose row predates the create spec and so records no NICs.
	networkKeepBridgeNICs
)

// restoredNetworkMode is how a restore renders the container's network. A
// peer move takes the NICs its source row records; a row with no create spec
// at all (an earlier build's) records none, so the archive's bridge NICs are
// kept, as on main, and every other kind dropped. An operator restore always
// renders the authorized spec's NICs (none: the default bridge), audited.
func restoredNetworkMode(operatorRestore bool, source *corrosion.ContainerRecord) networkMode {
	if !operatorRestore && source != nil && source.CreateSpec == "" {
		return networkKeepBridgeNICs
	}
	return networkRender
}

// containerConfigNICReader is a runtime that reads the bridge NICs a
// container's config holds (lxc.LxcRunner.ConfigNICs).
type containerConfigNICReader interface {
	ContainerConfigNICs(name string) ([]lxc.NetworkAttach, error)
}

// SetSourceRowWait sets how long a peer move's restore waits for the source
// row to reach this replica (tests).
func (s *Server) SetSourceRowWait(d time.Duration) { s.sourceRowWait = d }

// defaultSourceRowWait bounds how long a peer move's restore waits for the
// source row to reach this replica: well inside the coordinator's
// fresh-marker window, so a relocation that waits never races the
// coordinator's own fallback.
const defaultSourceRowWait = 20 * time.Second

// sourceRowPoll is how often that wait re-reads the replica.
const sourceRowPoll = 250 * time.Millisecond

// peerMoveSource is the row a peer move's container is authorized by: the
// spec the moving peer read off it and sent (req.SourceCreateSpec), else the
// row in this host's replica — the cold migrate's source row, or the row the
// failover coordinator marked for this restore — waited for up to
// sourceRowWait, since the move can outrun replication. A row that cannot be
// read fails the restore (Unavailable, retried). When the row still has not
// arrived:
//   - a cold migrate refuses before anything is written (FailedPrecondition,
//     which its source reads as "nothing landed" and rolls back, the
//     container intact);
//   - a relocation that sent no row comes from an earlier-build coordinator.
//     Refusing would end in its image-recreate fallback and lose the backed-up
//     data main restores, so it restores as main did: the source is nil (no
//     error), its NICs are admitted from the archive by their network records
//     (mainRelocationNICs), and host access and privilege are not carried.
func (s *Server) peerMoveSource(ctx context.Context, req *pb.RestoreContainerRequest, migrateSource string) (*corrosion.ContainerRecord, error) {
	if spec := req.GetSourceCreateSpec(); spec != "" {
		return &corrosion.ContainerRecord{Name: req.Name, CreateSpec: spec}, nil
	}
	token := relocateTokenFromMD(ctx)
	if token == "" && req.Proof != nil {
		token = req.Proof.GetRelocationToken()
	}
	lookup := func() (*corrosion.ContainerRecord, error) {
		if migrateSource != "" {
			return corrosion.GetContainer(ctx, s.db, migrateSource, req.Name)
		}
		return s.relocatingContainer(ctx, req.Name, s.hostName, token)
	}
	wait := s.sourceRowWait
	if wait <= 0 {
		wait = defaultSourceRowWait
	}
	deadline := time.Now().Add(wait)
	source, err := lookup()
	for err == nil && source == nil && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, status.Errorf(codes.Unavailable, "restore: waiting for container %q's source row: %v", req.Name, ctx.Err())
		case <-time.After(sourceRowPoll):
		}
		source, err = lookup()
	}
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "restore: read the source container's row (what authorizes its NICs, host access and privilege): %v", err)
	}
	if source != nil {
		return source, nil
	}
	if migrateSource != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "restore: this host has not seen container %q's source row yet (replication still catching up?): "+
			"a move takes the container's NICs, host access and privilege from that row, never from the archive; retry the move once it has replicated", req.Name)
	}
	slog.Warn("container relocation: no source row here and none sent (an earlier-build coordinator); restoring as before: NICs admitted from the archive by their network records, host access and privilege not carried",
		"name", req.Name, "waited", wait)
	return nil, nil
}

// rebuildContainerConfig renders name's config from the authorized spec cs.
// The security is cs's; where cs records none (an earlier build's
// container), what the config holds now — set by litevirt's own convert — is
// kept, and so is an id range the config holds that cs does not: neither is
// ever loosened by a rebuild. A runtime that cannot rebuild refuses, unless
// there is nothing to render.
func (s *Server) rebuildContainerConfig(ctx context.Context, name string, cs corrosion.ContainerCreateSpec) error {
	_, err := s.renderContainerConfig(ctx, name, cs, networkKeep)
	return err
}

// renderContainerConfig is rebuildContainerConfig that renders the network
// as net says, and returns what of the config was dropped.
func (s *Server) renderContainerConfig(ctx context.Context, name string, cs corrosion.ContainerCreateSpec, net networkMode) ([]string, error) {
	rb, ok := s.containerRuntime.(hostAccessRebuilder)
	if !ok {
		if len(cs.Mounts) > 0 || len(cs.Devices) > 0 || net != networkKeep {
			return nil, status.Error(codes.Unavailable, "this host's container runtime cannot render a container's config")
		}
		return nil, nil
	}
	cfg := AuthorizedContainerConfig{Confinement: cs.Confinement, IDMapBase: cs.IDMapBase}
	if sc, ok := s.containerRuntime.(containerSecurer); ok {
		if cur, err := sc.ContainerSecurity(name); err == nil {
			if cfg.Confinement == "" {
				cfg.Confinement = cur.Confinement
			}
			if cfg.IDMapBase == 0 && cur.IDMap != nil {
				cfg.IDMapBase = cur.IDMap.Base
			}
		}
	}
	cfg.Mounts, cfg.Devices = hostAccessOpts(cs)
	switch net {
	case networkRender:
		cfg.RenderNetwork = true
		cfg.Networks = s.authorizedContainerNICs(ctx, name, cs)
	case networkKeepBridgeNICs:
		rd, ok := s.containerRuntime.(containerConfigNICReader)
		if !ok {
			return nil, status.Error(codes.Unavailable, "this host's container runtime cannot read a container's NICs from its config")
		}
		nics, err := rd.ContainerConfigNICs(name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read %q's NICs from its config: %v", name, err)
		}
		cfg.RenderNetwork = true
		cfg.Networks = make([]ContainerNICOpt, 0, len(nics))
		for _, n := range nics {
			cfg.Networks = append(cfg.Networks, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: n.IP, MAC: n.MAC, Veth: n.Veth, Gateway: n.Gateway})
		}
	}
	dropped, err := rb.RebuildContainerConfig(ctx, name, cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "render %q's config from its authorized spec: %v", name, err)
	}
	return dropped, nil
}

// authorizedContainerNICs are the runtime NICs of cs's networks, as a
// relocation renders them: a managed NIC with its deterministic veth and the
// subnet's prefix and gateway, a raw bridge as recorded.
func (s *Server) authorizedContainerNICs(ctx context.Context, name string, cs corrosion.ContainerCreateSpec) []ContainerNICOpt {
	out := make([]ContainerNICOpt, 0, len(cs.Networks))
	haveGateway := false
	for i, n := range cs.Networks {
		if n.NetworkName == "" {
			out = append(out, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: n.IP, MAC: n.MAC})
			continue
		}
		runIP, gw := network.ContainerAddress(n.IP, s.containerNetworkSubnet(ctx, n.NetworkName))
		if haveGateway {
			gw = ""
		}
		haveGateway = haveGateway || gw != ""
		out = append(out, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: runIP, MAC: n.MAC, Veth: containerVethName(name, i), Gateway: gw})
	}
	return out
}

// containerNetworkSubnet is a managed network's subnet, or "" (none, or
// unreadable: the NIC then keeps its address as recorded).
func (s *Server) containerNetworkSubnet(ctx context.Context, name string) string {
	nr, err := corrosion.GetNetwork(ctx, s.db, name)
	if err != nil || nr == nil {
		return ""
	}
	var def struct{ Subnet string }
	if json.Unmarshal([]byte(nr.Config), &def) != nil {
		return ""
	}
	return def.Subnet
}

// sameHostAccess reports whether two specs carry the same mounts and devices.
func sameHostAccess(a, b corrosion.ContainerCreateSpec) bool {
	return reflect.DeepEqual(a.Mounts, b.Mounts) && reflect.DeepEqual(a.Devices, b.Devices)
}

// withoutHostAccess returns cs without its mounts and devices, and a
// description of what was dropped ("" when nothing was).
func withoutHostAccess(cs corrosion.ContainerCreateSpec) (corrosion.ContainerCreateSpec, string) {
	if len(cs.Mounts) == 0 && len(cs.Devices) == 0 {
		return cs, ""
	}
	mounts, devices := pbHostAccess(cs)
	what := hostAccessAudit(mounts, devices)
	cs.Mounts, cs.Devices = nil, nil
	return cs, what
}

// authorizeRestoredHostAccess decides which host mounts and devices a
// restored container may carry. They come from a backup's create spec, which
// grants nothing on its own:
//   - an operator restore keeps them only for a caller with the admin role,
//     while the release gate is open;
//   - a peer-driven relocation or cold migration keeps them only when they
//     are exactly what the SOURCE ROW (replicated, admin-authorized) records.
//
// Anything else is stripped; stripped describes what, for the audit row and
// the admin who re-applies them (lv ct convert --mount/--device).
//
// An operator restore that keeps them writes the feature's data afresh, so it
// takes the feature's grant on this node (the one that writes the row), and
// the row is written with it (createRestoredContainerRow). Before the release
// token latches it strips them, as main does. After the latch a gate refusal
// (a first use not yet acknowledged, a host rolled back after the latch) is
// returned as err and the restore refuses, so the admin can retry: what an
// admin restore keeps is never silently dropped. A peer move keeps what the
// source row already holds, and takes none.
//
// without is an operator restore's explicit request to leave them out (lv
// ct restore --without-host-access): they are stripped, said so, and no
// grant is asked. It is the disaster-recovery way out while the gate cannot
// grant the first use (a host down for good, or in release probation). A
// peer move ignores it: it carries what its source row records.
func (s *Server) authorizeRestoredHostAccess(ctx context.Context, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord, peer, without bool) (corrosion.ContainerCreateSpec, string, capabilities.FeatureGrant, error) {
	var none capabilities.FeatureGrant
	if !containerSpecSetsHostAccess(cs) {
		return cs, "", none, nil
	}
	if !peer && without {
		out, stripped := withoutHostAccess(cs)
		return out, stripped, none, nil
	}
	if peer {
		if source != nil && sameHostAccess(cs, corrosion.DecodeCreateSpec(source.CreateSpec)) {
			return cs, "", none, nil
		}
		out, stripped := withoutHostAccess(cs)
		return out, stripped, none, nil
	}
	if RequireRole(ctx, "admin") == nil {
		g, ok, err := s.passthroughGrantIfLatched(ctx)
		if err != nil {
			return cs, "", none, err
		}
		if ok {
			return cs, "", g, nil
		}
	}
	out, stripped := withoutHostAccess(cs)
	return out, stripped, none, nil
}

// createRestoredContainerRow writes a restored container's row, choosing the
// writer by what the row carries: host access an operator restore kept goes
// through the feature's writer with g (refused without the grant); a peer
// move keeping its source row's host access, or a container without any, is
// written as before.
func (s *Server) createRestoredContainerRow(ctx context.Context, g capabilities.FeatureGrant, peer bool, rec corrosion.ContainerRecord, ifaces []corrosion.ContainerInterfaceRecord) error {
	if !peer && containerSpecSetsHostAccess(corrosion.DecodeCreateSpec(rec.CreateSpec)) {
		return corrosion.CreateContainerAtomicWithHostAccess(ctx, s.db, g, rec, ifaces)
	}
	return corrosion.CreateContainerAtomic(ctx, s.db, rec, ifaces)
}

// escalatedSecurity reports whether a spec runs privileged (no id range) or
// with legacy confinement ("" is an earlier build's: legacy too).
func escalatedSecurity(cs corrosion.ContainerCreateSpec) bool {
	return cs.IDMapBase == 0 || cs.Confinement == "" || cs.Confinement == lxc.ConfinementLegacy
}

// sameSecurity reports whether two specs run with the same privilege mode and
// confinement.
func sameSecurity(a, b corrosion.ContainerCreateSpec) bool {
	norm := func(c string) string {
		if c == "" {
			return lxc.ConfinementLegacy
		}
		return c
	}
	return (a.IDMapBase == 0) == (b.IDMapBase == 0) && norm(a.Confinement) == norm(b.Confinement)
}

// authorizeRestoredSecurity decides whether a restored container keeps the
// privileged mode or legacy confinement its backup's create spec records —
// the same host-escalation class as a host mount, and decided the same way:
// kept for an admin's operator restore, or for a peer-driven move whose
// SOURCE ROW records exactly that mode; otherwise stripped. A stripped
// container runs with default confinement, and unprivilege reports that it
// needs an id range of its own (the caller allocates it and shifts its
// files). An admin re-applies the mode: legacy confinement with lv ct
// convert --confinement legacy, a privileged mode by restoring it as admin.
func (s *Server) authorizeRestoredSecurity(ctx context.Context, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord, peer bool) (out corrosion.ContainerCreateSpec, stripped string, unprivilege bool) {
	if !escalatedSecurity(cs) {
		return cs, "", false
	}
	if peer {
		if source != nil && sameSecurity(cs, corrosion.DecodeCreateSpec(source.CreateSpec)) {
			return cs, "", false
		}
	} else if RequireRole(ctx, "admin") == nil {
		return cs, "", false
	}
	var what []string
	if cs.IDMapBase == 0 {
		what = append(what, "privileged")
		unprivilege = true
	}
	if cs.Confinement != lxc.ConfinementDefault {
		what = append(what, "confinement=legacy")
	}
	cs.Confinement = lxc.ConfinementDefault
	return cs, strings.Join(what, " "), unprivilege
}

// unprivilegeContainer moves a stopped container that may not keep its
// privileged mode or legacy confinement into an id range of its own (its
// files shifted) with default confinement, and returns the range's base. A
// conversion an earlier attempt left unfinished is finished into the range
// its marker recorded — its files are already partly there — never a new one.
func (s *Server) unprivilegeContainer(ctx context.Context, sc containerSecurer, name string) (int64, error) {
	sec, err := sc.ContainerSecurity(name)
	if err != nil {
		return 0, err
	}
	var base int64
	switch {
	case sec.Converting && sec.ConvertTo != nil && sec.ConvertTo.IDMap != nil:
		base = sec.ConvertTo.IDMap.Base
	case sec.IDMap != nil:
		base = sec.IDMap.Base // already unprivileged: only the confinement moves
	default:
		if base, err = s.allocateIDMapBase(ctx, name); err != nil {
			return 0, err
		}
	}
	if err := sc.ConvertContainerSecurity(ctx, name, lxc.ConvertOpts{
		IDMap: &lxc.IDMap{Base: base, Size: lxc.IDMapSize}, Confinement: lxc.ConfinementDefault}); err != nil {
		return 0, err
	}
	return base, nil
}

// noteStrippedHostAccess records host access a restore or clone did not carry.
func (s *Server) noteStrippedHostAccess(ctx context.Context, action, name, stripped string) {
	if stripped == "" {
		return
	}
	slog.Warn("container: host access or privilege was not carried; an admin re-applies it", "container", name, "action", action, "stripped", stripped)
	s.audit(ctx, action, name, "not carried (an admin re-applies host mounts/devices with lv ct convert --mount/--device, legacy confinement with lv ct convert --confinement legacy, a privileged mode by restoring as admin): "+stripped, "ok")
}

// authorizeRestoredNICs decides where a restored container's NICs attach.
// The archive's spec names bridges and networks, and a bridge is host access
// too, so nothing is taken from it on its word.
//
// A peer move (peer: a cold migrate or a failover relocation) re-homes an
// existing container, so its NICs are the ones its SOURCE ROW records, matched
// by NIC name — managed NICs included (peerMoveNICs). An archive NIC the row
// does not record is dropped and said, wherever it points.
//
// An operator restore classifies each NIC first — a raw bridge that renders a
// managed network IS that network's NIC — and then admits it as create admits
// it, on what it now is:
//   - a managed NIC is kept only if its network record exists (a name with no
//     record is dropped: never the flat-bridge fallback, which would land it
//     on whatever host bridge carries that name), its type is one a container
//     can use (not direct or sriov), and the project may attach to it
//     (admitManagedNetwork, or admitNetworkAttach for a reclassified raw
//     bridge). It is rendered on its network's own bridge, whatever bridge the
//     spec names;
//   - a raw NIC (no managed network) is kept only for a caller with raw-bridge
//     authority (admitRawBridge, as create requires).
//
// Everything else is dropped and reported, and the restore proceeds. A
// network record or list that cannot be read fails the restore
// (Unavailable): "not found" is an answer that read did not give.
func (s *Server) authorizeRestoredNICs(ctx context.Context, project string, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord, peer bool) (corrosion.ContainerCreateSpec, []string, error) {
	if peer && source == nil {
		return s.mainRelocationNICs(ctx, project, cs)
	}
	if peer {
		return s.peerMoveNICs(ctx, cs, source)
	}
	var out []corrosion.ContainerNetwork
	var dropped []string
	for _, n := range cs.Networks {
		reclassified := false
		if n.NetworkName == "" {
			name, ok, err := s.resolveBridgeToNetwork(ctx, n.Bridge)
			if err != nil {
				return cs, nil, status.Errorf(codes.Unavailable, "restore: read the networks (what decides whether NIC %s's bridge %s is a managed network): %v", n.Name, n.Bridge, err)
			}
			if ok {
				n.NetworkName, reclassified = name, true
			}
		}
		if n.NetworkName != "" {
			def, err := lookupNetworkDef(ctx, s.db, n.NetworkName)
			if err != nil {
				return cs, nil, status.Errorf(codes.Unavailable, "restore: read network %q (what decides where NIC %s attaches): %v", n.NetworkName, n.Name, err)
			}
			if def == nil {
				dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+", which does not exist")
				continue
			}
			if def.Type == "direct" || def.Type == "sriov" {
				dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+" of type "+def.Type+", which containers cannot use")
				continue
			}
			admit := s.admitManagedNetwork
			if reclassified {
				admit = s.admitNetworkAttach
			}
			if aerr := admit(ctx, project, n.NetworkName); aerr != nil {
				if status.Code(aerr) != codes.PermissionDenied {
					return cs, nil, status.Errorf(codes.Unavailable, "restore: %s", status.Convert(aerr).Message())
				}
				dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+": "+status.Convert(aerr).Message())
				continue
			}
			n.Bridge = network.BridgeName(n.NetworkName, *def)
			out = append(out, n)
			continue
		}
		if s.admitRawBridge(ctx, n.Bridge) == nil {
			out = append(out, n)
			continue
		}
		dropped = append(dropped, "raw NIC "+n.Name+" on bridge "+n.Bridge)
	}
	cs.Networks = out
	return cs, dropped, nil
}

// mainRelocationNICs are the NICs of a relocation with no source row (an
// earlier-build coordinator whose mark never reached this replica,
// peerMoveSource): restored as main restored them, from the archive, but
// admitted by their network records — a managed NIC is kept when its record
// exists, is a container's type and is one the project may use, on that
// network's own bridge. A raw NIC (nothing here authorizes it), a missing
// network and another project's are dropped and said. A record that cannot
// be read fails the restore (Unavailable).
func (s *Server) mainRelocationNICs(ctx context.Context, project string, cs corrosion.ContainerCreateSpec) (corrosion.ContainerCreateSpec, []string, error) {
	var out []corrosion.ContainerNetwork
	var dropped []string
	for _, n := range cs.Networks {
		if n.NetworkName == "" {
			dropped = append(dropped, "raw NIC "+n.Name+" on bridge "+n.Bridge+": no source row here authorizes it")
			continue
		}
		def, err := lookupNetworkDef(ctx, s.db, n.NetworkName)
		if err != nil {
			return cs, nil, status.Errorf(codes.Unavailable, "restore: read network %q (what decides where NIC %s attaches): %v", n.NetworkName, n.Name, err)
		}
		if def == nil {
			dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+", which does not exist")
			continue
		}
		if def.Type == "direct" || def.Type == "sriov" {
			dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+" of type "+def.Type+", which containers cannot use")
			continue
		}
		if aerr := s.admitManagedNetwork(ctx, project, n.NetworkName); aerr != nil {
			if status.Code(aerr) != codes.PermissionDenied {
				return cs, nil, status.Errorf(codes.Unavailable, "restore: %s", status.Convert(aerr).Message())
			}
			dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+": "+status.Convert(aerr).Message())
			continue
		}
		n.Bridge = network.BridgeName(n.NetworkName, *def)
		out = append(out, n)
	}
	cs.Networks = out
	return cs, dropped, nil
}

// peerMoveNICs are a peer-moved container's NICs: exactly those its source
// row records, in the row's order, with the row's address and MAC (R4-I1,
// R4-I2). As on main, a NIC the container holds is never lost to the move:
//   - a managed NIC whose network record exists is rendered on that
//     network's bridge;
//   - one whose record is absent here (force-deleted, or not replicated yet)
//     keeps the bridge the row records — the row was admitted when it was
//     created — and so does a network now of a type containers cannot use
//     (direct, sriov: a network re-created under the same name);
//   - a raw NIC keeps its bridge.
//
// An archive NIC the row does not record is dropped and said. A row with no create spec records no
// NICs; its archive's network is kept (restoredNetworkMode) and its spec's
// NICs are not claimed for the restored row.
func (s *Server) peerMoveNICs(ctx context.Context, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord) (corrosion.ContainerCreateSpec, []string, error) {
	if source.CreateSpec == "" {
		cs.Networks = nil
		return cs, nil, nil
	}
	row := corrosion.DecodeCreateSpec(source.CreateSpec).Networks
	recorded := map[string]bool{}
	for _, n := range row {
		recorded[n.Name] = true
	}
	var dropped []string
	for _, n := range cs.Networks {
		if !recorded[n.Name] {
			where := n.Bridge
			if n.NetworkName != "" {
				where = n.NetworkName
			}
			dropped = append(dropped, "NIC "+n.Name+" on "+where+": the source container's row does not record it")
		}
	}
	out := make([]corrosion.ContainerNetwork, 0, len(row))
	for _, n := range row {
		if n.NetworkName != "" {
			def, err := lookupNetworkDef(ctx, s.db, n.NetworkName)
			if err != nil {
				return cs, nil, status.Errorf(codes.Unavailable, "restore: read network %q (what decides where NIC %s attaches): %v", n.NetworkName, n.Name, err)
			}
			if def != nil && def.Type != "direct" && def.Type != "sriov" {
				n.Bridge = network.BridgeName(n.NetworkName, *def)
			}
		}
		if n.Bridge == "" {
			// Nothing to attach it to: no record here, and the row names no
			// bridge (an earlier build's row). Said, never guessed.
			dropped = append(dropped, "NIC "+n.Name+" on network "+n.NetworkName+": no network record here and the row records no bridge")
			continue
		}
		out = append(out, n)
	}
	cs.Networks = out
	return cs, dropped, nil
}

// noteDroppedArchiveConfig says what of an archived config the rebuild
// dropped — network lines the spec does not render among them.
func (s *Server) noteDroppedArchiveConfig(ctx context.Context, action, name string, dropped []string) {
	if len(dropped) == 0 {
		return
	}
	slog.Warn("container: the archive's config lines were not carried; the config was rendered from the authorized spec", "container", name, "action", action, "dropped", dropped)
	s.audit(ctx, action, name, "archive config not carried (rendered from the authorized spec instead): "+strings.Join(dropped, "; "), "ok")
}

// cloneHostAccessAllowed refuses a non-admin clone of a container with host
// mounts or devices: the clone is a new container holding the same host
// access, which only the admin role grants.
func cloneHostAccessAllowed(ctx context.Context, src corrosion.ContainerRecord) error {
	spec := corrosion.DecodeCreateSpec(src.CreateSpec)
	if len(spec.Mounts) == 0 && len(spec.Devices) == 0 {
		return nil
	}
	if err := RequireRole(ctx, "admin"); err != nil {
		return status.Error(codes.PermissionDenied, "the source container has host mounts or devices; "+hostAccessDenied)
	}
	return nil
}

// hostAccessBusyCode is Unavailable (retry) for a runtime error saying the
// container's host-access lock stayed held — a policy refresh stuck in a
// lookup that does not return — and otherwise code.
func hostAccessBusyCode(err error, code codes.Code) codes.Code {
	if errors.Is(err, lxc.ErrHostAccessBusy) {
		return codes.Unavailable
	}
	return code
}

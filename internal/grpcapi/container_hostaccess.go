package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// asks for: the admin role, the usb_mounts_memory_v1 gate, and paths that can
// be judged at all. The owning host judges them against its allowed prefixes.
func (s *Server) containerHostAccessRequest(ctx context.Context, host string, mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) error {
	if len(mounts) == 0 && len(devices) == 0 {
		return nil
	}
	if err := RequireRole(ctx, "admin"); err != nil {
		return status.Error(codes.PermissionDenied, hostAccessDenied)
	}
	if !s.passthroughFeaturesActive(ctx) {
		return passthroughRefusal("container host mounts and devices")
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

// rebuildContainerConfig renders name's config from the authorized spec cs.
// The security is cs's; where cs records none (an earlier build's
// container), what the config holds now — set by litevirt's own convert — is
// kept, and so is an id range the config holds that cs does not: neither is
// ever loosened by a rebuild. A runtime that cannot rebuild refuses, unless
// there is nothing to render.
func (s *Server) rebuildContainerConfig(ctx context.Context, name string, cs corrosion.ContainerCreateSpec) error {
	_, err := s.renderContainerConfig(ctx, name, cs, false)
	return err
}

// renderContainerConfig is rebuildContainerConfig that, with renderNetwork,
// renders the network from cs as well, and returns what of the config was
// dropped.
func (s *Server) renderContainerConfig(ctx context.Context, name string, cs corrosion.ContainerCreateSpec, renderNetwork bool) ([]string, error) {
	rb, ok := s.containerRuntime.(hostAccessRebuilder)
	if !ok {
		if len(cs.Mounts) > 0 || len(cs.Devices) > 0 || renderNetwork {
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
	if renderNetwork {
		cfg.RenderNetwork = true
		cfg.Networks = s.authorizedContainerNICs(ctx, name, cs)
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
func (s *Server) authorizeRestoredHostAccess(ctx context.Context, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord, peer bool) (corrosion.ContainerCreateSpec, string) {
	if len(cs.Mounts) == 0 && len(cs.Devices) == 0 {
		return cs, ""
	}
	if peer {
		if source != nil && sameHostAccess(cs, corrosion.DecodeCreateSpec(source.CreateSpec)) {
			return cs, ""
		}
		return withoutHostAccess(cs)
	}
	if RequireRole(ctx, "admin") == nil && s.passthroughFeaturesActive(ctx) {
		return cs, ""
	}
	return withoutHostAccess(cs)
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
// too, so nothing is taken from it on its word. Each NIC is first classified
// — a raw bridge that renders a managed network IS that network's NIC — and
// then admitted as create admits it, on what it now is:
//   - a managed NIC is kept only if its network record exists (a name with no
//     record is dropped: never the flat-bridge fallback, which would land it
//     on whatever host bridge carries that name), its type is one a container
//     can use (not direct or sriov), and — for an operator restore — the
//     project may attach to it (admitManagedNetwork, or admitNetworkAttach for
//     a reclassified raw bridge). It is rendered on its network's own bridge,
//     whatever bridge the spec names. A peer move re-homes an existing
//     container, so a foreign network is recorded (foreignNetworks) rather
//     than dropped, but a raw bridge reclassified as a network is kept there
//     only when the SOURCE ROW records that NIC;
//   - a raw NIC (no managed network) is kept only for a caller with raw-bridge
//     authority (admitRawBridge, as create requires), or — on a peer move,
//     where the caller is the peer — when the SOURCE ROW records that raw NIC.
//
// Everything else is dropped and reported, and the restore proceeds. A
// network record that cannot be read fails the restore (Unavailable): "not
// found" is an answer that read did not give.
func (s *Server) authorizeRestoredNICs(ctx context.Context, project string, cs corrosion.ContainerCreateSpec, source *corrosion.ContainerRecord, peer bool) (corrosion.ContainerCreateSpec, []string, error) {
	var sourceRaw, sourceManaged map[string]bool
	if peer && source != nil {
		sourceRaw, sourceManaged = map[string]bool{}, map[string]bool{}
		for _, n := range corrosion.DecodeCreateSpec(source.CreateSpec).Networks {
			if n.NetworkName == "" {
				sourceRaw[n.Name+"\x00"+n.Bridge] = true
			} else {
				sourceManaged[n.Name+"\x00"+n.NetworkName] = true
			}
		}
	}
	var out []corrosion.ContainerNetwork
	var dropped []string
	for _, n := range cs.Networks {
		reclassified := false
		if n.NetworkName == "" {
			if name, ok := s.resolveBridgeToNetwork(ctx, n.Bridge); ok {
				if peer && !sourceRaw[n.Name+"\x00"+n.Bridge] && !sourceManaged[n.Name+"\x00"+name] {
					dropped = append(dropped, "NIC "+n.Name+" on bridge "+n.Bridge+" (network "+name+"): the source container's row does not record it")
					continue
				}
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
			if !peer {
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
			}
			n.Bridge = network.BridgeName(n.NetworkName, *def)
			out = append(out, n)
			continue
		}
		keep := false
		if peer {
			keep = sourceRaw[n.Name+"\x00"+n.Bridge]
		} else {
			keep = s.admitRawBridge(ctx, n.Bridge) == nil
		}
		if keep {
			out = append(out, n)
			continue
		}
		dropped = append(dropped, "raw NIC "+n.Name+" on bridge "+n.Bridge)
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

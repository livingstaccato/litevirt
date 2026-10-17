package grpcapi

import (
	"context"
	"fmt"
	"github.com/litevirt/litevirt/internal/network"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/vmimport"
)

// Per-NIC MTU (release feature nic_mtu). The value rides in the stored spec
// (NetworkAttachment.mtu); every render of the domain resolves it against the
// bridge on the defining host (libvirt.ResolveNICMTU), after that host's
// network provisioning.

// specSetsNICMTU reports whether a spec sets any NIC's MTU.
func specSetsNICMTU(spec *pb.VMSpec) bool {
	for _, n := range spec.GetNetwork() {
		if n.GetMtu() != 0 {
			return true
		}
	}
	return false
}

// validateSpecNICMTU checks each NIC's MTU the way the compose parser does.
func validateSpecNICMTU(spec *pb.VMSpec) error {
	for i, n := range spec.GetNetwork() {
		if err := compose.ValidateNICMTU(n.GetModel(), n.GetMtu()); err != nil {
			return fmt.Errorf("network %d: %w", i, err)
		}
	}
	return nil
}

// refuseUnlatchedNICMTU is the entry-node gate: a spec that sets an MTU is
// refused until the release token has latched, before anything is created or
// forwarded. It records nothing; the writing node takes the grant
// (nicMTUGrant). A spec with no MTU never asks.
func (s *Server) refuseUnlatchedNICMTU(ctx context.Context, spec *pb.VMSpec) error {
	if !specSetsNICMTU(spec) {
		return nil
	}
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureNICMTU)
}

// refuseUnlatchedStackNICMTU refuses a compose file that sets an MTU, up
// front, rather than by the Nth VM's create after N-1 are up.
func (s *Server) refuseUnlatchedStackNICMTU(ctx context.Context, f *compose.File) error {
	for name, vm := range f.VMs {
		if vm.IsContainer() {
			continue
		}
		for _, n := range vm.Network {
			if n.MTU.IsZero() {
				continue
			}
			if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureNICMTU); err != nil {
				return status.Errorf(codes.FailedPrecondition, "vm %q: %s", name, status.Convert(err).Message())
			}
			return nil
		}
	}
	return nil
}

// nicMTUGrant runs the feature's gate on THIS node, the one that writes the
// spec, and returns the grant its writer checks.
func (s *Server) nicMTUGrant(ctx context.Context) (capabilities.FeatureGrant, error) {
	var g capabilities.FeatureGrant
	err := s.WithReleaseFeature(ctx, capabilities.FeatureNICMTU,
		func(_ context.Context, got capabilities.FeatureGrant) error { g = got; return nil })
	return g, err
}

// restoredNICMTU is what restrictRestoredNICMTU decided for a restored or
// promoted spec.
type restoredNICMTU struct {
	// stripped: the spec's MTUs were dropped (the feature is not open).
	stripped bool
	// grant is the feature's grant when the MTUs are kept.
	grant capabilities.FeatureGrant
	// invalid names each MTU dropped because a create would refuse it.
	invalid []string
}

// restrictRestoredNICMTU is the gate for a spec that did not come from a
// validated create: a backup manifest or a promoted record. Before the
// feature is open the MTUs are dropped with a warning (a restore main allows
// is never refused over one); after it, an MTU a create would refuse is
// dropped and named, and the rest is kept under the feature's grant.
func (s *Server) restrictRestoredNICMTU(ctx context.Context, spec *pb.VMSpec) restoredNICMTU {
	var r restoredNICMTU
	if !specSetsNICMTU(spec) {
		return r
	}
	if s.ReleaseFeatureAvailable(capabilities.FeatureNICMTU) {
		for i, n := range spec.GetNetwork() {
			if err := compose.ValidateNICMTU(n.GetModel(), n.GetMtu()); err != nil {
				r.invalid = append(r.invalid, fmt.Sprintf("network %d mtu (%v)", i, err))
				n.Mtu = 0
			}
		}
		for _, d := range r.invalid {
			slog.Warn("restored spec: invalid NIC MTU dropped", "vm", spec.GetName(), "dropped", d)
		}
		if !specSetsNICMTU(spec) {
			return r
		}
		g, err := s.nicMTUGrant(ctx)
		if err == nil {
			r.grant = g
			return r
		}
		slog.Warn("restored spec: NIC MTU dropped", "vm", spec.GetName(), "why", status.Convert(err).Message())
	} else {
		slog.Warn("restored spec: NIC MTU dropped", "vm", spec.GetName(), "why", "the cluster upgrade has not finished")
	}
	for _, n := range spec.GetNetwork() {
		n.Mtu = 0
	}
	r.stripped = true
	return r
}

// renderStatus is the status of a failed domain render: a NIC MTU this host
// cannot carry is the operator's to fix (FailedPrecondition, the renderer's
// own words); anything else is Internal.
func renderStatus(what string, err error) error {
	code := codes.Internal
	if lv.IsNICMTUError(err) {
		code = codes.FailedPrecondition
	}
	return status.Errorf(code, "%s: %v", what, err)
}

// bridgeMTUReader reads a bridge's MTU on this host: through the libvirt
// backend when it answers per node (a test's), else the host's own.
func (s *Server) bridgeMTUReader() func(string) (int, error) {
	if r, ok := s.virt.(lv.BridgeMTUReader); ok {
		return r.BridgeMTU
	}
	return lv.ReadBridgeMTU
}

// withNICMTU gives a domain config this host's bridge-MTU reader and name, so
// its NICs' MTUs resolve against the bridges here.
func (s *Server) withNICMTU(cfg *lv.VMConfig) {
	cfg.BridgeMTU = s.bridgeMTUReader()
	cfg.HostName = s.hostName
}

// requestSetsNICMTU reports whether an update sets a NIC's MTU. Removing one
// (0) sets nothing.
func requestSetsNICMTU(req *pb.UpdateVMRequest) bool {
	for _, u := range req.GetNicMtu() {
		if u.GetMtu() != 0 {
			return true
		}
	}
	return false
}

// applyNICMTURequest merges an UpdateVM's NIC MTUs into spec, validated, and
// checks each against its bridge on this host, so a refusal comes before
// anything is stopped. Each update names a NIC by spec index, or by its
// position in the VM's NIC list (nicIndex). A NIC the stored spec does not describe (a hot-plugged
// one) gets an entry made from its NIC record, carrying its MAC, as does
// every such NIC before it in the list — except on a VM of a stack (stack
// non-empty), whose NIC list is its compose file's: a longer list would read
// as a topology change and recreate the VM at the next deploy, so such a NIC
// is refused.
func (s *Server) applyNICMTURequest(ctx context.Context, spec *pb.VMSpec, req *pb.UpdateVMRequest, stack string, ix nicIndex) error {
	nics := ix.nics
	// An entry made for an unlisted NIC takes its recorded model: the merged
	// row reads virtio when a newer vm_interfaces row wins the merge.
	rowModels, reattached, err := corrosion.NICModelSources(ctx, s.db, req.GetName(), nics, compose.SpecNICModelsByMAC(spec))
	if err != nil {
		return status.Errorf(codes.Internal, "read NIC models of %q: %v", req.GetName(), err)
	}
	// The model each live NIC renders with: an MTU is judged against it as
	// well as against the spec entry, which on a VM of a stack can be a
	// detached NIC's (a NIC attached again under its MAC with another model
	// leaves the entry as the compose file wrote it).
	nicModels := compose.NewNICModels(spec, rowModels, reattached)
	seen := map[int]bool{}
	for _, u := range req.GetNicMtu() {
		o := int(u.GetOrdinal())
		if seen[o] {
			return status.Errorf(codes.InvalidArgument, "NIC %d named twice", o)
		}
		seen[o] = true
		if !ix.byListPosition && o >= len(spec.Network) && stack == "" {
			// By spec index (an older client): main's entries for the unlisted
			// NICs up to o, made from the rows at the ordinals they stand for.
			if err := appendNICEntriesByOrdinal(spec, nics, o, rowModels, req.GetName()); err != nil {
				return err
			}
		}
		e, nic, ok := ix.resolve(spec, o)
		if (!ok || e < 0) && stack != "" {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q belongs to stack %q, whose compose file does not list NIC %d; set mtu: in the stack's compose file",
				req.GetName(), stack, o)
		}
		if !ok {
			return status.Errorf(codes.NotFound, "VM %q has no NIC %d", req.GetName(), o)
		}
		if e < 0 {
			e = appendNICEntries(spec, nics, nic, rowModels)
		}
		n := spec.Network[e]
		if err := compose.ValidateNICMTU(n.GetModel(), u.GetMtu()); err != nil {
			return status.Errorf(codes.InvalidArgument, "NIC %d: %v", o, err)
		}
		if nic != nil {
			m := nicModels.Model(nic.MAC, nic.NetworkName, nic.Ordinal, nic.Model)
			if err := compose.ValidateNICMTU(m, u.GetMtu()); err != nil {
				return status.Errorf(codes.InvalidArgument, "NIC %d: %v", o, err)
			}
		}
		n.Mtu = u.GetMtu()
		if n.Mtu == 0 {
			continue
		}
		bridge := resolveBridge(ctx, s.db, n.GetName())
		if strings.HasPrefix(bridge, "direct:") {
			return status.Errorf(codes.FailedPrecondition,
				"NIC %d: an MTU needs a bridged network (macvtap and SR-IOV networks are not supported)", o)
		}
		if _, err := lv.ResolveNICMTU(o, int(n.Mtu), bridge, s.bridgeMTUReader(), s.hostName); err != nil {
			return status.Errorf(codes.FailedPrecondition, "%v", err)
		}
	}
	return nil
}

// appendNICEntries gives target, a live NIC the spec does not describe, a
// spec entry made from its NIC record, and does the same for every NIC
// before it in the list that has none, so a VM whose ordinals run 0, 1, 2, ...
// keeps one entry per NIC at the NIC's own position. Each entry records its
// NIC's MAC, so it is found by that from then on. It returns target's entry.
func appendNICEntries(spec *pb.VMSpec, nics []corrosion.NICRecord, target *corrosion.NICRecord, rowModels map[string]string) int {
	for i := range nics {
		ic := &nics[i]
		e := compose.SpecEntryIndexForNIC(spec, ic.MAC, ic.Ordinal)
		if e < 0 {
			model := rowModels[strings.ToLower(ic.MAC)]
			if model == "" {
				model = ic.Model
			}
			spec.Network = append(spec.Network, &pb.NetworkAttachment{Name: ic.NetworkName, Model: model, Mac: ic.MAC})
			e = len(spec.Network) - 1
		}
		if ic == target {
			return e
		}
	}
	return -1
}

// appendNICEntriesByOrdinal is main's reading of an MTU update by spec index
// past the spec's end: an entry for each NIC from the spec's length up to o,
// made from the NIC row whose ordinal is that index. A missing row is
// NotFound, as on main.
func appendNICEntriesByOrdinal(spec *pb.VMSpec, nics []corrosion.NICRecord, o int, rowModels map[string]string, vm string) error {
	byOrdinal := make(map[int]corrosion.NICRecord, len(nics))
	for _, ic := range nics {
		byOrdinal[ic.Ordinal] = ic
	}
	for len(spec.Network) <= o {
		ic, ok := byOrdinal[len(spec.Network)]
		if !ok {
			return status.Errorf(codes.NotFound, "VM %q has no NIC %d", vm, len(spec.Network))
		}
		model := rowModels[strings.ToLower(ic.MAC)]
		if model == "" {
			model = ic.Model
		}
		spec.Network = append(spec.Network, &pb.NetworkAttachment{Name: ic.NetworkName, Model: model, Mac: ic.MAC})
	}
	return nil
}

// patchNICMTUInPlace applies an update's NIC MTUs (merged into spec) to the
// persistent definition by patching it, so the addresses libvirt assigned
// are not reshuffled. nets are the VM's NICs on this host; each update's NIC
// is found among them by its MAC.
func (s *Server) patchNICMTUInPlace(x string, req *pb.UpdateVMRequest, spec *pb.VMSpec, nets []lv.NetworkConfig, ix nicIndex) (string, error) {
	for _, u := range req.GetNicMtu() {
		o := int(u.GetOrdinal())
		e, nic, ok := ix.resolve(spec, o)
		if !ok || e < 0 || nic == nil {
			return "", fmt.Errorf("NIC %d not found for an in-place patch", o)
		}
		var nc *lv.NetworkConfig
		for i := range nets {
			if strings.EqualFold(nets[i].MAC, nic.MAC) {
				nc = &nets[i]
			}
		}
		if nc == nil {
			return "", fmt.Errorf("NIC %d not found for an in-place patch", o)
		}
		size := 0
		if mtu := int(spec.Network[e].GetMtu()); mtu != 0 {
			if nc.Direct != "" {
				return "", fmt.Errorf("NIC %d: an MTU needs a bridged network (macvtap and SR-IOV networks are not supported)", o)
			}
			var err error
			if size, err = lv.ResolveNICMTU(o, mtu, nc.Bridge, s.bridgeMTUReader(), s.hostName); err != nil {
				return "", err
			}
		}
		var err error
		if x, err = lv.PatchInactiveNICMTU(x, nc.MAC, size); err != nil {
			return "", err
		}
	}
	return x, nil
}

// nicMTUExpectations is what a migration's target must match: each NIC of the
// VM's live definition that carries an <mtu>, at the size it resolved to here
// (a `bridge` NIC included), with its network and ordinal. A VM whose spec
// sets no MTU sends none, and its definition is not read.
func (s *Server) nicMTUExpectations(ctx context.Context, vmName string) ([]*pb.NICMTUExpectation, error) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read VM %q for its NIC MTUs: %v", vmName, err)
	}
	if vm == nil || !specSetsNICMTU(vmSpecFor(vm)) {
		return nil, nil
	}
	x, err := s.virt.DumpXML(vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the definition of %q for its NIC MTUs: %v", vmName, err)
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list NICs of %q: %v", vmName, err)
	}
	byMAC := make(map[string]corrosion.NICRecord, len(nics))
	for _, n := range nics {
		byMAC[strings.ToLower(n.MAC)] = n
	}
	var out []*pb.NICMTUExpectation
	for _, n := range lv.InterfaceMTUs(x) {
		if n.MTU == 0 {
			continue
		}
		rec, ok := byMAC[n.MAC]
		if !ok {
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q has a NIC (MAC %s) with an MTU but no NIC record, so its network on the target is unknown", vmName, n.MAC)
		}
		out = append(out, &pb.NICMTUExpectation{Network: rec.NetworkName, Mtu: int32(n.MTU), Ordinal: int32(rec.Ordinal)})
	}
	return out, nil
}

// nicMTUProblem is a migration target's answer to the source's NIC MTUs: each
// NIC whose MTU its bridge here does not equal, in the create's words, joined;
// "" when every one matches (or none was sent).
func (s *Server) nicMTUProblem(ctx context.Context, want []*pb.NICMTUExpectation) string {
	var problems []string
	for _, e := range want {
		bridge := resolveBridge(ctx, s.db, e.GetNetwork())
		if served, ok := s.servedDef(e.GetNetwork()); ok {
			bridge = network.BridgeName(e.GetNetwork(), served)
		}
		if strings.HasPrefix(bridge, "direct:") {
			problems = append(problems, fmt.Sprintf("NIC %d: an MTU needs a bridged network, and %s is not one on host %s",
				e.GetOrdinal(), e.GetNetwork(), s.hostName))
			continue
		}
		if _, err := lv.ResolveNICMTU(int(e.GetOrdinal()), int(e.GetMtu()), bridge, s.bridgeMTUReader(), s.hostName); err != nil {
			problems = append(problems, err.Error())
		}
	}
	return strings.Join(problems, "; ")
}

// nicMTURefusal is the source's refusal of a migration whose target answered
// a NIC MTU problem; nil for none.
func nicMTURefusal(vmName, target, problem string) error {
	if problem == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition, "cannot move VM %q to %s: %s", vmName, target, problem)
}

// nicMTUUpdates lists what the desired spec changes in the stored one's NIC
// MTUs; a value left unset inherits.
func nicMTUUpdates(desired, stored *pb.VMSpec) []*pb.NICMTUUpdate {
	var out []*pb.NICMTUUpdate
	for i, n := range desired.GetNetwork() {
		if n == nil || n.GetMtu() == 0 || i >= len(stored.GetNetwork()) || stored.Network[i] == nil {
			continue
		}
		if n.GetMtu() != stored.Network[i].GetMtu() {
			out = append(out, &pb.NICMTUUpdate{Ordinal: int32(i), Mtu: n.GetMtu()})
		}
	}
	return out
}

// importNICMTUGrant decides an import's NIC MTUs: kept under the nic_mtu grant
// once the feature is open, else dropped with a warning (the import is never
// refused over one). A source with no MTU never asks the gate.
func (s *Server) importNICMTUGrant(ctx context.Context, fv *vmimport.ForeignVM) capabilities.FeatureGrant {
	var g capabilities.FeatureGrant
	set := false
	for _, n := range fv.NICs {
		set = set || n.MTU != 0
	}
	if !set {
		return g
	}
	if !s.ReleaseFeatureAvailable(capabilities.FeatureNICMTU) {
		fv.DropNICMTUs("the cluster upgrade has not finished (nic_mtu)")
		return g
	}
	g, err := s.nicMTUGrant(ctx)
	if err != nil {
		fv.DropNICMTUs("the nic_mtu gate refused: " + status.Convert(err).Message())
	}
	return g
}

// nicMTUPreflight asks targetHost, while the VM still runs, whether its
// bridges carry the VM's NIC MTUs: the move's own EnsureDisks asks too late
// for a cold move that shuts the guest down first. The VM's networks are set
// up there first, as the move would. Nil for a VM that sets no MTU.
func (s *Server) nicMTUPreflight(ctx context.Context, vm *corrosion.VMRecord, targetHost string) error {
	mtus, err := s.nicMTUExpectations(ctx, vm.Name)
	if err != nil || len(mtus) == 0 {
		return err
	}
	s.provisionVMNetworksOnRemote(ctx, vm.Name, targetHost)
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach %s to check the NIC MTUs of VM %q: %v", targetHost, vm.Name, err)
	}
	defer conn.Close()
	// No stubs and an empty ISO list: the target answers the MTUs and creates
	// nothing.
	resp, err := client.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: vm.Name, InstallerIsoListed: true, NicMtu: mtus})
	if err != nil {
		return nicMTUPreflightError(targetHost, vm.Name, err)
	}
	return nicMTURefusal(vm.Name, targetHost, resp.GetNicMtuProblem())
}

// nicMTUPreflightError is the error of a failed preflight EnsureDisks. Once
// the MTUs match, the target goes on to its other checks (the installer ISO,
// the ceph secrets), so an answer is the target refusing the move, in its own
// words and code; only a target that could not be asked failed the MTU check.
func nicMTUPreflightError(targetHost, vmName string, err error) error {
	code, msg := status.Code(err), status.Convert(err).Message()
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return status.Errorf(code, "could not ask %s to check the NIC MTUs of VM %q: %s", targetHost, vmName, msg)
	}
	return status.Errorf(code, "%s refused the move of VM %q: %s", targetHost, vmName, msg)
}

package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

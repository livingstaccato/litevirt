package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// vmSpecGrants are the release-feature grants one VM spec write took: disk/NIC
// tuning (ioGrant), USB devices and memory hot-add (passthroughGrant), CPU and
// NIC limits (recordLimitedSpec / recordLimitUpdate), NIC MTUs (nicMTUGrant).
// A spec can carry all of them, so a shared call site — a create, a restore's auto-define, a clone,
// an UpdateVM redefine — takes every grant its spec needs, each through its
// own gate, and writes through ONE writer that checks them all
// (corrosion.InsertVMWithReleaseFeatures / MutateDesiredSpecWithReleaseFeatures;
// integration checklist M9). A feature the spec does not carry needs no grant.
type vmSpecGrants struct {
	tuning, passthrough, limits, mtu capabilities.FeatureGrant
}

// vmSpecNeeds is which release features' data spec carries.
func vmSpecNeeds(spec *pb.VMSpec) corrosion.VMSpecFeatures {
	return corrosion.VMSpecFeatures{
		Tuning:      specSetsDiskNICIO(spec),
		Passthrough: vmSpecSetsPassthrough(spec),
		Limits:      specSetsLimits(spec),
		MTU:         specSetsNICMTU(spec),
	}
}

// insertVMWithGrants writes a new VM row for spec through the one writer that
// checks every release-feature grant the spec's data needs.
func (s *Server) insertVMWithGrants(ctx context.Context, spec *pb.VMSpec, gs vmSpecGrants, vm corrosion.VMRecord,
	ifaces []corrosion.InterfaceRecord, disks []corrosion.DiskRecord, nics []corrosion.NICRecord,
	pciIntents []corrosion.PCIIntentRecord, adopt bool) error {
	return corrosion.InsertVMWithReleaseFeatures(ctx, s.db, gs.tuning, gs.passthrough, gs.limits, gs.mtu, vmSpecNeeds(spec),
		vm, ifaces, disks, nics, pciIntents, adopt)
}

// refusal is the combined writer's grant check for spec, writing nothing
// (corrosion.CheckVMSpecGrants): nil exactly when insertVMWithGrants would
// accept the grants.
func (gs vmSpecGrants) refusal(spec *pb.VMSpec) error {
	return corrosion.CheckVMSpecGrants(gs.tuning, gs.passthrough, gs.limits, gs.mtu, vmSpecNeeds(spec))
}

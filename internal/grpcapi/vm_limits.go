package grpcapi

import (
	"context"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// limitsUpdate is what an UpdateVMRequest asks of the noisy-neighbour limits,
// after validation. applyTo folds it onto any copy of the spec, so the same
// update can be merged onto whatever spec is current under the VM lock.
type limitsUpdate struct {
	cpu         bool // cpu_limit and/or cpu_shares change
	limitTouch  bool
	newLimit    float64
	sharesTouch bool // cpu_shares is named (0 = restore the host's default weight)
	newShares   int32
	nicOrdinals []int
	nicNewRate  map[int]float64

	// What the update started from, for revertLimits.
	prevLimit   float64
	prevShares  int32
	nicPrevRate map[int]float64
}

func (u limitsUpdate) any() bool { return u.cpu || len(u.nicOrdinals) > 0 }

// applyTo sets the update's values on spec (leaving untouched limits alone).
func (u limitsUpdate) applyTo(spec *pb.VMSpec) {
	if u.limitTouch {
		spec.CpuLimit = u.newLimit
	}
	if u.sharesTouch {
		spec.CpuShares = u.newShares
	}
	for _, o := range u.nicOrdinals {
		if o < len(spec.Network) && spec.Network[o] != nil {
			spec.Network[o].RateMbSec = u.nicNewRate[o]
		}
	}
}

// vmLimitsRefusal is what a create or update that sets a limit is refused with
// until vm_limits_v1 has latched.
const vmLimitsRefusal = "VM limits (cpu-limit, cpu-shares, NIC rate) cannot be set yet: an older host would ignore " +
	"or drop them, so the cluster upgrade must finish first (vm_limits_v1 has not latched on every host)"

// vmLimitsActive reports whether vm_limits_v1 has latched: every host this
// node replicates to understands the limit fields. No config flag; a node with
// no gate wired has not proved it.
func (s *Server) vmLimitsActive(ctx context.Context) bool {
	return s.gate != nil && s.gate.Enforced(ctx, capabilities.VMLimitsV1)
}

// specSetsLimits reports whether a create spec carries any limit. A zero is
// not a limit.
func specSetsLimits(spec *pb.VMSpec) bool {
	if spec.GetCpuLimit() != 0 || spec.GetCpuShares() != 0 {
		return true
	}
	for _, n := range spec.GetNetwork() {
		if n.GetRateMbSec() != 0 {
			return true
		}
	}
	return false
}

// requestSetsLimits reports whether an update names a non-zero limit. Clearing
// one (zero) sets nothing, so it is allowed before the latch: nothing can be
// there to clear, and it must not block an operator undoing a limit.
func requestSetsLimits(req *pb.UpdateVMRequest) bool {
	if req.GetCpuLimit() != 0 || req.GetCpuShares() != 0 {
		return true
	}
	for _, nr := range req.GetNicRate() {
		if nr.GetRateMbSec() != 0 {
			return true
		}
	}
	return false
}

// refuseUnlatchedLimits refuses a create spec that sets a limit while
// vm_limits_v1 is unlatched. It runs at the entry node, before anything is
// created or forwarded.
func (s *Server) refuseUnlatchedLimits(ctx context.Context, spec *pb.VMSpec) error {
	if specSetsLimits(spec) && !s.vmLimitsActive(ctx) {
		return status.Error(codes.FailedPrecondition, vmLimitsRefusal)
	}
	return nil
}

// refuseUnlatchedLimitUpdate is the update-side twin, run before the request is
// forwarded to the owning host.
func (s *Server) refuseUnlatchedLimitUpdate(ctx context.Context, req *pb.UpdateVMRequest) error {
	if requestSetsLimits(req) && !s.vmLimitsActive(ctx) {
		return status.Error(codes.FailedPrecondition, vmLimitsRefusal)
	}
	return nil
}

// refuseUnlatchedStackLimits refuses a compose file that sets a VM limit while
// vm_limits_v1 is unlatched. Containers have no such limits and are skipped.
func (s *Server) refuseUnlatchedStackLimits(ctx context.Context, f *compose.File) error {
	if s.vmLimitsActive(ctx) {
		return nil
	}
	for name, vm := range f.VMs {
		if vm.Kind == compose.WorkloadKindLXC || vm.Kind == compose.WorkloadKindOCI {
			continue
		}
		set := vm.CPULimit != 0 || vm.CPUShares != 0
		for _, n := range vm.Network {
			set = set || n.Rate != 0
		}
		if set {
			return status.Errorf(codes.FailedPrecondition, "vm %q: %s", name, vmLimitsRefusal)
		}
	}
	return nil
}

// limitsRequested reports whether req names any noisy-neighbour limit.
func limitsRequested(req *pb.UpdateVMRequest) bool {
	return req.CpuLimit != nil || req.CpuShares != nil || len(req.NicRate) > 0
}

// mergeLimitUpdate validates req's limit fields against the VM's FINAL vCPU
// count and folds them into spec. It also re-validates a limit the request did
// not touch, because a vCPU shrink can strand it above the new count.
func mergeLimitUpdate(spec *pb.VMSpec, req *pb.UpdateVMRequest) (limitsUpdate, error) {
	up := limitsUpdate{
		nicNewRate: map[int]float64{}, nicPrevRate: map[int]float64{},
		prevLimit: spec.CpuLimit, prevShares: spec.CpuShares,
	}
	cpus := spec.Cpu
	if req.Cpu > 0 {
		cpus = req.Cpu
	}
	limit := spec.CpuLimit
	if req.CpuLimit != nil {
		limit = req.GetCpuLimit()
		up.cpu, up.limitTouch, up.newLimit = true, true, limit
	}
	if err := lv.ValidateCPULimit(limit, int(cpus)); err != nil {
		hint := ""
		if req.CpuLimit == nil {
			hint = " (the VM's existing cpu limit; lower it in the same update)"
		}
		return up, status.Errorf(codes.InvalidArgument, "%v%s", err, hint)
	}
	if req.CpuShares != nil {
		sh := req.GetCpuShares()
		if sh < 0 {
			return up, status.Errorf(codes.InvalidArgument, "cpu shares %d must be >= 0", sh)
		}
		if err := lv.ValidateCPUShares(int(sh)); err != nil {
			return up, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		up.cpu, up.sharesTouch, up.newShares = true, true, sh
	}
	seen := map[int]bool{}
	for _, nr := range req.NicRate {
		o := int(nr.GetOrdinal())
		if o < 0 || o >= len(spec.Network) {
			return up, status.Errorf(codes.InvalidArgument,
				"nic %d: the VM declares %d NIC(s) (0-based); a NIC hot-plugged after create has no spec entry to hold a rate", o, len(spec.Network))
		}
		if seen[o] {
			return up, status.Errorf(codes.InvalidArgument, "nic %d named twice", o)
		}
		seen[o] = true
		if err := lv.ValidateNICRate(nr.GetRateMbSec()); err != nil {
			return up, status.Errorf(codes.InvalidArgument, "nic %d: %v", o, err)
		}
		up.nicOrdinals = append(up.nicOrdinals, o)
		up.nicPrevRate[o] = spec.Network[o].RateMbSec
		up.nicNewRate[o] = nr.GetRateMbSec()
	}
	up.applyTo(spec)
	return up, nil
}

// applyLimitsToDomain writes the merged limits to the libvirt domain — the
// persistent config always, the running domain when there is one. A domain that
// does not exist (a VM stranded in error, rebuilt from the spec at its next
// start) is not an error: the spec is then the only home for the values.
func (s *Server) applyLimitsToDomain(ctx context.Context, name string, spec *pb.VMSpec, up limitsUpdate) error {
	if up.cpu {
		// Only a named weight is written: an update that touches the cap alone
		// leaves the weight where it is. Clearing writes the host's default
		// (libvirt cannot unset <shares>, only set it).
		shares := 0
		if up.sharesTouch {
			shares = int(spec.CpuShares)
			if shares == 0 {
				shares = lv.DefaultCPUWeight()
			}
		}
		if err := s.virt.SetCPUTune(name, spec.CpuLimit, shares); err != nil {
			if lv.IsNotFound(err) {
				return nil
			}
			return status.Errorf(codes.Internal, "apply cpu limits to %q: %v", name, err)
		}
	}
	if len(up.nicOrdinals) == 0 {
		return nil
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, name)
	if err != nil {
		return status.Errorf(codes.Internal, "read NICs for %q: %v", name, err)
	}
	byOrdinal := make(map[int]corrosion.NICRecord, len(nics))
	for _, n := range nics {
		byOrdinal[n.Ordinal] = n
	}
	for _, o := range up.nicOrdinals {
		nic, ok := byOrdinal[o]
		if !ok {
			return status.Errorf(codes.FailedPrecondition, "VM %q has no NIC %d", name, o)
		}
		// A spec entry describes the NIC at its position only while that NIC is
		// still on the network the entry names; the rebuild paths (failover,
		// redefine) apply the same test, so a cap set on a NIC that moved would
		// be lost at the next rebuild.
		if want := spec.Network[o].GetName(); nic.NetworkName != want {
			return status.Errorf(codes.FailedPrecondition,
				"NIC %d of %q is on network %q but the spec entry for it names %q; a rate set now would not survive a rebuild",
				o, name, nic.NetworkName, want)
		}
		if err := s.virt.SetNICRate(name, nic.MAC, spec.Network[o].RateMbSec); err != nil {
			if lv.IsNotFound(err) {
				return nil
			}
			return status.Errorf(codes.Internal, "apply rate to nic %d of %q: %v", o, name, err)
		}
	}
	return nil
}

// revertLimits puts the domain back on the values a failed update started
// from. Best effort: it is the cleanup of an update that is already failing.
func (s *Server) revertLimits(ctx context.Context, name string, spec *pb.VMSpec, up limitsUpdate) {
	prev := proto.Clone(spec).(*pb.VMSpec)
	prev.CpuLimit, prev.CpuShares = up.prevLimit, up.prevShares
	for o, r := range up.nicPrevRate {
		if o < len(prev.Network) {
			prev.Network[o].RateMbSec = r
		}
	}
	_ = s.applyLimitsToDomain(ctx, name, prev, up)
}

// checkCopiedSpecLimits judges a spec a path takes from somewhere other than a
// create request — a restore's --spec or manifest, a clone's source — the way a
// create is judged: gated on vm_limits_v1, and validated against its own vCPU
// count. Without it a limit reaches a stored spec by a side door.
func (s *Server) checkCopiedSpecLimits(ctx context.Context, spec *pb.VMSpec) error {
	if err := s.refuseUnlatchedLimits(ctx, spec); err != nil {
		return err
	}
	return validateCreateLimits(spec)
}

// splitLimitFields separates the noisy-neighbour field names in a live-metadata
// plan ("cpu_limit", "cpu_shares", "nic_rate_<n>") from the spec-only ones. The
// limits cannot ride the spec-only patch: libvirt has to be told, on the host
// that owns the domain, which UpdateVM forwards to.
func splitLimitFields(fields []string) (limits, rest []string) {
	for _, f := range fields {
		switch {
		case f == "cpu_limit", f == "cpu_shares", strings.HasPrefix(f, compose.NICRateFieldPrefix):
			limits = append(limits, f)
		default:
			rest = append(rest, f)
		}
	}
	return limits, rest
}

// limitUpdateFromDesired builds the UpdateVM request that moves a VM's limits
// to the values a desired spec declares, for the named limit fields.
func limitUpdateFromDesired(name string, desired *pb.VMSpec, limitFields []string) *pb.UpdateVMRequest {
	req := &pb.UpdateVMRequest{Name: name}
	for _, f := range limitFields {
		switch {
		case f == "cpu_limit":
			v := desired.CpuLimit
			req.CpuLimit = &v
		case f == "cpu_shares":
			v := desired.CpuShares
			req.CpuShares = &v
		case strings.HasPrefix(f, compose.NICRateFieldPrefix):
			n, err := strconv.Atoi(strings.TrimPrefix(f, compose.NICRateFieldPrefix))
			if err != nil || n < 0 || n >= len(desired.Network) {
				continue
			}
			req.NicRate = append(req.NicRate, &pb.NICRateUpdate{Ordinal: int32(n), RateMbSec: desired.Network[n].RateMbSec})
		}
	}
	return req
}

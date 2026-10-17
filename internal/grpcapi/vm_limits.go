package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
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
	// nicEntries are the spec entries of the NICs whose rate changes, each
	// keyed in nicAsked to the NIC index the request named it by.
	nicEntries []int
	nicAsked   map[int]int
	nicNewRate map[int]float64

	// What the update started from, for revertLimits.
	prevLimit   float64
	prevShares  int32
	nicPrevRate map[int]float64
}

func (u limitsUpdate) any() bool { return u.cpu || len(u.nicEntries) > 0 }

// applyTo sets the update's values on spec (leaving untouched limits alone).
func (u limitsUpdate) applyTo(spec *pb.VMSpec) {
	if u.limitTouch {
		spec.CpuLimit = u.newLimit
	}
	if u.sharesTouch {
		spec.CpuShares = u.newShares
	}
	for _, e := range u.nicEntries {
		if e < len(spec.Network) && spec.Network[e] != nil {
			spec.Network[e].RateMbSec = u.nicNewRate[e]
		}
	}
}

// admitLimitedSpec is the writer of a create-time limit: it takes the
// vm_limits grant and checks it, so a spec that carries a limit cannot reach
// the VM record or the domain XML without having passed the release gate.
func admitLimitedSpec(g capabilities.FeatureGrant, _ *pb.VMSpec) error {
	return g.Check(capabilities.FeatureVMLimits)
}

// admitLimitUpdate is admitLimitedSpec for an update: the vm_limits grant
// precedes any write of a limit to the domain or the stored spec.
func admitLimitUpdate(g capabilities.FeatureGrant, _ *pb.UpdateVMRequest) error {
	return g.Check(capabilities.FeatureVMLimits)
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

// The limits gate has two halves, because the gate has durable, cluster-wide
// side effects (it Pings the fleet and records the feature's first use, which
// a rollback below the release then quarantines on):
//
//   - precheck*: Server.ReleaseFeatureRefusal, the release gate's latch step
//     alone: it drives the latch and, when it has not formed, refuses with the
//     gate's own text (the lagging hosts and versions, and the pointer to
//     `lv cluster upgrade-status`), but records and grants nothing. It refuses
//     early, before any work, and is what a caller that is not the writer (an
//     entry node forwarding to the owner, a dry run, a preflight) uses.
//   - record*: the full gate (WithReleaseFeature). It runs on the node that
//     writes, immediately before the first write of a limit, after every
//     permission and validation check has passed, so a refused or failed
//     request never records a use.
//
// Limitless specs, zero values and clears are never gated by either.

// precheckLimitedSpec refuses a spec that sets a limit while the release token
// has not latched here. Records nothing.
func (s *Server) precheckLimitedSpec(ctx context.Context, spec *pb.VMSpec) error {
	if !specSetsLimits(spec) {
		return nil
	}
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureVMLimits)
}

// precheckLimitUpdate is precheckLimitedSpec for an update. An entry node runs
// it before forwarding: an owner on an older build would ignore the fields and
// answer success, and an older owner implies the token has not latched. The
// owner still runs the full gate.
func (s *Server) precheckLimitUpdate(ctx context.Context, req *pb.UpdateVMRequest) error {
	if !requestSetsLimits(req) {
		return nil
	}
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureVMLimits)
}

// recordLimitedSpec runs a spec that sets a limit through the release gate
// (vm_limits) on THIS node, immediately before the first write of that limit,
// and returns the grant the spec's writer checks (vmSpecGrants.limits). A spec
// with no limit takes none: the zero grant, which its writer does not check.
func (s *Server) recordLimitedSpec(ctx context.Context, spec *pb.VMSpec) (capabilities.FeatureGrant, error) {
	var granted capabilities.FeatureGrant
	if !specSetsLimits(spec) {
		return granted, nil
	}
	err := s.WithReleaseFeature(ctx, capabilities.FeatureVMLimits,
		func(_ context.Context, g capabilities.FeatureGrant) error {
			if err := admitLimitedSpec(g, spec); err != nil {
				return err
			}
			granted = g
			return nil
		})
	return granted, err
}

// recordLimitUpdate is recordLimitedSpec for an update, run on the owner.
func (s *Server) recordLimitUpdate(ctx context.Context, req *pb.UpdateVMRequest) (capabilities.FeatureGrant, error) {
	var granted capabilities.FeatureGrant
	if !requestSetsLimits(req) {
		return granted, nil
	}
	err := s.WithReleaseFeature(ctx, capabilities.FeatureVMLimits,
		func(_ context.Context, g capabilities.FeatureGrant) error {
			if err := admitLimitUpdate(g, req); err != nil {
				return err
			}
			granted = g
			return nil
		})
	return granted, err
}

// composeVMSetsLimit reports whether a compose VM entry names any limit this
// branch owns: the cpu cap, the weight, or a NIC rate. Containers have none.
func composeVMSetsLimit(vm compose.VMDef) bool {
	if vm.Kind == compose.WorkloadKindLXC || vm.Kind == compose.WorkloadKindOCI {
		return false
	}
	if vm.CPULimit != 0 || vm.CPUShares != 0 {
		return true
	}
	for _, n := range vm.Network {
		if n.Rate != 0 {
			return true
		}
	}
	return false
}

// precheckStackLimits fails a compose file that sets a limit anywhere in it
// before any VM is deployed, through the non-recording latch step: it records nothing,
// so a dry run or a deploy that later fails validation leaves no use behind.
// Every VM's own create runs the full gate when it writes.
func (s *Server) precheckStackLimits(ctx context.Context, f *compose.File) error {
	names := make([]string, 0, len(f.VMs))
	for name := range f.VMs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !composeVMSetsLimit(f.VMs[name]) {
			continue
		}
		if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureVMLimits); err != nil {
			return status.Errorf(status.Code(err), "vm %q: %s", name, status.Convert(err).Message())
		}
		return nil
	}
	return nil
}

// limitsRequested reports whether req names any noisy-neighbour limit.
func limitsRequested(req *pb.UpdateVMRequest) bool {
	return req.CpuLimit != nil || req.CpuShares != nil || len(req.NicRate) > 0
}

// mergeLimitUpdate validates req's limit fields against the VM's FINAL vCPU
// count and folds them into spec. It also re-validates a limit the request did
// not touch, because a vCPU shrink can strand it above the new count. A NIC
// rate names its NIC by its position in the NIC list (nicIndex), and needs
// the NIC's spec entry.
func mergeLimitUpdate(spec *pb.VMSpec, req *pb.UpdateVMRequest, ix nicIndex) (limitsUpdate, error) {
	up := limitsUpdate{
		nicNewRate: map[int]float64{}, nicPrevRate: map[int]float64{}, nicAsked: map[int]int{},
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
		e, _, ok := ix.resolve(spec, o)
		if !ok || e < 0 {
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
		if _, dup := up.nicAsked[e]; dup {
			return up, status.Errorf(codes.InvalidArgument, "nic %d named twice", o)
		}
		up.nicEntries = append(up.nicEntries, e)
		up.nicAsked[e] = o
		up.nicPrevRate[e] = spec.Network[e].RateMbSec
		up.nicNewRate[e] = nr.GetRateMbSec()
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
	if len(up.nicEntries) == 0 {
		return nil
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, name)
	if err != nil {
		return status.Errorf(codes.Internal, "read NICs for %q: %v", name, err)
	}
	for _, e := range up.nicEntries {
		o := up.nicAsked[e]
		// The NIC the entry describes: by its MAC, an entry that records none
		// by the NIC's ordinal (compose.SpecEntryIndexForNIC).
		nic := liveNICForEntry(spec, nics, e)
		if nic == nil {
			return status.Errorf(codes.FailedPrecondition, "VM %q has no NIC %d", name, o)
		}
		// A spec entry describes its NIC only while that NIC is still on the
		// network the entry names; the rebuild paths (failover, redefine)
		// apply the same test (compose.NICRate), so a cap set on a NIC that
		// moved would be lost at the next rebuild.
		if want := spec.Network[e].GetName(); nic.NetworkName != want {
			return status.Errorf(codes.FailedPrecondition,
				"NIC %d of %q is on network %q but the spec entry for it names %q; a rate set now would not survive a rebuild",
				o, name, nic.NetworkName, want)
		}
		if err := s.virt.SetNICRate(name, nic.MAC, spec.Network[e].RateMbSec); err != nil {
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
	for e, r := range up.nicPrevRate {
		if e < len(prev.Network) {
			prev.Network[e].RateMbSec = r
		}
	}
	_ = s.applyLimitsToDomain(ctx, name, prev, up)
}

// checkCopiedSpecLimits judges a spec a path takes from somewhere other than a
// create request — a clone's source — the way a create is judged (a restore or
// promotion, a recovery path, drops instead: restrictRestoredLimits,
// restrictPromotedReleaseFeatures): refused early while the release token has not latched
// (a local read, recording nothing; the caller records the use with
// recordLimitedSpec immediately before it writes), and validated against its
// own vCPU count. Without it a limit reaches a stored spec by a side door.
//
// The grant the vm_limits writers take (admitLimitedSpec, admitLimitUpdate)
// does not travel into InsertVM, DefineDomain or MutateDesiredSpec, because a
// limit lives in the generic spec JSON. So the guard test cannot see a NEW path
// that writes a limit: any path that takes a spec from outside must call this
// and recordLimitedSpec before it writes.
func (s *Server) checkCopiedSpecLimits(ctx context.Context, spec *pb.VMSpec) error {
	if err := s.precheckLimitedSpec(ctx, spec); err != nil {
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
// to the values a desired spec declares, for the named limit fields. Its NIC
// rates name spec entries (nic_by_spec_entry): a compose file's NICs are its
// entries.
func limitUpdateFromDesired(name string, desired *pb.VMSpec, limitFields []string) *pb.UpdateVMRequest {
	req := &pb.UpdateVMRequest{Name: name, NicBySpecEntry: true}
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

// vmSharesWeight is the cpu-shares weight, in the user's scale, a migration
// must render on the target's. A stored weight of 0 means the default, but a
// domain whose weight was SET and then cleared carries an explicit <shares> of
// the default for its host's scale (SetCPUTune writes it: libvirt cannot unset
// one), which must be re-rendered for the target like any other. So 0 with a
// <shares> in the domain is DefaultCPUWeight; 0 with none stays 0 (nothing to
// rewrite, and no reason to ask the target anything).
func (s *Server) vmSharesWeight(ctx context.Context, name string) int {
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return 0
	}
	if w := int(vmSpecFor(vm).GetCpuShares()); w > 0 {
		return w
	}
	if s.virt != nil {
		if x, derr := s.virt.DumpXML(name); derr == nil && strings.Contains(x, "<shares>") {
			return lv.DefaultCPUWeight()
		}
	}
	return 0
}

// stripLimits clears every limit of spec and names each one that was set.
func stripLimits(spec *pb.VMSpec) []string {
	var names []string
	if spec.CpuLimit != 0 {
		names = append(names, "cpu_limit")
	}
	if spec.CpuShares != 0 {
		names = append(names, "cpu_shares")
	}
	spec.CpuLimit, spec.CpuShares = 0, 0
	for i, n := range spec.Network {
		if n.RateMbSec != 0 {
			names = append(names, fmt.Sprintf("network %d rate_mb_sec", i))
		}
		n.RateMbSec = 0
	}
	return names
}

// dropInvalidLimits clears each limit of spec a create would refuse
// (validateCreateLimits, value by value) and names each, with the reason. The
// valid ones are kept.
func dropInvalidLimits(spec *pb.VMSpec) []string {
	var dropped []string
	if err := lv.ValidateCPULimit(spec.CpuLimit, int(spec.Cpu)); err != nil {
		dropped = append(dropped, fmt.Sprintf("cpu_limit (%v)", err))
		spec.CpuLimit = 0
	}
	if err := lv.ValidateCPUShares(int(spec.CpuShares)); err != nil {
		dropped = append(dropped, fmt.Sprintf("cpu_shares (%v)", err))
		spec.CpuShares = 0
	}
	for i, n := range spec.Network {
		if err := lv.ValidateNICRate(n.GetRateMbSec()); err != nil {
			dropped = append(dropped, fmt.Sprintf("network %d rate_mb_sec (%v)", i, err))
			n.RateMbSec = 0
		}
	}
	return dropped
}

// restrictRestoredLimits is the limits half of a live restore's spec gate. A
// restore is a recovery path main allowed, and main knows no limit fields, so
// nothing here refuses: before the release token has latched every limit is
// dropped (main's behaviour), and after it each value a create would refuse is.
// Each drop is logged by name. The use is still recorded, and the grant taken,
// immediately before the define (recordLimitedSpec), where a refusing gate
// drops the rest.
func (s *Server) restrictRestoredLimits(spec *pb.VMSpec) []string {
	if !specSetsLimits(spec) {
		return nil
	}
	var dropped []string
	if !s.ReleaseFeatureAvailable(capabilities.FeatureVMLimits) {
		for _, k := range stripLimits(spec) {
			dropped = append(dropped, k+" (the cluster upgrade has not finished)")
		}
	} else {
		dropped = dropInvalidLimits(spec)
	}
	for _, d := range dropped {
		slog.Warn("restored spec: CPU/NIC limit dropped", "vm", spec.GetName(), "dropped", d)
	}
	return dropped
}

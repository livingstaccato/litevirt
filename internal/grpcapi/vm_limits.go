package grpcapi

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// defaultCPUShares is the kernel's default CFS weight, which libvirt reports
// and which "restore the default" writes back: libvirt has no way to unset a
// <shares> on a running domain, only to set it to a value.
const defaultCPUShares = 1024

// limitsUpdate is what an UpdateVMRequest asks of the noisy-neighbour limits,
// after validation. The new values live in the spec it was merged into.
type limitsUpdate struct {
	cpu          bool // cpu_limit and/or cpu_shares changes
	sharesTouch  bool // cpu_shares is named (0 = restore the default)
	nicOrdinals  []int
	nicNewRate   map[int]float64
	nicPrevRate  map[int]float64
	prevLimit    float64
	prevShares   int32
	prevSpecCPUs int32
}

func (u limitsUpdate) any() bool { return u.cpu || len(u.nicOrdinals) > 0 }

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
		prevLimit: spec.CpuLimit, prevShares: spec.CpuShares, prevSpecCPUs: spec.Cpu,
	}
	cpus := spec.Cpu
	if req.Cpu > 0 {
		cpus = req.Cpu
	}
	limit := spec.CpuLimit
	if req.CpuLimit != nil {
		limit = req.GetCpuLimit()
		up.cpu = true
	}
	if err := lv.ValidateCPULimit(limit, int(cpus)); err != nil {
		hint := ""
		if req.CpuLimit == nil {
			hint = " (the VM's existing cpu limit; lower it in the same update)"
		}
		return up, status.Errorf(codes.InvalidArgument, "%v%s", err, hint)
	}
	spec.CpuLimit = limit
	if req.CpuShares != nil {
		sh := req.GetCpuShares()
		if sh < 0 {
			return up, status.Errorf(codes.InvalidArgument, "cpu shares %d must be >= 0", sh)
		}
		if err := lv.ValidateCPUShares(int(sh)); err != nil {
			return up, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		spec.CpuShares = sh
		up.cpu, up.sharesTouch = true, true
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
		spec.Network[o].RateMbSec = nr.GetRateMbSec()
	}
	return up, nil
}

// applyLimitsToDomain writes the merged limits to the libvirt domain — the
// persistent config always, the running domain when there is one. A domain
// that does not exist (a VM stranded in error, rebuilt from the spec at its
// next start) is not an error: the spec is then the only home for the values.
func (s *Server) applyLimitsToDomain(ctx context.Context, name string, spec *pb.VMSpec, up limitsUpdate, restoring bool) error {
	if up.cpu {
		shares := int(spec.CpuShares)
		if shares == 0 && up.sharesTouch {
			shares = defaultCPUShares
		}
		if err := s.virt.SetCPUTune(name, spec.CpuLimit, shares, int(spec.Cpu)); err != nil {
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
	macByOrdinal := make(map[int]string, len(nics))
	for _, n := range nics {
		macByOrdinal[n.Ordinal] = n.MAC
	}
	for _, o := range up.nicOrdinals {
		mac, ok := macByOrdinal[o]
		if !ok {
			return status.Errorf(codes.FailedPrecondition, "VM %q has no NIC %d", name, o)
		}
		if err := s.virt.SetNICRate(name, mac, spec.Network[o].RateMbSec); err != nil {
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
	prev.Cpu = up.prevSpecCPUs
	for o, r := range up.nicPrevRate {
		if o < len(prev.Network) {
			prev.Network[o].RateMbSec = r
		}
	}
	_ = s.applyLimitsToDomain(ctx, name, prev, up, true)
}

// reapplyCPULimit re-derives the per-vCPU quota after a vCPU count change.
func (s *Server) reapplyCPULimit(name string, spec *pb.VMSpec) error {
	if spec.CpuLimit <= 0 {
		return nil
	}
	if err := s.virt.SetCPUTune(name, spec.CpuLimit, 0, int(spec.Cpu)); err != nil && !lv.IsNotFound(err) {
		return fmt.Errorf("cpu limit: %w", err)
	}
	return nil
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

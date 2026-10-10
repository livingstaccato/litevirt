package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// tokenGate answers Enforced for vm_limits_v1 only.
type tokenGate struct {
	fakeServerGate
	on bool
}

func (g tokenGate) Enforced(_ context.Context, tok string) bool {
	return g.on && tok == capabilities.VMLimitsV1
}

func TestVMLimitsGate_UnlatchedRefusesEveryWayOfSettingALimit(t *testing.T) {
	ctx := context.Background()
	s := &Server{gate: tokenGate{on: false}}
	f := 1.5
	i := int32(512)
	for name, spec := range map[string]*pb.VMSpec{
		"cpu_limit":  {CpuLimit: 1},
		"cpu_shares": {CpuShares: 512},
		"nic rate":   {Network: []*pb.NetworkAttachment{{Name: "a"}, {Name: "b", RateMbSec: 2}}},
	} {
		err := s.refuseUnlatchedLimits(ctx, spec)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Errorf("create with %s: err = %v, want FailedPrecondition naming the cluster upgrade", name, err)
		}
	}
	for name, req := range map[string]*pb.UpdateVMRequest{
		"cpu_limit":  {CpuLimit: &f},
		"cpu_shares": {CpuShares: &i},
		"nic rate":   {NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 1}}},
	} {
		err := s.refuseUnlatchedLimitUpdate(ctx, req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Errorf("update with %s: err = %v, want FailedPrecondition naming the cluster upgrade", name, err)
		}
	}
	// A nil gate (no daemon wiring) is unlatched too.
	if err := (&Server{}).refuseUnlatchedLimits(ctx, &pb.VMSpec{CpuLimit: 1}); err == nil {
		t.Error("a server with no gate accepted a limit")
	}
}

// The recreate preflight judges a spec before a teardown; it must not let a
// limit through while unlatched either (it refuses before touching any state).
func TestVMLimitsGate_RecreatePreflightRefusesUnlatched(t *testing.T) {
	s := &Server{gate: tokenGate{on: false}}
	_, err := s.recreatePreflightSpec(context.Background(), &pb.VMSpec{Cpu: 2, CpuLimit: 1}, "host")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Errorf("err = %v, want FailedPrecondition naming the cluster upgrade", err)
	}
}

// Specs and updates without a limit behave exactly as on main — including a
// zero, which sets nothing (and which a clear of an absent limit sends).
func TestVMLimitsGate_UnlatchedLeavesLimitlessWorkAlone(t *testing.T) {
	ctx := context.Background()
	s := &Server{gate: tokenGate{on: false}}
	zero, zi := 0.0, int32(0)
	if err := s.refuseUnlatchedLimits(ctx, &pb.VMSpec{Cpu: 2, Network: []*pb.NetworkAttachment{{Name: "a"}}}); err != nil {
		t.Errorf("limitless create refused: %v", err)
	}
	if err := s.refuseUnlatchedLimitUpdate(ctx, &pb.UpdateVMRequest{Cpu: 4, CpuLimit: &zero, CpuShares: &zi,
		NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 0}}}); err != nil {
		t.Errorf("zero-valued limit update refused: %v", err)
	}
}

func TestVMLimitsGate_LatchedAllows(t *testing.T) {
	s := &Server{gate: tokenGate{on: true}}
	f := 1.5
	if err := s.refuseUnlatchedLimits(context.Background(), &pb.VMSpec{CpuLimit: 1, CpuShares: 9,
		Network: []*pb.NetworkAttachment{{RateMbSec: 2}}}); err != nil {
		t.Errorf("latched create refused: %v", err)
	}
	if err := s.refuseUnlatchedLimitUpdate(context.Background(), &pb.UpdateVMRequest{CpuLimit: &f}); err != nil {
		t.Errorf("latched update refused: %v", err)
	}
}

// The token is a fact about the binary: mandatory (no flag), advertised
// unconditionally, and replication-gated because a host that only receives
// replication — a maintenance host on the previous build — can still own and
// rewrite a spec.
func TestVMLimitsToken_Shape(t *testing.T) {
	tok := capabilities.VMLimitsV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Errorf("%s mandatory=%v replicationGated=%v, want both", tok, capabilities.Mandatory(tok), capabilities.ReplicationGated(tok))
	}
	if !capabilities.Has(capabilities.All(), tok) || !capabilities.Has(capabilities.Supported(), tok) {
		t.Errorf("%s must be in All() and Supported()", tok)
	}
	s := &Server{}
	if !s.tokenEnabled(tok) {
		t.Errorf("tokenEnabled(%s) = false: a flag-gated token would never latch", tok)
	}
	if !capabilities.Has((&Server{}).advertisedCapabilities(), tok) {
		t.Errorf("%s is not advertised by a bare server — it is unconditional", tok)
	}
}

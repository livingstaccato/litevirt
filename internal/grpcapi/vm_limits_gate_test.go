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

// limitsGate is a release-feature gate that refuses with the release refusal
// until latched, and counts the writes it let through.
type limitsGate struct {
	t       *testing.T
	latched bool
	runs    *int
	feature *capabilities.Feature
}

func (g limitsGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if !g.latched {
		return status.Errorf(codes.FailedPrecondition,
			"the cluster upgrade must finish first (%s needs %s): not every host runs this release", f, capabilities.ReleaseToken)
	}
	*g.runs++
	*g.feature = f
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g limitsGate) FeatureAvailable(capabilities.Feature) bool { return g.latched }

func newLimitsGate(t *testing.T, latched bool) limitsGate {
	runs := 0
	var f capabilities.Feature
	return limitsGate{t: t, latched: latched, runs: &runs, feature: &f}
}

func serverWithLimitsGate(t *testing.T, latched bool) *Server {
	s := &Server{}
	s.SetReleaseFeatureGate(newLimitsGate(t, latched))
	return s
}

func limitsServer(t *testing.T, latched bool) (*Server, *int, *capabilities.Feature) {
	runs := 0
	var f capabilities.Feature
	s := &Server{}
	s.SetReleaseFeatureGate(limitsGate{t: t, latched: latched, runs: &runs, feature: &f})
	return s, &runs, &f
}

const vmLimitsRelRefusal = "the cluster upgrade must finish first (vm_limits needs release_2026_11_v1)"

func TestVMLimitsGate_UnlatchedRefusesEveryWayOfSettingALimit(t *testing.T) {
	ctx := context.Background()
	s, runs, _ := limitsServer(t, false)
	f := 1.5
	i := int32(512)
	for name, spec := range map[string]*pb.VMSpec{
		"cpu_limit":  {CpuLimit: 1},
		"cpu_shares": {CpuShares: 512},
		"nic rate":   {Network: []*pb.NetworkAttachment{{Name: "a"}, {Name: "b", RateMbSec: 2}}},
	} {
		err := s.refuseUnlatchedLimits(ctx, spec)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
			t.Errorf("create with %s: err = %v, want the release refusal", name, err)
		}
	}
	for name, req := range map[string]*pb.UpdateVMRequest{
		"cpu_limit":  {CpuLimit: &f},
		"cpu_shares": {CpuShares: &i},
		"nic rate":   {NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 1}}},
	} {
		err := s.refuseUnlatchedLimitUpdate(ctx, req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
			t.Errorf("update with %s: err = %v, want the release refusal", name, err)
		}
	}
	if *runs != 0 {
		t.Errorf("%d gated write(s) ran while unlatched", *runs)
	}
	// A server with no gate wired fails closed.
	if err := (&Server{}).refuseUnlatchedLimits(ctx, &pb.VMSpec{CpuLimit: 1}); err == nil {
		t.Error("a server with no release gate accepted a limit")
	}
}

// The recreate preflight judges a spec before a teardown; it must not let a
// limit through while unlatched either.
func TestVMLimitsGate_RecreatePreflightRefusesUnlatched(t *testing.T) {
	s, _, _ := limitsServer(t, false)
	_, err := s.recreatePreflightSpec(context.Background(), &pb.VMSpec{Cpu: 2, CpuLimit: 1}, "host")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
		t.Errorf("err = %v, want the release refusal", err)
	}
}

// Specs and updates without a limit behave exactly as on main, including a
// zero, which sets nothing (a clear of an absent limit sends it). The gate is
// not even consulted.
func TestVMLimitsGate_UnlatchedLeavesLimitlessWorkAlone(t *testing.T) {
	ctx := context.Background()
	s, runs, _ := limitsServer(t, false)
	zero, zi := 0.0, int32(0)
	if err := s.refuseUnlatchedLimits(ctx, &pb.VMSpec{Cpu: 2, Network: []*pb.NetworkAttachment{{Name: "a"}}}); err != nil {
		t.Errorf("limitless create refused: %v", err)
	}
	if err := s.refuseUnlatchedLimitUpdate(ctx, &pb.UpdateVMRequest{Cpu: 4, CpuLimit: &zero, CpuShares: &zi,
		NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 0}}}); err != nil {
		t.Errorf("zero-valued limit update refused: %v", err)
	}
	if *runs != 0 {
		t.Errorf("the gate ran %d time(s) for work with no limit", *runs)
	}
}

// Latched: the write runs through the vm_limits feature with a grant.
func TestVMLimitsGate_LatchedRunsThroughTheFeature(t *testing.T) {
	s, runs, feat := limitsServer(t, true)
	f := 1.5
	if err := s.refuseUnlatchedLimits(context.Background(), &pb.VMSpec{CpuLimit: 1, CpuShares: 9,
		Network: []*pb.NetworkAttachment{{RateMbSec: 2}}}); err != nil {
		t.Errorf("latched create refused: %v", err)
	}
	if err := s.refuseUnlatchedLimitUpdate(context.Background(), &pb.UpdateVMRequest{CpuLimit: &f}); err != nil {
		t.Errorf("latched update refused: %v", err)
	}
	if *runs != 2 || *feat != capabilities.FeatureVMLimits {
		t.Errorf("gated writes = %d feature = %q, want 2 through vm_limits", *runs, *feat)
	}
}

// The feature is declared against the release token with its writers, and the
// branch-local vm_limits_v1 token is gone.
func TestVMLimitsFeature_Declared(t *testing.T) {
	info, ok := capabilities.LookupFeature(capabilities.FeatureVMLimits)
	if !ok || info.Token != capabilities.ReleaseToken || len(info.Writers) == 0 {
		t.Fatalf("vm_limits = %+v ok=%v, want the release token and its writers", info, ok)
	}
	if capabilities.Has(capabilities.All(), "vm_limits_v1") {
		t.Error("vm_limits_v1 is still a known token")
	}
}

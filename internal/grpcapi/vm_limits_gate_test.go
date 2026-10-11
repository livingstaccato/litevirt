package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
)

// limitsGate is a release-feature gate that refuses with the release refusal
// until latched, and counts the writes it let through.
type limitsGate struct {
	t        *testing.T
	latched  bool
	runs     *int
	refusals *int // FeatureRefusal calls: the non-recording latch step
	calls    *int // every WithFeature call, refused or not: each one is a Ping and a possible record
	feature  *capabilities.Feature
}

func (g limitsGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	*g.calls++
	if !g.latched {
		return status.Errorf(codes.FailedPrecondition,
			"the cluster upgrade must finish first (%s needs %s): not every host runs this release", f, capabilities.ReleaseToken)
	}
	*g.runs++
	*g.feature = f
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

// FeatureRefusal is the non-recording latch step the prechecks use.
func (g limitsGate) FeatureRefusal(_ context.Context, f capabilities.Feature) error {
	*g.refusals++
	if g.latched {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"the cluster upgrade must finish first (%s needs %s): not on this release yet: node-b (v0.1) — see `lv cluster upgrade-status`", f, capabilities.ReleaseToken)
}

func (g limitsGate) FeatureAvailable(capabilities.Feature) bool { return g.latched }

func newLimitsGate(t *testing.T, latched bool) limitsGate {
	runs, calls, refusals := 0, 0, 0
	var f capabilities.Feature
	return limitsGate{t: t, latched: latched, runs: &runs, calls: &calls, refusals: &refusals, feature: &f}
}

func serverWithLimitsGate(t *testing.T, latched bool) *Server {
	s := &Server{}
	s.SetReleaseFeatureGate(newLimitsGate(t, latched))
	return s
}

func limitsServer(t *testing.T, latched bool) (*Server, limitsGate) {
	g := newLimitsGate(t, latched)
	s := &Server{}
	s.SetReleaseFeatureGate(g)
	return s, g
}

const vmLimitsRelRefusal = "the cluster upgrade must finish first (vm_limits needs release_2026_11_v1)"

// Unlatched, every way of setting a limit is refused early, with the release
// refusal, by a LOCAL read: the full gate (a Ping sweep and a recorded use) is
// never reached by a request that is only being refused.
func TestVMLimitsGate_PrecheckRefusesEveryWayOfSettingALimit(t *testing.T) {
	ctx := context.Background()
	s, g := limitsServer(t, false)
	f := 1.5
	i := int32(512)
	for name, spec := range map[string]*pb.VMSpec{
		"cpu_limit":  {CpuLimit: 1},
		"cpu_shares": {CpuShares: 512},
		"nic rate":   {Network: []*pb.NetworkAttachment{{Name: "a"}, {Name: "b", RateMbSec: 2}}},
	} {
		err := s.precheckLimitedSpec(ctx, spec)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
			t.Errorf("create with %s: err = %v, want the release refusal", name, err)
		}
	}
	for name, req := range map[string]*pb.UpdateVMRequest{
		"cpu_limit":  {CpuLimit: &f},
		"cpu_shares": {CpuShares: &i},
		"nic rate":   {NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 1}}},
	} {
		err := s.precheckLimitUpdate(ctx, req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
			t.Errorf("update with %s: err = %v, want the release refusal", name, err)
		}
	}
	if *g.calls != 0 || *g.refusals == 0 {
		t.Errorf("the precheck made %d full-gate and %d non-recording calls; it must use only the non-recording step", *g.calls, *g.refusals)
	}
	if err := s.precheckLimitedSpec(ctx, &pb.VMSpec{CpuLimit: 1}); !strings.Contains(err.Error(), "lv cluster upgrade-status") || !strings.Contains(err.Error(), "node-b") {
		t.Errorf("the refusal lost the gate's text (lagging hosts, upgrade-status pointer): %v", err)
	}
	// A server with no gate wired fails closed.
	if err := (&Server{}).precheckLimitedSpec(context.Background(), &pb.VMSpec{CpuLimit: 1}); err == nil {
		t.Error("a server with no release gate accepted a limit")
	}
}

// The stack check looks at the WHOLE file: a limitless VM first, a shares-only
// or rate-only VM later, and the order of the map cannot hide it.
func TestVMLimitsGate_StackPrecheckSeesEveryLimitKindInTheWholeFile(t *testing.T) {
	ctx := context.Background()
	s, g := limitsServer(t, false)
	for name, vm := range map[string]compose.VMDef{
		"cpu cap": {CPULimit: 1},
		"shares":  {CPUShares: 200},
		"rate":    {Network: []compose.NetworkAttachment{{Name: "n", Rate: 2}}},
	} {
		f := &compose.File{VMs: map[string]compose.VMDef{"a-plain": {}, "b-plain": {}, "z": vm}}
		err := s.precheckStackLimits(ctx, f)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) || !strings.Contains(err.Error(), `"z"`) {
			t.Errorf("%s on the last VM: err = %v, want the release refusal naming z", name, err)
		}
	}
	// Containers carry no such limits; a limitless file is not refused.
	ct := &compose.File{VMs: map[string]compose.VMDef{"c": {Kind: compose.WorkloadKindLXC, CPULimit: 1}, "v": {}}}
	if err := s.precheckStackLimits(ctx, ct); err != nil {
		t.Errorf("limitless file refused: %v", err)
	}
	if *g.calls != 0 {
		t.Errorf("the stack precheck reached the full gate %d time(s); it must record nothing", *g.calls)
	}
}

// The recreate preflight judges a spec before a teardown; it must not let a
// limit through while unlatched either, and it records nothing.
func TestVMLimitsGate_RecreatePreflightRefusesUnlatched(t *testing.T) {
	s, g := limitsServer(t, false)
	_, err := s.recreatePreflightSpec(context.Background(), &pb.VMSpec{Cpu: 2, CpuLimit: 1}, "host")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), vmLimitsRelRefusal) {
		t.Errorf("err = %v, want the release refusal", err)
	}
	if *g.calls != 0 {
		t.Errorf("a preflight reached the full gate %d time(s)", *g.calls)
	}
}

// Specs and updates without a limit behave exactly as on main, including a
// zero, which sets nothing (a clear of an absent limit sends it). Neither half
// of the gate is even consulted.
func TestVMLimitsGate_LimitlessWorkIsNeverGated(t *testing.T) {
	ctx := context.Background()
	s, g := limitsServer(t, false)
	zero, zi := 0.0, int32(0)
	plain := &pb.VMSpec{Cpu: 2, Network: []*pb.NetworkAttachment{{Name: "a"}}}
	upd := &pb.UpdateVMRequest{Cpu: 4, CpuLimit: &zero, CpuShares: &zi, NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 0}}}
	if err := s.precheckLimitedSpec(ctx, plain); err != nil {
		t.Errorf("limitless create refused: %v", err)
	}
	if err := s.recordLimitedSpec(ctx, plain); err != nil {
		t.Errorf("limitless record refused: %v", err)
	}
	if err := s.precheckLimitUpdate(ctx, upd); err != nil {
		t.Errorf("zero-valued limit update refused: %v", err)
	}
	if err := s.recordLimitUpdate(ctx, upd); err != nil {
		t.Errorf("zero-valued limit update recorded/refused: %v", err)
	}
	if *g.calls != 0 {
		t.Errorf("the gate ran %d time(s) for work with no limit", *g.calls)
	}
}

// Latched: the recording half runs the write through the vm_limits feature
// with a grant, and the precheck passes.
func TestVMLimitsGate_LatchedRecordsThroughTheFeature(t *testing.T) {
	ctx := context.Background()
	s, g := limitsServer(t, true)
	f := 1.5
	spec := &pb.VMSpec{CpuLimit: 1, CpuShares: 9, Network: []*pb.NetworkAttachment{{RateMbSec: 2}}}
	req := &pb.UpdateVMRequest{CpuLimit: &f}
	if err := s.precheckLimitedSpec(ctx, spec); err != nil {
		t.Errorf("latched precheck refused: %v", err)
	}
	if err := s.recordLimitedSpec(ctx, spec); err != nil {
		t.Errorf("latched create refused: %v", err)
	}
	if err := s.recordLimitUpdate(ctx, req); err != nil {
		t.Errorf("latched update refused: %v", err)
	}
	if *g.runs != 2 || *g.feature != capabilities.FeatureVMLimits {
		t.Errorf("gated writes = %d feature = %q, want 2 through vm_limits", *g.runs, *g.feature)
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

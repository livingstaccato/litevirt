package grpcapi

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func TestApplyLiveResize_ReappliesThePerVCPUQuotaAfterAHotAdd(t *testing.T) {
	s := testServerR2(t)
	fake := libvirtfake.New()
	s.virt = fake
	const name = "web"
	if err := fake.DefineDomain("<domain type='kvm'><name>web</name><vcpu>2</vcpu><os/></domain>"); err != nil {
		t.Fatal(err)
	}
	prev := &pb.VMSpec{Cpu: 2, CpuLimit: 1}
	target := &pb.VMSpec{Cpu: 4, CpuLimit: 1}
	if err := s.applyLiveResize(adminCtx(), name, target, prev); err != nil {
		t.Fatalf("applyLiveResize: %v", err)
	}
	// 1 core over 4 vCPUs is 25000 per vCPU, not the 50000 it was at 2.
	if x := fake.DefinedXML(name); !strings.Contains(x, "<quota>25000</quota>") {
		t.Errorf("quota not re-derived for 4 vCPUs:\n%s", x)
	}
	// A VM with no cap gets no cputune from a hot-add.
	fake2 := libvirtfake.New()
	s.virt = fake2
	_ = fake2.DefineDomain("<domain type='kvm'><name>web</name><vcpu>2</vcpu><os/></domain>")
	if err := s.applyLiveResize(adminCtx(), name, &pb.VMSpec{Cpu: 4}, &pb.VMSpec{Cpu: 2}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fake2.DefinedXML(name), "cputune") {
		t.Error("an uncapped VM gained a cputune on hot-add")
	}
}

func TestMergeLimitUpdate(t *testing.T) {
	spec := func() *pb.VMSpec {
		return &pb.VMSpec{Cpu: 4, CpuLimit: 2, Network: []*pb.NetworkAttachment{{Name: "a"}, {Name: "b", RateMbSec: 3}}}
	}
	f := func(v float64) *float64 { return &v }
	i := func(v int32) *int32 { return &v }

	s := spec()
	up, err := mergeLimitUpdate(s, &pb.UpdateVMRequest{CpuLimit: f(3.5), CpuShares: i(100),
		NicRate: []*pb.NICRateUpdate{{Ordinal: 1, RateMbSec: 0}}})
	if err != nil {
		t.Fatal(err)
	}
	if s.CpuLimit != 3.5 || s.CpuShares != 100 || s.Network[1].RateMbSec != 0 || s.Network[0].RateMbSec != 0 {
		t.Errorf("merged spec = %+v", s)
	}
	if !up.cpu || !up.sharesTouch || len(up.nicOrdinals) != 1 || up.nicPrevRate[1] != 3 {
		t.Errorf("update record = %+v", up)
	}

	bad := map[string]*pb.UpdateVMRequest{
		"limit above vcpus":     {CpuLimit: f(4.5)},
		"negative limit":        {CpuLimit: f(-1)},
		"shares out of range":   {CpuShares: i(300000)},
		"negative shares":       {CpuShares: i(-1)},
		"nic beyond the spec":   {NicRate: []*pb.NICRateUpdate{{Ordinal: 2, RateMbSec: 1}}},
		"negative nic":          {NicRate: []*pb.NICRateUpdate{{Ordinal: -1, RateMbSec: 1}}},
		"nic named twice":       {NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 1}, {Ordinal: 0, RateMbSec: 2}}},
		"negative rate":         {NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: -3}}},
		"shrink strands limit":  {Cpu: 1},
		"limit vs the new cpus": {Cpu: 2, CpuLimit: f(2.5)},
	}
	for name, req := range bad {
		if _, err := mergeLimitUpdate(spec(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	// Shrinking is fine once the limit comes down with it.
	if _, err := mergeLimitUpdate(spec(), &pb.UpdateVMRequest{Cpu: 1, CpuLimit: f(1)}); err != nil {
		t.Errorf("shrink with a matching limit: %v", err)
	}
}

func TestValidateCreateLimits(t *testing.T) {
	ok := &pb.VMSpec{Cpu: 2, CpuLimit: 1.5, CpuShares: 2048, Network: []*pb.NetworkAttachment{{Name: "n", RateMbSec: 10}}}
	if err := validateCreateLimits(ok); err != nil {
		t.Errorf("valid spec refused: %v", err)
	}
	for name, spec := range map[string]*pb.VMSpec{
		"limit above cpu": {Cpu: 2, CpuLimit: 2.5},
		"shares":          {Cpu: 2, CpuShares: 1},
		"rate":            {Cpu: 2, Network: []*pb.NetworkAttachment{{Name: "n", RateMbSec: -1}}},
	} {
		if err := validateCreateLimits(spec); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	// Through the real create normalization, which defaults cpu first: a limit
	// of 3 on a VM that asked for no cpu is judged against the default of 2.
	if _, err := normalizeCreateVMSpec(&pb.VMSpec{CpuLimit: 3}, ""); err == nil {
		t.Error("cpu_limit 3 accepted for a default 2-vCPU VM")
	}
}

func TestLimitFieldRouting(t *testing.T) {
	limits, rest := splitLimitFields([]string{"labels", "cpu_limit", "nic_rate_1", "onboot", "cpu_shares"})
	if fmt.Sprint(limits) != "[cpu_limit nic_rate_1 cpu_shares]" || fmt.Sprint(rest) != "[labels onboot]" {
		t.Errorf("split = %v / %v", limits, rest)
	}
	desired := &pb.VMSpec{CpuLimit: 1, CpuShares: 7, Network: []*pb.NetworkAttachment{{}, {RateMbSec: 8}}}
	req := limitUpdateFromDesired("vm", desired, limits)
	if req.GetCpuLimit() != 1 || req.GetCpuShares() != 7 || len(req.NicRate) != 1 || req.NicRate[0].Ordinal != 1 || req.NicRate[0].RateMbSec != 8 {
		t.Errorf("request = %+v", req)
	}
}

func TestIsPureCPUGrowRequest_RefusesLimitFields(t *testing.T) {
	v := 1.0
	if !isPureCPUGrowRequest(&pb.UpdateVMRequest{Cpu: 4}) {
		t.Fatal("baseline: a bare cpu grow must be pure")
	}
	if isPureCPUGrowRequest(&pb.UpdateVMRequest{Cpu: 4, CpuLimit: &v}) {
		t.Error("a grow that also sets a limit took the limit-less live fast path")
	}
}

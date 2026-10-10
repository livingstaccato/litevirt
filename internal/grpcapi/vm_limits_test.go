package grpcapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// The cap is on the whole domain (global_quota), so a vCPU change moves nothing:
// a hot-add must not touch the cputune, and a limit that was valid at 2 vCPUs
// is valid at 8. (Under a per-vCPU quota a tiny cap fell under libvirt's floor
// after a grow, the re-apply failed, and the resize operation wedged.)
func TestLiveGrow_UnderATinyCapNeedsNothingMore(t *testing.T) {
	s := liveResizeServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, CpuLimit: 0.05}))
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>hp</name><memory unit='KiB'>2097152</memory><vcpu current='2'>8</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	fake := s.virt.(*libvirtfake.Fake)
	before := len(fake.EventLog())
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", Cpu: 8}); err != nil {
		t.Fatalf("live grow under a 0.05-core cap: %v", err)
	}
	if spec := loadStoredSpec(t, s, "hp"); spec.Cpu != 8 || spec.CpuLimit != 0.05 {
		t.Errorf("spec cpu=%d limit=%v, want 8 / 0.05", spec.Cpu, spec.CpuLimit)
	}
	for _, e := range fake.EventLog()[before:] {
		if e.Op == "set-cputune" {
			t.Errorf("a vCPU grow rewrote the cap: %s", e.Note)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "hp"); vm == nil || vm.CPUActual != 8 {
		t.Errorf("the grow did not complete: %+v", vm)
	}
}

// The limits-only update takes the VM lock and must then work from what the
// lock protects, not from the spec it read before waiting for it. A vCPU grow
// that completes in between must survive the limit write.
func TestUpdateVMLimits_WritesTheSpecReadUnderTheLock(t *testing.T) {
	s := reconfigServer(t)
	s.SetGate(tokenGate{on: true})
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "web", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 1024}))
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>web</name><memory unit='KiB'>1048576</memory><vcpu>2</vcpu></domain>`); err != nil {
		t.Fatal(err)
	}
	s.limitsPreLockHook = func(name string) {
		// The concurrent grow: commits cpu=4 while the update waits for the lock.
		if _, _, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
			sp := &pb.VMSpec{}
			if uerr := json.Unmarshal([]byte(old), sp); uerr != nil {
				return "", uerr
			}
			sp.Cpu = 4
			b, merr := json.Marshal(sp)
			return string(b), merr
		}); err != nil {
			t.Fatalf("simulated grow: %v", err)
		}
	}
	limit := 3.0 // valid at the grown 4 vCPUs, not at the stale 2
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "web", CpuLimit: &limit}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	spec := loadStoredSpec(t, s, "web")
	if spec.Cpu != 4 || spec.CpuLimit != 3 {
		t.Errorf("stored spec cpu=%d limit=%v, want 4 / 3: the update wrote back the spec it read before the lock", spec.Cpu, spec.CpuLimit)
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
		"shares out of range":   {CpuShares: i(20000)},
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
		"shares":          {Cpu: 2, CpuShares: 20000},
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

// A spec entry describes a NIC only while the NIC at that position still sits on
// the network the entry names (a retarget or an unplug shifts them); the rebuild
// paths already refuse the mismatch, so the live update must too, or the cap
// would vanish at the next failover.
func TestUpdateVMLimits_RefusesANICRateForANICThatMovedOffItsNetwork(t *testing.T) {
	s := reconfigServer(t)
	s.SetGate(tokenGate{on: true})
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 1024, Network: []*pb.NetworkAttachment{{Name: "old"}}}
	// The NIC row says the NIC at ordinal 0 is on another network now.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web", HostName: "test-host", Spec: seedSpecJSON(t, spec), State: "stopped", CPUActual: 2, MemActual: 1024,
	}, []corrosion.InterfaceRecord{{VMName: "web", NetworkName: "new", Ordinal: 0, MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>web</name><memory unit='KiB'>1048576</memory><vcpu>2</vcpu><devices><interface type='bridge'><mac address='52:54:00:00:00:01'/></interface></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "web", NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 5}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "network") {
		t.Fatalf("err = %v, want FailedPrecondition naming the network mismatch", err)
	}
	if got := loadStoredSpec(t, s, "web").Network[0].RateMbSec; got != 0 {
		t.Errorf("rate persisted as %v despite the refusal", got)
	}
}

// A restore defines a VM from an operator-supplied or manifest spec; a limit in
// it is judged like a create's: gated on the token, and validated.
func TestRestoreSpec_LimitsAreGatedAndValidated(t *testing.T) {
	ctx := adminCtx()
	unlatched := &Server{gate: tokenGate{on: false}}
	latched := &Server{gate: tokenGate{on: true}}
	limited := &pb.VMSpec{Cpu: 2, CpuLimit: 1}
	if err := unlatched.checkCopiedSpecLimits(ctx, limited); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Errorf("unlatched restore of a limited spec: err = %v, want the gate's refusal", err)
	}
	if err := latched.checkCopiedSpecLimits(ctx, limited); err != nil {
		t.Errorf("latched restore of a valid limit: %v", err)
	}
	for name, spec := range map[string]*pb.VMSpec{
		"cap above the vCPUs": {Cpu: 2, CpuLimit: 10},
		"weight out of range": {Cpu: 2, CpuShares: 500000},
		"negative rate":       {Cpu: 2, Network: []*pb.NetworkAttachment{{Name: "n", RateMbSec: -1}}},
	} {
		if err := latched.checkCopiedSpecLimits(ctx, spec); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	if err := unlatched.checkCopiedSpecLimits(ctx, &pb.VMSpec{Cpu: 2}); err != nil {
		t.Errorf("a limitless spec was refused: %v", err)
	}
}

// autoDefineRestoredVM runs the check on the resolved spec — an operator's
// --spec and a manifest's embedded spec alike — before it touches a domain.
func TestAutoDefineRestoredVM_RefusesALimitBeforeTheToken(t *testing.T) {
	s := reconfigServer(t)
	s.SetGate(tokenGate{on: false})
	ctx := adminCtx()
	noop := func(*pb.RestoreLiveProgress) error { return nil }
	embedded, _ := json.Marshal(&pb.VMSpec{Cpu: 2, CpuShares: 200})
	for name, tc := range map[string]struct {
		req      *pb.RestoreLiveRequest
		manifest *pbsstore.Manifest
	}{
		"operator spec": {&pb.RestoreLiveRequest{VmName: "r", Spec: &pb.VMSpec{Cpu: 2, CpuLimit: 1}}, &pbsstore.Manifest{}},
		"manifest spec": {&pb.RestoreLiveRequest{VmName: "r"}, &pbsstore.Manifest{VMSpecJSON: string(embedded)}},
	} {
		_, _, err := s.autoDefineRestoredVM(ctx, tc.req, nil, tc.manifest, "/nonexistent/overlay.qcow2", "_default", noop)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Errorf("%s: err = %v, want the gate's refusal", name, err)
		}
	}
}

// A clone copies the source's limits; the copy is judged as a create is.
func TestCloneVM_RefusesACopiedLimitBeforeTheToken(t *testing.T) {
	s := reconfigServer(t)
	s.SetGate(tokenGate{on: false})
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "src", Cpu: 2, MemoryMib: 1024, CpuLimit: 1}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "src", HostName: "test-host", Spec: seedSpecJSON(t, spec), State: "stopped", CPUActual: 2, MemActual: 1024,
	}, nil, []corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host", Path: "/nonexistent/src-root.qcow2", SizeBytes: 1 << 30}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	_, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "dst"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Fatalf("err = %v, want the gate's refusal", err)
	}
}

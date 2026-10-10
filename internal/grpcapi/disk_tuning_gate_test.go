package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ioGate is a release-feature gate for the disk/NIC feature: open it mints the
// feature's grant, closed it refuses as the real gate does. Writes records the
// order the grant was handed out in (see TestIOGrant_*).
type ioGate struct {
	t      testing.TB
	on     bool
	grants *int
}

func (g ioGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if !g.on {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	if g.grants != nil {
		*g.grants++
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g ioGate) FeatureAvailable(capabilities.Feature) bool { return g.on }

// Until the disk/NIC feature gate latches, every way of setting discard, detect_zeroes,
// a throttle or NIC queues is refused with FailedPrecondition naming the cluster
// upgrade: an older owner would drop them from the spec it rewrites.
//
// Mutations: make specSetsDiskNICIO ignore one field kind — that case goes red;
// make the refusal never fire — every case goes red.
func TestDiskNICIOGate_UnlatchedRefusesEveryWayOfSettingTuning(t *testing.T) {
	ctx := context.Background()
	s := &Server{releaseFeatures: ioGate{t: t, on: false}}
	for name, spec := range map[string]*pb.VMSpec{
		"discard":       {Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}}},
		"discard off":   {Disks: []*pb.DiskSpec{{Name: "root", Discard: "ignore"}}},
		"detect_zeroes": {Disks: []*pb.DiskSpec{{Name: "root", DetectZeroes: "on"}}},
		"iotune":        {Disks: []*pb.DiskSpec{{Name: "root"}, {Name: "d", Io: &pb.DiskIOLimits{ReadIopsSec: 1}}}},
		"queues":        {Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}},
	} {
		err := s.refuseUnlatchedDiskNICIO(ctx, spec)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Errorf("create with %s: err = %v, want FailedPrecondition naming the cluster upgrade", name, err)
		}
	}
	// A compose clear (`iotune: {}`) sets nothing: it is not refused.
	if err := s.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root", Io: &pb.DiskIOLimits{}}}}); err != nil {
		t.Errorf("an empty iotune was refused before the latch: %v", err)
	}
	// A spec with none of them is not refused.
	if err := s.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}}, Network: []*pb.NetworkAttachment{{Name: "n"}}}); err != nil {
		t.Errorf("an untuned spec was refused: %v", err)
	}
	// A latched cluster accepts them; a server with no gate is unlatched.
	latched := &Server{releaseFeatures: ioGate{t: t, on: true}}
	if err := latched.refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}); err != nil {
		t.Errorf("latched: %v", err)
	}
	if err := (&Server{}).refuseUnlatchedDiskNICIO(ctx, &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}); err == nil {
		t.Error("a server with no gate accepted queues")
	}
}

// The recreate preflight judges a spec before a teardown, so it must refuse an
// unlatched tuning before anything is touched.
func TestDiskNICIOGate_RecreatePreflightRefusesUnlatched(t *testing.T) {
	s := &Server{releaseFeatures: ioGate{t: t, on: false}}
	_, err := s.recreatePreflightSpec(context.Background(),
		&pb.VMSpec{Cpu: 2, Disks: []*pb.DiskSpec{{Name: "root", Io: &pb.DiskIOLimits{TotalIopsSec: 5}}}}, "host")
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

// lv disk-io is refused before the latch when it sets a limit, and clearing is
// not (there is nothing set to protect).
//
// Mutation: drop the refusal from SetDiskIO — the set case goes red.
func TestDiskNICIOGate_SetDiskIO(t *testing.T) {
	s, _, ctx := ioVM(t, "running")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	_, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Fatalf("set before the latch: %v", err)
	}
	if got := loadStoredSpec(t, s, "io").Disks[0].Io; got != nil {
		t.Errorf("a refused call recorded limits: %+v", got)
	}
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root"}); err != nil {
		t.Errorf("clearing before the latch: %v", err)
	}
	s.SetReleaseFeatureGate(ioGate{t: t, on: true})
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err != nil {
		t.Errorf("set after the latch: %v", err)
	}
}

// UpdateVM's explicit hardware redefine is refused before the latch, as is a
// request carrying tuning (below).
func TestDiskNICIOGate_HardwareRedefine(t *testing.T) {
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", RedefineHardware: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("UpdateVM redefine_hardware before the latch: %v", err)
	}
}

// CreateVM itself refuses (not only the compose entry): a direct create, a
// forwarded leg and a recreate all reach it.
//
// Mutation: drop the refusal from CreateVM — red.
func TestDiskNICIOGate_CreateVMRefusesUnlatched(t *testing.T) {
	s := testServer(t) // no gate: not latched
	_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "gated", Cpu: 1, MemoryMib: 256, Image: "img",
		Disks: []*pb.DiskSpec{{Name: "root", Discard: "unmap"}},
	}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
		t.Errorf("CreateVM with discard before the latch: %v", err)
	}
}

// UpdateVM carries the tuning itself (the owner applies it): before the latch a
// request naming any is refused at the entry node, and a refusal changes nothing.
func TestDiskNICIOGate_UpdateVMTuningRequestUnlatched(t *testing.T) {
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: false})
	for name, req := range map[string]*pb.UpdateVMRequest{
		"disk": {Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "ignore"}}},
		"nic":  {Name: "io", NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 0, Queues: 4}}},
	} {
		if _, err := s.UpdateVM(ctx, req); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Restore-live and promote take their spec from a backup manifest or a caller:
// before the gate opens the tuning is stripped (a restore main allows must still
// work), and after it the values are validated.
//
// Mutations: skip the strip — the unlatched case goes red; skip validation — the
// latched invalid case goes red.
func TestRestrictRestoredTuning(t *testing.T) {
	mk := func() *pb.VMSpec {
		return &pb.VMSpec{Name: "r",
			Disks:   []*pb.DiskSpec{{Name: "root", Discard: "unmap", DetectZeroes: "on", Io: &pb.DiskIOLimits{ReadIopsSec: 5}}},
			Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}}}
	}
	ctx := context.Background()
	un := &Server{releaseFeatures: ioGate{t: t, on: false}}
	spec := mk()
	stripped, _, err := un.restrictRestoredTuning(ctx, spec)
	if err != nil || !stripped || specSetsDiskNICIO(spec) {
		t.Errorf("unlatched: stripped=%v err=%v spec=%+v", stripped, err, spec)
	}
	if untouched := (&pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}}}); true {
		if st, _, err := un.restrictRestoredTuning(ctx, untouched); st || err != nil {
			t.Errorf("a spec with no tuning reported stripped=%v err=%v", st, err)
		}
	}
	la := &Server{releaseFeatures: ioGate{t: t, on: true}}
	spec = mk()
	st, g, err := la.restrictRestoredTuning(ctx, spec)
	if err != nil || st || !specSetsDiskNICIO(spec) || g.Check(capabilities.FeatureVMDiskNICIO) != nil {
		t.Errorf("latched valid: stripped=%v err=%v grant=%v", st, err, g)
	}
	bad := mk()
	bad.Network[0].Queues = 4096
	if _, _, err := la.restrictRestoredTuning(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("latched, queues 4096: %v, want InvalidArgument", err)
	}
	bad = mk()
	bad.Disks[0].Io = &pb.DiskIOLimits{TotalBytesSec: 1, ReadBytesSec: 1}
	if _, _, err := la.restrictRestoredTuning(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("latched, total with read: %v, want InvalidArgument", err)
	}
}

// The corrosion writers of the feature refuse a call without the feature's
// grant, so a write that skips the gate cannot land.
//
// Mutation: drop g.Check from either writer — the matching case goes red.
func TestDiskNICIOWriters_RefuseWithoutAGrant(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "w", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "w"}))
	var none capabilities.FeatureGrant
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, none, "w", func(old string) (string, error) { return old + " ", nil }); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("MutateDesiredSpecTuning without a grant: %v", err)
	}
	other := capabilities.GrantForTest(t, capabilities.FeatureVMLimits)
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, other, "w", func(old string) (string, error) { return old + " ", nil }); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("MutateDesiredSpecTuning with another feature's grant: %v", err)
	}
	if err := corrosion.InsertVMWithTuning(ctx, s.db, none, corrosion.VMRecord{Name: "x", HostName: "test-host", State: "stopped"}, nil, nil, nil, nil, false); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("InsertVMWithTuning without a grant: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "x"); vm != nil {
		t.Error("a refused insert wrote a row")
	}
	ok := capabilities.GrantForTest(t, capabilities.FeatureVMDiskNICIO)
	if _, _, err := corrosion.MutateDesiredSpecTuning(ctx, s.db, ok, "w", func(old string) (string, error) { return old, nil }); err != nil {
		t.Errorf("MutateDesiredSpecTuning with the grant: %v", err)
	}
}

// A VM created with the gate open and a tuned spec takes the grant on THIS node;
// an untuned create on a closed gate takes none (it creates as main does).
func TestIOGrant_TakenOnlyForTunedWrites(t *testing.T) {
	var n int
	s := &Server{releaseFeatures: ioGate{t: t, on: true, grants: &n}}
	if _, ok := s.ioGrantIfAvailable(context.Background()); !ok || n != 1 {
		t.Errorf("open gate: ok=%v grants=%d", ok, n)
	}
	closed := &Server{releaseFeatures: ioGate{t: t, on: false, grants: &n}}
	if _, ok := closed.ioGrantIfAvailable(context.Background()); ok {
		t.Error("closed gate handed out a grant")
	}
	if _, err := closed.ioGrant(context.Background()); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (vm_disk_nic_io needs release_2026_11_v1)") {
		t.Errorf("closed ioGrant: %v", err)
	}
}

// The node that WRITES tuning takes the feature's grant: an UpdateVM carrying
// tuning and a SetDiskIO that sets a limit each take one; a SetDiskIO that
// clears takes none (it adds nothing). The entry check is the local hint and
// takes none.
//
// Mutations: write UpdateVM's spec with plain MutateDesiredSpec and no grant —
// the UpdateVM case goes red; skip the grant in SetDiskIO — the set case does.
func TestIOGrant_TakenByTheNodeThatWritesTuning(t *testing.T) {
	var n int
	s, _, ctx := ioVM(t, "stopped")
	s.SetReleaseFeatureGate(ioGate{t: t, on: true, grants: &n})
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	if n != 1 {
		t.Errorf("UpdateVM with tuning took %d grants, want 1", n)
	}
	n = 0
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err != nil {
		t.Fatalf("SetDiskIO set: %v", err)
	}
	if n != 1 {
		t.Errorf("SetDiskIO set took %d grants, want 1", n)
	}
	n = 0
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root"}); err != nil {
		t.Fatalf("SetDiskIO clear: %v", err)
	}
	if n != 0 {
		t.Errorf("SetDiskIO clear took %d grants, want 0", n)
	}
}

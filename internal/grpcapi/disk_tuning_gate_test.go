package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ioGate answers Enforced for the disk/NIC feature gate only.
type ioGate struct {
	fakeServerGate
	on bool
}

func (g ioGate) Enforced(_ context.Context, tok string) bool {
	return g.on && tok == ioFeatureToken
}

// Until the disk/NIC feature gate latches, every way of setting discard, detect_zeroes,
// a throttle or NIC queues is refused with FailedPrecondition naming the cluster
// upgrade: an older owner would drop them from the spec it rewrites.
//
// Mutations: make specSetsDiskNICIO ignore one field kind — that case goes red;
// make the refusal never fire — every case goes red.
func TestDiskNICIOGate_UnlatchedRefusesEveryWayOfSettingTuning(t *testing.T) {
	ctx := context.Background()
	s := &Server{gate: ioGate{on: false}}
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
	latched := &Server{gate: ioGate{on: true}}
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
	s := &Server{gate: ioGate{on: false}}
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
	s.gate = ioGate{on: false}
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
	s.gate = ioGate{on: true}
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err != nil {
		t.Errorf("set after the latch: %v", err)
	}
}

// UpdateVM's explicit hardware redefine is refused before the latch, as is a
// request carrying tuning (below).
func TestDiskNICIOGate_HardwareRedefine(t *testing.T) {
	s, _, ctx := ioVM(t, "stopped")
	s.gate = ioGate{on: false}
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
	s.gate = ioGate{on: false}
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
	un := &Server{gate: ioGate{on: false}}
	spec := mk()
	stripped, err := un.restrictRestoredTuning(ctx, spec)
	if err != nil || !stripped || specSetsDiskNICIO(spec) {
		t.Errorf("unlatched: stripped=%v err=%v spec=%+v", stripped, err, spec)
	}
	if untouched := (&pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}}}); true {
		if st, err := un.restrictRestoredTuning(ctx, untouched); st || err != nil {
			t.Errorf("a spec with no tuning reported stripped=%v err=%v", st, err)
		}
	}
	la := &Server{gate: ioGate{on: true}}
	spec = mk()
	if st, err := la.restrictRestoredTuning(ctx, spec); err != nil || st || !specSetsDiskNICIO(spec) {
		t.Errorf("latched valid: stripped=%v err=%v", st, err)
	}
	bad := mk()
	bad.Network[0].Queues = 4096
	if _, err := la.restrictRestoredTuning(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("latched, queues 4096: %v, want InvalidArgument", err)
	}
	bad = mk()
	bad.Disks[0].Io = &pb.DiskIOLimits{TotalBytesSec: 1, ReadBytesSec: 1}
	if _, err := la.restrictRestoredTuning(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("latched, total with read: %v, want InvalidArgument", err)
	}
}

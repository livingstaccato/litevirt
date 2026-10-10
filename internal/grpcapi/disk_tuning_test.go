package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ioVM is a VM with a root disk (vda) and a data disk (vdb) defined in the fake
// libvirt and recorded in the spec.
func ioVM(t *testing.T, state string) (*Server, *libvirtfake.Fake, context.Context) {
	t.Helper()
	s := reconfigServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "io", Cpu: 2, MemoryMib: 512,
		Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}, {Name: "data", Bus: "virtio"}}}
	insertTestVMWithSpec(t, ctx, s.db, "io", "test-host", state, seedSpecJSON(t, spec))
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "io", CPU: 2, MemoryMiB: 512, Disks: []lv.DiskConfig{
		{Name: "root", Path: "/d/io-root.qcow2", Bus: "virtio"}, {Name: "data", Path: "/d/io-data.qcow2", Bus: "virtio"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	if state == "running" {
		fake.SetState("io", libvirtfake.StateRunning)
	}
	return s, fake, ctx
}

func ioOf(t *testing.T, fake *libvirtfake.Fake, dev string, inactive bool) lv.IOTune {
	t.Helper()
	dump := fake.DumpXML
	if inactive {
		dump = fake.DumpXMLInactive
	}
	x, err := dump("io")
	if err != nil {
		t.Fatal(err)
	}
	tune, ok := lv.DiskIOTuneFromXML(x, dev)
	if !ok {
		t.Fatalf("no disk %s in:\n%s", dev, x)
	}
	return tune
}

// A limit set on a running VM lands in the live and the persistent definition
// and in the stored spec — the spec is what every later render reads — and
// clearing removes all three.
//
// Mutations: skip the libvirt call (both XML reads go red); skip the spec write
// (the spec read goes red, and a redefine would drop the limit); write the spec
// without clearing on an empty request (the clear's spec read goes red).
func TestSetDiskIO_AppliesPersistsAndClears(t *testing.T) {
	s, fake, ctx := ioVM(t, "running")
	want := lv.IOTune{ReadBytesSec: 10 << 20, WriteIopsSec: 300, WriteIopsSecMax: 900, BurstSec: 5}
	lim := &pb.DiskIOLimits{ReadBytesSec: 10 << 20, WriteIopsSec: 300, WriteIopsSecMax: 900, BurstSeconds: 5}
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "data", Limits: lim}); err != nil {
		t.Fatalf("SetDiskIO: %v", err)
	}
	if got := ioOf(t, fake, "vdb", false); got != want {
		t.Errorf("live definition of vdb = %+v, want %+v", got, want)
	}
	if got := ioOf(t, fake, "vdb", true); got != want {
		t.Errorf("persistent definition of vdb = %+v, want %+v", got, want)
	}
	if got := ioOf(t, fake, "vda", false); !got.IsZero() {
		t.Errorf("the other disk was throttled too: %+v", got)
	}
	spec := loadStoredSpec(t, s, "io")
	if spec.Disks[1].Io.GetWriteIopsSec() != 300 || spec.Disks[0].Io != nil {
		t.Errorf("stored spec disks = %+v %+v", spec.Disks[0], spec.Disks[1])
	}

	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "data"}); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if got := ioOf(t, fake, "vdb", false); !got.IsZero() {
		t.Errorf("live definition after a clear = %+v", got)
	}
	if got := loadStoredSpec(t, s, "io").Disks[1].Io; got != nil {
		t.Errorf("stored spec after a clear = %+v", got)
	}
}

func TestSetDiskIO_StoppedVMTakesTheConfigOnly(t *testing.T) {
	s, fake, ctx := ioVM(t, "stopped")
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root",
		Limits: &pb.DiskIOLimits{TotalIopsSec: 50}}); err != nil {
		t.Fatal(err)
	}
	if got := ioOf(t, fake, "vda", true); got.TotalIopsSec != 50 {
		t.Errorf("persistent definition = %+v", got)
	}
	if got := loadStoredSpec(t, s, "io").Disks[0].Io.GetTotalIopsSec(); got != 50 {
		t.Errorf("stored spec total_iops_sec = %d", got)
	}
}

func TestSetDiskIO_Refusals(t *testing.T) {
	s, fake, ctx := ioVM(t, "running")
	for name, tc := range map[string]struct {
		req  *pb.SetDiskIORequest
		code codes.Code
	}{
		"total with read": {&pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5, ReadIopsSec: 1}}, codes.InvalidArgument},
		"unknown disk":    {&pb.SetDiskIORequest{VmName: "io", DiskName: "nope", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}, codes.NotFound},
		"unknown VM":      {&pb.SetDiskIORequest{VmName: "ghost", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}, codes.NotFound},
		"no names":        {&pb.SetDiskIORequest{Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}, codes.InvalidArgument},
	} {
		if _, err := s.SetDiskIO(ctx, tc.req); status.Code(err) != tc.code {
			t.Errorf("%s: code = %v (%v), want %v", name, status.Code(err), err, tc.code)
		}
	}
	// libvirt refuses: nothing is recorded, so the spec never says "limited"
	// of a disk that is not.
	//
	// Mutation: persist the spec before calling libvirt — the spec read goes red.
	fake.FailSetDiskIOTune = func(string, string) error { return status.Error(codes.Internal, "boom") }
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); err == nil {
		t.Fatal("a libvirt failure was swallowed")
	}
	if got := loadStoredSpec(t, s, "io").Disks[0].Io; got != nil {
		t.Errorf("spec records limits libvirt refused: %+v", got)
	}
	fake.FailSetDiskIOTune = nil

	// An operation holds the mutation barrier.
	insertTestVMWithSpec(t, ctx, s.db, "busy", "test-host", "running", seedSpecJSON(t, &pb.VMSpec{Name: "busy", Disks: []*pb.DiskSpec{{Name: "root"}}}))
	op := corrosion.OperationRecord{ID: "op-io", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "busy",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := s.db.BeginVMOperation(ctx, op, seedSpecJSON(t, &pb.VMSpec{Name: "busy"}), 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: ok=%v err=%v", ok, err)
	}
	if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "busy", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("operation active: %v, want FailedPrecondition", err)
	}
}

// A disk hot-plugged onto the VM is in vm_disks but not in the spec, and the
// limits live in the spec: refusing is better than a throttle the next redefine
// silently drops.
func TestSetDiskIO_HotPluggedDiskIsRefusedPlainly(t *testing.T) {
	s, _, ctx := ioVM(t, "running")
	_, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "hot", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
	if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "spec") {
		t.Errorf("err = %v", err)
	}
}

func TestValidateSpecTuningNormalizesAndRefuses(t *testing.T) {
	spec := &pb.VMSpec{
		Disks:   []*pb.DiskSpec{{Name: "root", Discard: "ON"}},
		Network: []*pb.NetworkAttachment{{Name: "n", Queues: 4}},
	}
	if err := validateSpecTuning(spec); err != nil || spec.Disks[0].Discard != "unmap" {
		t.Fatalf("err=%v discard=%q, want on normalized to unmap", err, spec.Disks[0].Discard)
	}
	for name, bad := range map[string]*pb.VMSpec{
		"discard": {Disks: []*pb.DiskSpec{{Name: "root", Discard: "x"}}},
		"zeroes":  {Disks: []*pb.DiskSpec{{Name: "root", DetectZeroes: "unmap"}}},
		"queues":  {Network: []*pb.NetworkAttachment{{Name: "n", Queues: 9999}}},
		"model":   {Network: []*pb.NetworkAttachment{{Name: "n", Model: "e1000", Queues: 2}}},
		"iotune":  {Disks: []*pb.DiskSpec{{Name: "root", Io: &pb.DiskIOLimits{TotalBytesSec: 1, ReadBytesSec: 1}}}},
	} {
		if validateSpecTuning(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The create-time default: thin-capable storage on a TRIM-carrying bus gets
// unmap; NFS/iSCSI and a legacy bus do not.
func TestDefaultDiscard(t *testing.T) {
	for _, tc := range []struct{ storage, bus, want string }{
		{"local", "virtio", "unmap"}, {"zfs", "scsi", "unmap"}, {"lvm-thin", "sata", "unmap"}, {"ceph", "virtio", "unmap"},
		{"nfs", "virtio", ""}, {"iscsi", "virtio", ""}, {"local", "ide", ""},
	} {
		if got := defaultDiscard(tc.storage, tc.bus); got != tc.want {
			t.Errorf("defaultDiscard(%s,%s) = %q, want %q", tc.storage, tc.bus, got, tc.want)
		}
	}
}

// A cpu grow that also changes disk/NIC tuning must not take the live vCPU
// hot-add path: that path applies the vCPU count only, and would drop the
// tuning without a word.
//
// Mutation: drop `!req.RedefineHardware` from isPureCPUGrowRequest — red.
func TestIsPureCPUGrowRequest_RefusesHardwareRedefine(t *testing.T) {
	if !isPureCPUGrowRequest(&pb.UpdateVMRequest{Name: "x", Cpu: 4}) {
		t.Fatal("a bare cpu grow must be eligible for the live path")
	}
	if isPureCPUGrowRequest(&pb.UpdateVMRequest{Name: "x", Cpu: 4, RedefineHardware: true}) {
		t.Error("a cpu grow carrying a hardware redefine took the live path")
	}
}

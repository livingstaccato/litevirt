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
	s.SetReleaseFeatureGate(ioGate{t: t, on: true}) // feature gate open
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

// A disk the spec does not list is throttled all the same when vm_disks has it
// (an implicit root disk, a hot-plugged one): the entry is made in the spec, so
// every later render carries the limit. A disk nobody has is refused with a
// message that names it.
//
// Mutation: drop the synthesis — the implicit-root and hot-plugged cases go red.
func TestSetDiskIO_DiskTheSpecDoesNotListIsThrottledAndRecorded(t *testing.T) {
	s := reconfigServer(t)
	s.SetReleaseFeatureGate(ioGate{t: t, on: true})
	fake := s.virt.(*libvirtfake.Fake)
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "io", Cpu: 2, MemoryMib: 512} // no Disks: the implicit-root shape
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "io", HostName: "test-host", State: "running",
		CPUActual: 2, MemActual: 512, Spec: seedSpecJSON(t, spec)}, nil, []corrosion.DiskRecord{
		{VMName: "io", DiskName: "root", HostName: "test-host", Path: "/d/io-root.qcow2", StorageType: "local", TargetDev: "vda", Bus: "virtio", SizeBytes: 1 << 30},
		{VMName: "io", DiskName: "hot", HostName: "test-host", Path: "/d/io-hot.qcow2", StorageType: "local", TargetDev: "vdb", Bus: "virtio", SizeBytes: 1 << 30},
	}); err != nil {
		t.Fatal(err)
	}
	x, _ := lv.GenerateDomainXML(lv.VMConfig{Name: "io", CPU: 2, MemoryMiB: 512, Disks: []lv.DiskConfig{
		{Name: "root", Path: "/d/io-root.qcow2", Bus: "virtio"}, {Name: "hot", Path: "/d/io-hot.qcow2", Bus: "virtio"}}})
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	fake.SetState("io", libvirtfake.StateRunning)

	for disk, dev := range map[string]string{"root": "vda", "hot": "vdb"} {
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: disk, Limits: &pb.DiskIOLimits{TotalIopsSec: 77}}); err != nil {
			t.Fatalf("%s: %v", disk, err)
		}
		if got := ioOf(t, fake, dev, true); got.TotalIopsSec != 77 {
			t.Errorf("%s: persistent throttle = %+v", disk, got)
		}
	}
	got := loadStoredSpec(t, s, "io")
	if len(got.Disks) != 2 || got.Disks[0].Name != "root" || got.Disks[0].Io.GetTotalIopsSec() != 77 || got.Disks[1].Io.GetTotalIopsSec() != 77 {
		t.Errorf("the spec did not record the limits of the unlisted disks: %+v", got.Disks)
	}
	_, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "nope", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
	if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), `"nope"`) || strings.Contains(err.Error(), "hot-plugged") {
		t.Errorf("unknown disk: %v, want NotFound naming the disk and no false hot-plug claim", err)
	}
}

// A failure partway through leaves the cluster as it was: the persistent
// definition keeps the old limit when the live call fails, and both come back
// when the spec cannot be written; the spec is unchanged in every case.
//
// Mutations: drop the restore after a live failure — the inactive-XML check goes
// red; drop the restore after a spec failure — the XML checks go red.
func TestSetDiskIO_RollsBackOnPartialFailure(t *testing.T) {
	old := &pb.DiskIOLimits{ReadIopsSec: 100}
	next := &pb.DiskIOLimits{ReadIopsSec: 900, WriteBytesSec: 1 << 20}
	fresh := func(t *testing.T) (*Server, *libvirtfake.Fake, context.Context) {
		s, fake, ctx := ioVM(t, "running")
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: old}); err != nil {
			t.Fatal(err)
		}
		return s, fake, ctx
	}
	assertOld := func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
		t.Helper()
		for _, inactive := range []bool{true, false} {
			if got := ioOf(t, fake, "vda", inactive); got.ReadIopsSec != 100 || got.WriteBytesSec != 0 {
				t.Errorf("(inactive=%v) throttle = %+v, want the old read_iops_sec=100 only", inactive, got)
			}
		}
		if got := loadStoredSpec(t, s, "io").Disks[0].Io; got.GetReadIopsSec() != 100 || got.GetWriteBytesSec() != 0 {
			t.Errorf("spec limits = %+v, want unchanged", got)
		}
	}

	t.Run("config step fails", func(t *testing.T) {
		s, fake, ctx := fresh(t)
		fake.FailSetDiskIOTune = func(string, string) error { return status.Error(codes.Internal, "boom") }
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: next}); err == nil {
			t.Fatal("swallowed")
		}
		assertOld(t, s, fake)
	})
	t.Run("live step fails after the config took it", func(t *testing.T) {
		s, fake, ctx := fresh(t)
		fake.FailSetDiskIOTuneLive = func(string, string) error { return status.Error(codes.Internal, "job lock timeout") }
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: next}); err == nil {
			t.Fatal("swallowed")
		}
		fake.FailSetDiskIOTuneLive = nil
		assertOld(t, s, fake)
	})
	t.Run("spec write fails after libvirt took it", func(t *testing.T) {
		s, fake, ctx := fresh(t)
		s.ioSpecWriteHook = func() {
			op := corrosion.OperationRecord{ID: "op-race", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "io",
				OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
			cur, _ := corrosion.GetVM(ctx, s.db, "io")
			if ok, err := s.db.BeginVMOperation(ctx, op, seedSpecJSON(t, loadStoredSpec(t, s, "io")), cur.OwnerEpoch, cur.SpecGeneration); err != nil || !ok {
				t.Errorf("BeginVMOperation: ok=%v err=%v", ok, err)
			}
		}
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: next}); err == nil {
			t.Fatal("swallowed")
		}
		assertOld(t, s, fake)
	})
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

// UpdateVM carries the discard / detect_zeroes / queues change and applies it
// to ITS spec, writing the spec only after the domain has the setting. A define
// failure therefore leaves the spec as it was: it never claims what the domain
// lacks, and the operator's re-apply still plans the change.
//
// Mutations: write the spec before the define — the failure case goes red; drop
// the tuning merge — the success case goes red.
func TestUpdateVM_TuningRequestWritesTheSpecOnlyAfterTheDefine(t *testing.T) {
	s, fake, ctx := ioVM(t, "stopped")
	req := &pb.UpdateVMRequest{Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}

	fake.FailDefineDomain = func(string) error { return status.Error(codes.Internal, "define refused") }
	if _, err := s.UpdateVM(ctx, req); err == nil {
		t.Fatal("a define failure was swallowed")
	}
	fake.FailDefineDomain = nil
	if got := loadStoredSpec(t, s, "io").Disks[0].Discard; got != "" {
		t.Fatalf("the spec claims discard %q after a failed define", got)
	}

	if _, err := s.UpdateVM(ctx, req); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	if got := loadStoredSpec(t, s, "io").Disks[0].Discard; got != "unmap" {
		t.Errorf("spec discard = %q, want unmap", got)
	}
	if x := fake.DefinedXML("io"); !strings.Contains(x, `discard="unmap"`) && !strings.Contains(x, `discard='unmap'`) {
		t.Errorf("the redefined domain lacks discard:\n%s", x)
	}
	// An invalid value is refused before anything is touched.
	bad := &pb.UpdateVMRequest{Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", DetectZeroes: "unmap", Discard: "ignore"}}}
	if _, err := s.UpdateVM(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("detect_zeroes unmap with discard ignore: %v, want InvalidArgument", err)
	}
}

// A discard change patches the persistent definition instead of regenerating
// it, so what libvirt assigned (PCI addresses a Windows guest keys licensing and
// a static NIC configuration off) survives.
//
// Mutation: make the in-place path ineligible for tuning — the marker is lost.
func TestUpdateVM_TuningRequestPatchesTheDefinitionInPlace(t *testing.T) {
	s, fake, ctx := ioVM(t, "stopped")
	x, _ := fake.DumpXMLInactive("io")
	marked := strings.Replace(x, "<name>io</name>", "<name>io</name><description>libvirt-assigned-marker</description>", 1)
	fake.SetInactiveXML("io", marked)
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	got := fake.DefinedXML("io")
	if !strings.Contains(got, "libvirt-assigned-marker") {
		t.Errorf("the definition was regenerated, not patched:\n%s", got)
	}
	if !strings.Contains(got, "discard='unmap'") && !strings.Contains(got, `discard="unmap"`) {
		t.Errorf("the patched definition lacks discard:\n%s", got)
	}
}

// When the previous limits cannot be read, a failed step cannot be undone: the
// error says so rather than claiming nothing changed.
//
// Mutation: drop the !haveCfg message — red.
func TestSetDiskIO_SaysWhenThePreviousLimitsCouldNotBeRead(t *testing.T) {
	s, fake, ctx := ioVM(t, "running")
	fake.FailDumpXMLInactive = func(string) error { return status.Error(codes.Internal, "dump failed") }
	fake.FailSetDiskIOTune = func(string, string) error { return status.Error(codes.Internal, "boom") }
	_, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: "io", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 5}})
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("err = %v, want one saying the previous limits could not be read", err)
	}
}

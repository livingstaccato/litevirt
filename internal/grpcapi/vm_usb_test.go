package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// enableUsbMountsMemory turns the local flag on and latches the token.
func enableUsbMountsMemory(s *Server, extra ...string) {
	s.SetUsbMountsMemory(true)
	tok := map[string]bool{capabilities.UsbMountsMemoryV1: true}
	for _, e := range extra {
		tok[e] = true
	}
	s.SetGate(fakeServerGate{enforcedTok: tok})
}

func usbCreateRequest(name string, usb ...*pb.USBDeviceSpec) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.UsbDevices = usb
	return req
}

func addUSBMapping(t *testing.T, s *Server, name, host, addr string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.CreateResourceMapping(ctx, s.db, name, ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, name, host, addr, "", ""); err != nil {
		t.Fatal(err)
	}
}

// Setting USB passthrough needs the local flag AND the cluster latch; either
// alone refuses, and a refusal writes nothing.
func TestCreateVM_USBGatedOnFlagAndLatch(t *testing.T) {
	ctx := adminCtx()
	dev := &pb.USBDeviceSpec{Vendor: "046D", Product: "0xC52B"}

	for _, tc := range []struct {
		name   string
		flag   bool
		latch  bool
		wantOK bool
	}{
		{"neither", false, false, false},
		{"flag only", true, false, false},
		{"latch only", false, true, false},
		{"both", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			s.SetUsbMountsMemory(tc.flag)
			if tc.latch {
				s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.UsbMountsMemoryV1: true}})
			}
			_, err := s.CreateVM(ctx, usbCreateRequest("u1", dev))
			if !tc.wantOK {
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), usbMountsMemoryRefusalText) {
					t.Fatalf("CreateVM = %v; want the usb_mounts_memory refusal", err)
				}
				if row, _ := corrosion.GetVM(ctx, s.db, "u1"); row != nil {
					t.Fatal("a refused create left a VM row")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			spec := loadStoredSpec(t, s, "u1")
			if len(spec.UsbDevices) != 1 || spec.UsbDevices[0].Vendor != "046d" || spec.UsbDevices[0].Product != "c52b" {
				t.Fatalf("stored usb_devices = %v; want one normalized 046d:c52b", spec.UsbDevices)
			}
			x, _ := fake.DumpXMLInactive("u1")
			if !strings.Contains(x, `type="usb"`) || !strings.Contains(x, `<vendor id="0x046d">`) || !strings.Contains(x, `<product id="0xc52b">`) {
				t.Fatalf("defined domain lacks the USB hostdev:\n%s", x)
			}
		})
	}
}

// A raw device is plugged into one host, so a create must say which.
func TestCreateVM_RawUSBNeedsAPin(t *testing.T) {
	s, _ := provableCreateServer(t)
	enableUsbMountsMemory(s)
	req := usbCreateRequest("u1", &pb.USBDeviceSpec{BusPort: "1-2"})
	req.Spec.Placement = nil
	if _, err := s.CreateVM(adminCtx(), req); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "pin the VM") {
		t.Fatalf("unpinned raw USB create = %v; want InvalidArgument asking for a pin", err)
	}
}

func TestCreateVM_USBShapeValidation(t *testing.T) {
	s, _ := provableCreateServer(t)
	enableUsbMountsMemory(s)
	for _, bad := range []*pb.USBDeviceSpec{
		{},
		{Vendor: "046d"},
		{Vendor: "046d", Product: "c52b", BusPort: "1-2"},
		{BusPort: "1-2", Mapping: "m"},
		{BusPort: "../../etc"},
		{Vendor: "xyz1", Product: "c52b"},
	} {
		if _, err := s.CreateVM(adminCtx(), usbCreateRequest("u1", bad)); status.Code(err) != codes.InvalidArgument {
			t.Errorf("USB device %+v: CreateVM = %v; want InvalidArgument", bad, err)
		}
	}
}

// A mapped device resolves to the mapping's row for the owning host; a
// missing mapping or a PCI one is refused.
func TestCreateVM_USBThroughMapping(t *testing.T) {
	s, fake := provableCreateServer(t)
	enableUsbMountsMemory(s)
	ctx := adminCtx()
	addUSBMapping(t, s, "dongle", "test-host", "usb:1a86:7523")
	addUSBMapping(t, s, "gpu", "test-host", "0000:41:00.0")

	if _, err := s.CreateVM(ctx, usbCreateRequest("missing", &pb.USBDeviceSpec{Mapping: "nosuch"})); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown mapping: %v; want NotFound", err)
	}
	if _, err := s.CreateVM(ctx, usbCreateRequest("pci", &pb.USBDeviceSpec{Mapping: "gpu"})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("PCI mapping as USB: %v; want InvalidArgument", err)
	}
	req := usbCreateRequest("u1", &pb.USBDeviceSpec{Mapping: "dongle"})
	req.Spec.Placement = nil // a mapped device needs no pin
	if _, err := s.CreateVM(ctx, req); err != nil {
		t.Fatalf("mapped create: %v", err)
	}
	x, _ := fake.DumpXMLInactive("u1")
	if !strings.Contains(x, `<vendor id="0x1a86">`) || !strings.Contains(x, `<product id="0x7523">`) {
		t.Fatalf("domain lacks the mapping's device:\n%s", x)
	}
}

// A bus-port is read from the owning host's sysfs at define time.
func TestCreateVM_USBBusPortFromSysfs(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "3-1.4")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dev, "busnum"), []byte("3\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "devnum"), []byte("11\n"), 0o644)
	defer lv.SetUSBSysfsRootForTest(root)()

	s, fake := provableCreateServer(t)
	enableUsbMountsMemory(s)
	if _, err := s.CreateVM(adminCtx(), usbCreateRequest("u1", &pb.USBDeviceSpec{BusPort: "3-1.4"})); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	x, _ := fake.DumpXMLInactive("u1")
	if !strings.Contains(x, `<address bus="3" device="11">`) {
		t.Fatalf("domain lacks the resolved bus/device:\n%s", x)
	}
	// A port with nothing in it refuses the create: never define a VM missing
	// the device it asks for.
	if _, err := s.CreateVM(adminCtx(), usbCreateRequest("u2", &pb.USBDeviceSpec{BusPort: "3-2"})); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("empty port: %v; want FailedPrecondition", err)
	}
}

// Migration: live is refused with any USB device; cold needs every device
// mapped and the target to hold each mapping.
func TestRefuseUSBMigration(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	addUSBMapping(t, s, "dongle", "test-host", "usb:1a86:7523")
	if err := corrosion.AddMappingDevice(ctx, s.db, "dongle", "other", "usb:1a86:7523", "", ""); err != nil {
		t.Fatal(err)
	}
	vm := &corrosion.VMRecord{Name: "u", HostName: "test-host"}
	mapped := &pb.VMSpec{UsbDevices: []*pb.USBDeviceSpec{{Mapping: "dongle"}}}
	raw := &pb.VMSpec{UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}}

	if err := s.refuseUSBMigration(ctx, vm, mapped, "other", false); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("live migrate of a mapped USB VM: %v; want refused", err)
	}
	if err := s.refuseUSBMigration(ctx, vm, raw, "other", true); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cold migrate of a raw USB VM: %v; want refused", err)
	}
	if err := s.refuseUSBMigration(ctx, vm, mapped, "third", true); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cold migrate to a host without the mapping: %v; want refused", err)
	}
	if err := s.refuseUSBMigration(ctx, vm, mapped, "other", true); err != nil {
		t.Errorf("cold migrate to a mapped host: %v; want allowed", err)
	}
	if err := s.refuseUSBMigration(ctx, vm, &pb.VMSpec{}, "third", false); err != nil {
		t.Errorf("a VM without USB: %v; want no refusal", err)
	}
}

// UpdateVM sets and clears USB devices on a stopped VM; adding needs the gate,
// clearing does not.
func TestUpdateVM_SetAndClearUSB(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "u", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "u", Cpu: 1, MemoryMib: 1024}))

	set := &pb.UpdateVMRequest{Name: "u", SetUsbDevices: true, UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}}
	if _, err := s.UpdateVM(ctx, set); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("set USB ungated: %v; want FailedPrecondition", err)
	}
	if got := loadStoredSpec(t, s, "u").UsbDevices; len(got) != 0 {
		t.Fatalf("a refused update stored usb_devices %v", got)
	}
	enableUsbMountsMemory(s)
	if _, err := s.UpdateVM(ctx, set); err != nil {
		t.Fatalf("set USB: %v", err)
	}
	if got := loadStoredSpec(t, s, "u").UsbDevices; len(got) != 1 {
		t.Fatalf("usb_devices = %v; want one", got)
	}
	x, _ := s.virt.DumpXMLInactive("u")
	if !strings.Contains(x, `<vendor id="0x046d">`) {
		t.Fatalf("redefined domain lacks the USB hostdev:\n%s", x)
	}

	// Clearing is allowed with the flag off: it removes a field, losing nothing.
	s.SetUsbMountsMemory(false)
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", SetUsbDevices: true}); err != nil {
		t.Fatalf("clear USB: %v", err)
	}
	if got := loadStoredSpec(t, s, "u").UsbDevices; len(got) != 0 {
		t.Fatalf("usb_devices = %v after clear", got)
	}
	x, _ = s.virt.DumpXMLInactive("u")
	if strings.Contains(x, `type="usb"`) {
		t.Fatalf("a cleared USB hostdev is still defined:\n%s", x)
	}
}

// A cpu grow that also sets USB devices must not take the live vCPU path,
// which would apply the cpu and silently drop the devices.
func TestUpdateVM_CPUGrowWithUSBIsNotPureCPU(t *testing.T) {
	req := &pb.UpdateVMRequest{Name: "u", Cpu: 4, SetUsbDevices: true}
	if isPureCPUGrowRequest(req) {
		t.Fatal("a cpu grow carrying USB devices was classed as a pure cpu grow")
	}
	req = &pb.UpdateVMRequest{Name: "u", MemoryMib: 4096, MemoryHotplugMaxMib: proto.Int32(8192)}
	if isPureMemoryRequest(req) {
		t.Fatal("a memory change carrying a hot-add ceiling was classed as memory-only")
	}
}

// ── Memory hot-add ──

func TestCreateVM_MemoryHotplug(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	req := disklessCreateRequest("m1")
	req.Spec.MemoryMib = 1024
	req.Spec.MemoryHotplugMaxMib = 4096
	req.Spec.MemoryHotplugBaseMib = 64 // server-owned: a client value is ignored

	if _, err := s.CreateVM(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ungated hot-add create: %v; want FailedPrecondition", err)
	}
	enableUsbMountsMemory(s)
	if _, err := s.CreateVM(ctx, req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	spec := loadStoredSpec(t, s, "m1")
	if spec.MemoryHotplugMaxMib != 4096 || spec.MemoryHotplugBaseMib != 1024 {
		t.Fatalf("stored hot-add = max %d base %d; want 4096/1024", spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib)
	}
	x, _ := fake.DumpXMLInactive("m1")
	for _, want := range []string{`<maxMemory slots="16" unit="KiB">4194304</maxMemory>`, `model="virtio-mem"`, `<cell id="0" cpus="0" memory="1048576" unit="KiB">`} {
		if !strings.Contains(x, want) {
			t.Errorf("domain lacks %s:\n%s", want, x)
		}
	}

	bad := disklessCreateRequest("m2")
	bad.Spec.MemoryMib = 1024
	bad.Spec.MemoryHotplugMaxMib = 2048
	bad.Spec.MaxMemoryMib = 1536
	if _, err := s.CreateVM(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("hot-add with a balloon ceiling: %v; want InvalidArgument", err)
	}
}

// seedHotplugVM defines a running hot-add VM whose domain is what CreateVM
// would have generated.
func seedHotplugVM(t *testing.T, s *Server, name string, base, max, mem int32) {
	t.Helper()
	spec := &pb.VMSpec{Name: name, Cpu: 2, MemoryMib: mem, MemoryHotplugBaseMib: base, MemoryHotplugMaxMib: max}
	seedRunningVM(t, s, name, spec, 2, int(mem))
	_ = s.virt.UndefineDomain(name, false)
	x, err := lv.GenerateDomainXML(baseDomainConfig(spec, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
}

var reRequestedKiB = regexp.MustCompile(`<requested[^>]*>(\d+)</requested>`)

// virtioMemRequestedMiB is how much of name's virtio-mem region its persistent
// definition plugs.
func virtioMemRequestedMiB(t *testing.T, s *Server, name string) int {
	t.Helper()
	x, _ := s.virt.DumpXMLInactive(name)
	m := reRequestedKiB.FindStringSubmatch(x)
	if m == nil {
		t.Fatalf("no virtio-mem <requested> in %s:\n%s", name, x)
	}
	kib, _ := strconv.Atoi(m[1])
	return kib / 1024
}

// A running hot-add VM grows and shrinks live within its band, through both
// the pre-latch and the coordinated path, and the stored spec follows.
func TestUpdateVM_MemoryHotplugLive(t *testing.T) {
	for _, coordinated := range []bool{false, true} {
		name := "hp-direct"
		s := reconfigServer(t)
		if coordinated {
			name = "hp-coord"
			s.SetOperationProtocol(true)
			enableUsbMountsMemory(s, capabilities.OperationProtocolV1)
		}
		ctx := adminCtx()
		seedHotplugVM(t, s, name, 1024, 4096, 1024)

		if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: name, MemoryMib: 3072}); err != nil {
			t.Fatalf("%s: live hot-add: %v", name, err)
		}
		vm, _ := corrosion.GetVM(ctx, s.db, name)
		if vm.State != "running" {
			t.Fatalf("%s: a hot-add stopped the VM (state %s)", name, vm.State)
		}
		if got := virtioMemRequestedMiB(t, s, name); got != 2048 {
			t.Fatalf("%s: plugged %d MiB; want 2048 (3072 minus the 1024 boot cell)", name, got)
		}
		if spec := loadStoredSpec(t, s, name); spec.MemoryMib != 3072 || spec.MemoryHotplugBaseMib != 1024 {
			t.Fatalf("%s: stored memory %d base %d; want 3072/1024", name, spec.MemoryMib, spec.MemoryHotplugBaseMib)
		}
		var balloon bool
		for _, e := range s.virt.(*libvirtfake.Fake).EventLog() {
			if e.Op == "set-memory" {
				balloon = true
			}
		}
		if balloon {
			t.Fatalf("%s: a hot-add VM was ballooned instead of plugged", name)
		}
		if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: name, TargetMib: 2048}); err != nil {
			t.Fatalf("%s: set-memory shrink: %v", name, err)
		}
		if got := virtioMemRequestedMiB(t, s, name); got != 1024 {
			t.Fatalf("%s: plugged %d MiB after shrink; want 1024", name, got)
		}
		for _, bad := range []int32{8192, 512, 2049} {
			_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: name, MemoryMib: bad})
			if c := status.Code(err); c != codes.FailedPrecondition && c != codes.InvalidArgument {
				t.Errorf("%s: live resize to %d MiB = %v; want refused up front (outside the band or misaligned)", name, bad, err)
			}
			if got := loadStoredSpec(t, s, name).MemoryMib; got != 2048 {
				t.Errorf("%s: a refused resize to %d MiB left the stored memory at %d", name, bad, got)
			}
		}
	}
}

// Turning hot-add on for a stopped VM records its memory as the boot cell and
// regenerates the domain with the region.
func TestUpdateVM_EnableMemoryHotplugStopped(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "m", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "m", Cpu: 1, MemoryMib: 2048}))
	req := &pb.UpdateVMRequest{Name: "m", MemoryHotplugMaxMib: proto.Int32(8192)}
	if _, err := s.UpdateVM(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ungated: %v; want FailedPrecondition", err)
	}
	enableUsbMountsMemory(s)
	if _, err := s.UpdateVM(ctx, req); err != nil {
		t.Fatalf("enable hot-add: %v", err)
	}
	spec := loadStoredSpec(t, s, "m")
	if spec.MemoryHotplugMaxMib != 8192 || spec.MemoryHotplugBaseMib != 2048 {
		t.Fatalf("stored max %d base %d; want 8192/2048", spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib)
	}
	x, _ := s.virt.DumpXMLInactive("m")
	if !strings.Contains(x, `model="virtio-mem"`) {
		t.Fatalf("domain not regenerated with virtio-mem:\n%s", x)
	}
	// A stopped memory change above the ceiling is refused before anything.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "m", MemoryMib: 16384}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("memory above the hot-add ceiling: %v; want InvalidArgument", err)
	}
	// Off again: the VM keeps its memory, as fixed memory.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "m", MemoryHotplugMaxMib: proto.Int32(0)}); err != nil {
		t.Fatalf("disable hot-add: %v", err)
	}
	if spec := loadStoredSpec(t, s, "m"); spec.MemoryHotplugMaxMib != 0 || spec.MemoryHotplugBaseMib != 0 || spec.MemoryMib != 2048 {
		t.Fatalf("after disable: %+v", spec)
	}
}

// The reconcile primitive must not drop a VM's USB hostdevs: its in-place
// patcher manages PCI hostdevs by alias and deletes any hostdev it does not
// know, so a VM with USB devices is regenerated, which re-resolves them.
func TestReconcile_KeepsUSBHostdevs(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "ru", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "ru", Cpu: 1, MemoryMib: 1024,
			UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}}))
	// A prior definition exists, so the patch path is available.
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>ru</name><memory unit='KiB'>1048576</memory><vcpu>1</vcpu><devices>` +
		`<hostdev mode='subsystem' type='usb' managed='yes'><source><vendor id='0x046d'/><product id='0xc52b'/></source></hostdev>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "ru"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	x, _ := s.virt.DumpXMLInactive("ru")
	if !strings.Contains(x, "0x046d") || !strings.Contains(x, "0xc52b") {
		t.Fatalf("reconcile dropped the USB hostdev:\n%s", x)
	}
}

// A mapping holds one kind of device; a USB address must parse.
func TestAddMappingDevice_USBKind(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	add := func(mapping, addr string) error {
		_, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: mapping, Host: "test-host", Address: addr})
		return err
	}
	if err := add("dongle", "usb:046d:c52b"); err != nil {
		t.Fatalf("USB device into a new mapping: %v", err)
	}
	if err := add("dongle", "0000:41:00.0"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("PCI device into a USB mapping: %v; want FailedPrecondition", err)
	}
	if err := add("gpu", "0000:41:00.0"); err != nil {
		t.Fatalf("PCI device into a new mapping: %v", err)
	}
	if err := add("gpu", "usb:1-2"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("USB device into a PCI mapping: %v; want FailedPrecondition", err)
	}
	if err := add("bad", "usb:1-2/../x"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed USB address: %v; want InvalidArgument", err)
	}
}

// Every start re-resolves a bus-port: a re-plugged device has a new device
// number, and the old one must not stay in the definition.
func TestPrepareHardwareForStart_RefreshesUSBBusPort(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "1-2")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dev, "busnum"), []byte("1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "devnum"), []byte("5\n"), 0o644)
	defer lv.SetUSBSysfsRootForTest(root)()

	s, fake := provableCreateServer(t)
	enableUsbMountsMemory(s)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, usbCreateRequest("u1", &pb.USBDeviceSpec{BusPort: "1-2"})); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	_ = os.WriteFile(filepath.Join(dev, "devnum"), []byte("9\n"), 0o644) // re-plugged
	release, err := s.PrepareHardwareForStart(ctx, mustGetVM(t, s, "u1"))
	if err != nil {
		t.Fatalf("PrepareHardwareForStart: %v", err)
	}
	release()
	x, _ := fake.DumpXMLInactive("u1")
	if !strings.Contains(x, `device="9"`) || strings.Contains(x, `device="5"`) {
		t.Fatalf("the start did not re-resolve the port:\n%s", x)
	}
	// Unplugged: the start is refused.
	_ = os.RemoveAll(dev)
	if _, err := s.PrepareHardwareForStart(ctx, mustGetVM(t, s, "u1")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the device gone = %v; want FailedPrecondition", err)
	}
}

// The hot-add boot memory is server-owned even when hot-add is off: a client
// cannot plant one in a spec that has no hot-add ceiling.
func TestCreateVM_HotplugBaseIsServerOwned(t *testing.T) {
	s, _ := provableCreateServer(t)
	req := disklessCreateRequest("m0")
	req.Spec.MemoryHotplugBaseMib = 64
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got := loadStoredSpec(t, s, "m0").MemoryHotplugBaseMib; got != 0 {
		t.Fatalf("stored hot-add base = %d; a client-supplied base was kept", got)
	}
}

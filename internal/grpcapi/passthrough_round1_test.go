package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	"github.com/litevirt/litevirt/internal/qcow2"
)

// ── USB permissions (I6) ──

// A raw USB device is the host's own: the admin role's, as on Proxmox VE
// (Sys.Modify on /). A mapped one needs resourcemap.use on the mapping, which
// with no role bindings is the admin role's too.
func TestCreateVM_USBPermissions(t *testing.T) {
	s, _ := provableCreateServer(t)
	addUSBMapping(t, s, "dongle", "test-host", "usb:1a86:7523")
	op := userCtx("op", "operator")
	if err := s.RequirePerm(op, vmRBACPathFor("", "u"), "vm.create", "operator"); err != nil {
		t.Fatalf("premise: an operator may create VMs: %v", err)
	}
	for _, dev := range []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}, {BusPort: "1-2"}, {Mapping: "dongle"}} {
		_, err := s.CreateVM(op, usbCreateRequest("u", dev))
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("operator create with %+v = %v; want PermissionDenied", dev, err)
		}
	}
	if _, err := s.CreateVM(adminCtx(), usbCreateRequest("u", &pb.USBDeviceSpec{Mapping: "dongle"})); err != nil {
		t.Fatalf("admin create with a mapping: %v", err)
	}
}

// UpdateVM judges USB permission on the entry node, before the forward: a
// VM on another host is never dialled for a refused request.
func TestUpdateVM_USBPermissionBeforeForward(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "far", "other-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "far", Cpu: 1, MemoryMib: 512}))
	_, err := s.UpdateVM(userCtx("op", "operator"), &pb.UpdateVMRequest{Name: "far", SetUsbDevices: true,
		UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator update forwarding a raw USB device = %v; want PermissionDenied on the entry node", err)
	}
}

// ── container host access across forwards and restores (C1, C2) ──

// An operator's clone of a mounted container is refused before the forward,
// so the source's host — which runs a forwarded call as the peer, i.e. as
// admin — never sees it.
func TestCloneContainer_HostAccessJudgedBeforeForward(t *testing.T) {
	s, rt := secServer(t)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "far-host", Name: "m", State: "stopped", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download",
			Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CloneContainer(ctOperatorCtx(), &pb.CloneContainerRequest{Source: "m", Target: "x", HostName: "far-host", Project: "acme"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator clone of a mounted container on another host = %v; want PermissionDenied before the forward", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatal("the refused clone reached a runtime")
	}
}

// A clone's config is rendered from the clone's spec: the source's spec
// mounts are carried (the caller was judged an admin), and a host-access
// block the spec does not record is not.
func TestCloneContainer_RebuildsFromTheSpec(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "m", "stopped", corrosion.ContainerCreateSpec{Template: "download",
		Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
	seedSecCT(t, s, rt, "plain", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	for _, src := range []string{"m", "plain"} {
		if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: src, Target: src + "2", HostName: "host-a"}); err != nil {
			t.Fatalf("clone %s: %v", src, err)
		}
	}
	if rb, ok := rt.lastRebuild("m2"); !ok || len(rb.cfg.Mounts) != 1 || rb.cfg.Mounts[0].HostPath != "/srv/data" {
		t.Fatalf("clone of m rebuilt with %+v (ok %v); want its source's mount", rb, ok)
	}
	if rb, ok := rt.lastRebuild("plain2"); !ok || len(rb.cfg.Mounts) != 0 {
		t.Fatalf("clone of plain rebuilt with %+v (ok %v); want a rebuild with no host access", rb, ok)
	}
}

// What a restored spec may carry: an operator restore strips host access, an
// admin's keeps it (the gate open), and a peer-driven move keeps exactly
// what the SOURCE ROW records.
func TestAuthorizeRestoredHostAccess(t *testing.T) {
	s, _ := secServer(t)
	cs := corrosion.ContainerCreateSpec{Template: "download",
		Mounts:  []corrosion.ContainerHostMount{{HostPath: "/srv/secrets", ContainerPath: "/s", ReadWrite: true}},
		Devices: []corrosion.ContainerHostDevice{{HostPath: "/dev/ttyUSB0"}}}
	source := &corrosion.ContainerRecord{Name: "m", CreateSpec: corrosion.EncodeCreateSpec(cs)}
	other := &corrosion.ContainerRecord{Name: "m", CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download"})}

	for _, tc := range []struct {
		name   string
		ctx    context.Context
		source *corrosion.ContainerRecord
		peer   bool
		closed bool
		keep   bool
	}{
		{"operator restore", ctOperatorCtx(), nil, false, false, false},
		{"admin restore", adminCtx(), nil, false, false, true},
		{"admin restore, gate closed", adminCtx(), nil, false, true, false},
		{"peer move, source row agrees", adminCtx(), source, true, false, true},
		{"peer move, source row differs", adminCtx(), other, true, false, false},
		{"peer move, no source row", adminCtx(), nil, true, false, false},
	} {
		s.SetPassthroughGate(nil)
		if tc.closed {
			closePassthroughGate(s)
		}
		got, stripped := s.authorizeRestoredHostAccess(tc.ctx, cs, tc.source, tc.peer)
		kept := len(got.Mounts) == 1 && len(got.Devices) == 1
		if kept != tc.keep || (stripped == "") != tc.keep {
			t.Errorf("%s: kept=%v stripped=%q; want kept=%v", tc.name, kept, stripped, tc.keep)
		}
	}
}

// lv ct convert --mount/--device is how an admin re-applies host access; an
// operator may only clear it.
func TestConvertContainer_SetHostAccess(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "c", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	set := &pb.ConvertContainerRequest{Name: "c", HostName: "host-a", SetHostAccess: true,
		Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}
	if _, err := s.ConvertContainer(ctOperatorCtx(), set); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator convert --mount = %v; want PermissionDenied", err)
	}
	ct, err := s.ConvertContainer(adminCtx(), set)
	if err != nil {
		t.Fatalf("admin convert --mount: %v", err)
	}
	if len(ct.Mounts) != 1 || len(specOf(t, s, "host-a", "c").Mounts) != 1 || len(rt.hostAccess["c"]) != 1 {
		t.Fatalf("mount not applied: reported %+v, runtime %+v", ct.Mounts, rt.hostAccess["c"])
	}
	if _, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "c", HostName: "host-a", SetHostAccess: true}); err != nil {
		t.Fatalf("operator clearing host access: %v", err)
	}
	if len(specOf(t, s, "host-a", "c").Mounts) != 0 || len(rt.hostAccess["c"]) != 0 {
		t.Fatal("clearing left the mount")
	}
}

// Nothing litevirt uses on the host — a VM disk — is also handed to a container.
func TestCreateContainer_RefusesAPathLitevirtUses(t *testing.T) {
	s, _ := secServer(t)
	enableUsbMountsMemory(s)
	if err := corrosion.InsertDisk(context.Background(), s.db, corrosion.DiskRecord{
		VMName: "v", DiskName: "root", HostName: "host-a", Path: "/dev/sdz", DeleteWithVM: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "c", HostName: "host-a", Template: "download", Distro: "alpine",
		Devices: []*pb.ContainerDevice{{HostPath: "/dev/sdz"}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "disk of VM v") {
		t.Fatalf("a VM's disk passed to a container = %v; want FailedPrecondition naming the VM", err)
	}
}

// ── memory hot-add (I4, I5, I7) ──

// A running hot-add VM whose domain has no virtio-mem device (an older or
// drifted definition) is refused fast: nothing committed, no barrier held.
func TestSetVMMemory_NoVirtioMemFailsFastWithoutWedging(t *testing.T) {
	for _, coordinated := range []bool{false, true} {
		s := reconfigServer(t)
		if coordinated {
			s.SetOperationProtocol(true)
			enableUsbMountsMemory(s, capabilities.OperationProtocolV1)
		}
		ctx := adminCtx()
		seedRunningVM(t, s, "dr", &pb.VMSpec{Name: "dr", Cpu: 2, MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096}, 2, 1024)
		_, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "dr", TargetMib: 2048})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "virtio-mem") {
			t.Fatalf("coordinated=%v: set-memory without a virtio-mem device = %v; want FailedPrecondition", coordinated, err)
		}
		vm, _ := corrosion.GetVM(ctx, s.db, "dr")
		if vm.ActiveOperationID != "" {
			t.Fatalf("coordinated=%v: the refusal left the barrier held by %q", coordinated, vm.ActiveOperationID)
		}
		if got := loadStoredSpec(t, s, "dr").MemoryMib; got != 1024 {
			t.Fatalf("coordinated=%v: the refusal committed memory %d", coordinated, got)
		}
		// Refused before anything began: no operation was ever opened.
		if rows, err := s.db.Query(ctx, `SELECT id FROM operations WHERE resource_id = ?`, "dr"); err != nil || len(rows) != 0 {
			t.Fatalf("coordinated=%v: %d operation(s) opened for a refused resize (err %v)", coordinated, len(rows), err)
		}
	}
}

// If the region vanishes after the preflight (the apply finds no device), the
// operation ends FAILED — barrier cleared, desired memory put back — rather
// than being left for a recovery that would retry forever.
func TestResize_NoVirtioMemAtApplyIsTerminal(t *testing.T) {
	s := reconfigServer(t)
	s.SetOperationProtocol(true)
	enableUsbMountsMemory(s, capabilities.OperationProtocolV1)
	ctx := adminCtx()
	seedHotplugVM(t, s, "hv", 1024, 4096, 1024)
	s.virt.(*libvirtfake.Fake).FailSetVirtioMem = func(string, int) error { return lv.ErrNoVirtioMem }
	_, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "hv", TargetMib: 2048})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("apply with no virtio-mem device = %v; want FailedPrecondition", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "hv")
	if vm.ActiveOperationID != "" {
		t.Fatalf("the operation is still holding the barrier (%q); it must end, not wait for recovery", vm.ActiveOperationID)
	}
	if got := loadStoredSpec(t, s, "hv").MemoryMib; got != 1024 {
		t.Fatalf("desired memory left at %d; want it put back to 1024", got)
	}
	// And recovery has nothing to retry.
	s.virt.(*libvirtfake.Fake).FailSetVirtioMem = nil
	s.RecoverResourceOperations(ctx)
	if vm, _ := corrosion.GetVM(ctx, s.db, "hv"); vm.ActiveOperationID != "" {
		t.Fatal("recovery found an operation to resume")
	}
}

// An unplug the guest has not completed still holds the memory: mem_actual —
// what placement and admission count — is the boot cell plus what the guest
// actually has plugged, when that is more than was requested.
func TestResize_HotplugCountsWhatTheGuestHolds(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	seedHotplugVM(t, s, "hc", 1024, 8192, 5120)
	f := s.virt.(*libvirtfake.Fake)
	live, _ := f.DumpXML("hc")
	// The guest holds 4 GiB plugged and will not give it back.
	f.SetActiveXML("hc", strings.Replace(live, "</requested>", "</requested><current unit=\"KiB\">4194304</current>", 1))
	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "hc", TargetMib: 2048}); err != nil {
		t.Fatalf("set-memory shrink: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "hc")
	if vm.MemActual != 1024+4096 {
		t.Fatalf("mem_actual = %d; want 5120 (1024 boot + 4096 the guest still holds)", vm.MemActual)
	}
}

// A live restore takes USB devices and hot-add only from the cluster's own
// row; a client or manifest spec is stripped of both.
func TestAdmitRestoredUSBAndHotplug(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "r", MemoryMib: 1024, MemoryHotplugBaseMib: 64, MemoryHotplugMaxMib: 4096,
		UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}}
	if err := s.admitRestoredUSBAndHotplug(ctx, spec, "r", false); err != nil {
		t.Fatal(err)
	}
	if len(spec.UsbDevices) != 0 || spec.MemoryHotplugMaxMib != 0 || spec.MemoryHotplugBaseMib != 0 {
		t.Fatalf("a manifest spec kept %+v", spec)
	}
	own := &pb.VMSpec{Name: "r", MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096,
		UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}}
	if err := s.admitRestoredUSBAndHotplug(userCtx("op", "operator"), proto.Clone(own).(*pb.VMSpec), "r", true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator restoring a raw USB device from the row = %v; want PermissionDenied", err)
	}
	if err := s.admitRestoredUSBAndHotplug(ctx, own, "r", true); err != nil || own.MemoryHotplugMaxMib != 4096 || len(own.UsbDevices) != 1 {
		t.Fatalf("the row's spec was not kept for an admin: %v %+v", err, own)
	}
}

// A VM clone carries the hot-add band into its definition and drops USB
// devices (one device, one guest; a raw one is the source host's).
func TestCloneVM_CarriesHotplugDropsUSB(t *testing.T) {
	s := cloneSourceTemplate(t)
	enableUsbMountsMemory(s)
	ctx := adminCtx()
	src := filepath.Join(t.TempDir(), "hp-root.qcow2")
	if err := qcow2.Create(src, 64*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "hp", Cpu: 1, MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096,
		UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "hp", HostName: "test-host", State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "hp", DiskName: "root", HostName: "test-host", Path: src, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "hp", Target: "hp2"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	x, _ := s.virt.DumpXMLInactive("hp2")
	if !strings.Contains(x, `model="virtio-mem"`) {
		t.Fatalf("the clone was defined without its hot-add region:\n%s", x)
	}
	if got := loadStoredSpec(t, s, "hp2"); len(got.UsbDevices) != 0 || got.MemoryHotplugMaxMib != 4096 {
		t.Fatalf("clone spec usb=%v max=%d; want no USB, the band kept", got.UsbDevices, got.MemoryHotplugMaxMib)
	}
	_ = os.Remove(src)
}

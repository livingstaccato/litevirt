package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// latchedButRefusingGate says the release token has latched here (the local
// hint) but refuses every grant: a host rolled back after the latch, which the
// gate's fresh re-confirmation catches on the node that writes.
type latchedButRefusingGate struct{}

func (latchedButRefusingGate) WithFeature(_ context.Context, f capabilities.Feature,
	_ func(context.Context, capabilities.FeatureGrant) error) error {
	return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s): host-z does not advertise it",
		f, capabilities.Release202611V1)
}

func (latchedButRefusingGate) FeatureAvailable(capabilities.Feature) bool { return true }

// wantReleaseRefusal fails unless err is the release gate's refusal of
// usb_mounts_memory, returned unchanged.
func wantReleaseRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.HasPrefix(status.Convert(err).Message(), passthroughRefusalText) {
		t.Errorf("%s: %v; want FailedPrecondition %q", what, err, passthroughRefusalText)
	}
}

// Before the release token latches, every way of SETTING USB devices, memory
// hot-add or container host access is refused with the release gate's own
// text, unchanged, and writes nothing. A server with no gate wired refuses
// too (fail closed).
//
// Mutation: the stub's shape (an entry check only, the owner writing through
// the plain writers with no grant) with that entry check removed — every case
// goes red. The entry check alone is a fail-fast; the owner's grant refuses
// with the same text.
func TestPassthroughRelease_RefusedWithTheReleaseText(t *testing.T) {
	ctx := adminCtx()
	dev := &pb.USBDeviceSpec{Vendor: "046d", Product: "c52b"}
	for _, wire := range []string{"closed", "unwired"} {
		vm := reconfigServer(t)
		if wire == "closed" {
			closePassthroughGate(vm)
		}
		insertTestVMWithSpec(t, ctx, vm.db, "u", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "u", Cpu: 1, MemoryMib: 1024}))
		_, err := vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", SetUsbDevices: true, UsbDevices: []*pb.USBDeviceSpec{dev}})
		wantReleaseRefusal(t, wire+": UpdateVM usb", err)
		_, err = vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", MemoryHotplugMaxMib: proto.Int32(4096)})
		wantReleaseRefusal(t, wire+": UpdateVM hot-add", err)
		if sp := loadStoredSpec(t, vm, "u"); len(sp.UsbDevices) != 0 || sp.MemoryHotplugMaxMib != 0 {
			t.Errorf("%s: a refused update stored %+v", wire, sp)
		}

		cr, _ := provableCreateServer(t)
		if wire == "closed" {
			closePassthroughGate(cr)
		}
		_, err = cr.CreateVM(ctx, usbCreateRequest("c1", dev))
		wantReleaseRefusal(t, wire+": CreateVM usb", err)
		hot := disklessCreateRequest("c2")
		hot.Spec.MemoryMib, hot.Spec.MemoryHotplugMaxMib = 1024, 4096
		_, err = cr.CreateVM(ctx, hot)
		wantReleaseRefusal(t, wire+": CreateVM hot-add", err)

		ct, rt := secServer(t)
		if wire == "closed" {
			closePassthroughGate(ct)
		}
		_, err = ct.CreateContainer(ctx, hostAccessReq("k1"))
		wantReleaseRefusal(t, wire+": CreateContainer", err)
		seedSecCT(t, ct, rt, "k2", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
		_, err = ct.ConvertContainer(ctx, &pb.ConvertContainerRequest{Name: "k2", HostName: "host-a", SetHostAccess: true,
			Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
		wantReleaseRefusal(t, wire+": ConvertContainer", err)
		if len(specOf(t, ct, "host-a", "k2").Mounts) != 0 || len(rt.hostAccess["k2"]) != 0 || len(rt.createCalls) != 0 {
			t.Errorf("%s: a refused container write changed something", wire)
		}
	}
}

// The node that WRITES the feature's data takes the grant: an entry check that
// passes (the token latched here) does not let a write through when the gate
// refuses the grant — a host rolled back after the latch. Nothing is written
// and nothing reaches the runtime. An admin's restore falls back to stripping
// the backup's host access, as main does.
//
// Mutation: write any of these through the plain writer without the grant
// (the stub's shape: check once at entry, then write) — its case goes red.
func TestPassthroughRelease_TheWritingNodeTakesTheGrant(t *testing.T) {
	ctx := adminCtx()
	dev := &pb.USBDeviceSpec{Vendor: "046d", Product: "c52b"}

	cr, fake := provableCreateServer(t)
	cr.SetReleaseFeatureGate(latchedButRefusingGate{})
	_, err := cr.CreateVM(ctx, usbCreateRequest("c1", dev))
	wantReleaseRefusal(t, "CreateVM usb", err)
	if row, _ := corrosion.GetVM(ctx, cr.db, "c1"); row != nil {
		t.Error("CreateVM wrote a row the gate refused")
	}
	if x, _ := fake.DumpXMLInactive("c1"); x != "" {
		t.Error("CreateVM defined a domain the gate refused")
	}

	vm := reconfigServer(t)
	vm.SetReleaseFeatureGate(latchedButRefusingGate{})
	insertTestVMWithSpec(t, ctx, vm.db, "u", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "u", Cpu: 1, MemoryMib: 1024}))
	_, err = vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", MemoryHotplugMaxMib: proto.Int32(4096)})
	wantReleaseRefusal(t, "UpdateVM hot-add", err)
	if sp := loadStoredSpec(t, vm, "u"); sp.MemoryHotplugMaxMib != 0 {
		t.Errorf("UpdateVM stored hot-add the gate refused: %+v", sp)
	}

	ct, rt := secServer(t)
	ct.SetReleaseFeatureGate(latchedButRefusingGate{})
	_, err = ct.CreateContainer(ctx, hostAccessReq("k1"))
	wantReleaseRefusal(t, "CreateContainer", err)
	if len(rt.createCalls) != 0 {
		t.Errorf("CreateContainer reached the runtime: %+v", rt.createCalls)
	}
	seedSecCT(t, ct, rt, "k2", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	_, err = ct.ConvertContainer(ctx, &pb.ConvertContainerRequest{Name: "k2", HostName: "host-a", SetHostAccess: true,
		Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
	wantReleaseRefusal(t, "ConvertContainer", err)
	if len(specOf(t, ct, "host-a", "k2").Mounts) != 0 || len(rt.hostAccess["k2"]) != 0 {
		t.Error("ConvertContainer applied host access the gate refused")
	}

	cs := corrosion.ContainerCreateSpec{Template: "download", Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv", ContainerPath: "/s"}}}
	got, stripped, g := ct.authorizeRestoredHostAccess(ctx, cs, nil, false)
	if len(got.Mounts) != 0 || stripped == "" || passthroughGranted(g) {
		t.Errorf("admin restore with the grant refused: kept %+v, stripped %q, granted %v; want stripped", got.Mounts, stripped, passthroughGranted(g))
	}
}

// Secure, don't remove: with the gate closed, everything main allows still
// works — a VM or container without the fields, a metadata update, and
// clearing them — and none of it takes a grant once the gate is open.
//
// Mutation: take the grant unconditionally in createVM, UpdateVM,
// CreateContainer or ConvertContainer — the closed-gate case goes red.
func TestPassthroughRelease_OnlyWritesThatAddTheFieldsTakeAGrant(t *testing.T) {
	ctx := adminCtx()
	for _, open := range []bool{false, true} {
		grants := 0
		gate := passthroughGate{on: open, grants: &grants}

		cr, _ := provableCreateServer(t)
		cr.SetReleaseFeatureGate(gate)
		if _, err := cr.CreateVM(ctx, disklessCreateRequest("plain")); err != nil {
			t.Errorf("open=%v: a plain CreateVM: %v", open, err)
		}

		vm := reconfigServer(t)
		vm.SetReleaseFeatureGate(gate)
		insertTestVMWithSpec(t, ctx, vm.db, "u", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "u", Cpu: 1, MemoryMib: 1024,
			UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}}, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096}))
		if _, err := vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", Onboot: proto.Bool(true)}); err != nil {
			t.Errorf("open=%v: a metadata update of a VM that has them: %v", open, err)
		}
		if _, err := vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", SetUsbDevices: true, MemoryHotplugMaxMib: proto.Int32(0)}); err != nil {
			t.Errorf("open=%v: clearing USB and hot-add: %v", open, err)
		}
		if sp := loadStoredSpec(t, vm, "u"); len(sp.UsbDevices) != 0 || sp.MemoryHotplugMaxMib != 0 {
			t.Errorf("open=%v: clear left %+v", open, sp)
		}

		ct, rt := secServer(t)
		ct.SetReleaseFeatureGate(gate)
		if _, err := ct.CreateContainer(ctx, &pb.CreateContainerRequest{Name: "k0", Template: "download", Distro: "alpine"}); err != nil {
			t.Errorf("open=%v: a plain CreateContainer: %v", open, err)
		}
		seedSecCT(t, ct, rt, "k1", "stopped", corrosion.ContainerCreateSpec{Template: "download",
			Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
		if _, err := ct.ConvertContainer(ctx, &pb.ConvertContainerRequest{Name: "k1", HostName: "host-a", SetHostAccess: true}); err != nil {
			t.Errorf("open=%v: clearing host access: %v", open, err)
		}
		if grants != 0 {
			t.Errorf("open=%v: %d grants taken by writes that add nothing", open, grants)
		}
	}
}

// With the gate open, a write that adds the fields takes exactly one grant —
// on the node that writes (here the entry node is the owner, and its entry
// check reads only the local hint) — and stores them.
func TestPassthroughRelease_AnAddTakesOneGrantAndWrites(t *testing.T) {
	ctx := adminCtx()
	grants := 0
	gate := passthroughGate{on: true, grants: &grants}

	cr, _ := provableCreateServer(t)
	cr.SetReleaseFeatureGate(gate)
	if _, err := cr.CreateVM(ctx, usbCreateRequest("c1", &pb.USBDeviceSpec{Vendor: "046d", Product: "c52b"})); err != nil {
		t.Fatalf("CreateVM usb: %v", err)
	}
	if grants != 1 || len(loadStoredSpec(t, cr, "c1").UsbDevices) != 1 {
		t.Fatalf("CreateVM usb: %d grants, spec %+v; want one grant and the device stored", grants, loadStoredSpec(t, cr, "c1"))
	}

	grants = 0
	vm := reconfigServer(t)
	vm.SetReleaseFeatureGate(gate)
	insertTestVMWithSpec(t, ctx, vm.db, "u", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{Name: "u", Cpu: 1, MemoryMib: 1024}))
	if _, err := vm.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "u", MemoryHotplugMaxMib: proto.Int32(4096)}); err != nil {
		t.Fatalf("UpdateVM hot-add: %v", err)
	}
	if grants != 1 || loadStoredSpec(t, vm, "u").MemoryHotplugMaxMib != 4096 {
		t.Fatalf("UpdateVM hot-add: %d grants; want one and the band stored", grants)
	}

	grants = 0
	ct, rt := secServer(t)
	ct.SetReleaseFeatureGate(gate)
	if _, err := ct.CreateContainer(ctx, hostAccessReq("k1")); err != nil {
		t.Fatalf("CreateContainer with host access: %v", err)
	}
	seedSecCT(t, ct, rt, "k2", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	if _, err := ct.ConvertContainer(ctx, &pb.ConvertContainerRequest{Name: "k2", HostName: "host-a", SetHostAccess: true,
		Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}); err != nil {
		t.Fatalf("ConvertContainer --mount: %v", err)
	}
	if grants != 2 || len(specOf(t, ct, "host-a", "k1").Mounts) != 1 || len(specOf(t, ct, "host-a", "k2").Mounts) != 1 {
		t.Fatalf("container adds: %d grants; want two, and both specs holding the mount", grants)
	}
}

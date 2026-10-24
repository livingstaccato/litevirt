package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/vfio"
)

// Nothing attaches a MIG instance yet, so a device asking for a MIG profile
// is refused wherever a DeviceSpec enters, rather than ignored and given the
// whole GPU.

func wantMIGProfileRefused(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "MIG attach is not supported yet; mig_profile must be empty") {
		t.Fatalf("err = %v; want InvalidArgument refusing mig_profile", err)
	}
}

func migProfileSpec(name string) *pb.VMSpec {
	return &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256,
		Devices: []*pb.DeviceSpec{{Type: "gpu"}, {Type: "gpu", MigProfile: "1g.5gb"}}}
}

func TestCreateVM_RefusesMIGProfile(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: migProfileSpec("migvm")})
	wantMIGProfileRefused(t, err)
	if !strings.Contains(err.Error(), "device 1") {
		t.Fatalf("refusal %v does not name the device", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "migvm"); vm != nil {
		t.Fatalf("a refused create wrote a VM row: %+v", vm)
	}
}

func TestRecreatePreflight_RefusesMIGProfile(t *testing.T) {
	s := testServerR2(t)
	wantMIGProfileRefused(t, s.recreatePreflight(adminCtx(), migProfileSpec("migvm"), "test-host"))
}

func TestRestoreLiveSpec_RefusesMIGProfile(t *testing.T) {
	s := testServerR2(t)
	_, err := s.resolveRestoreSpec(adminCtx(), &pb.RestoreLiveRequest{Spec: migProfileSpec("migvm")}, &pbsstore.Manifest{})
	wantMIGProfileRefused(t, err)
}

func TestAttachDevice_RefusesMIGProfile(t *testing.T) {
	for _, dev := range []*pb.DeviceSpec{
		{Address: "0000:41:00.0", MigProfile: "3g.20gb"}, // the journaled address path
		{Type: "gpu", MigProfile: "3g.20gb"},             // the legacy selector path
	} {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		fs := newPCIBindFakeFS()
		restore := vfio.SetFS(fs)
		ctx := adminCtx()
		seedNICVM(t, s, "vm1", "running")
		seedPCIGPU(t, s, "0000:41:00.0", -1)

		_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1", PciDevice: dev})
		restore()
		wantMIGProfileRefused(t, err)
		if fs.binds != 0 || pciOwnerOf(t, ctx, s, "0000:41:00.0") != "" || len(liveIntents(t, ctx, s, "vm1")) != 0 {
			t.Fatalf("%+v: a refused attach bound, claimed or recorded the GPU", dev)
		}
	}
}

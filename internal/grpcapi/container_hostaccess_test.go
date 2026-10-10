package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func hostAccessReq(name string) *pb.CreateContainerRequest {
	return &pb.CreateContainerRequest{Name: name, Template: "download", Distro: "alpine",
		Mounts:  []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}},
		Devices: []*pb.ContainerDevice{{HostPath: "/dev/ttyUSB0"}},
	}
}

// Host mounts and devices are the admin's, never an operator's, and refused
// until the gate is open; a refusal never reaches the runtime.
func TestCreateContainer_HostAccessIsAdminOnlyAndGated(t *testing.T) {
	s, rt := secServer(t)
	if _, err := s.CreateContainer(ctOperatorCtx(), hostAccessReq("c1")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator with mounts: %v; want PermissionDenied", err)
	}
	opOnlyDevice := &pb.CreateContainerRequest{Name: "c2", Template: "download", Distro: "alpine",
		Devices: []*pb.ContainerDevice{{HostPath: "/dev/ttyUSB0"}}}
	if _, err := s.CreateContainer(ctOperatorCtx(), opOnlyDevice); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator with a device: %v; want PermissionDenied", err)
	}
	if _, err := s.CreateContainer(adminCtx(), hostAccessReq("c1")); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), usbMountsMemoryRefusalText) {
		t.Fatalf("admin with the gate closed: %v; want the usb_mounts_memory refusal", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("a refused create reached the runtime: %+v", rt.createCalls)
	}

	s.SetUsbMountsMemory(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.UsbMountsMemoryV1: true}})
	bad := hostAccessReq("c3")
	bad.Mounts[0].HostPath = "/srv/data\nlxc.mount.entry = / host none bind 0 0"
	if _, err := s.CreateContainer(adminCtx(), bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a config-injecting path: %v; want InvalidArgument", err)
	}

	ct, err := s.CreateContainer(adminCtx(), hostAccessReq("c1"))
	if err != nil {
		t.Fatalf("admin create: %v", err)
	}
	o := rt.createCalls[0]
	if len(o.Mounts) != 1 || o.Mounts[0].HostPath != "/srv/data" || o.Mounts[0].ReadWrite ||
		len(o.Devices) != 1 || o.Devices[0].HostPath != "/dev/ttyUSB0" {
		t.Fatalf("runtime got mounts %+v devices %+v", o.Mounts, o.Devices)
	}
	if o.IDMapBase == 0 {
		t.Fatal("a container with host mounts lost its id map (became privileged)")
	}
	spec := specOf(t, s, "host-a", "c1")
	if len(spec.Mounts) != 1 || len(spec.Devices) != 1 {
		t.Fatalf("create spec records mounts %+v devices %+v", spec.Mounts, spec.Devices)
	}
	if len(ct.Mounts) != 1 || ct.Mounts[0].ContainerPath != "/data" || len(ct.Devices) != 1 {
		t.Fatalf("reported %+v", ct)
	}
}

// A clone of a container with host mounts is a new container holding them:
// the admin's too.
func TestCloneContainer_HostAccessIsAdminOnly(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "m", "stopped", corrosion.ContainerCreateSpec{Template: "download",
		Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
	if _, err := s.CloneContainer(ctOperatorCtx(), &pb.CloneContainerRequest{Source: "m", Target: "m2", HostName: "host-a", Project: "acme"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator clone of a mounted container: %v; want PermissionDenied", err)
	}
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "m", Target: "m2", HostName: "host-a"}); err != nil {
		t.Fatalf("admin clone: %v", err)
	}
}

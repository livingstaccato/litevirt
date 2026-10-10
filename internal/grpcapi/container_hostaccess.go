package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Container host bind mounts and device nodes (Proxmox mpN / devN).
//
// A host path inside a container is host access, so it is the admin role's
// to grant, as a privileged container is — and, unlike that opt-out, never
// inherited by a compose recreate. The host that creates (or recreates, or
// starts) the container then judges every path against its own
// containers.bind_mount_paths / containers.device_paths (internal/lxc
// mounts.go): resolved there, symlinks followed, read-only by default, nosuid
// and nodev. Unprivileged containers keep their id map.

// hostAccessDenied is the refusal for a non-admin caller.
const hostAccessDenied = "bind-mounting a host path or passing a host device into a container requires the admin role (a host path inside a container is access to the host)"

// containerHostAccessRequest is a create's check of the mounts and devices it
// asks for: the admin role, the usb_mounts_memory_v1 gate, and paths that can
// be judged at all. The owning host judges them against its allowed prefixes.
func (s *Server) containerHostAccessRequest(ctx context.Context, mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) error {
	if len(mounts) == 0 && len(devices) == 0 {
		return nil
	}
	if err := RequireRole(ctx, "admin"); err != nil {
		return status.Error(codes.PermissionDenied, hostAccessDenied)
	}
	if !s.usbMountsMemoryActive(ctx) {
		return usbMountsMemoryRefusal("container host mounts and devices")
	}
	if err := lxc.CheckHostAccessShape(lxcMountsFromPb(mounts), lxcDevicesFromPb(devices)); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return nil
}

func lxcMountsFromPb(in []*pb.ContainerMount) []lxc.Mount {
	out := make([]lxc.Mount, 0, len(in))
	for _, m := range in {
		out = append(out, lxc.Mount{HostPath: m.GetHostPath(), ContainerPath: m.GetContainerPath(), ReadWrite: m.GetReadWrite()})
	}
	return out
}

func lxcDevicesFromPb(in []*pb.ContainerDevice) []lxc.Device {
	out := make([]lxc.Device, 0, len(in))
	for _, d := range in {
		out = append(out, lxc.Device{HostPath: d.GetHostPath(), ContainerPath: d.GetContainerPath()})
	}
	return out
}

// hostAccessSpec converts a create's mounts and devices into the create
// spec's record of them.
func hostAccessSpec(mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) ([]corrosion.ContainerHostMount, []corrosion.ContainerHostDevice) {
	var ms []corrosion.ContainerHostMount
	for _, m := range mounts {
		ms = append(ms, corrosion.ContainerHostMount{HostPath: m.GetHostPath(), ContainerPath: m.GetContainerPath(), ReadWrite: m.GetReadWrite()})
	}
	var ds []corrosion.ContainerHostDevice
	for _, d := range devices {
		ds = append(ds, corrosion.ContainerHostDevice{HostPath: d.GetHostPath(), ContainerPath: d.GetContainerPath()})
	}
	return ms, ds
}

// hostAccessOpts is the create spec's mounts and devices as runtime options.
func hostAccessOpts(spec corrosion.ContainerCreateSpec) ([]ContainerMountOpt, []ContainerDeviceOpt) {
	var ms []ContainerMountOpt
	for _, m := range spec.Mounts {
		ms = append(ms, ContainerMountOpt{HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadWrite: m.ReadWrite})
	}
	var ds []ContainerDeviceOpt
	for _, d := range spec.Devices {
		ds = append(ds, ContainerDeviceOpt{HostPath: d.HostPath, ContainerPath: d.ContainerPath})
	}
	return ms, ds
}

// pbHostAccess is a container record's mounts and devices for the API.
func pbHostAccess(spec corrosion.ContainerCreateSpec) ([]*pb.ContainerMount, []*pb.ContainerDevice) {
	var ms []*pb.ContainerMount
	for _, m := range spec.Mounts {
		ms = append(ms, &pb.ContainerMount{HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadWrite: m.ReadWrite})
	}
	var ds []*pb.ContainerDevice
	for _, d := range spec.Devices {
		ds = append(ds, &pb.ContainerDevice{HostPath: d.HostPath, ContainerPath: d.ContainerPath})
	}
	return ms, ds
}

// hostAccessAudit renders mounts and devices for an audit row.
func hostAccessAudit(mounts []*pb.ContainerMount, devices []*pb.ContainerDevice) string {
	var parts []string
	for _, m := range mounts {
		mode := "ro"
		if m.GetReadWrite() {
			mode = "rw"
		}
		parts = append(parts, "mount="+m.GetHostPath()+":"+m.GetContainerPath()+":"+mode)
	}
	for _, d := range devices {
		parts = append(parts, "device="+d.GetHostPath())
	}
	return strings.Join(parts, " ")
}

// cloneHostAccessAllowed refuses a non-admin clone of a container with host
// mounts or devices: the clone is a new container holding the same host
// access, which only the admin role grants.
func cloneHostAccessAllowed(ctx context.Context, src corrosion.ContainerRecord) error {
	spec := corrosion.DecodeCreateSpec(src.CreateSpec)
	if len(spec.Mounts) == 0 && len(spec.Devices) == 0 {
		return nil
	}
	if err := RequireRole(ctx, "admin"); err != nil {
		return status.Error(codes.PermissionDenied, "the source container has host mounts or devices; "+hostAccessDenied)
	}
	return nil
}

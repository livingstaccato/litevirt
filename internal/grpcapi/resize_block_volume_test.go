package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Follow-up 2: a stopped VM's disk on a zfs or lvm-thin pool is grown with
// the volume manager — `qemu-img resize` (or the qcow2 code) cannot grow a
// zvol or an LV. A running VM's is grown the same way first, then qemu is
// told. Only grow, as the API allows.
func TestResizeDisk_BlockVolumesGrowWithTheirTool(t *testing.T) {
	for _, state := range []string{"stopped", "running"} {
		t.Run(state, func(t *testing.T) {
			log := fakeBlockTools(t)
			s, fake := provableCreateServer(t)
			ctx := adminCtx()
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: state}, nil, []corrosion.DiskRecord{
				{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: "/dev/zvol/tank/acme/vm1-root", SizeBytes: 1 << 30, StorageType: "zfs", StorageVolume: "tank"},
				{VMName: "vm1", DiskName: "data", HostName: s.hostName, Path: "/dev/vg0/vm1-data", SizeBytes: 1 << 30, StorageType: "lvm-thin", StorageVolume: "thin"},
			}); err != nil {
				t.Fatal(err)
			}
			if state == "running" {
				fake.SetState("vm1", libvirtfake.StateRunning)
			}
			for _, d := range []string{"root", "data"} {
				if _, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: "vm1", DiskName: d, Size: "2G"}); err != nil {
					t.Fatalf("resize %s: %v", d, err)
				}
			}
			calls := blockToolCalls(t, log)
			for _, want := range []string{"zfs set volsize=2147483648 -- tank/acme/vm1-root", "lvextend -L 2147483648b -- vg0/vm1-data"} {
				if !strings.Contains(calls, want) {
					t.Errorf("tool calls lack %q:\n%s", want, calls)
				}
			}
			disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
			for _, d := range disks {
				if d.SizeBytes != 2<<30 {
					t.Errorf("disk %s recorded at %d bytes, want %d", d.DiskName, d.SizeBytes, 2<<30)
				}
			}
			// Never a shrink, and never a tool call for one.
			before := blockToolCalls(t, log)
			if _, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: "vm1", DiskName: "root", Size: "1G"}); status.Code(err) != codes.InvalidArgument {
				t.Errorf("shrink: got %v, want InvalidArgument", err)
			}
			if blockToolCalls(t, log) != before {
				t.Errorf("a refused shrink ran a tool")
			}
		})
	}
}

// Follow-up 2: the volume a resize names is derived from the disk's path and
// must be in its driver's strict form, so nothing else reaches the tool.
func TestResizeDisk_BlockVolumePathMustBeItsDriversForm(t *testing.T) {
	log := fakeBlockTools(t)
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped"}, nil, []corrosion.DiskRecord{
		{VMName: "vm1", DiskName: "a", HostName: s.hostName, Path: "/var/lib/x/vm1-a.qcow2", SizeBytes: 1 << 30, StorageType: "zfs"},
		{VMName: "vm1", DiskName: "b", HostName: s.hostName, Path: "/dev/zvol/-o/x", SizeBytes: 1 << 30, StorageType: "zfs"},
		{VMName: "vm1", DiskName: "c", HostName: s.hostName, Path: "/dev/vg0/sub/lv", SizeBytes: 1 << 30, StorageType: "lvm-thin"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a", "b", "c"} {
		if _, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: "vm1", DiskName: d, Size: "2G"}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("resize %s: got %v, want FailedPrecondition", d, err)
		}
	}
	if c := blockToolCalls(t, log); c != "" {
		t.Errorf("a malformed volume reached a tool:\n%s", c)
	}
}

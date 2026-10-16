package health

import (
	"reflect"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

type diskLayout struct{ name, bus, target string }

func layout(cfgs []lv.DiskConfig) []diskLayout {
	var out []diskLayout
	for i, c := range cfgs {
		target := c.TargetDev
		if target == "" {
			target = lv.DiskDevName(c.Bus, i)
		}
		out = append(out, diskLayout{c.Name, c.Bus, target})
	}
	return out
}

// A spec that lists no disks (a VM created before the disk-tuning latch, or
// on a cluster without it) still boots its root: the root row goes first
// whatever target a disk hot-plugged since sorts to (a sata sda sorts ahead of
// vda), and the generator gives the first disk boot order 1.
//
// Mutation: sort every row of such a spec by target alone — data (sda) goes
// first and the test goes red.
func TestFailoverDiskConfigs_NoSpecDisksBootsTheRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []corrosion.DiskRecord
	}{
		{"named root", []corrosion.DiskRecord{
			{DiskName: "data", Path: "/d", TargetDev: "sda", Bus: "sata"},
			{DiskName: "root", Path: "/r", TargetDev: "vda"},
		}},
		{"image-backed", []corrosion.DiskRecord{
			{DiskName: "data", Path: "/d", TargetDev: "sda", Bus: "sata"},
			{DiskName: "os", Path: "/r", TargetDev: "vda", BackingImage: "debian12"},
		}},
		{"first target of its bus", []corrosion.DiskRecord{
			{DiskName: "a-data", Path: "/d", TargetDev: "sdb", Bus: "sata"},
			{DiskName: "os", Path: "/r", TargetDev: "vda"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := failoverDiskConfigs(&pb.VMSpec{}, tc.rows)
			if len(got) != 2 || got[0].Path != "/r" {
				t.Fatalf("disks = %+v, want the root (/r) first", layout(got))
			}
		})
	}
}

// A spec disk keeps the target its row records: one that is withheld or gone
// must not shift a later spec disk down into a hot-plugged disk's slot.
//
// Mutation: give spec disks positional targets again — data takes vdb, the
// hot disk's, and the test goes red.
func TestFailoverDiskConfigs_SpecDisksKeepTheirRecordedTargets(t *testing.T) {
	spec := &pb.VMSpec{Disks: []*pb.DiskSpec{
		{Name: "root", Bus: "virtio"},
		{Name: "shared", Bus: "scsi"},
		{Name: "data", Bus: "virtio"},
	}}
	rows := []corrosion.DiskRecord{ // "shared" withheld: no row
		{DiskName: "data", Path: "/d", TargetDev: "vdc"},
		{DiskName: "hot", Path: "/h", TargetDev: "vdb", Bus: "virtio"},
		{DiskName: "root", Path: "/r", TargetDev: "vda"},
	}
	want := []diskLayout{{"root", "virtio", "vda"}, {"data", "virtio", "vdc"}, {"hot", "virtio", "vdb"}}
	if got := layout(failoverDiskConfigs(spec, rows)); !reflect.DeepEqual(got, want) {
		t.Fatalf("disks = %+v, want %+v", got, want)
	}
}

// Only disk-shaped rows are rendered as disks, as on a redefine.
//
// Mutation: drop the DeviceKind guard — the cdrom row is rendered and the
// test goes red.
func TestFailoverDiskConfigs_SkipsRowsThatAreNotDisks(t *testing.T) {
	rows := []corrosion.DiskRecord{
		{DiskName: "root", Path: "/r", TargetDev: "vda", DeviceKind: "disk"},
		{DiskName: "media", Path: "/m", TargetDev: "sdb", DeviceKind: "cdrom"},
	}
	got := layout(failoverDiskConfigs(&pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root"}, {Name: "media"}}}, rows))
	if want := []diskLayout{{"root", "virtio", "vda"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("disks = %+v, want %+v", got, want)
	}
}

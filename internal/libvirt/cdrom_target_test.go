package libvirt

import (
	"reflect"
	"testing"
)

// renderedTargets renders cfg and returns its disk targets in document order.
func renderedTargets(t *testing.T, cfg VMConfig) []string {
	t.Helper()
	out, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	got, err := DomainDiskTargets(out)
	if err != nil {
		t.Fatalf("DomainDiskTargets: %v", err)
	}
	return got
}

func TestDomainDiskTargets_ReadsDisksAndCDROMs(t *testing.T) {
	doc := `<domain><devices>
<disk type="file" device="disk"><source file="/r.qcow2"/><target dev="vda" bus="virtio"/></disk>
<disk type="file" device="cdrom"><source file="/seed.iso"/><target dev="sdb" bus="sata"/><readonly/></disk>
<disk type="file" device="cdrom"><target dev="sdc" bus="sata"/></disk>
</devices></domain>`
	got, err := DomainDiskTargets(doc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"vda", "sdb", "sdc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if _, err := DomainDiskTargets("<domain"); err == nil {
		t.Fatal("an unparseable definition must be an error, not an empty target set")
	}
}

// The create layouts keep the targets they always had: a CD-ROM's target is
// still derived from its position when nothing holds it.
func TestGenerateDomainXML_CDROMTargetsOfACreateAreUnchanged(t *testing.T) {
	cases := []struct {
		name string
		cfg  VMConfig
		want []string
	}{
		{"root+seed", VMConfig{Name: "a", CPU: 1, MemoryMiB: 512, CloudInitISO: "/ci/a.iso",
			Disks: []DiskConfig{{Name: "root", Path: "/r", Bus: "virtio"}}},
			[]string{"vda", "sdb"}},
		{"root+installer+seed", VMConfig{Name: "a", CPU: 1, MemoryMiB: 512, CloudInitISO: "/ci/a.iso",
			Disks: []DiskConfig{{Name: "root", Path: "/r", Bus: "virtio"}, {Name: "installer", Path: "/i.iso", IsISO: true}}},
			[]string{"vda", "sdb", "sdc"}},
		{"scsi disks+installer+seed", VMConfig{Name: "a", CPU: 1, MemoryMiB: 512, CloudInitISO: "/ci/a.iso",
			Disks: []DiskConfig{{Name: "root", Path: "/r", Bus: "scsi"}, {Name: "data", Path: "/d", Bus: "scsi"},
				{Name: "installer", Path: "/i.iso", IsISO: true}}},
			[]string{"sda", "sdb", "sdc", "sdd"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderedTargets(t, tc.cfg); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("targets = %v, want %v", got, tc.want)
			}
		})
	}
}

// A regenerate carries a hot-plugged sata/scsi disk at its recorded target.
// When that is the target a CD-ROM's position derives, the CD-ROM moves to
// the next free one instead of being defined on top of the disk.
//
// Mutation: derive the CD-ROM targets from the position alone (the old rule)
// — both cases go red with a duplicate target.
func TestGenerateDomainXML_CDROMTargetSkipsADiskTarget(t *testing.T) {
	cases := []struct {
		name string
		cfg  VMConfig
	}{
		{"seed after a hot-plugged sata disk", VMConfig{Name: "a", CPU: 1, MemoryMiB: 512, CloudInitISO: "/ci/a.iso",
			Disks: []DiskConfig{
				{Name: "root", Path: "/r", Bus: "virtio"},
				{Name: "data", Path: "/d", Bus: "sata", TargetDev: "sdc"},
			}}},
		{"installer and seed after hot-plugged scsi disks", VMConfig{Name: "a", CPU: 1, MemoryMiB: 512, CloudInitISO: "/ci/a.iso",
			Disks: []DiskConfig{
				{Name: "root", Path: "/r", Bus: "virtio"},
				{Name: "d1", Path: "/d1", Bus: "scsi", TargetDev: "sdc"},
				{Name: "d2", Path: "/d2", Bus: "scsi", TargetDev: "sdd"},
				{Name: "installer", Path: "/i.iso", IsISO: true},
			}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderedTargets(t, tc.cfg)
			seen := map[string]bool{}
			for _, dev := range got {
				if seen[dev] {
					t.Fatalf("target %s is defined twice: %v", dev, got)
				}
				seen[dev] = true
			}
			// Every explicit disk target is kept as recorded.
			for _, d := range tc.cfg.Disks {
				if d.TargetDev != "" && !seen[d.TargetDev] {
					t.Fatalf("disk %s lost its recorded target %s: %v", d.Name, d.TargetDev, got)
				}
			}
		})
	}
}

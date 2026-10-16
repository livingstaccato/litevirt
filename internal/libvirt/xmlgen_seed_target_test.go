package libvirt

import (
	"encoding/xml"
	"testing"
)

// The cloud-init seed's sata target never repeats a disk's: a disk that keeps
// a recorded target (one hot-plugged since the create) can sit in the slot the
// seed would take by position, and libvirt refuses a domain with two disks on
// one target. With no clash the seed keeps its positional target.
//
// Mutation: take sd('a'+len(Disks)) without the skip — the clash case renders
// two sdc and goes red.
func TestGenerateDomainXML_SeedTargetSkipsADisksTarget(t *testing.T) {
	targets := func(cfg VMConfig) []string {
		t.Helper()
		x, err := GenerateDomainXML(cfg)
		if err != nil {
			t.Fatalf("GenerateDomainXML: %v", err)
		}
		var d struct {
			Disks []struct {
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"devices>disk"`
		}
		if err := xml.Unmarshal([]byte(x), &d); err != nil {
			t.Fatalf("parse: %v", err)
		}
		var out []string
		for _, dk := range d.Disks {
			out = append(out, dk.Target.Dev)
		}
		return out
	}
	base := VMConfig{Name: "s", CPU: 1, MemoryMiB: 512, CloudInitISO: "/tmp/seed.iso"}

	clash := base
	clash.Disks = []DiskConfig{
		{Name: "root", Path: "/tmp/root.qcow2", Bus: "virtio"},
		{Name: "hot", Path: "/tmp/hot.qcow2", Bus: "sata", TargetDev: "sdc"},
	}
	got := targets(clash)
	seen := map[string]bool{}
	for _, dev := range got {
		if seen[dev] {
			t.Fatalf("targets %v repeat %s", got, dev)
		}
		seen[dev] = true
	}
	if len(got) != 3 || got[2] != "sdd" {
		t.Fatalf("targets = %v, want the seed on sdd past the hot disk's sdc", got)
	}

	plain := base
	plain.Disks = []DiskConfig{{Name: "root", Path: "/tmp/root.qcow2", Bus: "virtio"}}
	if got := targets(plain); len(got) != 2 || got[1] != "sdb" {
		t.Fatalf("targets = %v, want the seed on its positional sdb", got)
	}
}

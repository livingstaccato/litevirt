package libvirt

import "testing"

// Round 4 (N4): whether a domain definition attaches a seed is read from its
// cdroms only, by the exact (decoded) source file.
//
// Mutation: match any <disk> — the "a disk, not a cdrom" case goes red; match
// by substring — the "a longer path" case goes red.
func TestDomainAttachesCDROM(t *testing.T) {
	const seed = "/var/lib/litevirt/cloudinit/x.iso"
	dom := func(devices string) string {
		return "<domain type='kvm'><name>x</name><devices>" + devices + "</devices></domain>"
	}
	cdrom := func(file string) string {
		return "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + file + "'/><target dev='sdb' bus='sata'/><readonly/></disk>"
	}
	for _, tc := range []struct {
		name, xml, path string
		want            bool
	}{
		{"the seed's cdrom", dom(cdrom(seed)), seed, true},
		{"escaped path", dom(cdrom("/d/a&amp;b.iso")), "/d/a&b.iso", true},
		{"another cdrom", dom(cdrom("/var/lib/litevirt/cloudinit/y.iso")), seed, false},
		{"a longer path", dom(cdrom(seed + ".old")), seed, false},
		{"a disk, not a cdrom", dom("<disk type='file' device='disk'><source file='" + seed + "'/></disk>"), seed, false},
		{"an empty cdrom", dom("<disk type='file' device='cdrom'><target dev='sdb' bus='sata'/></disk>"), seed, false},
		{"no devices", "<domain type='kvm'><name>x</name><devices></devices></domain>", seed, false},
		{"no domain", "", seed, false},
		{"not XML", "<domain><devices>", seed, false},
	} {
		if got := DomainAttachesCDROM(tc.xml, tc.path); got != tc.want {
			t.Errorf("%s: DomainAttachesCDROM = %v, want %v", tc.name, got, tc.want)
		}
	}
}

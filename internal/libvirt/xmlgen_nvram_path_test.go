package libvirt

import "testing"

func TestNvramPathFromXML(t *testing.T) {
	for x, want := range map[string]string{
		`<domain><os><type>hvm</type><nvram template='/t'>/var/lib/libvirt/qemu/nvram/a_VARS.fd</nvram></os></domain>`: "/var/lib/libvirt/qemu/nvram/a_VARS.fd",
		`<domain><os><type>hvm</type></os></domain>`: "",
		`not xml`: "",
	} {
		if got := NvramPathFromXML(x); got != want {
			t.Errorf("NvramPathFromXML(%q) = %q, want %q", x, got, want)
		}
	}
}

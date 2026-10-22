package libvirt

import (
	"strings"
	"testing"
)

// A short-form BDF ("41:00.0", domain omitted, as lspci prints it) used to
// render as 0000:00:00.0, the host bridge, because the parser wanted three
// ':'-separated parts and fell back to zeros. It is the same device as
// 0000:41:00.0 and renders as it; an address that is no BDF at all is refused,
// never rendered as some other device.
//
// Mutation: restore the zero fallback in ParsePCIAddress: red.
func TestGenerateDomainXML_HostdevAddressIsCanonicalOrRefused(t *testing.T) {
	cfg := func(addr string) VMConfig {
		return VMConfig{Name: "gpu", CPU: 1, MemoryMiB: 512, Firmware: "bios",
			Disks:    []DiskConfig{{Name: "root", Path: "/d.qcow2", Bus: "virtio"}},
			Hostdevs: []HostdevConfig{{Address: addr}}}
	}
	x, err := GenerateDomainXML(cfg("41:00.0"))
	if err != nil {
		t.Fatalf("short-form BDF: %v", err)
	}
	if got := HostdevSourcePCIAddresses(x); len(got) != 1 || got[0] != "0000:41:00.0" {
		t.Fatalf("short-form 41:00.0 rendered as %v, want [0000:41:00.0]", got)
	}
	for _, bad := range []string{"", "short", "0000:41", "0000:41:00", "0000:41:20.0", "0000:41:00.8"} {
		if x, err := GenerateDomainXML(cfg(bad)); err == nil {
			t.Errorf("hostdev address %q rendered as %v, want a refusal", bad, HostdevSourcePCIAddresses(x))
		} else if !strings.Contains(err.Error(), "PCI address") {
			t.Errorf("hostdev address %q: %v, want an error naming the PCI address", bad, err)
		}
	}
}

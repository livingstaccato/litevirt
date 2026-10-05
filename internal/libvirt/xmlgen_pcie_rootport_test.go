package libvirt

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestGenerateDomainXML_SparePCIeRootPorts covers the q35 hot-plug fix: N spare,
// empty `<controller type='pci' model='pcie-root-port'>` entries, indexed 1..N
// (0 is libvirt's own implicit pcie-root, never declared here), with no
// <address>/<target> — those are libvirt's to assign at define time.
func TestGenerateDomainXML_SparePCIeRootPorts(t *testing.T) {
	cfg := VMConfig{
		Name:               "vm-spare",
		CPU:                2,
		MemoryMiB:          2048,
		Machine:            "q35",
		SparePCIeRootPorts: 4,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}

	var dom domain
	if err := xml.Unmarshal([]byte(xmlOut), &dom); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}

	var rootPorts []controllerDevice
	for _, c := range dom.Devices.Controllers {
		if c.Type == "pci" && c.Model == "pcie-root-port" {
			rootPorts = append(rootPorts, c)
		}
	}
	if len(rootPorts) != 4 {
		t.Fatalf("got %d pcie-root-port controllers, want 4: %+v", len(rootPorts), rootPorts)
	}
	seen := map[int]bool{}
	for _, c := range rootPorts {
		if c.Index == 0 {
			t.Errorf("root port must not use index 0 (reserved for libvirt's implicit pcie-root): %+v", c)
		}
		if seen[c.Index] {
			t.Errorf("duplicate root-port index %d", c.Index)
		}
		seen[c.Index] = true
	}
	for i := 1; i <= 4; i++ {
		if !seen[i] {
			t.Errorf("missing root-port index %d, got indices %v", i, seen)
		}
	}
}

// TestGenerateDomainXML_SparePCIeRootPortsZero_NoOp pins "0 = old behavior,
// byte-identical" — the safe default for every VM defined before this feature
// existed and for an operator who explicitly wants none.
func TestGenerateDomainXML_SparePCIeRootPortsZero_NoOp(t *testing.T) {
	base := VMConfig{
		Name:      "vm-nospare",
		CPU:       2,
		MemoryMiB: 2048,
		Machine:   "q35",
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
	}
	withZero := base
	withZero.SparePCIeRootPorts = 0

	gotBase, err := GenerateDomainXML(base)
	if err != nil {
		t.Fatalf("GenerateDomainXML(base): %v", err)
	}
	gotZero, err := GenerateDomainXML(withZero)
	if err != nil {
		t.Fatalf("GenerateDomainXML(zero): %v", err)
	}
	if gotBase != gotZero {
		t.Fatalf("SparePCIeRootPorts=0 must be byte-identical to the zero-value default:\nbase: %s\nzero: %s", gotBase, gotZero)
	}
	if strings.Contains(gotBase, "pcie-root-port") {
		t.Fatalf("SparePCIeRootPorts=0 must emit no pcie-root-port controller: %s", gotBase)
	}
}

// TestGenerateDomainXML_SparePCIeRootPorts_NonQ35Ignored: i440fx ("pc") has no
// pcie-root-port controller model — emitting one would produce XML libvirt
// refuses to define. A spare-port request on a non-q35 machine is silently a
// no-op rather than a definition-time error, mirroring how other q35-only
// fields (Secure Boot) are gated by isQ35Machine elsewhere in this builder.
func TestGenerateDomainXML_SparePCIeRootPorts_NonQ35Ignored(t *testing.T) {
	cfg := VMConfig{
		Name:               "vm-i440fx",
		CPU:                2,
		MemoryMiB:          2048,
		Machine:            "pc",
		SparePCIeRootPorts: 4,
		Disks: []DiskConfig{
			{Name: "root", Path: "/disks/root.qcow2", Bus: "virtio"},
		},
	}

	xmlOut, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	if strings.Contains(xmlOut, "pcie-root-port") {
		t.Fatalf("a non-q35 machine must get no pcie-root-port controllers: %s", xmlOut)
	}
}

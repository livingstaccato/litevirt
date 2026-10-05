package libvirt

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// The fixtures are `virsh dumpxml --inactive` of domains defined on libvirt
// 10.0.0 / QEMU 8.2 from GenerateDomainXML output (q35, UEFI, guest agent,
// VNC, cloud-init): what libvirt really does with the XML we generate.
//
//   - typical_nospare: 1 disk, 1 NIC, no declared root ports. libvirt adds a
//     port for each of its five PCIe devices (NIC, the qemu-xhci and
//     virtio-serial controllers it adds itself, disk, balloon) plus ONE
//     spare: 6 ports, 1 free.
//   - typical_4declared: the same domain with four declared, unaddressed
//     root ports (the builder as it was). libvirt hands all four to the
//     domain's own devices and adds one more for the fifth, with no spare:
//     5 ports, 0 free. This is the lab's "No more available PCI slots" on
//     the first hot-plug of a new VM.
//   - rich_nospare: 2 disks, 2 NICs: 8 ports, 1 free.
//   - typical_toppedup: typical_nospare redefined from the output of
//     TopUpSparePCIeRootPorts(…, 4): libvirt kept every device where it was
//     and indexed the three new ports: 9 ports, 4 free.
func TestFreePCIeRootPorts_RealLibvirtDumps(t *testing.T) {
	for _, tc := range []struct {
		fixture     string
		total, free int
	}{
		{"rootports_libvirt10_typical_nospare.xml", 6, 1},
		{"rootports_libvirt10_typical_4declared.xml", 5, 0},
		{"rootports_libvirt10_rich_nospare.xml", 8, 1},
		{"rootports_libvirt10_typical_toppedup.xml", 9, 4},
	} {
		total, free, err := FreePCIeRootPorts(readFixture(t, tc.fixture))
		if err != nil {
			t.Fatalf("%s: %v", tc.fixture, err)
		}
		if total != tc.total || free != tc.free {
			t.Errorf("%s: total=%d free=%d, want total=%d free=%d", tc.fixture, total, free, tc.total, tc.free)
		}
	}
}

// The invariant: after the top-up, the domain libvirt assigned has at least
// `want` root ports no device sits on — whatever libvirt did with the
// domain's own devices. Existing addresses are left exactly as libvirt
// assigned them, so the redefine moves no device.
func TestTopUpSparePCIeRootPorts_LeavesWantFree(t *testing.T) {
	for _, tc := range []struct {
		fixture   string
		want      int
		wantAdded int
	}{
		{"rootports_libvirt10_typical_nospare.xml", 4, 3},
		{"rootports_libvirt10_typical_4declared.xml", 4, 4},
		{"rootports_libvirt10_rich_nospare.xml", 4, 3},
		{"rootports_libvirt10_rich_nospare.xml", 1, 0},
		{"rootports_libvirt10_typical_nospare.xml", 0, 0},
		{"rootports_libvirt10_typical_toppedup.xml", 4, 0},
	} {
		in := readFixture(t, tc.fixture)
		out, added, err := TopUpSparePCIeRootPorts(in, tc.want)
		if err != nil {
			t.Fatalf("%s want=%d: %v", tc.fixture, tc.want, err)
		}
		if added != tc.wantAdded {
			t.Errorf("%s want=%d: added %d, want %d", tc.fixture, tc.want, added, tc.wantAdded)
		}
		_, free, err := FreePCIeRootPorts(out)
		if err != nil {
			t.Fatalf("%s: re-parse topped-up XML: %v", tc.fixture, err)
		}
		if free < tc.want {
			t.Errorf("%s want=%d: %d free root ports after the top-up", tc.fixture, tc.want, free)
		}
		if added == 0 && out != in {
			t.Errorf("%s want=%d: nothing to add, yet the XML changed", tc.fixture, tc.want)
		}
		// Everything libvirt wrote is still there, in order: the top-up only
		// inserts new controllers.
		if stripped := strings.ReplaceAll(out, spareRootPortElement, ""); stripped != in {
			t.Errorf("%s: the top-up changed more than the inserted controllers", tc.fixture)
		}
	}
}

// A hostdev's <source><address> is the HOST device's address, not a guest
// slot: its bus must not mark a guest root port as used, even when it is
// written with type='pci' (libvirt accepts that on input).
func TestFreePCIeRootPorts_IgnoresHostdevSourceAddress(t *testing.T) {
	x := `<domain type='kvm'><name>v</name><os><type machine='pc-q35-8.2'>hvm</type></os><devices>
<controller type='pci' index='0' model='pcie-root'/>
<controller type='pci' index='1' model='pcie-root-port'><address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/></controller>
<controller type='pci' index='2' model='pcie-root-port'><address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x1'/></controller>
<hostdev mode='subsystem' type='pci' managed='yes'><source><address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/></source>
<address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/></hostdev>
</devices></domain>`
	total, free, err := FreePCIeRootPorts(x)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || free != 1 {
		t.Fatalf("total=%d free=%d, want 2 and 1 (port 1 holds the hostdev; host bus 0x02 is not guest port 2)", total, free)
	}
}

// i440fx has no pcie-root-port model: a top-up there would make XML libvirt
// refuses, so it is a no-op.
func TestTopUpSparePCIeRootPorts_NonQ35NoOp(t *testing.T) {
	x := `<domain type='kvm'><name>v</name><os><type machine='pc-i440fx-8.2'>hvm</type></os><devices></devices></domain>`
	out, added, err := TopUpSparePCIeRootPorts(x, 4)
	if err != nil || added != 0 || out != x {
		t.Fatalf("i440fx: added=%d err=%v changed=%v", added, err, out != x)
	}
}

type fakeDefiner struct {
	xml       map[string]string
	defines   int
	dumpErr   error
	defineErr error
}

func (f *fakeDefiner) DumpXMLInactive(name string) (string, error) {
	if f.dumpErr != nil {
		return "", f.dumpErr
	}
	x, ok := f.xml[name]
	if !ok {
		return "", errors.New("no domain")
	}
	return x, nil
}

func (f *fakeDefiner) DefineDomain(x string) error {
	f.defines++
	if f.defineErr != nil {
		return f.defineErr
	}
	f.xml[domainName(x)] = x
	return nil
}

func domainName(x string) string {
	i := strings.Index(x, "<name>")
	j := strings.Index(x, "</name>")
	return x[i+len("<name>") : j]
}

// EnsureSparePCIeRootPorts reads what libvirt assigned and redefines only
// when the domain is short of spares.
func TestEnsureSparePCIeRootPorts(t *testing.T) {
	in := readFixture(t, "rootports_libvirt10_typical_4declared.xml")
	d := &fakeDefiner{xml: map[string]string{"zz-pcitest-typical-s4": in}}
	added, err := EnsureSparePCIeRootPorts(d, "zz-pcitest-typical-s4", 4)
	if err != nil || added != 4 || d.defines != 1 {
		t.Fatalf("added=%d err=%v defines=%d, want 4 added in one redefine", added, err, d.defines)
	}
	if _, free, _ := FreePCIeRootPorts(d.xml["zz-pcitest-typical-s4"]); free != 4 {
		t.Fatalf("redefined domain has %d free root ports, want 4", free)
	}
	// Already enough: no second define.
	if added, err := EnsureSparePCIeRootPorts(d, "zz-pcitest-typical-s4", 4); err != nil || added != 0 || d.defines != 1 {
		t.Fatalf("second call: added=%d err=%v defines=%d, want a no-op", added, err, d.defines)
	}
	// want 0 never reads or defines anything.
	d0 := &fakeDefiner{xml: map[string]string{}, dumpErr: errors.New("must not be read")}
	if added, err := EnsureSparePCIeRootPorts(d0, "x", 0); err != nil || added != 0 || d0.defines != 0 {
		t.Fatalf("want=0: added=%d err=%v defines=%d", added, err, d0.defines)
	}
	// A failed redefine is reported.
	d2 := &fakeDefiner{xml: map[string]string{"zz-pcitest-typical-s4": in}, defineErr: errors.New("boom")}
	if _, err := EnsureSparePCIeRootPorts(d2, "zz-pcitest-typical-s4", 4); err == nil {
		t.Fatal("a failed redefine must be returned")
	}
}

// The builder declares no root ports of its own. Any it declared without an
// address, libvirt would give to the domain's own devices at define time
// (typical_4declared above) — so spare ports are added after libvirt has
// placed every device, by EnsureSparePCIeRootPorts.
func TestGenerateDomainXML_DeclaresNoRootPorts(t *testing.T) {
	cfg := VMConfig{
		Name: "vm", CPU: 1, MemoryMiB: 256, Machine: "q35", Firmware: "uefi",
		GuestAgent: true, EnableVNC: true,
		Disks:    []DiskConfig{{Name: "root", Path: "/d/root.qcow2", Bus: "virtio"}},
		Networks: []NetworkConfig{{Bridge: "br0"}},
	}
	x, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(x, "pcie-root-port") {
		t.Fatalf("the builder must leave root ports to libvirt:\n%s", x)
	}
}

package libvirt

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parsedDomain is the subset of a generated domain these tests read back.
type parsedDomain struct {
	Memory struct {
		Value int    `xml:",chardata"`
		Unit  string `xml:"unit,attr"`
	} `xml:"memory"`
	MaxMemory *struct {
		Value int    `xml:",chardata"`
		Slots int    `xml:"slots,attr"`
		Unit  string `xml:"unit,attr"`
	} `xml:"maxMemory"`
	CurrentMemory *struct {
		Value int `xml:",chardata"`
	} `xml:"currentMemory"`
	CPU *struct {
		Mode  string `xml:"mode,attr"`
		Cells []struct {
			ID     string `xml:"id,attr"`
			CPUs   string `xml:"cpus,attr"`
			Memory int    `xml:"memory,attr"`
			Unit   string `xml:"unit,attr"`
		} `xml:"numa>cell"`
	} `xml:"cpu"`
	Hostdevs []struct {
		Type    string `xml:"type,attr"`
		Mode    string `xml:"mode,attr"`
		Managed string `xml:"managed,attr"`
		Source  struct {
			Vendor *struct {
				ID string `xml:"id,attr"`
			} `xml:"vendor"`
			Product *struct {
				ID string `xml:"id,attr"`
			} `xml:"product"`
			Address *struct {
				Domain string `xml:"domain,attr"`
				Bus    string `xml:"bus,attr"`
				Slot   string `xml:"slot,attr"`
				Device string `xml:"device,attr"`
			} `xml:"address"`
		} `xml:"source"`
	} `xml:"devices>hostdev"`
	MemDevs []struct {
		Model  string `xml:"model,attr"`
		Target struct {
			Size      int `xml:"size"`
			Node      int `xml:"node"`
			Block     int `xml:"block"`
			Requested int `xml:"requested"`
		} `xml:"target"`
	} `xml:"devices>memory"`
}

func genParsed(t *testing.T, cfg VMConfig) (string, parsedDomain) {
	t.Helper()
	out, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	var d parsedDomain
	if err := xml.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("parse generated XML: %v\n%s", err, out)
	}
	return out, d
}

func TestGenerateDomainXML_USBHostdevByVendorProduct(t *testing.T) {
	_, d := genParsed(t, VMConfig{Name: "u1", CPU: 1, MemoryMiB: 512,
		USBHostdevs: []USBHostdevConfig{{Vendor: "046d", Product: "c52b"}}})
	if len(d.Hostdevs) != 1 {
		t.Fatalf("hostdevs = %d, want 1", len(d.Hostdevs))
	}
	h := d.Hostdevs[0]
	if h.Type != "usb" || h.Mode != "subsystem" || h.Managed != "yes" {
		t.Errorf("hostdev = type %q mode %q managed %q, want usb/subsystem/yes", h.Type, h.Mode, h.Managed)
	}
	if h.Source.Vendor == nil || h.Source.Vendor.ID != "0x046d" || h.Source.Product == nil || h.Source.Product.ID != "0xc52b" {
		t.Errorf("source = %+v, want vendor 0x046d product 0xc52b", h.Source)
	}
	if h.Source.Address != nil {
		t.Errorf("a vendor:product device carries an address: %+v", h.Source.Address)
	}
}

func TestGenerateDomainXML_USBHostdevByBusDevice(t *testing.T) {
	_, d := genParsed(t, VMConfig{Name: "u2", CPU: 1, MemoryMiB: 512,
		USBHostdevs: []USBHostdevConfig{{Bus: 3, Device: 7}}})
	if len(d.Hostdevs) != 1 || d.Hostdevs[0].Type != "usb" {
		t.Fatalf("hostdevs = %+v, want one usb hostdev", d.Hostdevs)
	}
	a := d.Hostdevs[0].Source.Address
	if a == nil || a.Bus != "3" || a.Device != "7" || a.Domain != "" || a.Slot != "" {
		t.Errorf("address = %+v, want bus 3 device 7 and no PCI attributes", a)
	}
	if d.Hostdevs[0].Source.Vendor != nil {
		t.Error("a bus/device USB hostdev carries a vendor")
	}
}

func TestGenerateDomainXML_PCIHostdevUnchangedBesideUSB(t *testing.T) {
	_, d := genParsed(t, VMConfig{Name: "u3", CPU: 1, MemoryMiB: 512,
		Hostdevs:    []HostdevConfig{{Address: "0000:41:00.0"}},
		USBHostdevs: []USBHostdevConfig{{Vendor: "046d", Product: "c52b"}}})
	if len(d.Hostdevs) != 2 {
		t.Fatalf("hostdevs = %d, want 2", len(d.Hostdevs))
	}
	pci := d.Hostdevs[0]
	if pci.Type != "pci" || pci.Source.Address == nil || pci.Source.Address.Bus != "0x41" || pci.Source.Address.Domain != "0x0000" {
		t.Errorf("pci hostdev = %+v", pci)
	}
}

func TestGenerateDomainXML_USBHostdevRejectsMalformed(t *testing.T) {
	for _, bad := range []USBHostdevConfig{
		{},                                 // nothing
		{Vendor: "046d"},                   // half a pair
		{Vendor: "046d", Product: "zzzz"},  // not hex
		{Vendor: "046d'", Product: "c52b"}, // quote
		{Vendor: "046d", Product: "c52b", Bus: 1, Device: 2}, // both forms
		{Bus: 0, Device: 4}, // bus 0 is not a USB bus
	} {
		if _, err := GenerateDomainXML(VMConfig{Name: "u4", CPU: 1, MemoryMiB: 512, USBHostdevs: []USBHostdevConfig{bad}}); err == nil {
			t.Errorf("GenerateDomainXML accepted malformed USB device %+v", bad)
		}
	}
}

func TestGenerateDomainXML_MemoryHotplug(t *testing.T) {
	out, d := genParsed(t, VMConfig{Name: "m1", CPU: 2, MaxCPU: 4, MemoryMiB: 3072, CPUMode: "host-model",
		HotplugBaseMiB: 2048, HotplugMaxMiB: 8192})
	if d.MaxMemory == nil || d.MaxMemory.Value != 8192*1024 || d.MaxMemory.Slots <= 0 || d.MaxMemory.Unit != "KiB" {
		t.Fatalf("maxMemory = %+v, want 8192 MiB with slots", d.MaxMemory)
	}
	if d.Memory.Value != 8192*1024 {
		t.Errorf("memory = %d KiB, want the boot cell plus the virtio-mem region (%d)", d.Memory.Value, 8192*1024)
	}
	if d.CurrentMemory != nil {
		t.Errorf("a hot-add domain carries currentMemory %d; the balloon ceiling is not used", d.CurrentMemory.Value)
	}
	if d.CPU == nil || d.CPU.Mode != "host-model" || len(d.CPU.Cells) != 1 {
		t.Fatalf("cpu = %+v, want host-model with one NUMA cell", d.CPU)
	}
	c := d.CPU.Cells[0]
	if c.ID != "0" || c.CPUs != "0-3" || c.Memory != 2048*1024 || c.Unit != "KiB" {
		t.Errorf("cell = %+v, want id 0, cpus 0-3 (the vCPU ceiling), 2048 MiB", c)
	}
	if len(d.MemDevs) != 1 {
		t.Fatalf("memory devices = %d, want 1\n%s", len(d.MemDevs), out)
	}
	m := d.MemDevs[0]
	if m.Model != "virtio-mem" || m.Target.Size != 6144*1024 || m.Target.Node != 0 || m.Target.Block != 2048 || m.Target.Requested != 1024*1024 {
		t.Errorf("virtio-mem = %+v, want size 6144 MiB, node 0, block 2048 KiB, requested 1024 MiB", m)
	}
}

func TestGenerateDomainXML_MemoryHotplugWithoutCPUModeStillHasCell(t *testing.T) {
	out, d := genParsed(t, VMConfig{Name: "m2", CPU: 1, MemoryMiB: 1024, HotplugBaseMiB: 1024, HotplugMaxMiB: 2048})
	if d.CPU == nil || len(d.CPU.Cells) != 1 || d.CPU.Cells[0].CPUs != "0" {
		t.Fatalf("cpu = %+v, want one NUMA cell with cpus 0", d.CPU)
	}
	if strings.Contains(out, `mode=""`) {
		t.Errorf("an empty cpu mode was emitted: %s", out)
	}
}

func TestGenerateDomainXML_NoHotplugNoMaxMemory(t *testing.T) {
	out, d := genParsed(t, VMConfig{Name: "m3", CPU: 1, MemoryMiB: 1024})
	if d.MaxMemory != nil || len(d.MemDevs) != 0 || d.CPU != nil {
		t.Errorf("a plain domain grew hot-add elements: %s", out)
	}
}

func TestGenerateDomainXML_MemoryHotplugRejectsBadBand(t *testing.T) {
	for _, c := range []VMConfig{
		{MemoryMiB: 1024, HotplugBaseMiB: 1024, HotplugMaxMiB: 1024},                     // no region
		{MemoryMiB: 1024, HotplugBaseMiB: 1024, HotplugMaxMiB: 2047},                     // region not a 2 MiB multiple
		{MemoryMiB: 4096, HotplugBaseMiB: 1024, HotplugMaxMiB: 2048},                     // current above max
		{MemoryMiB: 512, HotplugBaseMiB: 1024, HotplugMaxMiB: 2048},                      // current below base
		{MemoryMiB: 1024, HotplugBaseMiB: 0, HotplugMaxMiB: 2048},                        // no boot cell
		{MemoryMiB: 1024, MaxMemoryMiB: 1536, HotplugBaseMiB: 1024, HotplugMaxMiB: 2048}, // balloon ceiling too
	} {
		c.Name, c.CPU = "m4", 1
		if _, err := GenerateDomainXML(c); err == nil {
			t.Errorf("GenerateDomainXML accepted hot-add band %+v", c)
		}
	}
}

const usbDomXML = `<domain type='kvm'>
  <name>u</name>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <hostdev mode='subsystem' type='usb' managed='yes'>
      <source>
        <vendor id='0x046d'/>
        <product id='0xc52b'/>
      </source>
      <alias name='hostdev0'/>
      <address type='usb' bus='0' port='1'/>
    </hostdev>
    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/>
      </source>
    </hostdev>
    <hostdev mode="subsystem" type="usb" managed="yes">
      <source>
        <address bus="1" device="4"/>
      </source>
    </hostdev>
  </devices>
</domain>`

func TestReplaceUSBHostdevs(t *testing.T) {
	out, err := ReplaceUSBHostdevs(usbDomXML, []USBHostdevConfig{{Vendor: "1a86", Product: "7523"}})
	if err != nil {
		t.Fatalf("ReplaceUSBHostdevs: %v", err)
	}
	if strings.Contains(out, "0x046d") || strings.Contains(out, `device="4"`) {
		t.Errorf("an old USB hostdev survived:\n%s", out)
	}
	if !strings.Contains(out, "bus='0x41'") {
		t.Errorf("the PCI hostdev was touched:\n%s", out)
	}
	var d parsedDomain
	if err := xml.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, out)
	}
	var usb int
	for _, h := range d.Hostdevs {
		if h.Type == "usb" {
			usb++
			if h.Source.Vendor == nil || h.Source.Vendor.ID != "0x1a86" {
				t.Errorf("replacement = %+v", h.Source)
			}
		}
	}
	if usb != 1 {
		t.Errorf("usb hostdevs = %d, want 1:\n%s", usb, out)
	}

	cleared, err := ReplaceUSBHostdevs(usbDomXML, nil)
	if err != nil || strings.Contains(cleared, "type='usb'") || strings.Contains(cleared, `type="usb"`) {
		t.Errorf("clearing left USB hostdevs (err %v):\n%s", err, cleared)
	}
	if _, err := ReplaceUSBHostdevs("<domain/>", []USBHostdevConfig{{Vendor: "1a86", Product: "7523"}}); err == nil {
		t.Error("a domain with no </devices> was accepted")
	}
}

const virtioMemDomXML = `<domain type='kvm'>
  <devices>
    <memory model='virtio-mem'>
      <target>
        <size unit='KiB'>6291456</size>
        <node>0</node>
        <block unit='KiB'>2048</block>
        <requested unit='KiB'>1048576</requested>
        <current unit='KiB'>1048576</current>
      </target>
      <alias name='virtiomem0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </memory>
  </devices>
</domain>`

func TestVirtioMemUpdateXML(t *testing.T) {
	elem, err := VirtioMemUpdateXML(virtioMemDomXML, 3072)
	if err != nil {
		t.Fatalf("VirtioMemUpdateXML: %v", err)
	}
	if !strings.Contains(elem, "<requested unit='KiB'>3145728</requested>") {
		t.Errorf("requested not set to 3072 MiB: %s", elem)
	}
	for _, keep := range []string{"<alias name='virtiomem0'/>", "slot='0x05'", "<size unit='KiB'>6291456</size>"} {
		if !strings.Contains(elem, keep) {
			t.Errorf("element lost %q: %s", keep, elem)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(elem), "<memory model='virtio-mem'>") || !strings.HasSuffix(strings.TrimSpace(elem), "</memory>") {
		t.Errorf("not a single memory element: %s", elem)
	}
	if _, err := VirtioMemUpdateXML(virtioMemDomXML, 8192); err == nil {
		t.Error("a request above the region size was accepted")
	}
	if _, err := VirtioMemUpdateXML(virtioMemDomXML, -2); err == nil {
		t.Error("a negative request was accepted")
	}
	if _, err := VirtioMemUpdateXML(usbDomXML, 1024); err == nil {
		t.Error("a domain with no virtio-mem device was accepted")
	}
}

func TestResolveUSBBusPort(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "1-2.3")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dev, "busnum"), []byte("1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "devnum"), []byte("9\n"), 0o644)
	defer SetUSBSysfsRootForTest(root)()

	got, err := ResolveUSBBusPort("1-2.3")
	if err != nil || got.Bus != 1 || got.Device != 9 {
		t.Fatalf("ResolveUSBBusPort = %+v, %v; want bus 1 device 9", got, err)
	}
	if _, err := ResolveUSBBusPort("1-4"); err == nil {
		t.Error("an absent port resolved")
	}
	for _, bad := range []string{"../1-2", "1-2/..", "usb1", "1-", "-2", "1-2.", "a-b"} {
		if _, err := ResolveUSBBusPort(bad); err == nil {
			t.Errorf("malformed port %q resolved", bad)
		}
	}
}

func TestParseUSBMappingAddress(t *testing.T) {
	for in, want := range map[string]USBDeviceRef{
		"usb:046d:c52b": {Vendor: "046d", Product: "c52b"},
		"usb:046D:C52B": {Vendor: "046d", Product: "c52b"},
		"usb:3-1.4":     {BusPort: "3-1.4"},
	} {
		got, err := ParseUSBMappingAddress(in)
		if err != nil || got != want {
			t.Errorf("ParseUSBMappingAddress(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0000:41:00.0", "usb:", "usb:046d", "usb:046d:c52b:1", "usb:zz:c52b", "usb:1-2/../x"} {
		if _, err := ParseUSBMappingAddress(bad); err == nil {
			t.Errorf("ParseUSBMappingAddress(%q) accepted", bad)
		}
	}
}

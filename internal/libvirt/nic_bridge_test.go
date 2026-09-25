package libvirt

import (
	"strings"
	"testing"
)

const retargetDomXML = `<domain type='kvm'>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:01'/>
      <source bridge='hc_hc'/>
      <target dev='vnet3'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
    <interface type="bridge">
      <mac address="52:54:00:AA:BB:02"/>
      <source bridge="br0"/>
      <model type="e1000"/>
    </interface>
  </devices>
</domain>`

func TestRetargetInterfaceXML(t *testing.T) {
	elem, ok := RetargetInterfaceXML(retargetDomXML, "52:54:00:AA:BB:01", "br-iso-hc")
	if !ok {
		t.Fatal("interface with MAC 52:54:00:aa:bb:01 not found")
	}
	if !strings.Contains(elem, "<source bridge='br-iso-hc'/>") {
		t.Errorf("source not retargeted: %s", elem)
	}
	for _, keep := range []string{"52:54:00:aa:bb:01", "<target dev='vnet3'/>", "<model type='virtio'/>", "<alias name='net0'/>", "slot='0x00'"} {
		if !strings.Contains(elem, keep) {
			t.Errorf("element lost %q: %s", keep, elem)
		}
	}
	if strings.Contains(elem, "br0") || strings.Contains(elem, "e1000") {
		t.Errorf("element includes the other interface: %s", elem)
	}

	elem, ok = RetargetInterfaceXML(retargetDomXML, "52:54:00:aa:bb:02", "br-lan")
	if !ok || !strings.Contains(elem, `<source bridge="br-lan"/>`) || strings.Contains(elem, "hc_hc") {
		t.Errorf("double-quoted interface: ok=%v elem=%s", ok, elem)
	}

	if _, ok := RetargetInterfaceXML(retargetDomXML, "52:54:00:aa:bb:99", "x"); ok {
		t.Error("an unknown MAC was found")
	}
}

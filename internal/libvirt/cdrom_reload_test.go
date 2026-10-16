package libvirt

import (
	"strings"
	"testing"
)

// The live definition of a running domain with its seed on sdb, as libvirt
// reports it (index, backingStore, alias, address).
const reloadLiveXML = `<domain type='kvm' id='3'>
  <name>vm</name>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/litevirt/disks/vm-root.qcow2' index='2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/litevirt/cloudinit/vm.iso' index='1'/>
      <backingStore/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
      <alias name='sata0-0-1'/>
      <address type='drive' controller='0' bus='0' target='0' unit='1'/>
    </disk>
  </devices>
</domain>`

// Round 1: libvirt changes a cdrom's media only when the update names
// another source, and the seed is rewritten at the same path. The reload is
// therefore an eject (the cdrom with no source) and an insert (the cdrom as
// it is): qemu opens the file again and the guest reads the new seed.
//
// Mutation: keep the <source> in the eject — red; match a cdrom by target
// rather than by its source file — the other-path case goes red.
func TestCDROMReloadElems(t *testing.T) {
	eject, insert, ok := cdromReloadElems(reloadLiveXML, "/var/lib/litevirt/cloudinit/vm.iso")
	if !ok {
		t.Fatal("the seed cdrom was not found")
	}
	if strings.Contains(eject, "<source") || !strings.Contains(eject, "<target dev='sdb' bus='sata'/>") ||
		!strings.Contains(eject, "device='cdrom'") {
		t.Errorf("eject element:\n%s", eject)
	}
	if !strings.Contains(insert, "<source file='/var/lib/litevirt/cloudinit/vm.iso' index='1'/>") ||
		!strings.Contains(insert, "<target dev='sdb' bus='sata'/>") || strings.Contains(insert, "vda") {
		t.Errorf("insert element:\n%s", insert)
	}
	if _, _, ok := cdromReloadElems(reloadLiveXML, "/var/lib/litevirt/cloudinit/other.iso"); ok {
		t.Error("a cdrom with another source was taken for the seed")
	}
	if _, _, ok := cdromReloadElems(reloadLiveXML, "/var/lib/litevirt/disks/vm-root.qcow2"); ok {
		t.Error("a disk was taken for a cdrom")
	}
}

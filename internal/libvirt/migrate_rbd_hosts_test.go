package libvirt

import (
	"strings"
	"testing"
)

const rbdLiveXML = `<domain type='kvm'>
  <name>vm</name>
  <devices>
    <disk type='network' device='disk'>
      <driver name='qemu' type='raw'/>
      <source protocol='rbd' name='lv/vm-root'>
        <host name='10.0.0.1' port='6789'/>
        <host name='10.0.0.2' port='6789'/>
        <auth username='litevirt'>
          <secret type='ceph' uuid='6f1b3c0e-6a52-5d0c-9a49-1c2f3b6e8d10'/>
        </auth>
      </source>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='network' device='disk'>
      <driver name='qemu' type='raw'/>
      <source protocol='rbd' name='lv/vm-data'/>
      <target dev='vdb' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <source file='/var/lib/litevirt/disks/vm-other.qcow2'/>
      <target dev='vdc' bus='virtio'/>
    </disk>
  </devices>
</domain>`

// N5. A live migration hands the destination the pool's CURRENT monitors,
// resolved on the source when it migrates — not the ones the running domain
// was defined with, which may all be gone after a monitor re-address.
func TestMigrationDomainXML_RewritesRBDHostsWithCurrentMonitors(t *testing.T) {
	defer SetCephMonitorResolver(func(pool string) ([]string, bool) {
		if pool == "ceph" {
			return []string{"10.9.9.9:6789", "10.9.9.8"}, true
		}
		return nil, false
	})()
	p := MigrateParams{RBDLocators: map[string]string{
		"lv/vm-root": "rbd:lv/vm-root:id=litevirt:keyring=/k:lvpool=ceph",
		"lv/vm-data": "rbd:lv/vm-data:id=litevirt:keyring=/k:lvpool=ceph",
	}}
	dest, persist, err := MigrationDomainXML(rbdLiveXML, rbdLiveXML, p)
	if err != nil {
		t.Fatal(err)
	}
	for name, x := range map[string]string{"dest": dest, "persist": persist} {
		if strings.Contains(x, "10.0.0.1") || strings.Contains(x, "10.0.0.2") {
			t.Errorf("%s still names the old monitors:\n%s", name, x)
		}
		if strings.Count(x, "name='10.9.9.9' port='6789'") != 2 || strings.Count(x, "<host name='10.9.9.8'/>") != 2 {
			t.Errorf("%s lacks the current monitors on both rbd disks:\n%s", name, x)
		}
		if !strings.Contains(x, "<secret type='ceph' uuid='6f1b3c0e-6a52-5d0c-9a49-1c2f3b6e8d10'/>") ||
			!strings.Contains(x, "/var/lib/litevirt/disks/vm-other.qcow2") {
			t.Errorf("%s lost something it should carry as it was:\n%s", name, x)
		}
	}
}

// With nothing to rewrite the domain migrates as it is (no destination XML).
func TestMigrationDomainXML_NothingToRewrite(t *testing.T) {
	dest, persist, err := MigrationDomainXML(rbdLiveXML, rbdLiveXML, MigrateParams{})
	if err != nil || dest != "" || persist != "" {
		t.Fatalf("dest %q persist %q err %v; want none", dest, persist, err)
	}
}

// A <host> written right after the <source> tag (libvirt's compact form) is
// replaced, and the new list survives.
func TestRewriteRBDHosts_CompactSource(t *testing.T) {
	x := `<domain><devices><disk type='network' device='disk'><source protocol='rbd' name='lv/a'><host name='1.1.1.1'/></source></disk></devices></domain>`
	out, err := RewriteRBDHosts(x, map[string][]diskSourceHost{"lv/a": {{Name: "2.2.2.2", Port: "6789"}}})
	if err != nil || !strings.Contains(out, "<source protocol='rbd' name='lv/a'><host name='2.2.2.2' port='6789'/></source>") {
		t.Fatalf("got %q, %v", out, err)
	}
}

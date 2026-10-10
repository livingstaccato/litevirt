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

// m3. A disk whose locator does not resolve now (its non-default conf is
// unreadable here and the pool is gone), or resolves to no monitors, keeps
// the <host> list the running domain has; neither fails the migration.
func TestMigrationDomainXML_UnresolvedDiskKeepsItsHosts(t *testing.T) {
	defer SetCephMonitorResolver(func(string) ([]string, bool) { return nil, false })()
	p := MigrateParams{RBDLocators: map[string]string{
		"lv/vm-root": "rbd:lv/vm-root:id=litevirt:keyring=/k:conf=/nonexistent/cluster.conf:lvpool=gone", // does not resolve
		"lv/vm-data": "rbd:lv/vm-data:id=litevirt:keyring=/k:lvpool=gone",                                // resolves to no hosts
	}}
	dest, persist, err := MigrationDomainXML(rbdLiveXML, rbdLiveXML, p)
	if err != nil {
		t.Fatalf("a disk that does not re-resolve failed the migration: %v", err)
	}
	for _, x := range []string{dest, persist} {
		if !strings.Contains(x, "<host name='10.0.0.1' port='6789'/>") || !strings.Contains(x, "<host name='10.0.0.2' port='6789'/>") {
			t.Fatalf("the running domain's hosts were dropped:\n%s", x)
		}
		if !strings.Contains(x, "<source protocol='rbd' name='lv/vm-data'/>") {
			t.Fatalf("an empty <host> list was written:\n%s", x)
		}
	}
}

// m4. The persistent definition is rewritten from ITSELF, not from the live
// one: what only it carries survives, and what only the live one carries does
// not leak into it.
func TestMigrationDomainXML_PersistentIsRewrittenFromItself(t *testing.T) {
	defer SetCephMonitorResolver(func(string) ([]string, bool) { return []string{"10.9.9.9:6789"}, true })()
	persist := strings.Replace(rbdLiveXML, "<name>vm</name>", "<name>vm</name><description>persistent-only</description>", 1)
	live := strings.Replace(rbdLiveXML, "<name>vm</name>", "<name>vm</name><description>live-only</description>", 1)
	dest, pout, err := MigrationDomainXML(live, persist, MigrateParams{RBDLocators: map[string]string{
		"lv/vm-root": "rbd:lv/vm-root:id=litevirt:keyring=/k:lvpool=ceph"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pout, "persistent-only") || strings.Contains(pout, "live-only") || !strings.Contains(pout, "10.9.9.9") {
		t.Fatalf("persistent definition:\n%s", pout)
	}
	if !strings.Contains(dest, "live-only") || strings.Contains(dest, "persistent-only") {
		t.Fatalf("destination definition:\n%s", dest)
	}
}

// m4. CD-ROM and rbd rewrites compose; a non-rbd network disk of the same
// name is never touched.
func TestMigrationDomainXML_CDROMAndRBDTogether(t *testing.T) {
	defer SetCephMonitorResolver(func(string) ([]string, bool) { return []string{"10.9.9.9:6789"}, true })()
	x := `<domain><devices>` +
		`<disk type='file' device='cdrom'><source file='/iso/a.iso'/><target dev='sda'/></disk>` +
		`<disk type='network' device='disk'><source protocol='rbd' name='lv/r'><host name='1.1.1.1'/></source></disk>` +
		`<disk type='network' device='disk'><source protocol='nbd' name='lv/r'><host name='5.5.5.5'/></source></disk>` +
		`</devices></domain>`
	dest, _, err := MigrationDomainXML(x, x, MigrateParams{
		CDROMSources: map[string]string{"/iso/a.iso": "/iso/b.iso"},
		RBDLocators:  map[string]string{"lv/r": "rbd:lv/r:lvpool=ceph"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/iso/b.iso", "<host name='10.9.9.9' port='6789'/>", "<source protocol='nbd' name='lv/r'><host name='5.5.5.5'/>"} {
		if !strings.Contains(dest, want) {
			t.Errorf("dest lacks %s:\n%s", want, dest)
		}
	}
	if strings.Contains(dest, "1.1.1.1") {
		t.Errorf("rbd host not rewritten:\n%s", dest)
	}
}

// m4. MigrateToTarget's choice of whether to build destination definitions:
// rbd locators alone are enough (not only CD-ROM remaps).
func TestMigrationDefinitions_RBDLocatorsAloneRewrite(t *testing.T) {
	defer SetCephMonitorResolver(func(string) ([]string, bool) { return []string{"10.9.9.9:6789"}, true })()
	fetched := 0
	get := func() (string, error) { fetched++; return rbdLiveXML, nil }
	dest, persist, err := migrationDefinitions(MigrateParams{RBDLocators: map[string]string{"lv/vm-root": "rbd:lv/vm-root:lvpool=ceph"}}, get, get)
	if err != nil || fetched != 2 || !strings.Contains(dest, "10.9.9.9") || !strings.Contains(persist, "10.9.9.9") {
		t.Fatalf("fetched %d, err %v, dest has new host %v", fetched, err, strings.Contains(dest, "10.9.9.9"))
	}
	fetched = 0
	if dest, _, _ := migrationDefinitions(MigrateParams{}, get, get); fetched != 0 || dest != "" {
		t.Fatal("a plain migration fetched or rewrote the definitions")
	}
}

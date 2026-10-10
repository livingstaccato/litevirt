package libvirt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The locator the ceph driver records for a pool with a restricted client key
// becomes a network disk that authenticates as that client through a libvirt
// ceph secret, with the monitors as <host> elements — no keyring path, no conf,
// and never client.admin.
const labLocator = `rbd:lv/vm-root:id=litevirt:keyring=/etc/ceph/ceph.client.litevirt.keyring:conf=/etc/ceph/ceph.conf:lvpool=ceph:mon_host=10.78.0.22\:6789\;10.78.0.23\:6789`

func TestDiskBacking_RestrictedKeyBecomesAuthAndHosts(t *testing.T) {
	dt, src, drv, err := diskBacking(labLocator)
	if err != nil {
		t.Fatalf("diskBacking: %v", err)
	}
	if dt != "network" || drv != "raw" || src.Protocol != "rbd" || src.Name != "lv/vm-root" {
		t.Fatalf("type=%q driver=%q source=%+v", dt, drv, src)
	}
	if len(src.Hosts) != 2 || src.Hosts[0] != (diskSourceHost{Name: "10.78.0.22", Port: "6789"}) || src.Hosts[1].Name != "10.78.0.23" {
		t.Fatalf("hosts = %+v", src.Hosts)
	}
	want := CephSecretUUID("ceph", "litevirt")
	if src.Auth == nil || src.Auth.Username != "litevirt" || src.Auth.Secret.Type != "ceph" || src.Auth.Secret.UUID != want {
		t.Fatalf("auth = %+v, want username litevirt, ceph secret %s", src.Auth, want)
	}
}

// The generated domain carries the <auth> and the <host>s, so qemu opens the
// image as the restricted client.
func TestGenerateDomainXML_CephDiskAuthenticatesThroughTheSecret(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{
		Name: "vm", UUID: "11111111-2222-3333-4444-555555555555", CPU: 1, MemoryMiB: 256,
		Machine: "q35", Firmware: "bios",
		Disks: []DiskConfig{{Name: "root", Path: labLocator, Bus: "virtio"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := CephSecretUUID("ceph", "litevirt")
	for _, want := range []string{
		`<disk type="network" device="disk">`,
		`<source protocol="rbd" name="lv/vm-root">`,
		`<host name="10.78.0.22" port="6789"></host>`,
		`<auth username="litevirt">`,
		`<secret type="ceph" uuid="` + u + `"></secret>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("domain XML lacks %s:\n%s", want, x)
		}
	}
	for _, never := range []string{"keyring", "ceph.conf", "admin"} {
		if strings.Contains(x, never) {
			t.Errorf("domain XML names %q:\n%s", never, x)
		}
	}
}

// A disk hot-plugged into a running domain carries the same <auth>.
func TestMarshalNewDisk_CephCarriesAuth(t *testing.T) {
	frag, err := marshalNewDisk("    ", WantDisk{Path: labLocator, TargetDev: "vdb", Bus: "virtio"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, `<auth username="litevirt">`) || !strings.Contains(frag, `<secret type="ceph" uuid="`) {
		t.Fatalf("hot-plugged disk has no auth:\n%s", frag)
	}
}

// I2. The secret UUID is a function of the litevirt pool and the client
// only — never of where a host keeps its keyring — so every host with the pool
// names the same secret, whatever its filesystem layout. Different pools or
// clients differ.
func TestCephSecretUUID_IsPerPool(t *testing.T) {
	a, ok := CephSecretOfLocator("rbd:lv/x:id=litevirt:keyring=/etc/ceph/ceph.client.litevirt.keyring:lvpool=ceph")
	b, ok2 := CephSecretOfLocator("rbd:lv/x:id=litevirt:keyring=/srv/other/litevirt.keyring:lvpool=ceph")
	if !ok || !ok2 || a != b {
		t.Fatalf("one pool's disks name different secrets by keyring path: %q %q", a, b)
	}
	if a != CephSecretUUID("ceph", "litevirt") {
		t.Errorf("locator secret %q is not the pool's %q", a, CephSecretUUID("ceph", "litevirt"))
	}
	if a == CephSecretUUID("ceph2", "litevirt") || a == CephSecretUUID("ceph", "other") {
		t.Error("different pools or clients share a secret")
	}
	if _, ok := CephSecretOfLocator("rbd:lv/x"); ok {
		t.Error("a locator with no keyring names a secret")
	}
}

// A keyring with no litevirt pool to name its secret by cannot authenticate.
func TestDiskBacking_KeyringWithoutPoolIsRefused(t *testing.T) {
	if _, _, _, err := diskBacking("rbd:lv/x:id=litevirt:keyring=/k"); err == nil || !strings.Contains(err.Error(), "lvpool") {
		t.Fatalf("got %v, want a refusal naming lvpool", err)
	}
}

// I5. The monitors come from the conf when the domain is defined, not when
// the disk was made: a re-IP'd monitor set reaches the next start.
func TestDiskBacking_MonitorsFromTheConfAtDefineTime(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "cluster.conf")
	write := func(mon string) {
		if err := os.WriteFile(conf, []byte("[global]\nmon_host = [v2:"+mon+":3300/0,v1:"+mon+":6789/0]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loc := "rbd:lv/x:id=litevirt:keyring=/k:conf=" + conf + ":lvpool=ceph"
	write("10.0.0.1")
	_, src, _, err := diskBacking(loc)
	if err != nil || len(src.Hosts) != 1 || src.Hosts[0].Name != "10.0.0.1" {
		t.Fatalf("hosts %+v, %v", src.Hosts, err)
	}
	write("10.0.0.9")
	_, src, _, err = diskBacking(loc)
	if err != nil || len(src.Hosts) != 1 || src.Hosts[0].Name != "10.0.0.9" {
		t.Fatalf("after the conf changed: hosts %+v, %v; want the new monitor", src.Hosts, err)
	}
}

// I5. The pool's current monitors (its mon_host option, or its conf) win over
// a fallback fixed into the locator.
func TestDiskBacking_PoolMonitorsWinOverTheLocators(t *testing.T) {
	defer SetCephMonitorResolver(func(pool string) ([]string, bool) {
		if pool == "ceph" {
			return []string{"10.9.9.9:6789"}, true
		}
		return nil, false
	})()
	_, src, _, err := diskBacking(`rbd:lv/x:lvpool=ceph:mon_host=10.0.0.1\:6789`)
	if err != nil || len(src.Hosts) != 1 || src.Hosts[0].Name != "10.9.9.9" {
		t.Fatalf("hosts %+v, %v; want the pool's current monitor", src.Hosts, err)
	}
	// A pool this host does not have: the locator's fallback.
	_, src, _, err = diskBacking(`rbd:lv/x:lvpool=gone:mon_host=10.0.0.1\:6789`)
	if err != nil || len(src.Hosts) != 1 || src.Hosts[0].Name != "10.0.0.1" {
		t.Fatalf("hosts %+v, %v; want the locator's fallback", src.Hosts, err)
	}
}

// M3. The default conf however spelled is the default: accepted with no
// monitors, as at create.
func TestDiskBacking_DefaultConfSpelledDifferently(t *testing.T) {
	if _, _, _, err := diskBacking("rbd:lv/x:conf=/etc/ceph//ceph.conf"); err != nil {
		t.Fatalf("default conf with a doubled slash: %v", err)
	}
}

// The secret definition is ephemeral and private and never carries the value.
func TestCephSecretXML(t *testing.T) {
	x := cephSecretXML("6f1b3c0e-6a52-5d0c-9a49-1c2f3b6e8d10", "litevirt")
	for _, want := range []string{"ephemeral='yes'", "private='yes'", "<usage type='ceph'>", "<name>" + CephSecretUsagePrefix} {
		if !strings.Contains(x, want) {
			t.Errorf("secret XML lacks %s:\n%s", want, x)
		}
	}
}

package libvirt

import (
	"strings"
	"testing"
)

// The locator the ceph driver records for a pool with a restricted client key
// becomes a network disk that authenticates as that client through a libvirt
// ceph secret, with the monitors as <host> elements — no keyring path, no conf,
// and never client.admin.
const labLocator = `rbd:lv/vm-root:id=litevirt:keyring=/etc/ceph/ceph.client.litevirt.keyring:conf=/etc/ceph/ceph.conf:mon_host=10.78.0.22\:6789\;10.78.0.23\:6789`

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
	want := CephSecretUUID("litevirt", "/etc/ceph/ceph.client.litevirt.keyring")
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
	u := CephSecretUUID("litevirt", "/etc/ceph/ceph.client.litevirt.keyring")
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

// The secret UUID is a function of the client and keyring path only, so every
// host keeping the same keyring at the same path names the same secret — what
// a live migration's destination needs. Different clients or keyrings differ.
func TestCephSecretUUID_IsDerived(t *testing.T) {
	a := CephSecretUUID("litevirt", "/etc/ceph/ceph.client.litevirt.keyring")
	if a != CephSecretUUID("litevirt", "/etc/ceph//ceph.client.litevirt.keyring") {
		t.Error("the same keyring spelled differently names another secret")
	}
	if a == CephSecretUUID("other", "/etc/ceph/ceph.client.litevirt.keyring") ||
		a == CephSecretUUID("litevirt", "/srv/ceph/ceph.client.litevirt.keyring") {
		t.Error("different identities share a secret")
	}
	if u, ok := CephSecretOfLocator(labLocator); !ok || u != a {
		t.Errorf("CephSecretOfLocator = %q %v, want %q", u, ok, a)
	}
	if _, ok := CephSecretOfLocator("rbd:lv/x"); ok {
		t.Error("a locator with no keyring names a secret")
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

package storage

import "testing"

// Every driver's source, and the options that name objects, must be in their
// strict form: a value starting with "-" would reach mount, rbd, zfs, lvs or
// iscsiadm as an option.
func TestValidateSourceRefusesOptionLikeAndMalformedValues(t *testing.T) {
	bad := []Config{
		{Driver: "nfs", Source: "-oexec:/x"},
		{Driver: "nfs", Source: "nas:/x,suid"},
		{Driver: "nfs", Source: "nas"},
		{Driver: "nfs", Source: ".."},
		{Driver: "ceph", Source: "-c/tmp/evil.conf"},
		{Driver: "ceph", Source: "rbd", Options: map[string]string{"id": "--keyring=/x"}},
		{Driver: "zfs", Source: "-o"},
		{Driver: "zfs", Source: "tank//x"},
		{Driver: "lvm-thin", Source: "-v", Options: map[string]string{"thinpool": "tp"}},
		{Driver: "lvm-thin", Source: "vg0", Options: map[string]string{"thinpool": "--config=x"}},
		{Driver: "iscsi", Source: "-x"},
		{Driver: "iscsi", Source: "iqn.2024-01.com.example:s", Options: map[string]string{"portal": "-p"}},
		{Driver: "btrfs", Source: "-x"},
		{Driver: "local", Source: "-x"},
	}
	for _, c := range bad {
		if err := ValidateSource(c); err == nil {
			t.Errorf("%s source %q options %v: accepted", c.Driver, c.Source, c.Options)
		}
	}
	good := []Config{
		{Driver: "nfs", Source: "nas.internal:/srv/exports/litevirt"},
		{Driver: "nfs", Source: "10.0.10.1:/exports/vms"},
		{Driver: "nfs", Source: "[fd00::1]:/x"},
		{Driver: "ceph", Source: "rbd", Options: map[string]string{"id": "admin", "conf": "/etc/ceph/ceph.conf"}},
		{Driver: "zfs", Source: "tank/litevirt"},
		{Driver: "lvm-thin", Source: "vg0", Options: map[string]string{"thinpool": "pool0"}},
		{Driver: "iscsi", Source: "iqn.2024-01.com.example:storage", Options: map[string]string{"portal": "10.0.0.5:3260"}},
		{Driver: "btrfs", Source: "/mnt/btrfs/litevirt"},
		{Driver: "local"},
	}
	for _, c := range good {
		if err := ValidateSource(c); err != nil {
			t.Errorf("%s source %q: %v", c.Driver, c.Source, err)
		}
	}
}

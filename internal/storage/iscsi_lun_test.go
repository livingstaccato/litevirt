package storage

import (
	"context"
	"testing"
)

// An iscsi pool hands every disk the same device: the pool's LUN. The key a
// pool's disks are compared by is the LUN itself, so two spellings of one LUN
// must agree and two different LUNs must not.
func TestFixedDevice_ISCSIKeyIsTheLUN(t *testing.T) {
	cfg := func(target, portal, lun string) Config {
		o := map[string]string{}
		if portal != "" {
			o["portal"] = portal
		}
		if lun != "" {
			o["lun"] = lun
		}
		return Config{Driver: "iscsi", Source: target, Options: o}
	}
	key := func(c Config) string {
		t.Helper()
		k, _, ok := FixedDevice(c)
		if !ok {
			t.Fatalf("FixedDevice(%+v): not a fixed device", c)
		}
		return k
	}
	base := key(cfg("iqn.2020-01.com.example:store", "10.0.0.1", "3"))
	for _, same := range []Config{
		cfg("iqn.2020-01.com.example:store", "10.0.0.1:3260", "3"),
		cfg("IQN.2020-01.COM.EXAMPLE:STORE", "10.0.0.1", "3"),
		cfg("iqn.2020-01.com.example:store", "10.0.0.1", "03"),
	} {
		if k := key(same); k != base {
			t.Errorf("%+v keyed %q, want the same LUN as %q", same.Options, k, base)
		}
	}
	for _, other := range []Config{
		cfg("iqn.2020-01.com.example:store", "10.0.0.1", "4"),
		cfg("iqn.2020-01.com.example:other", "10.0.0.1", "3"),
		cfg("iqn.2020-01.com.example:store", "10.0.0.2", "3"),
		cfg("iqn.2020-01.com.example:store", "10.0.0.1:3261", "3"),
	} {
		if k := key(other); k == base {
			t.Errorf("%+v keyed %q: a different LUN read as the same one", other.Options, k)
		}
	}
	// No lun option is LUN 0, no portal the driver's 127.0.0.1 default.
	if a, b := key(cfg("iqn.x:y", "", "")), key(cfg("iqn.x:y", "127.0.0.1:3260", "0")); a != b {
		t.Errorf("defaults keyed %q, want %q", a, b)
	}
}

// The device FixedDevice names is the one CreateDisk hands out, and a recorded
// disk path keys back to the same LUN, so a disk row and a pool compare.
func TestFixedDevice_MatchesCreateDiskAndRecordedPath(t *testing.T) {
	for _, opts := range []map[string]string{
		{"portal": "10.0.0.1", "lun": "3"},
		{"portal": "san-iscsi-1.example:3260", "lun": "12"},
		{"portal": "[fd00::1]:3260"},
		{},
	} {
		c := Config{Driver: "iscsi", Source: "iqn.2020-01.com.example:store", Options: opts}
		key, dev, ok := FixedDevice(c)
		if !ok {
			t.Fatalf("FixedDevice(%v): not a fixed device", opts)
		}
		drv, err := New(t.TempDir(), c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := drv.CreateDisk(context.Background(), DiskOptions{VMName: "a", DiskName: "root"})
		if err != nil {
			t.Fatal(err)
		}
		if got != dev {
			t.Errorf("%v: CreateDisk handed out %q, FixedDevice names %q", opts, got, dev)
		}
		if k, ok := FixedDeviceKeyOfPath(got); !ok || k != key {
			t.Errorf("%v: recorded path %q keys to (%q, %v), want %q", opts, got, k, ok, key)
		}
	}
}

// Every other driver allocates a new object per disk, so none is a fixed
// device, and no path of theirs keys to a LUN.
func TestFixedDevice_OnlyISCSI(t *testing.T) {
	for _, d := range SupportedDrivers {
		if d == "iscsi" {
			continue
		}
		if _, _, ok := FixedDevice(Config{Driver: d, Source: "x", Target: "/t"}); ok {
			t.Errorf("driver %q reported as a fixed device", d)
		}
	}
	for _, p := range []string{
		"/var/lib/litevirt/disks/a-root.qcow2",
		"/dev/zvol/tank/a-root",
		"/dev/vg0/a-root",
		"rbd:pool/a-root",
		"/dev/disk/by-path/pci-0000:00:1f.2-ata-1",
		"",
	} {
		if k, ok := FixedDeviceKeyOfPath(p); ok {
			t.Errorf("path %q keyed to LUN %q", p, k)
		}
	}
}

package network

import "testing"

func privateDeviceFiles(t *testing.T) {
	t.Helper()
	pid, lease, records, sys, sysfs := dnsmasqPIDDir, dnsmasqLeaseDir, createdBridgeDir, sysClassNet, sysfsNet
	dnsmasqPIDDir, dnsmasqLeaseDir, createdBridgeDir, sysClassNet = t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	sysfsNet = sysClassNet
	t.Cleanup(func() {
		dnsmasqPIDDir, dnsmasqLeaseDir, createdBridgeDir, sysClassNet, sysfsNet = pid, lease, records, sys, sysfs
	})
}

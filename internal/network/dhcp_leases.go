package network

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// dnsmasqLeaseFile is the lease file the dnsmasq for bridge writes: the one
// name dnsmasqArgs launches with, stopDHCPAndForgetLeases removes, and
// lv.DiscoverIPForMACOnBridge reads.
func dnsmasqLeaseFile(bridge string) string {
	return lv.DHCPLeaseFile(dnsmasqLeaseDir, bridge)
}

// stopDHCPAndForgetLeases stops a network's dnsmasq for good and removes its
// lease file. It is for TEARDOWN only — a drift restart keeps the file, so
// guests keep their addresses across it.
//
// A file left behind outlives the network: discovery reads every lease file
// on the host, and a lease there for a MAC now served elsewhere would name an
// address the guest no longer has. The process is waited for before the file
// goes, so a dnsmasq writing its leases out on the way down cannot put it
// back.
func stopDHCPAndForgetLeases(pidFile, bridge string) {
	pid := readPidFile(pidFile)
	ours := pid > 0 && processRunning(pid) && procIsOurDnsmasq(pid, pidFile)
	StopDHCP(pidFile) //nolint:errcheck
	if ours {
		waitProcessExit(pid, 3*time.Second)
	}
	if err := os.Remove(dnsmasqLeaseFile(bridge)); err != nil && !os.IsNotExist(err) {
		slog.Warn("network: could not remove the lease file of a deprovisioned dnsmasq",
			"bridge", bridge, "file", dnsmasqLeaseFile(bridge), "error", err)
	}
}

// LeaseBridge names the bridge whose litevirt dnsmasq would lease a NIC on
// networkName its address — the device BridgeName gives the network — or ""
// when the network has no readable record here, in which case a lookup must
// not be restricted to any one bridge.
func LeaseBridge(ctx context.Context, db *corrosion.Client, networkName string) string {
	if db == nil || networkName == "" {
		return ""
	}
	rec, err := corrosion.GetNetwork(ctx, db, networkName)
	if err != nil || rec == nil {
		return ""
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(rec.Config), &def); err != nil {
		return ""
	}
	def.Type = rec.Type
	return BridgeName(networkName, def)
}

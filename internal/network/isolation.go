package network

import (
	"fmt"
)

// NAT, SNAT, and host-isolation nftables rules are not applied here. They are
// recorded as per-host intent (corrosion.host_fw_intent) by provisioning and
// the LB path, and rendered by the single canonical nftables reconciler
// (internal/firewall) into the atomic `inet litevirt-fw` table.

// EnableIPForwarding turns on IPv4 forwarding, needed for both masquerade and
// SNAT. Called explicitly where NAT/SNAT intent is recorded.
func EnableIPForwarding() error {
	if out, err := execCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip forwarding: %w: %s", err, out)
	}
	return nil
}

// Package nictap names the host tap device of a guest NIC.
//
// libvirt hands out vnetN to a NIC whose domain XML names no tap, a new one on
// every start and on every host, so its name is known only once the domain
// runs — and the per-NIC firewall, the NIC guard above all, could then only
// follow the guest's first frames. A NIC litevirt defines names its tap after
// its MAC instead (libvirt's <target dev>): known before the domain first
// starts, identical on a migration target, never reused by another NIC. The
// firewall renders a guarded NIC under this name whether or not it is running
// (docs/firewall.md, "When a guard takes effect").
package nictap

import (
	"net"
	"strings"
)

// Prefix begins every tap name Name returns. libvirt reserves vnet, vif and
// macvtap for names it generates; this is none of them.
const Prefix = "lvt"

// Name is the tap name of the NIC with this MAC: "lvt" and the MAC's twelve
// hex digits, fifteen characters — Linux's longest interface name. "" when mac
// is not an Ethernet address.
func Name(mac string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return Prefix + strings.ReplaceAll(hw.String(), ":", "")
}

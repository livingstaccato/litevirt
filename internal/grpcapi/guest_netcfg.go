package grpcapi

import (
	"fmt"
	"strings"
)

// guestNIC is one VM NIC as the network-config in its cloud-init seed sees it.
type guestNIC struct {
	Ordinal int
	MAC     string
	// Static is the NIC's static addressing, or nil when it has none.
	Static *isolatedIface
	// DHCP: the NIC has no static address and asks DHCP for one. A NIC that
	// is neither (a host-isolated network litevirt could give no address)
	// is left for the guest to leave unconfigured.
	DHCP bool
}

// guestNetworkConfig is the network-config litevirt writes into a VM's seed
// for its NICs, "" for none.
//
// Two shapes it has always produced are kept byte for byte, because guests
// boot correctly on them today:
//
//   - no NIC is static and the VM has at most one NIC: no network-config, so
//     cloud-init's own fallback brings up DHCP on that NIC;
//   - every configured NIC is static: the V1 document of
//     buildIsolatedNetworkConfig.
//
// Otherwise — a VM with a DHCP NIC and any other NIC — a cloud-init fallback
// configures one NIC only and leaves the rest DOWN, and a V1 document of the
// static NICs alone does the same to the DHCP ones. Such a VM gets a V2
// document naming every NIC by MAC (guestNetworkConfigV2).
func guestNetworkConfig(nics []guestNIC) string {
	var statics []isolatedIface
	dhcp := 0
	for _, n := range nics {
		switch {
		case n.Static != nil:
			statics = append(statics, *n.Static)
		case n.DHCP:
			dhcp++
		}
	}
	if dhcp == 0 {
		return buildIsolatedNetworkConfig(statics)
	}
	if len(statics) == 0 && len(nics) <= 1 {
		return ""
	}
	return guestNetworkConfigV2(nics)
}

// guestNetworkConfigV2 renders a cloud-init network-config version 2 document
// for nics, each matched by MAC. It is written for netplan, which cloud-init
// passes it to verbatim, and stays within what cloud-init's own V2 parser
// reads for the other renderers.
//
// The entry is keyed eth<ordinal> with no set-name: the guest keeps its own
// interface name where cloud-init can find the NIC by MAC.
//
// A DHCP NIC asks for IPv4 and IPv6 as cloud-init's fallback does. Every
// route a NIC brings — a DHCP lease's or a static gateway's — carries a metric
// of 100 plus the NIC's ordinal, so when more than one network offers a
// default route the guest prefers its first NIC's, as it did when only that
// NIC came up, rather than whichever lease came last or an isolated network's
// gateway. Every DHCP NIC but the first NIC written is optional: a network
// that answers no DHCP does not hold the guest's boot in
// systemd-networkd-wait-online, where before that NIC was simply left DOWN.
// The first NIC is the one the guest is waited for, as cloud-init's fallback
// NIC was.
func guestNetworkConfigV2(nics []guestNIC) string {
	var b strings.Builder
	b.WriteString("version: 2\nethernets:\n")
	first := true
	for _, n := range nics {
		if n.Static == nil && !n.DHCP {
			continue
		}
		optional := !first
		first = false
		fmt.Fprintf(&b, "  eth%d:\n    match:\n      macaddress: %q\n", n.Ordinal, n.MAC)
		if n.DHCP {
			fmt.Fprintf(&b, "    dhcp4: true\n    dhcp4-overrides:\n      route-metric: %d\n", 100+n.Ordinal)
			fmt.Fprintf(&b, "    dhcp6: true\n    dhcp6-overrides:\n      route-metric: %d\n", 100+n.Ordinal)
			if optional {
				b.WriteString("    optional: true\n")
			}
			continue
		}
		s := n.Static
		b.WriteString("    addresses:\n")
		if s.Address != "" {
			fmt.Fprintf(&b, "      - %s\n", s.Address)
		}
		if s.Address6 != "" {
			fmt.Fprintf(&b, "      - %s\n", s.Address6)
		}
		var routes []string
		if s.Address != "" && s.Gateway != "" {
			// Address is the NIC's `ip:`, which may itself be IPv6.
			to := "0.0.0.0/0"
			if strings.Contains(s.Address, ":") {
				to = "::/0"
			}
			routes = append(routes, fmt.Sprintf("      - to: %s\n        via: %s\n        metric: %d\n", to, s.Gateway, 100+n.Ordinal))
		}
		if s.Address6 != "" && s.Gateway6 != "" {
			routes = append(routes, fmt.Sprintf("      - to: ::/0\n        via: %s\n        metric: %d\n", s.Gateway6, 100+n.Ordinal))
		}
		if len(routes) > 0 {
			b.WriteString("    routes:\n")
			for _, r := range routes {
				b.WriteString(r)
			}
		}
		if s.Address != "" && len(s.DNS) > 0 {
			b.WriteString("    nameservers:\n      addresses:\n")
			for _, ns := range s.DNS {
				fmt.Fprintf(&b, "        - %s\n", ns)
			}
		}
	}
	return b.String()
}

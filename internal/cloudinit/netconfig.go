package cloudinit

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/network"
)

// NIC is one VM NIC as its seed's network-config is derived from it. Create,
// clone and every rebuild of the seed (failover, migration) fill it from the
// same facts — the spec's NIC entry, its NIC row, its network — so a rebuilt
// seed is the one the VM was created with.
type NIC struct {
	Ordinal int
	MAC     string
	// IP, Gateway, IPv6 and IPv6Gateway are the spec's `ip:`, `gateway:`,
	// `ipv6:` and `ipv6-gateway:`.
	IP, Gateway, IPv6, IPv6Gateway string
	// RecordedIP is the address the NIC's row records. It is static only
	// where litevirt itself gave it — a NetBox claim (Bound) or a
	// host-isolated network's pick; anywhere else it is a DHCP lease or
	// reservation, or what the IP scanner saw, and the NIC asks DHCP.
	RecordedIP string
	// Net is the NIC's network definition; nil for a network with no record.
	Net *compose.NetworkDef
	// Bound: the network is bound to a NetBox prefix, whose claim RecordedIP is.
	Bound bool
	// Name is the NIC's guest name, set-name in the document; "" names it by
	// its place among the document's NICs, as create does. Unnamed matches it
	// by MAC alone and renames nothing (see Prior).
	Name    string
	Unnamed bool
}

// NetworkConfig is the network-config litevirt writes into a VM's seed for
// nics, "" for none (see GuestNetworkConfig). A NIC whose MAC is not known
// cannot be matched in the guest, so a set with one gets none at all — the
// guest boots on cloud-init's fallback, as before litevirt derived a
// network-config for DHCP NICs.
func NetworkConfig(nics []NIC) string {
	for _, n := range nics {
		if strings.TrimSpace(n.MAC) == "" {
			return ""
		}
	}
	var guest []GuestNIC
	for _, n := range nics {
		ip := n.IP
		if ip == "" && n.RecordedIP != "" && (n.Bound || HostIsolatedAddressable(n.Net)) {
			ip = n.RecordedIP
		}
		if ip == "" {
			// No static address: the guest asks DHCP — except on a
			// host-isolated network, which serves none, so there is nothing
			// to configure.
			dhcp := n.Net == nil || !n.Net.HostIsolation
			guest = append(guest, GuestNIC{Ordinal: n.Ordinal, MAC: n.MAC, Name: n.Name, Unnamed: n.Unnamed, DHCP: dhcp,
				DHCP6:    dhcp && (n.Net == nil || n.Net.Subnet == "" || subnetIsIPv6(n.Net.Subnet)),
				NoRoutes: noRouter(n.Net)})
			continue
		}
		address, gateway := StaticAddress(ip, n.Gateway, n.Net)
		var dns []string
		if n.Net != nil {
			dns = n.Net.DNS
		}
		if len(dns) == 0 {
			dns = []string{"1.1.1.1", "8.8.8.8"}
		}
		// IPv6: a NIC can carry an explicit `ipv6:` (with optional
		// `ipv6-gateway:`); when omitted the guest falls through to SLAAC /
		// RA, which dnsmasq emits when the network's subnet is IPv6.
		address6 := n.IPv6
		if address6 != "" && !strings.Contains(address6, "/") {
			address6 += "/64"
		}
		guest = append(guest, GuestNIC{Ordinal: n.Ordinal, MAC: n.MAC, Name: n.Name, Unnamed: n.Unnamed, Static: &StaticIface{
			MAC: n.MAC, Name: n.Name, Address: address, Gateway: gateway, DNS: dns,
			Address6: address6, Gateway6: n.IPv6Gateway,
		}, NoRoutes: n.Gateway == "" && noRouter(n.Net)})
	}
	return GuestNetworkConfig(guest)
}

// noRouter reports whether def is a network with no router: an isolated
// network, a host-local bridge with no uplink. Its dnsmasq still hands out
// the bridge's address as a router, which a guest must not take as a default
// route beside its other NICs.
func noRouter(def *compose.NetworkDef) bool {
	return def != nil && def.Type == "isolated"
}

func subnetIsIPv6(subnet string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	return err == nil && p.Addr().Is6() && !p.Addr().Is4In6()
}

// HostIsolatedAddressable reports whether a NIC that names no address on
// network def is given one by litevirt (compose.NetworkDef.HostIsolatedAddressable).
func HostIsolatedAddressable(def *compose.NetworkDef) bool {
	return def != nil && def.HostIsolatedAddressable()
}

// StaticIface is one NIC's static addressing in a network-config.
type StaticIface struct {
	MAC string
	// Name is the guest name the V1 document gives it; "" is eth<its place
	// among the static NICs>.
	Name     string
	Address  string // CIDR, e.g. "10.100.0.10/24"
	Gateway  string
	DNS      []string
	Address6 string // IPv6 CIDR, e.g. "2001:db8::10/64"; empty = no static v6 (SLAAC/RA)
	Gateway6 string
}

// GuestNIC is one VM NIC as the network-config document sees it.
type GuestNIC struct {
	Ordinal int
	MAC     string
	// Name and Unnamed are NIC's (see there).
	Name    string
	Unnamed bool
	// Static is the NIC's static addressing, or nil when it has none.
	Static *StaticIface
	// DHCP: the NIC has no static address and asks DHCP for one. A NIC that
	// is neither (a host-isolated network litevirt could give no address)
	// is left for the guest to leave unconfigured.
	DHCP bool
	// DHCP6: the NIC also asks DHCPv6 — its network has an IPv6 subnet, or
	// litevirt has no record of the network.
	DHCP6 bool
	// NoRoutes: the NIC's network has no router (an isolated network). In a
	// V2 document a DHCP NIC takes no route from its lease (use-routes:
	// false), and a static one whose spec names no `gateway:` gets no default
	// route (the subnet's first host is the host's bridge, not a router). The
	// V1 document, written for a VM whose NICs are all static, is as it was.
	NoRoutes bool
}

// GuestNetworkConfig is the network-config for nics, "" for none.
//
// Two shapes are kept byte for byte as they have always been written:
//
//   - no NIC is static and the VM has at most one NIC: no network-config, so
//     cloud-init's own fallback brings up DHCP on that NIC — unless a rebuild
//     names it (the one NIC a detach left of several keeps its name);
//   - every configured NIC is static: the V1 document of BuildV1.
//
// Any other VM — a DHCP NIC and any other NIC — gets a V2 document naming
// every NIC by MAC (guestNetworkConfigV2). Only a NIC the document configures
// counts: one with nothing to configure is not written.
func GuestNetworkConfig(nics []GuestNIC) string {
	var statics []StaticIface
	dhcp, unnamed, named := 0, false, false
	for _, n := range nics {
		if n.Static == nil && !n.DHCP {
			continue
		}
		unnamed = unnamed || n.Unnamed
		named = named || n.Name != ""
		switch {
		case n.Static != nil:
			statics = append(statics, *n.Static)
		case n.DHCP:
			dhcp++
		}
	}
	// A V1 entry always names its device; a NIC matched by MAC alone needs V2.
	if dhcp == 0 && !unnamed {
		return BuildV1(statics)
	}
	if len(statics) == 0 && len(nics) <= 1 && !named {
		return ""
	}
	return guestNetworkConfigV2(nics)
}

// guestNetworkConfigV2 renders a cloud-init network-config version 2 document
// for nics, each matched by MAC and named eth<ordinal> by set-name, as the V1
// document names its NICs: every cloud-init renderer (netplan, networkd,
// sysconfig, ENI) renames the NIC so its configuration applies.
//
// A DHCP NIC asks IPv4, and IPv6 where its network has an IPv6 subnet. Every
// route a NIC brings — a DHCP lease's or a static gateway's — has metric 100
// plus the NIC's ordinal; a DHCP NIC on a network with no router takes none
// from its lease (use-routes: false). Every DHCP NIC but the first NIC written
// is optional.
func guestNetworkConfigV2(nics []GuestNIC) string {
	var b strings.Builder
	b.WriteString("version: 2\nethernets:\n")
	first := true
	for _, n := range nics {
		if n.Static == nil && !n.DHCP {
			continue
		}
		optional := !first
		first = false
		switch {
		case n.Unnamed:
			// Matched by MAC alone: cloud-init configures the device it finds
			// with that MAC under the name it has (network_state, LP #1855945).
			fmt.Fprintf(&b, "  nic%s:\n    match:\n      macaddress: %q\n", strings.ReplaceAll(strings.ToLower(n.MAC), ":", ""), n.MAC)
		default:
			name := n.Name
			if name == "" {
				name = fmt.Sprintf("eth%d", n.Ordinal)
			}
			fmt.Fprintf(&b, "  %s:\n    match:\n      macaddress: %q\n    set-name: %s\n", name, n.MAC, name)
		}
		if n.DHCP {
			noRoutes := ""
			if n.NoRoutes {
				noRoutes = "      use-routes: false\n"
			}
			fmt.Fprintf(&b, "    dhcp4: true\n    dhcp4-overrides:\n      route-metric: %d\n%s", 100+n.Ordinal, noRoutes)
			if n.DHCP6 {
				fmt.Fprintf(&b, "    dhcp6: true\n    dhcp6-overrides:\n      route-metric: %d\n%s", 100+n.Ordinal, noRoutes)
			}
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
		if s.Address != "" && s.Gateway != "" && !n.NoRoutes {
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

// BuildV1 generates a cloud-init V1 network-config for static NICs. Uses MAC
// matching for distro-agnostic interface binding (works on Ubuntu, CentOS,
// Arch, Debian, Alpine, etc.).
//
// IPv6: when iface.Address6 is set we emit a second `static6` subnet on
// the same interface (cloud-init's V1 schema accepts dual-stack via
// repeated `subnets:` entries with type `static` for v4 and `static6`
// for v6).
func BuildV1(ifaces []StaticIface) string {
	if len(ifaces) == 0 {
		return ""
	}
	cfg := "version: 1\nconfig:\n"
	for i, iface := range ifaces {
		name := iface.Name
		if name == "" {
			name = fmt.Sprintf("eth%d", i)
		}
		cfg += fmt.Sprintf("  - type: physical\n    name: %s\n    mac_address: %q\n    subnets:\n", name, iface.MAC)
		if iface.Address != "" {
			cfg += fmt.Sprintf("      - type: static\n        address: %s\n", iface.Address)
			if iface.Gateway != "" {
				cfg += fmt.Sprintf("        gateway: %s\n", iface.Gateway)
			}
			if len(iface.DNS) > 0 {
				cfg += "        dns_nameservers:\n"
				for _, ns := range iface.DNS {
					cfg += fmt.Sprintf("          - %s\n", ns)
				}
			}
		}
		if iface.Address6 != "" {
			cfg += fmt.Sprintf("      - type: static6\n        address: %s\n", iface.Address6)
			if iface.Gateway6 != "" {
				cfg += fmt.Sprintf("        gateway: %s\n", iface.Gateway6)
			}
		}
	}
	return cfg
}

// StaticAddress derives the network-config address (with CIDR prefix) and the
// gateway for a NIC's static IP. The NIC's own gateway wins, then the
// network's `gateway:` (its router when the subnet's first host is not), then
// the subnet's first host. All are written as BARE addresses — SubnetRange
// returns the first host with a prefix, which netplan/ENI reject. The address
// takes the subnet's prefix, but only when the caller did NOT already supply
// one, so a submitted "10.0.1.50/24" is preserved rather than doubled to
// "10.0.1.50/24/24". With no subnet def, a bare address gets a family default
// (/64 for IPv6, /24 for IPv4).
func StaticAddress(ip, gateway string, netDef *compose.NetworkDef) (string, string) {
	address := ip
	if gateway == "" && netDef != nil && netDef.Gateway != "" {
		gateway = splitCIDR(strings.TrimSpace(netDef.Gateway))[0]
	}
	if netDef != nil && netDef.Subnet != "" {
		gw, _, _, _, err := network.SubnetRange(netDef.Subnet)
		if err == nil {
			if gateway == "" {
				gateway = splitCIDR(gw)[0]
			}
			parts := splitCIDR(netDef.Subnet)
			if parts[1] != "" && !strings.Contains(ip, "/") {
				address = ip + "/" + parts[1]
			}
		}
	} else if !strings.Contains(address, "/") {
		// No subnet in network def — pick a sensible default based on address
		// family. /24 for v4, /64 for v6 (the standard host prefix for end-user
		// assignments).
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
			address = ip + "/64"
		} else {
			address = ip + "/24"
		}
	}
	return address, gateway
}

// splitCIDR splits "10.0.0.0/24" into ["10.0.0.0", "24"].
func splitCIDR(cidr string) [2]string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return [2]string{cidr[:i], cidr[i+1:]}
	}
	return [2]string{cidr, ""}
}

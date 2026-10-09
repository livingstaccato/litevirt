package network

import (
	"net"
	"strconv"
	"strings"
)

// ContainerAddress is the address and default gateway a container NIC on a
// managed network with subnet gets: ip with the subnet's prefix (unless ip
// already carries one) and the subnet's first host as a bare gateway — the
// gateway litevirt gives the network's bridge and its dnsmasq. LXC reads a
// bare lxc.net.N.ipv4.address classfully (172.16.77.2 became a /8 with no
// default route), so the prefix is not optional. A subnet that does not parse,
// or an IPv6 one, returns ip unchanged and no gateway.
func ContainerAddress(ip, subnet string) (addr, gateway string) {
	if ip == "" || subnet == "" {
		return ip, ""
	}
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil || ipNet.IP.To4() == nil {
		return ip, ""
	}
	gw, _, _, _, err := SubnetRange(subnet)
	if err != nil {
		return ip, ""
	}
	gateway, _, _ = strings.Cut(gw, "/")
	if strings.Contains(ip, "/") {
		return ip, gateway
	}
	ones, _ := ipNet.Mask.Size()
	return ip + "/" + strconv.Itoa(ones), gateway
}

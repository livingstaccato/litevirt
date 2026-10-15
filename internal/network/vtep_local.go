package network

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/netutil"
)

// localAddrs is this host's addresses, each mapped to the interface holding
// it, read once (hostAddrs) and passed to every check of a pass, not re-read
// per entry.
type localAddrs map[string]string

// has reports whether ip is an address of this host. A VXLAN forwarding entry
// whose destination is one of them sends the frame back into the same vxlan
// device without encapsulating it: a flood entry like that loops every
// broadcast back onto the bridge, and nothing reaches a peer.
func (l localAddrs) has(ip string) bool {
	if p := net.ParseIP(ip); p != nil && (p.IsLoopback() || p.IsUnspecified()) {
		return true
	}
	_, ok := l[ip]
	return ok
}

// loadLocalAddrs reads this host's addresses. An unreadable list is empty:
// nothing is then taken to be local.
func loadLocalAddrs() localAddrs {
	m, err := hostAddrs()
	if err != nil {
		return localAddrs{}
	}
	return m
}

// isLocalAddress is localAddrs.has on a fresh read, for a single check.
func isLocalAddress(ip string) bool { return loadLocalAddrs().has(ip) }

// hostAddrs lists this host's interface addresses. A var so a test can model a
// multi-homed host.
var hostAddrs = hostInterfaceAddrs

func hostInterfaceAddrs() (localAddrs, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := localAddrs{}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				out[ip.String()] = ifc.Name
			}
		}
	}
	return out, nil
}

// deviceCarries reports whether dev can carry a VXLAN tunnel. A loopback or
// dummy interface (the /32 of a routed-to-the-host fabric) or a vxlan device
// cannot: frames sent "out" of it go nowhere. A var so a test can model them;
// asked only of the one interface holding the host address (ResolveVTEP).
var deviceCarries = hostDeviceCarries

func hostDeviceCarries(dev string) bool {
	if ifc, err := net.InterfaceByName(dev); err == nil && ifc.Flags&net.FlagLoopback != 0 {
		return false
	}
	return !nonCarrierKind(dev)
}

// nonCarrierKind reports whether dev is a dummy or vxlan device, from the
// link kind `ip -d -o link show` prints as the start of a detail segment.
func nonCarrierKind(dev string) bool {
	out, err := execCommand("ip", "-d", "-o", "link", "show", "dev", dev)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(string(out), "\\") {
		f := strings.Fields(seg)
		if len(f) > 0 && (f[0] == "dummy" || f[0] == "vxlan") {
			return true
		}
	}
	return false
}

// VTEPRefusal is a vxlan network this host will not set up a tunnel for,
// because no address it could use as the tunnel's local address is held where
// the tunnel would run. Nothing on the host is changed.
type VTEPRefusal struct {
	Network string
	Device  string // the underlay, when one is named or found
	Reason  string
}

func (e *VTEPRefusal) Error() string {
	if e.Device != "" {
		return fmt.Sprintf("vxlan network %q on underlay %s: %s", e.Network, e.Device, e.Reason)
	}
	return fmt.Sprintf("vxlan network %q: %s", e.Network, e.Reason)
}

// ResolveVTEP decides a vxlan network's tunnel endpoint on this host: the
// local address and the underlay device.
//
// Before switched (the release token's latch) it is what every earlier build
// used — the default-route source address, over the network's underlay or the
// default-route interface — so a host on this build keeps the same tunnel as
// its peers on the previous one.
//
// After it, the local address is hostAddress, the host's cluster address. The
// one exception is a network that names its underlay: the local address is
// then one that device holds (hostAddress if it is one of them), and a device
// with no IPv4 address is refused. Without a named underlay, the device is the
// interface holding hostAddress, or the default-route interface when that is
// a loopback or dummy device. An address no interface holds is refused.
func ResolveVTEP(networkName string, def compose.NetworkDef, hostAddress string, switched bool) (local, dev string, err error) {
	if !switched {
		dev = def.Underlay
		if dev == "" {
			dev = defaultRouteInterface()
		}
		return netutil.HostAddress(""), dev, nil
	}
	addrs := loadLocalAddrs()
	if def.Underlay != "" {
		var held []string
		for ip, a := range addrs {
			if a == def.Underlay && net.ParseIP(ip).To4() != nil {
				held = append(held, ip)
			}
		}
		if len(held) == 0 {
			return "", "", &VTEPRefusal{Network: networkName, Device: def.Underlay,
				Reason: "the named underlay holds no IPv4 address, so the tunnel has no local address on it; " +
					"give the device an address or name another underlay"}
		}
		sort.Strings(held)
		local = held[0]
		for _, ip := range held {
			if ip == hostAddress {
				local = ip
			}
		}
		return local, def.Underlay, nil
	}
	if hostAddress == "" {
		return "", "", &VTEPRefusal{Network: networkName, Reason: "this host's address is not known yet"}
	}
	holder, ok := addrs[hostAddress]
	if !ok {
		return "", "", &VTEPRefusal{Network: networkName,
			Reason: fmt.Sprintf("no interface holds this host's address %s (advertise_address), so it cannot be the tunnel's local address; "+
				"name an underlay for the network", hostAddress)}
	}
	if deviceCarries(holder) {
		return hostAddress, holder, nil
	}
	dev = defaultRouteInterface()
	if dev == "" {
		return "", "", &VTEPRefusal{Network: networkName, Device: holder,
			Reason: "this host's address is on a loopback or dummy device and there is no default route to carry the tunnel; name an underlay"}
	}
	return hostAddress, dev, nil
}

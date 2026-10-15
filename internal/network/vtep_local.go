package network

import (
	"log/slog"
	"net"
)

// hostAddrs lists this host's interface addresses, each mapped to the
// interface that holds it. A var so a test can model a multi-homed host.
var hostAddrs = hostInterfaceAddrs

func hostInterfaceAddrs() (map[string]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
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

// isLocalAddress reports whether ip is an address of this host. A VXLAN
// forwarding entry whose destination is one of them sends the frame back into
// the same vxlan device without encapsulating it: a flood entry like that
// loops every broadcast back onto the bridge, and nothing reaches a peer.
func isLocalAddress(ip string) bool {
	if p := net.ParseIP(ip); p != nil && (p.IsLoopback() || p.IsUnspecified()) {
		return true
	}
	addrs, err := hostAddrs()
	if err != nil {
		return false
	}
	_, ok := addrs[ip]
	return ok
}

// underlayFor is the interface a VXLAN tunnel whose local address is localIP
// runs over: the interface holding that address. The default-route interface
// is only the fallback, for an address no interface holds (or a loopback
// one): on a multi-homed host it is not the cluster network.
func underlayFor(localIP string) string {
	if p := net.ParseIP(localIP); p != nil && !p.IsLoopback() {
		if addrs, err := hostAddrs(); err == nil {
			if dev := addrs[localIP]; dev != "" {
				return dev
			}
		}
		slog.Warn("vxlan: no interface holds this host's address; using the default-route interface as the underlay",
			"address", localIP)
	}
	return defaultRouteInterface()
}

package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses the `trusted_proxies` CIDR list (bare addresses
// are taken as a single-address prefix).
func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(c)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q is not an address or CIDR", c)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// PeerTrusted reports whether r's TCP peer is a listed trusted proxy.
func PeerTrusted(r *http.Request, trusted []netip.Prefix) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	return isTrusted(peer, trusted)
}

// hopAddr is an X-Forwarded-For hop's address: a bare address, or one with a
// port ("1.2.3.4:5678", "[2001:db8::1]:443", which some load balancers emit),
// the port dropped. Anything else ("unknown", an obfuscated name) is not an
// address.
func hopAddr(hop string) (netip.Addr, bool) {
	hop = strings.TrimSpace(hop)
	if a, err := netip.ParseAddr(hop); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(hop); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func isTrusted(addr string, trusted []netip.Prefix) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientAddress is the address of the client a web request came from, for the
// per-address bound on in-progress OIDC sign-ins. It is the TCP peer, unless
// the peer is one of the configured trusted proxies: then it is the
// right-most X-Forwarded-For hop that is not itself a trusted proxy (the first
// address no trusted proxy vouches for; everything left of it is what the
// client claims). With no trusted proxies — the default — no forwarding
// header is ever believed.
func ClientAddress(r *http.Request, trusted []netip.Prefix) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if len(trusted) == 0 || !isTrusted(peer, trusted) {
		return peer
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := hopAddr(hops[i])
		if !ok || !isTrusted(a.String(), trusted) {
			if ok {
				return a.String()
			}
			// A hop that is not an address is the client's own claim: fall
			// back to the trusted proxy that recorded it.
			if i+1 < len(hops) {
				if a, ok := hopAddr(hops[i+1]); ok {
					return a.String()
				}
			}
			return peer
		}
	}
	// Every hop is a trusted proxy (or there is no header): the left-most
	// trusted hop, else the peer.
	if len(hops) > 0 {
		if a, ok := hopAddr(hops[0]); ok {
			return a.String()
		}
	}
	return peer
}

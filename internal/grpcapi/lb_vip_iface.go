package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/network"
)

// lbPlacement is where this host puts a load balancer's VIP: the device,
// and the network that device is this host's bridge of ("" when no network's
// subnet holds the VIP). The LB's isolation intent is recorded for exactly
// that network (updateIsolationForLB), never looked up again by device name.
type lbPlacement struct {
	iface   string
	network string
}

// lbVIPInterface decides where this host puts a load balancer's VIP.
//
// A VIP inside a live network's subnet goes on that network's bridge — the
// segment its backends are on — whether or not the bridge carries an address
// in the subnet: a host-isolated network's bridge carries none on a bridge
// litevirt did not make, and the address lookup below then answered the
// default-route device, where the VIP's prefix took the backends' route off
// the bridge. A stack LB considers only its own stack's networks and networks
// of no stack; when several subnets hold the VIP, its own stack's network
// wins, then the most specific subnet, then the name. If that network's
// bridge cannot be found on this host the VIP is refused, never put on
// another device (lbNetworkDevice).
//
// A VIP in no network's subnet (an address on the host's own LAN) goes where
// it always did: on the device whose subnet holds it, else the default-route
// device (lb.DetectInterfaceForIP), with no network.
//
// stack names the LB's stack when the caller knows it (a peer apply carries
// it, since the LB's row may not have replicated here yet); "" reads it from
// the LB's row.
func (s *Server) lbVIPInterface(ctx context.Context, lbName, stack, vip string) (lbPlacement, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(vip))
	if err != nil {
		return lbPlacement{}, fmt.Errorf("VIP %q is not an address: %w", vip, err)
	}
	if stack == "" && lbName != "" {
		lrows, err := s.db.Query(ctx, `SELECT COALESCE(stack_name, '') AS stack_name FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, lbName)
		if err != nil {
			return lbPlacement{}, fmt.Errorf("read load balancer %q to place VIP %s: %w", lbName, vip, err)
		}
		if len(lrows) > 0 {
			stack = lrows[0].String("stack_name")
		}
	}
	nets, err := s.lbNetworks(ctx)
	if err != nil {
		return lbPlacement{}, fmt.Errorf("read networks to place VIP %s: %w", vip, err)
	}
	type match struct {
		n        lbNetwork
		bits     int
		ownStack bool
	}
	var matches []match
	for _, n := range nets {
		if stack != "" && n.stack != "" && n.stack != stack {
			continue // another stack's network is never this LB's segment
		}
		if !n.prefix.IsValid() || !n.prefix.Contains(addr) {
			continue
		}
		matches = append(matches, match{n: n, bits: n.prefix.Bits(), ownStack: stack != "" && n.stack == stack})
	}
	if len(matches) == 0 {
		return lbPlacement{iface: lb.DetectInterfaceForIP(vip)}, nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].ownStack != matches[j].ownStack {
			return matches[i].ownStack
		}
		if matches[i].bits != matches[j].bits {
			return matches[i].bits > matches[j].bits
		}
		return matches[i].n.name < matches[j].n.name
	})
	m := matches[0].n
	dev, why := s.lbNetworkDevice(m, nets)
	if dev == "" {
		return lbPlacement{}, fmt.Errorf("VIP %s is in network %q, %s on %s: the VIP goes on its network's bridge and nowhere else",
			vip, m.name, why, s.hostName)
	}
	return lbPlacement{iface: dev, network: m.name}, nil
}

// lbNetwork is one live network row as the VIP placement reads it.
type lbNetwork struct {
	name, stack string
	def         compose.NetworkDef
	prefix      netip.Prefix
}

// lbNetworks reads every live bridge-family network, in name order.
func (s *Server) lbNetworks(ctx context.Context) ([]lbNetwork, error) {
	rows, err := s.db.Query(ctx, `SELECT name, type, config, COALESCE(stack_name, '') AS stack_name
		FROM networks WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []lbNetwork
	for _, r := range rows {
		var def compose.NetworkDef
		if json.Unmarshal([]byte(r.String("config")), &def) != nil {
			continue
		}
		def.Type = r.String("type")
		switch def.Type {
		case "", "bridge", "vxlan", "isolated":
		default:
			continue // no bridge of litevirt's to put a VIP on
		}
		n := lbNetwork{name: r.String("name"), stack: r.String("stack_name"), def: def}
		if p, err := netip.ParsePrefix(strings.TrimSpace(def.Subnet)); err == nil {
			n.prefix = p.Masked()
		}
		out = append(out, n)
	}
	return out, nil
}

// splitNamed reports whether n is a stack's `bridge` network that hosts may
// have provisioned under either of two names: an older build's deploy put it
// on its short name on the deploy's target host and on the scoped name on a
// peer target, and the row holds whichever write replicated last (a deploy
// now names the scoped device everywhere, defaultStackNetworkDevices). It
// returns the scoped and the short name.
func splitNamed(n lbNetwork) (scoped, short string, ok bool) {
	if n.def.Type != "" && n.def.Type != "bridge" || n.stack == "" {
		return "", "", false
	}
	short = strings.TrimPrefix(n.name, n.stack+"_")
	if short == n.name || (n.def.Interface != "" && n.def.Interface != short) {
		return "", "", false // an interface the file named is the same on every host
	}
	return network.FlatBridgeName(n.name), short, true
}

// lbNetworkDevice finds network m's bridge on this host, or "" and why not.
//
// A network that is on one name everywhere (network.BridgeName) is on that
// device or nowhere. A split-named stack network (splitNamed) is on its
// scoped name when that exists — unique to the network — else on its short
// name, but a short name is not unique across stacks (two stacks may each
// have a `backend`): when another live network may be on it too, the device
// is taken only if it carries an address in m's subnet (the gateway litevirt
// gives a host-isolated bridge it made, the dnsmasq gateway, or the VIP from
// an earlier apply), and is refused otherwise.
func (s *Server) lbNetworkDevice(m lbNetwork, nets []lbNetwork) (string, string) {
	scoped, short, split := splitNamed(m)
	if !split {
		dev := network.BridgeName(m.name, m.def)
		if s.bridgeExistsHere(dev) {
			return dev, ""
		}
		return "", "whose bridge " + dev + " is not"
	}
	if s.bridgeExistsHere(scoped) {
		return scoped, ""
	}
	if !s.bridgeExistsHere(short) {
		return "", "whose bridge " + scoped + " or " + short + " is not"
	}
	claimed := false
	for _, o := range nets {
		if o.name == m.name {
			continue
		}
		if network.BridgeName(o.name, o.def) == short {
			claimed = true
		}
		if _, osh, ok := splitNamed(o); ok && osh == short {
			claimed = true
		}
	}
	if !claimed {
		return short, ""
	}
	if m.prefix.IsValid() {
		for _, a := range s.linkAddrsHere(short) {
			if m.prefix.Contains(a.Addr()) {
				return short, ""
			}
		}
	}
	return "", "whose bridge here may be " + short + ", which another network may be on too and which carries no address in " + m.def.Subnet + " to tell; it is not placed"
}

// linkAddrsHere is a device's IP addresses on this host.
func (s *Server) linkAddrsHere(dev string) []netip.Prefix {
	if s.linkAddrs != nil {
		return s.linkAddrs(dev)
	}
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(ipn.String()); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

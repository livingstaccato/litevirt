package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
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
	dev, why := s.lbNetworkDevice(m)
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

// lbNetworkDevice finds network m's bridge on this host, or "" and why not.
// A network is on one name on every host (network.BridgeName): that device
// or nowhere.
func (s *Server) lbNetworkDevice(m lbNetwork) (string, string) {
	dev := network.BridgeName(m.name, m.def)
	if s.bridgeExistsHere(dev) {
		return dev, ""
	}
	return "", "whose bridge " + dev + " is not"
}

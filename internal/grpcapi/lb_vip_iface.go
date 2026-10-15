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

// lbVIPInterface names the device this host puts a load balancer's VIP on.
//
// A VIP inside a live network's subnet goes on that network's bridge — the
// segment its backends are on — whether or not the bridge carries an address
// in the subnet: a host-isolated network's bridge carries none, and the
// address lookup below then answered the default-route device, where the
// VIP's prefix took the backends' route off the bridge. When several
// networks' subnets hold it, the most specific one wins. If that bridge is
// not on this host the VIP is refused, never put on another device.
//
// A VIP in no network's subnet (an address on the host's own LAN) goes where
// it always did: on the device whose subnet holds it, else the default-route
// device (lb.DetectInterfaceForIP).
func (s *Server) lbVIPInterface(ctx context.Context, vip string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(vip))
	if err != nil {
		return "", fmt.Errorf("VIP %q is not an address: %w", vip, err)
	}
	rows, err := s.db.Query(ctx, `SELECT name, type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return "", fmt.Errorf("read networks to place VIP %s: %w", vip, err)
	}
	type match struct {
		name, bridge string
		bits         int
	}
	var matches []match
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
		p, err := netip.ParsePrefix(strings.TrimSpace(def.Subnet))
		if err != nil || !p.Masked().Contains(addr) {
			continue
		}
		matches = append(matches, match{name: r.String("name"), bridge: network.BridgeName(r.String("name"), def), bits: p.Bits()})
	}
	if len(matches) == 0 {
		return lb.DetectInterfaceForIP(vip), nil
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].bits != matches[j].bits {
			return matches[i].bits > matches[j].bits
		}
		return matches[i].name < matches[j].name
	})
	m := matches[0]
	if !s.bridgeExistsHere(m.bridge) {
		return "", fmt.Errorf("VIP %s is in network %q, whose bridge %s is not on %s: the VIP goes on its network's bridge and nowhere else",
			vip, m.name, m.bridge, s.hostName)
	}
	return m.bridge, nil
}

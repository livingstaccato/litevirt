package corrosion

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/litevirt/litevirt/internal/compose"
)

// NICOwner is the workload a NIC row belongs to.
type NICOwner struct {
	Kind string // "vm" | "ct"
	Name string
	Host string // the VM's or container's host
}

// DuplicateAddress is one address on a host-isolated network that live NIC
// rows of more than one workload record.
type DuplicateAddress struct {
	Network string
	IP      string
	Owners  []NICOwner // sorted by kind, host, name
}

// HostIsolatedDuplicateAddrs lists the addresses on host-isolated networks
// that more than one workload's live NIC rows hold: VM NICs (vm_nics and
// vm_interfaces; a NIC both hold is one owner) and container NICs.
// On such a network every address is litevirt's to give (or the operator's
// explicit one) and nothing re-reads it from a lease, so two holders are two
// guests configured with one address — two creates on two hosts that picked
// at once, or an operator's `ip:` that repeats another. Read only; a
// diagnostic for the firewall reconciler's pass.
func HostIsolatedDuplicateAddrs(ctx context.Context, c *Client) ([]DuplicateAddress, error) {
	nets, err := c.Query(ctx, `SELECT name, type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	isolated := map[string]bool{}
	for _, r := range nets {
		var def compose.NetworkDef
		if json.Unmarshal([]byte(r.String("config")), &def) == nil && def.HostIsolation {
			isolated[r.String("name")] = true
		}
	}
	if len(isolated) == 0 {
		return nil, nil
	}

	type key struct{ network, ip string }
	holders := map[key]map[NICOwner]bool{}
	add := func(network, ip string, o NICOwner) {
		if !isolated[network] || ip == "" {
			return
		}
		if p, err := netip.ParsePrefix(ip); err == nil {
			ip = p.Addr().String()
		} else if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.String()
		} else {
			return
		}
		k := key{network, ip}
		if holders[k] == nil {
			holders[k] = map[NICOwner]bool{}
		}
		holders[k][o] = true
	}
	for _, q := range []string{
		`SELECT n.vm_name AS vm, n.network_name AS net, COALESCE(n.ip,'') AS ip, COALESCE(v.host_name,'') AS host
		 FROM vm_nics n LEFT JOIN vms v ON v.name = n.vm_name AND v.deleted_at IS NULL WHERE n.deleted_at IS NULL`,
		`SELECT i.vm_name AS vm, i.network_name AS net, COALESCE(i.ip,'') AS ip, COALESCE(v.host_name,'') AS host
		 FROM vm_interfaces i LEFT JOIN vms v ON v.name = i.vm_name AND v.deleted_at IS NULL WHERE i.deleted_at IS NULL`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			add(r.String("net"), r.String("ip"), NICOwner{Kind: "vm", Name: r.String("vm"), Host: r.String("host")})
		}
	}
	rows, err := c.Query(ctx, `SELECT host_name, ct_name, network_name, COALESCE(ip,'') AS ip
		FROM container_interfaces WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		add(r.String("network_name"), r.String("ip"), NICOwner{Kind: "ct", Name: r.String("ct_name"), Host: r.String("host_name")})
	}

	var out []DuplicateAddress
	for k, set := range holders {
		if len(set) < 2 {
			continue
		}
		d := DuplicateAddress{Network: k.network, IP: k.ip}
		for o := range set {
			d.Owners = append(d.Owners, o)
		}
		sort.Slice(d.Owners, func(i, j int) bool {
			a, b := d.Owners[i], d.Owners[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Host != b.Host {
				return a.Host < b.Host
			}
			return a.Name < b.Name
		})
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Network != out[j].Network {
			return out[i].Network < out[j].Network
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

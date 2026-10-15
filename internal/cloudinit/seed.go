package cloudinit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SeedNetworkConfig is the network-config of vm's seed, derived from what the
// cluster records: the spec's NIC entries, the VM's NIC rows (the address a
// NetBox claim or a host-isolated pick gave each), and each network's
// definition. A rebuild of the seed on another host — failover, migration —
// therefore writes the document the VM was created with. A network-config the
// spec names wins, as at create.
func SeedNetworkConfig(ctx context.Context, db *corrosion.Client, vmName string, spec *pb.VMSpec) (string, error) {
	if spec == nil {
		return "", nil
	}
	if spec.CloudInit != nil && spec.CloudInit.Networkconfig != "" {
		return spec.CloudInit.Networkconfig, nil
	}
	rows, err := corrosion.GetVMInterfaces(ctx, db, vmName)
	if err != nil {
		return "", fmt.Errorf("read NICs of %q: %w", vmName, err)
	}
	// Each spec NIC's row: by MAC where the spec records one. A VM created
	// before the spec recorded generated MACs has none, and takes the row at
	// its position on its network — (ordinal, network), as matchStoredNIC and
	// NICRate match a spec NIC to its row; every create path writes a NIC's
	// ordinal as its spec index. An entry that names an `ip:` takes that row only
	// when the row records the same IPv4 address, which every create path wrote
	// from the spec. Nothing else: after a hot detach and attach a row on the
	// same network is another NIC. A NIC whose row cannot be told has no MAC,
	// and NetworkConfig then writes no network-config.
	type pos struct {
		ordinal int
		network string
	}
	byMAC := map[string]corrosion.InterfaceRecord{}
	byPos := map[pos]corrosion.InterfaceRecord{}
	for _, r := range rows {
		byMAC[strings.ToLower(r.MAC)] = r
		byPos[pos{r.Ordinal, r.NetworkName}] = r
	}
	// A row is one NIC's: one another spec NIC already took is not taken
	// again.
	macs := make([]string, len(spec.Network))
	taken := map[string]bool{}
	for i, n := range spec.Network {
		if m := strings.ToLower(strings.TrimSpace(n.GetMac())); m != "" {
			macs[i] = m
			taken[m] = true
		}
	}
	for i, n := range spec.Network {
		if macs[i] != "" {
			continue
		}
		if r, ok := byPos[pos{i, n.GetName()}]; ok && !taken[strings.ToLower(r.MAC)] &&
			(n.GetIp() == "" || sameAddr(r.IP, n.GetIp())) {
			macs[i] = strings.ToLower(r.MAC)
			taken[macs[i]] = true
		}
	}
	nics := make([]NIC, 0, len(spec.Network))
	for i, n := range spec.Network {
		mac := strings.TrimSpace(n.GetMac())
		if mac == "" {
			mac = macs[i]
		}
		row := byMAC[strings.ToLower(mac)]
		def, err := NetworkDef(ctx, db, n.GetName())
		if err != nil {
			return "", err
		}
		bound := false
		if b, err := corrosion.GetBindingByNetwork(ctx, db, n.GetName()); err != nil {
			return "", fmt.Errorf("read binding of %q: %w", n.GetName(), err)
		} else if b != nil {
			bound = true
		}
		nics = append(nics, NIC{
			Ordinal: i, MAC: mac,
			IP: n.GetIp(), Gateway: n.GetGateway(), IPv6: n.GetIpv6(), IPv6Gateway: n.GetIpv6Gateway(),
			RecordedIP: row.IP,
			Net:        def, Bound: bound,
		})
	}
	return NetworkConfig(nics), nil
}

// sameAddr reports whether a and b name the same IP address, ignoring a
// prefix length ("10.1.0.50/24" is "10.1.0.50"). An empty or unparseable
// address matches nothing.
func sameAddr(a, b string) bool {
	pa, ok := parseAddr(a)
	if !ok {
		return false
	}
	pb, ok := parseAddr(b)
	return ok && pa == pb
}

func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// NetworkDef reads a network's definition: (nil, nil) when the network has
// no record, or a record this build cannot parse (flat-bridge mode); an error
// when it could not be read.
func NetworkDef(ctx context.Context, db *corrosion.Client, name string) (*compose.NetworkDef, error) {
	rows, err := db.Query(ctx,
		`SELECT type, config FROM networks WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, fmt.Errorf("read network %q: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(rows[0].String("config")), &def); err != nil {
		return nil, nil
	}
	def.Type = rows[0].String("type")
	return &def, nil
}

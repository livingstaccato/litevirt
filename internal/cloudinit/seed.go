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
// cluster records: the VM's live NICs (the vm_nics/vm_interfaces overlay that
// create, attach and detach maintain on every cluster, MergedVMNICs), the
// spec's entry for each, the address each NIC row records (a NetBox claim or
// a host-isolated pick), and each network's definition. A rebuild of the seed
// — after a hot attach or detach, on failover, on migration — therefore lists
// exactly the NICs the VM has: a detached NIC, its MAC and its address are
// gone, an attached one is there. A network-config the spec names wins, as at
// create.
//
// The NICs are written in ordinal order, MAC breaking a tie, and named
// eth<position> in that order: a NIC attached after a detach can share its
// ordinal with one that stayed. For a VM no NIC was attached to or detached
// from, position is ordinal is spec index, so the document is the one create
// wrote.
func SeedNetworkConfig(ctx context.Context, db *corrosion.Client, vmName string, spec *pb.VMSpec) (string, error) {
	if spec == nil {
		return "", nil
	}
	if spec.CloudInit != nil && spec.CloudInit.Networkconfig != "" {
		return spec.CloudInit.Networkconfig, nil
	}
	rows, err := corrosion.MergedVMNICs(ctx, db, vmName)
	if err != nil {
		return "", fmt.Errorf("read NICs of %q: %w", vmName, err)
	}
	// Each live NIC's spec entry: the one that records its MAC. A VM created
	// before the spec recorded generated MACs has none, and its entry is the
	// one at the NIC's position on its network — (ordinal, network), as
	// matchStoredNIC and NICRate match a spec NIC to its row; every create
	// path writes a NIC's ordinal as its spec index, and nothing changes it.
	// An entry that names an `ip:` takes that row only when the row records
	// the same IPv4 address, which every create path wrote from the spec.
	// Nothing else: after a hot detach and attach a row on the same network
	// is another NIC. A NIC with no entry was hot-attached: it is written
	// from its row and network alone.
	//
	// A MAC-less entry whose position holds a live row no entry took (one
	// that records another address) cannot be told from that row, and the
	// seed then carries no network-config. An entry whose position holds no
	// live row was detached and is left out.
	type pos struct {
		ordinal int
		network string
	}
	entryByMAC := map[string]int{}
	for i, n := range spec.Network {
		if m := strings.ToLower(strings.TrimSpace(n.GetMac())); m != "" {
			entryByMAC[m] = i
		}
	}
	used := make([]bool, len(spec.Network))
	entryOf := make([]int, len(rows))
	for k, r := range rows {
		entryOf[k] = -1
		if i, ok := entryByMAC[strings.ToLower(r.MAC)]; ok && !used[i] {
			entryOf[k], used[i] = i, true
		}
	}
	for k, r := range rows {
		if entryOf[k] >= 0 {
			continue
		}
		i := r.Ordinal
		if i < 0 || i >= len(spec.Network) || used[i] {
			continue
		}
		if n := spec.Network[i]; strings.TrimSpace(n.GetMac()) == "" && n.GetName() == r.NetworkName &&
			(n.GetIp() == "" || sameAddr(r.IP, n.GetIp())) {
			entryOf[k], used[i] = i, true
		}
	}
	unmatched := map[pos]bool{}
	for k, r := range rows {
		if entryOf[k] < 0 {
			unmatched[pos{r.Ordinal, r.NetworkName}] = true
		}
	}
	for i, n := range spec.Network {
		if !used[i] && strings.TrimSpace(n.GetMac()) == "" && unmatched[pos{i, n.GetName()}] {
			return "", nil
		}
	}
	nics := make([]NIC, 0, len(rows))
	for k, r := range rows {
		n := &pb.NetworkAttachment{}
		if entryOf[k] >= 0 {
			n = spec.Network[entryOf[k]]
		}
		def, err := NetworkDef(ctx, db, r.NetworkName)
		if err != nil {
			return "", err
		}
		bound := false
		if b, err := corrosion.GetBindingByNetwork(ctx, db, r.NetworkName); err != nil {
			return "", fmt.Errorf("read binding of %q: %w", r.NetworkName, err)
		} else if b != nil {
			bound = true
		}
		nics = append(nics, NIC{
			Ordinal: k, MAC: r.MAC,
			IP: n.GetIp(), Gateway: n.GetGateway(), IPv6: n.GetIpv6(), IPv6Gateway: n.GetIpv6Gateway(),
			RecordedIP: r.IP,
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

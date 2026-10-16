package cloudinit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

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
// The NICs are written in ordinal order, MAC breaking a tie. Each keeps the
// guest name it was given (see names): prior, the seed being replaced, says
// which names the guest has; with no prior (nil) the names are derived from
// the records alone, the same names. For a VM no NIC was attached to or
// detached from, the document is the one create wrote.
func SeedNetworkConfig(ctx context.Context, db *corrosion.Client, vmName string, spec *pb.VMSpec, prior *Prior) (string, error) {
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
			return "", fmt.Errorf("%w: spec NIC %d (network %q) records no MAC, and the NIC at its position records another address",
				ErrNICsAmbiguous, i, n.GetName())
		}
	}
	nics := make([]NIC, 0, len(rows))
	for k, r := range rows {
		n := &pb.NetworkAttachment{}
		if entryOf[k] >= 0 {
			n = spec.Network[entryOf[k]]
		}
		nic, err := seedNIC(ctx, db, r, n)
		if err != nil {
			return "", err
		}
		nic.Ordinal = k
		nics = append(nics, nic)
	}
	// Every row the VM's NICs ever had, a detach's tombstone included.
	var all []corrosion.NICRecord
	for _, table := range []string{"vm_nics", "vm_interfaces"} {
		raw, err := corrosion.GetVMNICsRaw(ctx, db, table, vmName)
		if err != nil {
			return "", fmt.Errorf("read NICs of %q: %w", vmName, err)
		}
		all = append(all, raw...)
	}
	sort.SliceStable(all, func(a, b int) bool {
		return strings.ToLower(all[a].MAC) < strings.ToLower(all[b].MAC)
	})
	created, err := createdNames(ctx, db, spec, rows, entryOf, all)
	if err != nil {
		return "", err
	}
	// An ordinal another NIC of the VM ever had, or a spec position: only an
	// earlier build's attach (or two attaches racing) gives a NIC one.
	shared := map[int]bool{}
	macsAt := map[int]map[string]bool{}
	for _, r := range all {
		if macsAt[r.Ordinal] == nil {
			macsAt[r.Ordinal] = map[string]bool{}
		}
		macsAt[r.Ordinal][strings.ToLower(r.MAC)] = true
	}
	for o, m := range macsAt {
		shared[o] = len(m) > 1 || o < len(spec.Network)
	}
	prior.names(nics, rows, entryOf, created, shared)
	return NetworkConfig(nics), nil
}

// seedNIC is NIC row r, whose spec entry is n (empty for a NIC with none), as
// its seed's network-config is derived from it.
func seedNIC(ctx context.Context, db *corrosion.Client, r corrosion.NICRecord, n *pb.NetworkAttachment) (NIC, error) {
	def, err := NetworkDef(ctx, db, r.NetworkName)
	if err != nil {
		return NIC{}, err
	}
	bound := false
	if b, err := corrosion.GetBindingByNetwork(ctx, db, r.NetworkName); err != nil {
		return NIC{}, fmt.Errorf("read binding of %q: %w", r.NetworkName, err)
	} else if b != nil {
		bound = true
	}
	return NIC{
		Ordinal: r.Ordinal, MAC: r.MAC,
		IP: n.GetIp(), Gateway: n.GetGateway(), IPv6: n.GetIpv6(), IPv6Gateway: n.GetIpv6Gateway(),
		RecordedIP: r.IP,
		Net:        def, Bound: bound,
	}, nil
}

// createdNames is the guest name the seed vm was created with gives each of
// its spec's NIC entries, by entry index: "" for an entry it named none
// (a one-NIC VM with no static address has no network-config; a NIC with
// nothing to configure is not listed). Create wrote one NIC per entry, in
// spec order, from the entry and its NIC row, so the document is derived
// again from the same facts: the live row each entry has (entryOf), else the
// row a detach left (a tombstone, among gone: every row, sorted by MAC), else
// the entry alone. The facts include each network's definition as it is now:
// a network whose definition changed since create in a way that changes what
// its NICs are configured with can change these names.
func createdNames(ctx context.Context, db *corrosion.Client, spec *pb.VMSpec, rows []corrosion.NICRecord, entryOf []int, gone []corrosion.NICRecord) (map[int]string, error) {
	rowOf := make(map[int]corrosion.NICRecord, len(spec.Network))
	for k, i := range entryOf {
		if i >= 0 {
			rowOf[i] = rows[k]
		}
	}
	nics := make([]NIC, len(spec.Network))
	macs := make([]string, len(spec.Network))
	for i, n := range spec.Network {
		r, ok := rowOf[i]
		if !ok {
			mac := strings.ToLower(strings.TrimSpace(n.GetMac()))
			for _, g := range gone {
				if mac != "" && strings.ToLower(g.MAC) == mac ||
					mac == "" && g.Ordinal == i && g.NetworkName == n.GetName() && (n.GetIp() == "" || sameAddr(g.IP, n.GetIp())) {
					r, ok = g, true
					break
				}
			}
		}
		if !ok {
			r = corrosion.NICRecord{NetworkName: n.GetName(), MAC: n.GetMac(), Ordinal: i}
		}
		if strings.TrimSpace(r.MAC) == "" {
			// An entry whose NIC left no record: only whether it was
			// configured counts here, and a MAC no NIC of the VM has stands
			// in for its own.
			r.MAC = fmt.Sprintf("00:00:00:00:%02x:%02x", i>>8&0xff, i&0xff)
		}
		nic, err := seedNIC(ctx, db, r, n)
		if err != nil {
			return nil, err
		}
		nic.Ordinal = i
		nics[i], macs[i] = nic, strings.ToLower(r.MAC)
	}
	listed := PriorFrom(NetworkConfig(nics)).Names
	out := make(map[int]string, len(spec.Network))
	for i := range spec.Network {
		out[i] = listed[macs[i]]
	}
	return out, nil
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

// ErrNICsAmbiguous is SeedNetworkConfig's answer when a spec NIC that
// records no MAC (a VM created before the spec recorded generated MACs)
// cannot be told from the NIC row at its position. There is then no
// network-config litevirt can stand behind, and a caller keeps the seed it has
// rather than writing one without it: a seed with no network-config is
// cloud-init's fallback, DHCP on one NIC, which re-applied at the next boot
// loses every static address.
var ErrNICsAmbiguous = errors.New("the VM's NICs cannot all be told from its spec")

// Prior is what the seed a rebuild replaces says about the guest's NIC names.
// A NIC's guest name never changes once a seed gave it one: cloud-init renames
// NICs by the seed on every boot it applies it, and a rename breaks whatever
// in the guest names the interface.
type Prior struct {
	// Names maps a folded MAC to the name the seed's network-config gives it,
	// "" for an entry that matches it by MAC with no set-name. A MAC that is
	// not a key had no entry.
	Names map[string]string
	// Added are the folded MACs of NICs attached since that seed was written.
	Added map[string]bool
	// Stale: the seed may predate NICs attached since (a copy a host kept
	// while the VM ran elsewhere), so a NIC it does not list, or lists by a
	// name, that has no spec entry is named as with no seed. Without it a NIC
	// the seed does not list was never named.
	Stale bool
}

// PriorFrom reads the guest names of networkConfig, a seed's network-config
// ("" for a seed with none: every NIC named by the guest's kernel), with
// added the MACs of NICs attached since. A document it cannot read names
// nothing.
func PriorFrom(networkConfig string, added ...string) *Prior {
	p := &Prior{Names: map[string]string{}, Added: map[string]bool{}}
	for _, m := range added {
		p.Added[strings.ToLower(strings.TrimSpace(m))] = true
	}
	var doc struct {
		Version int `yaml:"version"`
		Config  []struct {
			Type       string `yaml:"type"`
			Name       string `yaml:"name"`
			MACAddress string `yaml:"mac_address"`
		} `yaml:"config"`
		Ethernets map[string]struct {
			Match struct {
				MACAddress string `yaml:"macaddress"`
			} `yaml:"match"`
			SetName string `yaml:"set-name"`
		} `yaml:"ethernets"`
	}
	if networkConfig == "" || yaml.Unmarshal([]byte(networkConfig), &doc) != nil {
		return p
	}
	for _, c := range doc.Config {
		if c.Type == "physical" && c.MACAddress != "" {
			p.Names[strings.ToLower(c.MACAddress)] = c.Name
		}
	}
	for _, e := range doc.Ethernets {
		if e.Match.MACAddress != "" {
			p.Names[strings.ToLower(e.Match.MACAddress)] = e.SetName
		}
	}
	return p
}

// names gives nics (in position order; rows[k] is nics[k]'s row, entryOf[k]
// its spec entry or -1) their guest names, so that a NIC's name is a function
// of what the cluster records, the same on every host, with or without a seed:
//
//   - a NIC with a spec entry has the name the VM's create gave it (created),
//     or none: matched by MAC alone, under the name the guest's kernel gave
//     it;
//   - a NIC attached since has eth<its ordinal>. attach gives a NIC an
//     ordinal no NIC of the VM ever had and above every spec position
//     (nextNICOrdinal), so the name is free, never a detached NIC's and never
//     the kernel name eth<n> of a NIC the seed leaves unnamed (a guest booted
//     with net.ifnames=0 numbers them eth0..). One an earlier build attached
//     (or two attaches racing) can have an ordinal another NIC of the VM ever
//     had, live or detached, or a spec position (shared): it takes
//     lv<its MAC's hex digits>, a name no other NIC has, a detached one
//     included, and that no later attach changes.
//
// p, the seed being replaced, wins where it knows: a NIC it lists keeps its
// listing, one it marks attached since is new, and — unless p is Stale — one it
// does not list stays unnamed (a NIC an earlier build attached, or one a seed
// from before litevirt named NICs left to the kernel).
func (p *Prior) names(nics []NIC, rows []corrosion.NICRecord, entryOf []int, created map[int]string, shared map[int]bool) {
	used := map[string]bool{}
	kept := 0
	keep := func(k int, name string) {
		if name == "" {
			nics[k].Unnamed = true
		} else {
			nics[k].Name, used[name] = name, true
		}
		kept++
	}
	var added []int
	for k := range nics {
		mac := strings.ToLower(nics[k].MAC)
		inSpec := entryOf[k] >= 0
		if p != nil {
			name, listed := p.Names[mac]
			switch {
			case listed && (name == "" || inSpec || !p.Stale):
				keep(k, name)
				continue
			case p.Added[mac]:
				added = append(added, k)
				continue
			case !listed && (inSpec || !p.Stale):
				keep(k, "")
				continue
			}
		}
		if inSpec {
			keep(k, created[entryOf[k]])
		} else {
			added = append(added, k)
		}
	}
	for i := 0; i < kept; i++ {
		used[fmt.Sprintf("eth%d", i)] = true
	}
	for _, k := range added {
		n := fmt.Sprintf("eth%d", rows[k].Ordinal)
		if rows[k].Ordinal < 0 || shared[rows[k].Ordinal] || used[n] {
			// Not an ordinal this NIC alone ever had: a name from its MAC,
			// which no other NIC has, and which no later attach changes.
			n = "lv" + strings.ReplaceAll(strings.ToLower(nics[k].MAC), ":", "")
		}
		nics[k].Name, used[n] = n, true
	}
}

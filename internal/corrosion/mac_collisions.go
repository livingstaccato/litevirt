package corrosion

import (
	"context"
	"sort"
	"strings"
)

// MACHolder is one live workload NIC that records a MAC.
type MACHolder struct {
	Kind    string // "vm" or "ct"
	Name    string // the VM or container name
	Host    string // the host the workload is on
	Network string
	// Owner is the NIC's owner as LiveNICIdentities and the guards name it:
	// the VM name, or ContainerGuardOwner(host, name).
	Owner string
	// Identity is the workload: the VM name, or for a container its lineage
	// (create spec owner_id), so that both rows of a container that is
	// mid-migrate, or whose source a migrate parked, are one workload. A
	// container with no lineage recorded is its Owner.
	Identity string
}

// LiveMACHolders is the one answer to "which live NICs hold this MAC",
// keyed by lower-cased MAC: the NICs of live VMs as the vm_nics /
// vm_interfaces overlay (MergedVMNICs) has them, so the legacy row of a NIC
// a latched cluster detached holds nothing, and the NICs of live containers.
// One entry per workload Identity and host: both rows of a container a
// migrate is moving are kept, each naming its host, and count as one
// workload (Identity).
func LiveMACHolders(ctx context.Context, c *Client) (map[string][]MACHolder, error) {
	out := map[string][]MACHolder{}
	seen := map[string]bool{} // mac|identity|host
	add := func(mac string, h MACHolder) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		key := mac + "|" + h.Identity + "|" + h.Host
		if mac == "" || seen[key] {
			return
		}
		seen[key] = true
		out[mac] = append(out[mac], h)
	}

	vmRows, err := c.Query(ctx, `SELECT name, host_name FROM vms WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	hostOf := make(map[string]string, len(vmRows))
	for _, r := range vmRows {
		hostOf[r.String("name")] = r.String("host_name")
	}
	nicRows, err := c.Query(ctx,
		`SELECT vm_name, id, network_name, model, mac, ordinal,
		        COALESCE(ip, '') AS ip, COALESCE(tap_device, '') AS tap_device,
		        COALESCE(security_groups, '') AS security_groups,
		        updated_at, COALESCE(deleted_at, '') AS deleted_at
		 FROM vm_nics`)
	if err != nil {
		return nil, err
	}
	ifRows, err := c.Query(ctx,
		`SELECT vm_name, network_name, mac, ordinal,
		        COALESCE(ip, '') AS ip, COALESCE(tap_device, '') AS tap_device,
		        COALESCE(security_groups, '') AS security_groups,
		        updated_at, COALESCE(deleted_at, '') AS deleted_at
		 FROM vm_interfaces`)
	if err != nil {
		return nil, err
	}
	for _, n := range mergeNICRows(vmInterfacesRows(ifRows), vmNICsRows(nicRows)) {
		host, live := hostOf[n.VMName]
		if !live {
			continue
		}
		add(n.MAC, MACHolder{Kind: "vm", Name: n.VMName, Host: host, Network: n.NetworkName,
			Owner: n.VMName, Identity: n.VMName})
	}

	ctRows, err := c.Query(ctx,
		`SELECT i.mac, i.ct_name, i.network_name, i.host_name, COALESCE(ct.create_spec, '') AS create_spec
		 FROM container_interfaces i
		 JOIN containers ct ON ct.host_name = i.host_name AND ct.name = i.ct_name
		 WHERE i.deleted_at IS NULL AND ct.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	for _, r := range ctRows {
		host, name := r.String("host_name"), r.String("ct_name")
		owner := ContainerGuardOwner(host, name)
		identity := owner
		if id := DecodeCreateSpec(r.String("create_spec")).OwnerID; id != "" {
			identity = "ct-lineage:" + id
		}
		add(r.String("mac"), MACHolder{Kind: "ct", Name: name, Host: host,
			Network: r.String("network_name"), Owner: owner, Identity: identity})
	}
	return out, nil
}

// MACCollision is a MAC that NICs of more than one workload record.
type MACCollision struct {
	MAC     string
	Holders []MACHolder // one per workload and host, sorted by owner then host
}

// ListMACCollisions returns every MAC that the live NICs of two or more
// workloads hold (LiveMACHolders). Nothing is rewritten: a running guest
// keeps its MAC until an operator changes it.
func ListMACCollisions(ctx context.Context, c *Client) ([]MACCollision, error) {
	holders, err := LiveMACHolders(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []MACCollision
	for mac, hs := range holders {
		workloads := map[string]bool{}
		for _, h := range hs {
			workloads[h.Identity] = true
		}
		if len(workloads) < 2 {
			continue
		}
		col := MACCollision{MAC: mac, Holders: append([]MACHolder(nil), hs...)}
		sort.Slice(col.Holders, func(i, j int) bool {
			if col.Holders[i].Owner != col.Holders[j].Owner {
				return col.Holders[i].Owner < col.Holders[j].Owner
			}
			return col.Holders[i].Host < col.Holders[j].Host
		})
		out = append(out, col)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

// LiveLeaseMACs returns the MAC of every live IPAM lease, with the owner
// LiveNICIdentities names: a lease is a DHCP reservation by MAC, so a MAC
// one holds is not free for another workload.
func LiveLeaseMACs(ctx context.Context, c *Client) (map[string][]string, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(mac, '') AS mac, CASE owner_kind WHEN 'ct' THEN 'ct:' || owner_host || ':' || vm_name ELSE vm_name END AS owner
		 FROM ip_allocations WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, r := range rows {
		if m := strings.ToLower(strings.TrimSpace(r.String("mac"))); m != "" {
			out[m] = append(out[m], r.String("owner"))
		}
	}
	return out, nil
}

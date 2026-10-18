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
	// Owner is the identity two rows of one NIC share: the VM name, or
	// ContainerGuardOwner for a container.
	Owner string
}

// MACCollision is a MAC that NICs of more than one workload record.
type MACCollision struct {
	MAC     string
	Holders []MACHolder // one per workload, sorted by owner
}

// ListMACCollisions returns every MAC that the live NICs of two or more
// workloads record — of live VMs (vm_nics and vm_interfaces; both rows of
// one NIC count once) and of live containers (container_interfaces). Nothing
// is rewritten: a running guest keeps its MAC until an operator changes it.
func ListMACCollisions(ctx context.Context, c *Client) ([]MACCollision, error) {
	byMAC := map[string]map[string]MACHolder{} // mac -> owner -> holder
	add := func(mac string, h MACHolder) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if mac == "" {
			return
		}
		if byMAC[mac] == nil {
			byMAC[mac] = map[string]MACHolder{}
		}
		if _, ok := byMAC[mac][h.Owner]; !ok { // vm_nics is read first and wins
			byMAC[mac][h.Owner] = h
		}
	}
	for _, q := range []string{
		`SELECT n.mac, n.vm_name, n.network_name, v.host_name
		 FROM vm_nics n JOIN vms v ON v.name = n.vm_name
		 WHERE n.deleted_at IS NULL AND v.deleted_at IS NULL`,
		`SELECT i.mac, i.vm_name, i.network_name, v.host_name
		 FROM vm_interfaces i JOIN vms v ON v.name = i.vm_name
		 WHERE i.deleted_at IS NULL AND v.deleted_at IS NULL`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			name := r.String("vm_name")
			add(r.String("mac"), MACHolder{Kind: "vm", Name: name, Host: r.String("host_name"),
				Network: r.String("network_name"), Owner: name})
		}
	}
	rows, err := c.Query(ctx,
		`SELECT i.mac, i.ct_name, i.network_name, i.host_name
		 FROM container_interfaces i
		 JOIN containers ct ON ct.host_name = i.host_name AND ct.name = i.ct_name
		 WHERE i.deleted_at IS NULL AND ct.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		host, name := r.String("host_name"), r.String("ct_name")
		add(r.String("mac"), MACHolder{Kind: "ct", Name: name, Host: host,
			Network: r.String("network_name"), Owner: ContainerGuardOwner(host, name)})
	}

	// A VM's NICs are what the vm_nics/vm_interfaces overlay says they are
	// (MergedVMNICs): a live legacy row a newer vm_nics tombstone hides is a
	// detached NIC, not a holder. Read only for the VMs of a candidate.
	merged := map[string]map[string]bool{} // vm -> live macs
	liveOn := func(vm, mac string) (bool, error) {
		if merged[vm] == nil {
			nics, err := MergedVMNICs(ctx, c, vm)
			if err != nil {
				return false, err
			}
			merged[vm] = map[string]bool{}
			for _, n := range nics {
				merged[vm][strings.ToLower(n.MAC)] = true
			}
		}
		return merged[vm][mac], nil
	}
	var out []MACCollision
	for mac, hs := range byMAC {
		owners := map[string]bool{}
		for _, h := range hs {
			owners[h.Owner] = true
		}
		if len(owners) < 2 {
			continue
		}
		col := MACCollision{MAC: mac}
		owners = map[string]bool{}
		for _, h := range hs {
			if h.Kind == "vm" {
				live, err := liveOn(h.Name, mac)
				if err != nil {
					return nil, err
				}
				if !live {
					continue
				}
			}
			owners[h.Owner] = true
			col.Holders = append(col.Holders, h)
		}
		if len(owners) < 2 {
			continue
		}
		sort.Slice(col.Holders, func(i, j int) bool { return col.Holders[i].Owner < col.Holders[j].Owner })
		out = append(out, col)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

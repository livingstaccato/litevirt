package corrosion

import (
	"context"
	"sort"
	"strings"
)

// HostVMNIC is one live NIC of a VM placed on a host, as the firewall
// reconciler needs it: who owns it, its MAC (what libvirt is asked for the tap
// by) and the security groups bound to it.
//
// It deliberately carries no tap device. vm_interfaces.tap_device is written
// once, at create, and libvirt hands out a new vnetN on every start, on every
// host, so the recorded name goes stale on a stop and start, a migration or a
// failover — and can then name ANOTHER VM's tap on this host. The reconciler
// asks libvirt for the tap at render time instead.
type HostVMNIC struct {
	VMName         string
	VMState        string
	NetworkName    string
	MAC            string
	Ordinal        int
	SecurityGroups []string
}

// ListHostVMNICs returns every live NIC of every live VM whose row places it on
// hostName, read through the same vm_nics/vm_interfaces overlay MergedVMNICs
// applies, so a NIC exists here exactly when the hardware view shows it.
//
// The security groups come from the NIC's live vm_nics row when it has one, and
// from its vm_interfaces row only when it does not. vm_nics is where every
// hardware_v2 writer puts them: a hot-attached NIC has its groups ONLY there
// (once hardware_v2 has latched it writes no legacy row at all), and before the
// latch its legacy row is written after the vm_nics row, so a newest-row-wins
// pick would choose the legacy row and could see no groups. A legacy-only change
// (BindSecurityGroups, or a write by a peer on an older build) reaches vm_nics
// through the hardware bridge (BridgeVMNICs), which mirrors a strictly newer
// legacy row.
func ListHostVMNICs(ctx context.Context, c *Client, hostName string) ([]HostVMNIC, error) {
	nicRows, err := c.Query(ctx,
		`SELECT n.vm_name, n.id, n.network_name, n.model, n.mac, n.ordinal,
		        COALESCE(n.security_groups, '') AS security_groups,
		        n.updated_at, COALESCE(n.deleted_at, '') AS deleted_at,
		        COALESCE(v.state, '') AS vm_state
		 FROM vm_nics n
		 JOIN vms v ON v.name = n.vm_name
		 WHERE v.host_name = ? AND v.deleted_at IS NULL`, hostName)
	if err != nil {
		return nil, err
	}
	ifaceRows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.mac, i.ordinal,
		        COALESCE(i.security_groups, '') AS security_groups,
		        i.updated_at, COALESCE(i.deleted_at, '') AS deleted_at,
		        COALESCE(v.state, '') AS vm_state
		 FROM vm_interfaces i
		 JOIN vms v ON v.name = i.vm_name
		 WHERE v.host_name = ? AND v.deleted_at IS NULL`, hostName)
	if err != nil {
		return nil, err
	}

	state := map[string]string{}
	nics := make([]NICRecord, 0, len(nicRows))
	liveNICGroups := map[nicKey]string{}
	for _, r := range nicRows {
		rec := NICRecord{
			VMName:         r.String("vm_name"),
			ID:             r.String("id"),
			NetworkName:    r.String("network_name"),
			Model:          r.String("model"),
			MAC:            r.String("mac"),
			Ordinal:        r.Int("ordinal"),
			SecurityGroups: r.String("security_groups"),
			UpdatedAt:      r.String("updated_at"),
			DeletedAt:      r.String("deleted_at"),
		}
		state[rec.VMName] = r.String("vm_state")
		nics = append(nics, rec)
		if rec.DeletedAt == "" {
			liveNICGroups[nicJoinKey(rec)] = rec.SecurityGroups
		}
	}
	ifaces := make([]NICRecord, 0, len(ifaceRows))
	for _, r := range ifaceRows {
		vmn, mac := r.String("vm_name"), r.String("mac")
		state[vmn] = r.String("vm_state")
		ifaces = append(ifaces, NICRecord{
			VMName:         vmn,
			ID:             DeterministicNICID(vmn, mac),
			NetworkName:    r.String("network_name"),
			Model:          "virtio",
			MAC:            mac,
			Ordinal:        r.Int("ordinal"),
			SecurityGroups: r.String("security_groups"),
			UpdatedAt:      r.String("updated_at"),
			DeletedAt:      r.String("deleted_at"),
		})
	}

	merged := mergeNICRows(ifaces, nics)
	out := make([]HostVMNIC, 0, len(merged))
	for _, m := range merged {
		groups := m.SecurityGroups
		if g, ok := liveNICGroups[nicJoinKey(m)]; ok {
			groups = g
		}
		out = append(out, HostVMNIC{
			VMName:         m.VMName,
			VMState:        state[m.VMName],
			NetworkName:    m.NetworkName,
			MAC:            m.MAC,
			Ordinal:        m.Ordinal,
			SecurityGroups: decodeSGs(groups),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VMName != out[j].VMName {
			return out[i].VMName < out[j].VMName
		}
		if out[i].Ordinal != out[j].Ordinal {
			return out[i].Ordinal < out[j].Ordinal
		}
		return strings.ToLower(out[i].MAC) < strings.ToLower(out[j].MAC)
	})
	return out, nil
}

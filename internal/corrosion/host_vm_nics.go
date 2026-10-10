package corrosion

import (
	"context"
	"encoding/json"
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
	// IP is the address litevirt assigned the NIC (IPAM, NetBox or a static
	// address in the spec), as its NIC row records it; "" when the guest gets
	// one some other way, such as from a DHCP server's dynamic range. It may
	// carry a prefix length ("10.0.0.5/24").
	IP string
	// TrunkVIDs are the VLANs of a NIC on the `trunk:` feature (two or more
	// VLANs in the VM spec, configured as a tagged trunk on its bridge port);
	// nil for any other NIC, an access-mode NIC (one VLAN) included.
	TrunkVIDs []int
	// VMUUID is the incarnation of the VM (its spec uuid): a guard record
	// written for another incarnation guards nothing.
	VMUUID string
}

// specTrunks reads each NIC's trunk VLANs from a stored VM spec (encoding/json
// of VMSpec): by MAC where the spec names one, else by position, which is the
// NIC's ordinal for every NIC created with the VM. Only trunks (two or more
// VLANs) are returned.
func specTrunks(spec string) (byMAC map[string][]int, byOrdinal map[int][]int, uuid string) {
	var s struct {
		UUID    string `json:"uuid"`
		Network []struct {
			Mac   string  `json:"mac"`
			Trunk []int32 `json:"trunk"`
		} `json:"network"`
	}
	if spec == "" || json.Unmarshal([]byte(spec), &s) != nil {
		return nil, nil, ""
	}
	uuid = s.UUID
	byMAC, byOrdinal = map[string][]int{}, map[int][]int{}
	for i, n := range s.Network {
		if len(n.Trunk) < 2 {
			continue
		}
		vids := make([]int, len(n.Trunk))
		for j, v := range n.Trunk {
			vids[j] = int(v)
		}
		if n.Mac != "" {
			byMAC[strings.ToLower(n.Mac)] = vids
		} else {
			byOrdinal[i] = vids
		}
	}
	return byMAC, byOrdinal, uuid
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
//
// extraVMs are VMs listed whatever host their row names: a VM about to start
// or migrate in here, whose row may still name the host it comes from.
func ListHostVMNICs(ctx context.Context, c *Client, hostName string, extraVMs ...string) ([]HostVMNIC, error) {
	where, args := "v.host_name = ?", []interface{}{hostName}
	if len(extraVMs) > 0 {
		where = "(v.host_name = ? OR v.name IN (?" + strings.Repeat(", ?", len(extraVMs)-1) + "))"
		for _, vm := range extraVMs {
			args = append(args, vm)
		}
	}
	nicRows, err := c.Query(ctx,
		`SELECT n.vm_name, n.id, n.network_name, n.model, n.mac, n.ordinal,
		        COALESCE(n.security_groups, '') AS security_groups, COALESCE(n.ip, '') AS ip,
		        n.updated_at, COALESCE(n.deleted_at, '') AS deleted_at,
		        COALESCE(v.state, '') AS vm_state, COALESCE(v.spec, '') AS vm_spec
		 FROM vm_nics n
		 JOIN vms v ON v.name = n.vm_name
		 WHERE `+where+` AND v.deleted_at IS NULL`, args...)
	if err != nil {
		return nil, err
	}
	ifaceRows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.mac, i.ordinal,
		        COALESCE(i.security_groups, '') AS security_groups, COALESCE(i.ip, '') AS ip,
		        i.updated_at, COALESCE(i.deleted_at, '') AS deleted_at,
		        COALESCE(v.state, '') AS vm_state, COALESCE(v.spec, '') AS vm_spec
		 FROM vm_interfaces i
		 JOIN vms v ON v.name = i.vm_name
		 WHERE `+where+` AND v.deleted_at IS NULL`, args...)
	if err != nil {
		return nil, err
	}

	state := map[string]string{}
	specs := map[string]string{}
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
			IP:             r.String("ip"),
			SecurityGroups: r.String("security_groups"),
			UpdatedAt:      r.String("updated_at"),
			DeletedAt:      r.String("deleted_at"),
		}
		state[rec.VMName] = r.String("vm_state")
		specs[rec.VMName] = r.String("vm_spec")
		nics = append(nics, rec)
		if rec.DeletedAt == "" {
			liveNICGroups[nicJoinKey(rec)] = rec.SecurityGroups
		}
	}
	ifaces := make([]NICRecord, 0, len(ifaceRows))
	for _, r := range ifaceRows {
		vmn, mac := r.String("vm_name"), r.String("mac")
		state[vmn] = r.String("vm_state")
		specs[vmn] = r.String("vm_spec")
		ifaces = append(ifaces, NICRecord{
			VMName:         vmn,
			ID:             DeterministicNICID(vmn, mac),
			NetworkName:    r.String("network_name"),
			Model:          "virtio",
			MAC:            mac,
			Ordinal:        r.Int("ordinal"),
			IP:             r.String("ip"),
			SecurityGroups: r.String("security_groups"),
			UpdatedAt:      r.String("updated_at"),
			DeletedAt:      r.String("deleted_at"),
		})
	}

	merged := mergeNICRows(ifaces, nics)
	out := make([]HostVMNIC, 0, len(merged))
	type trunks struct {
		byMAC     map[string][]int
		byOrdinal map[int][]int
		uuid      string
	}
	parsed := map[string]trunks{}
	for _, m := range merged {
		groups := m.SecurityGroups
		if g, ok := liveNICGroups[nicJoinKey(m)]; ok {
			groups = g
		}
		tr, ok := parsed[m.VMName]
		if !ok {
			tr.byMAC, tr.byOrdinal, tr.uuid = specTrunks(specs[m.VMName])
			parsed[m.VMName] = tr
		}
		vids := tr.byMAC[strings.ToLower(m.MAC)]
		if vids == nil {
			vids = tr.byOrdinal[m.Ordinal]
		}
		out = append(out, HostVMNIC{
			VMName:         m.VMName,
			VMState:        state[m.VMName],
			NetworkName:    m.NetworkName,
			MAC:            m.MAC,
			Ordinal:        m.Ordinal,
			SecurityGroups: decodeSGs(groups),
			IP:             m.IP,
			TrunkVIDs:      vids,
			VMUUID:         tr.uuid,
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

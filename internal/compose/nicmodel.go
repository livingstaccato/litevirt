package compose

import (
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// NICModels gives each live NIC of a VM the model it was created with, for a
// builder that renders the VM's domain from its NIC rows. Call Model once
// per NIC, in ordinal order: a spec NIC is matched to one live NIC at most.
//
// The sources, strongest first:
//   - the spec NIC with the NIC's MAC: the create recorded it;
//   - the NIC's vm_nics row: a hot-plug records only there;
//   - the spec NIC at the NIC's ordinal on its network, for a spec from
//     before MACs were recorded in it. Weaker than the row: a NIC detached
//     and another hot-plugged leaves the old one's entry at the reused
//     ordinal;
//   - the merged row's model, else virtio.
//
// The merged row alone is not enough: a vm_interfaces row has no model
// column and reads as virtio, and it wins the overlay when it is newer.
type NICModels struct {
	stored []*pb.NetworkAttachment
	used   []bool
	rows   map[string]string
}

// NewNICModels builds the resolver from the stored spec and the models of
// the VM's live vm_nics rows, keyed by MAC (any case).
func NewNICModels(spec *pb.VMSpec, vmNICRowModels map[string]string) *NICModels {
	stored := spec.GetNetwork()
	rows := make(map[string]string, len(vmNICRowModels))
	for mac, m := range vmNICRowModels {
		rows[strings.ToLower(mac)] = m
	}
	return &NICModels{stored: stored, used: make([]bool, len(stored)), rows: rows}
}

// Model is the model of the live NIC with mac on network at ordinal, whose
// merged NIC row says mergedModel.
func (m *NICModels) Model(mac, network string, ordinal int, mergedModel string) string {
	byMAC, byOrdinal := -1, -1
	for i, a := range m.stored {
		if !m.used[i] && a != nil && a.Mac != "" && strings.EqualFold(a.Mac, mac) {
			byMAC = i
			break
		}
	}
	if byMAC < 0 && ordinal >= 0 && ordinal < len(m.stored) && !m.used[ordinal] {
		if a := m.stored[ordinal]; a != nil && a.Mac == "" && a.Name == network {
			byOrdinal = ordinal
		}
	}
	if byMAC >= 0 {
		m.used[byMAC] = true
		if md := m.stored[byMAC].GetModel(); md != "" {
			return md
		}
	}
	if byOrdinal >= 0 {
		m.used[byOrdinal] = true
	}
	if md := m.rows[strings.ToLower(mac)]; md != "" {
		return md
	}
	if byOrdinal >= 0 {
		if md := m.stored[byOrdinal].GetModel(); md != "" {
			return md
		}
	}
	if mergedModel != "" {
		return mergedModel
	}
	return "virtio"
}

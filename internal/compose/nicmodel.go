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
//   - the spec NIC with the NIC's MAC: the create recorded it. Not when the
//     NIC under that MAC was detached and a NIC attached again with it (a
//     driver swap that keeps the MAC's lease): the spec entry is the old
//     NIC's and the attach recorded the new one only in its vm_nics row,
//     which then decides;
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
	stored     []*pb.NetworkAttachment
	used       []bool
	rows       map[string]string
	reattached map[string]bool
}

// NewNICModels builds the resolver from the stored spec, the models of the
// VM's live vm_nics rows and the MACs a NIC was detached under and attached
// again (both keyed by MAC, any case).
func NewNICModels(spec *pb.VMSpec, vmNICRowModels map[string]string, reattached map[string]bool) *NICModels {
	stored := spec.GetNetwork()
	rows := make(map[string]string, len(vmNICRowModels))
	for mac, m := range vmNICRowModels {
		rows[strings.ToLower(mac)] = m
	}
	again := make(map[string]bool, len(reattached))
	for mac, r := range reattached {
		again[strings.ToLower(mac)] = r
	}
	return &NICModels{stored: stored, used: make([]bool, len(stored)), rows: rows, reattached: again}
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
		if md := m.rows[strings.ToLower(mac)]; md != "" && m.reattached[strings.ToLower(mac)] {
			return md
		}
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

// RewriteSpecNICForAttach makes every spec NIC carrying mac describe the NIC
// being attached under it with model. A NIC attach and detach write only the
// NIC rows, so a spec entry with the MAC is a detached NIC's (the attach
// refuses a MAC a live NIC holds): left as it was, its model and tuning
// would be applied to the new NIC at every later define. Tuning the new model
// cannot take is dropped — an MTU or a queue count other than 1 on a NIC that
// is not virtio, which a define refuses. Reports whether spec changed.
func RewriteSpecNICForAttach(spec *pb.VMSpec, mac, model string) bool {
	if spec == nil || mac == "" {
		return false
	}
	if model == "" {
		model = "virtio"
	}
	changed := false
	for _, a := range spec.Network {
		if a == nil || a.Mac == "" || !strings.EqualFold(a.Mac, mac) {
			continue
		}
		if a.Model != model {
			a.Model = model
			changed = true
		}
		if a.Mtu != 0 && ValidateNICMTU(model, a.Mtu) != nil {
			a.Mtu = 0
			changed = true
		}
		if a.Queues > 1 && model != "virtio" {
			a.Queues = 0
			changed = true
		}
	}
	return changed
}

// SpecNICModelsByMAC is the model of each spec NIC that records a MAC, keyed
// by the lower-cased MAC (corrosion.NICModelSources).
func SpecNICModelsByMAC(spec *pb.VMSpec) map[string]string {
	out := map[string]string{}
	for _, a := range spec.GetNetwork() {
		if a != nil && a.Mac != "" && a.Model != "" {
			out[strings.ToLower(a.Mac)] = a.Model
		}
	}
	return out
}

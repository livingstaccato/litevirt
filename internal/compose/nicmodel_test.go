package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The spec NIC with the NIC's MAC decides; a vm_nics row decides for a NIC
// the spec does not record (a hot-plug); a MAC-less legacy spec NIC is
// matched by ordinal only when no vm_nics row speaks for the NIC.
//
// Mutations: the row before a MAC match — "spec MAC beats a bridged row"
// goes red; the ordinal entry before the row — "a reused ordinal" goes red;
// no shared used slice — "one spec NIC, two rows" goes red; ignore the
// merged model — "merged fallback" goes red.
func TestNICModels(t *testing.T) {
	type nic struct {
		mac, network string
		ordinal      int
		merged, want string
	}
	cases := []struct {
		name string
		spec []*pb.NetworkAttachment
		rows map[string]string
		nics []nic
	}{
		{"spec MAC beats a bridged row",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: "52:54:00:00:00:01"}},
			map[string]string{"52:54:00:00:00:01": "virtio"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}},
		{"a vm_nics row speaks for a vm_interfaces winner",
			nil,
			map[string]string{"52:54:00:00:00:01": "e1000"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}},
		{"a legacy spec NIC with no row",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}},
			nil,
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}},
		{"a reused ordinal",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}, {Name: "lan", Model: "e1000"}},
			map[string]string{"52:54:00:00:00:09": "virtio"},
			[]nic{
				{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"},
				{"52:54:00:00:00:09", "lan", 1, "virtio", "virtio"},
			}},
		{"one spec NIC, two rows",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}},
			nil,
			[]nic{
				{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"},
				{"52:54:00:00:00:02", "lan", 0, "rtl8139", "rtl8139"},
			}},
		{"merged fallback",
			nil, nil,
			[]nic{{"52:54:00:00:00:01", "lan", 0, "rtl8139", "rtl8139"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewNICModels(&pb.VMSpec{Network: tc.spec}, tc.rows)
			for _, n := range tc.nics {
				if got := m.Model(n.mac, n.network, n.ordinal, n.merged); got != n.want {
					t.Errorf("NIC %s: model %q, want %q", n.mac, got, n.want)
				}
			}
		})
	}
}

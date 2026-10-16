package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The spec NIC with the NIC's MAC decides; a vm_nics row decides for a NIC
// the spec does not record (a hot-plug); a MAC-less legacy spec NIC is
// matched by ordinal only when no vm_nics row speaks for the NIC.
//
// A spec entry stops speaking for its MAC once a NIC was detached under it
// and another attached with it: the row, which the attach wrote, decides.
//
// Mutations: the row before a MAC match — "spec MAC beats a bridged row"
// goes red; the ordinal entry before the row — "a reused ordinal" goes red;
// no shared used slice — "one spec NIC, two rows" goes red; ignore the
// merged model — "merged fallback" goes red; ignore reattached — both
// "a re-attached MAC" cases go red.
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
		// reattached: MACs a NIC was detached under and attached again.
		reattached map[string]bool
	}{
		{"spec MAC beats a bridged row",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: "52:54:00:00:00:01"}},
			map[string]string{"52:54:00:00:00:01": "virtio"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}, nil},
		{"a vm_nics row speaks for a vm_interfaces winner",
			nil,
			map[string]string{"52:54:00:00:00:01": "e1000"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}, nil},
		{"a legacy spec NIC with no row",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}},
			nil,
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"}}, nil},
		{"a reused ordinal",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}, {Name: "lan", Model: "e1000"}},
			map[string]string{"52:54:00:00:00:09": "virtio"},
			[]nic{
				{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"},
				{"52:54:00:00:00:09", "lan", 1, "virtio", "virtio"},
			}, nil},
		{"one spec NIC, two rows",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000"}},
			nil,
			[]nic{
				{"52:54:00:00:00:01", "lan", 0, "virtio", "e1000"},
				{"52:54:00:00:00:02", "lan", 0, "rtl8139", "rtl8139"},
			}, nil},
		{"a re-attached MAC: the row beats the old NIC's spec entry",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: "52:54:00:00:00:01"}},
			map[string]string{"52:54:00:00:00:01": "virtio"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "virtio", "virtio"}},
			map[string]bool{"52:54:00:00:00:01": true}},
		{"a re-attached MAC, the other way",
			[]*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mac: "52:54:00:00:00:01"}},
			map[string]string{"52:54:00:00:00:01": "e1000"},
			[]nic{{"52:54:00:00:00:01", "lan", 0, "e1000", "e1000"}},
			map[string]bool{"52:54:00:00:00:01": true}},
		{"merged fallback",
			nil, nil,
			[]nic{{"52:54:00:00:00:01", "lan", 0, "rtl8139", "rtl8139"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewNICModels(&pb.VMSpec{Network: tc.spec}, tc.rows, tc.reattached)
			for _, n := range tc.nics {
				if got := m.Model(n.mac, n.network, n.ordinal, n.merged); got != n.want {
					t.Errorf("NIC %s: model %q, want %q", n.mac, got, n.want)
				}
			}
		})
	}
}

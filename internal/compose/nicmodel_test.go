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

// An attach under a MAC a spec entry carries rewrites that entry to the new
// NIC's model and drops the tuning the model cannot take; an entry for
// another MAC, and tuning the model can take, are left alone.
//
// Mutations: skip the model rewrite — "virtio -> e1000" goes red; keep the
// MTU — its mtu check goes red; keep the queues — its queues check goes red.
func TestRewriteSpecNICForAttach(t *testing.T) {
	const x, y = "52:54:00:00:00:01", "52:54:00:00:00:02"
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{
		{Name: "lan", Model: "virtio", Mac: x, Mtu: 9000, Queues: 4},
		{Name: "lan2", Model: "virtio", Mac: y, Mtu: 9000, Queues: 4},
	}}
	if !RewriteSpecNICForAttach(spec, "52:54:00:00:00:01", "e1000") {
		t.Fatal("virtio -> e1000 reported no change")
	}
	if a := spec.Network[0]; a.Model != "e1000" || a.Mtu != 0 || a.Queues != 0 {
		t.Errorf("virtio -> e1000: entry %+v, want e1000 with no mtu and no queues", a)
	}
	if b := spec.Network[1]; b.Model != "virtio" || b.Mtu != 9000 || b.Queues != 4 {
		t.Errorf("another MAC's entry changed: %+v", b)
	}

	back := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: x}}}
	if !RewriteSpecNICForAttach(back, x, "virtio") || back.Network[0].Model != "virtio" {
		t.Errorf("e1000 -> virtio: entry %+v", back.Network[0])
	}
	same := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mac: x, Mtu: 9000, Queues: 4}}}
	if RewriteSpecNICForAttach(same, x, "virtio") || same.Network[0].Mtu != 9000 || same.Network[0].Queues != 4 {
		t.Errorf("virtio -> virtio changed the entry: %+v", same.Network[0])
	}
}

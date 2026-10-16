package apimeta

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The four forms of the Firewall tags line (spec §4.2, m-3).
//
// Mutations: skip the orphan note — red; read the first entry as the
// workload whatever it is — red.
func TestFirewallTagsLine(t *testing.T) {
	live := func(id string, tags map[string]string) *pb.FirewallTags {
		return &pb.FirewallTags{Kind: "vm", Workload: "web", FwId: id, Tags: tags}
	}
	orphan := &pb.FirewallTags{Kind: "vm", Workload: "web", FwId: "bb", Tags: map[string]string{"role": "web"}, Orphan: true}
	for _, tc := range []struct {
		in   []*pb.FirewallTags
		want string
	}{
		{[]*pb.FirewallTags{live("aa", map[string]string{"role": "web", "env": "prod"})}, "env=prod role=web"},
		{[]*pb.FirewallTags{live("aa", nil)}, "none"},
		{[]*pb.FirewallTags{live("", nil)}, "none (no firewall identity yet)"},
		{[]*pb.FirewallTags{orphan, live("", nil)}, "none (a row for an earlier incarnation of this name exists, fw_id bb, not applied)"},
		{[]*pb.FirewallTags{live("aa", map[string]string{"role": "db"}), orphan}, "role=db"},
		{nil, ""},
	} {
		if got := FirewallTagsLine(tc.in); got != tc.want {
			t.Errorf("FirewallTagsLine(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

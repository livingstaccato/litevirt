package apimeta

import (
	"maps"
	"slices"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// FirewallTagsLeftHeader is the response header a restore into a freed name
// and a cutover set to say which firewall tags the incarnation they replaced
// left behind, with the command that sets them again.
const FirewallTagsLeftHeader = "x-litevirt-firewall-tags-left"

// FirewallTagsLine is the value of the "Firewall tags:" line `lv inspect`,
// `lv ct inspect` and the web UI show for one workload, from what
// ListFirewallTags answered for it (the workload first, then any orphan row
// of its name): the tags; none; none (no firewall identity yet); or, when
// the workload has none and a row an earlier incarnation of its name left
// exists, that row named as not applied.
func FirewallTagsLine(entries []*pb.FirewallTags) string {
	var live *pb.FirewallTags
	var orphan *pb.FirewallTags
	for _, e := range entries {
		switch {
		case !e.GetOrphan() && live == nil:
			live = e
		case e.GetOrphan() && orphan == nil:
			orphan = e
		}
	}
	if live == nil {
		return ""
	}
	if len(live.GetTags()) > 0 {
		var pairs []string
		for _, k := range slices.Sorted(maps.Keys(live.GetTags())) {
			pairs = append(pairs, k+"="+live.GetTags()[k])
		}
		return strings.Join(pairs, " ")
	}
	if orphan != nil {
		return "none (a row for an earlier incarnation of this name exists, fw_id " + orphan.GetFwId() + ", not applied)"
	}
	if live.GetFwId() == "" {
		return "none (no firewall identity yet)"
	}
	return "none"
}

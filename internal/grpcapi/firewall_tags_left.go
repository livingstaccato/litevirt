package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// firewallTagsLeftMD is the response header RestoreContainerReplica says, in
// firewallTagsLeftNote's words, which firewall tags the deleted container
// left behind.
const firewallTagsLeftMD = "x-litevirt-firewall-tags-left"

// firewallTagsLeftNote is what a restore into the freed name of a deleted
// workload says (spec §4.3, R3-I1): the restored workload is a new one with no
// firewall identity, so the deleted incarnation's tags, still on its row,
// do not follow it; an sg.write holder sets them again with the command it
// names. "" when the deleted incarnation left none. Read before the restore
// writes its row, which takes the name's tombstone over. host is the host
// the restored container lands on (ignored for a VM).
func (s *Server) firewallTagsLeftNote(ctx context.Context, kind, project, name, host string) string {
	id, _, tags, err := corrosion.DeletedFirewallTags(ctx, s.db, kind, project, name)
	if err != nil {
		slog.Warn("restore: could not read the deleted incarnation's firewall tags", "kind", kind, "name", name, "error", err)
		return ""
	}
	var pairs []string
	for k, v := range tags {
		if corrosion.ValidFirewallTagWord(k) && corrosion.ValidFirewallTagWord(v) {
			pairs = append(pairs, k+"="+v)
		}
	}
	if id == "" || len(pairs) == 0 {
		return ""
	}
	sort.Strings(pairs)
	what, cmd := "VM", "lv firewall tag set "+name // ci:skip-cmd until D3 registers the command
	if kind == corrosion.TagMemberCT {
		what, cmd = "container", cmd+" --container --host "+host
	}
	return fmt.Sprintf("the deleted %s %s's firewall tags (fw_id %s) do not follow this restore, which is a new %s "+
		"with no firewall identity: %s. To set them again (sg.write): %s %s",
		what, name, id, what, strings.Join(pairs, " "), cmd, strings.Join(pairs, " "))
}

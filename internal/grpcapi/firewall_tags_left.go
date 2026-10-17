package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// firewallTagsLeftMD is the response header a restore into a freed name and
// a cutover say, in firewallTagsLeftText's words, which firewall tags the
// incarnation they replaced left behind.
const firewallTagsLeftMD = apimeta.FirewallTagsLeftHeader

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
	if id == "" {
		return ""
	}
	what := "VM"
	if kind == corrosion.TagMemberCT {
		what = "container"
	}
	return firewallTagsLeftText(kind, name, host, fmt.Sprintf("the deleted %s %s's firewall tags (fw_id %s) do not follow this "+
		"restore, which is a new %s with no firewall identity", what, name, id, what), tags)
}

// recreateFirewallTagsLeft is what a rebuild or recreate that failed after
// its teardown says about the VM's firewall tags (D2b review M-5): they stay
// on the torn-down incarnation's row, and the VM created again by hand is a
// new one with no firewall identity. "" when it left none.
func (s *Server) recreateFirewallTagsLeft(ctx context.Context, name string) string {
	id, _, tags, err := corrosion.DeletedFirewallTags(ctx, s.db, corrosion.TagMemberVM, "", name)
	if err != nil || id == "" {
		return ""
	}
	return firewallTagsLeftText(corrosion.TagMemberVM, name, "", fmt.Sprintf("Its firewall tags (fw_id %s) stay with the torn-down VM, and "+
		"a VM created again under its name is a new one with no firewall identity", id), tags)
}

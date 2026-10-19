package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// Tag-group condition codes (firewall extras spec §4.6), one row per host.
const (
	// A rule names a tag group this host's replica does not hold.
	CondFirewallTagGroupMissing = "firewall.tag_group.missing"
	// A tag group's row cannot be read here.
	CondFirewallTagGroupUnreadable = "firewall.tag_group.unreadable"
	// A workload's firewall-tags row cannot be read: its NICs are held at
	// drop on the networks a tag group binds.
	CondFirewallTagsUnreadable = "firewall.tag_group.tags_unreadable"
	// Two live workloads hold one firewall identity: every NIC of each is
	// held at drop (D1 review I-2).
	CondFirewallTagIdentityShared = "firewall.tag_group.identity_shared"
	// A workload has no firewall identity while a tags row of an earlier
	// incarnation of its name remains: its membership did not follow it
	// (D2b review M-7), and its NICs are held at drop as for an unreadable
	// tags row (Track D final review I-1).
	CondFirewallTagIdentityLost = "firewall.tag_group.identity_lost"
)

// conditionListMax bounds the items one condition's evidence names.
const conditionListMax = 10

// recordTagGroupState raises or resolves this host's tag-group conditions
// from one pass's report.
func (s *Server) recordTagGroupState(ctx context.Context, r firewall.TagGroupReport) {
	s.setFirewallCondition(ctx, CondFirewallTagGroupMissing, len(r.Missing) > 0, corrosion.SeverityCritical,
		tagRefsText("rules name a tag group this host's replica does not hold", r.Missing))
	unreadable := tagRefsText("tag groups this host cannot read or cannot declare a set for", r.Unreadable)
	if len(r.UnreadableHolds) > 0 {
		unreadable += ". " + tagHoldsText("held at drop on every network until the group reads", r.UnreadableHolds)
	}
	s.setFirewallCondition(ctx, CondFirewallTagGroupUnreadable, len(r.Unreadable) > 0, corrosion.SeverityCritical, unreadable)
	s.setFirewallCondition(ctx, CondFirewallTagsUnreadable, len(r.TagsUnreadable) > 0, corrosion.SeverityCritical,
		tagHoldsText("firewall-tags rows that cannot be read grant no membership; the workload's NICs are held at drop "+
			"on the networks a tag group binds security groups on (all of them while a drop or reject rule names a tag group, "+
			"or every network while a tag group cannot be read). "+
			"Set the tags again with lv firewall tag set", r.TagsUnreadable))
	s.setFirewallCondition(ctx, CondFirewallTagIdentityShared, len(r.SharedIdentity) > 0, corrosion.SeverityCritical,
		tagHoldsText("workloads share a firewall identity with another live workload (a copy): neither is a member of any tag group, "+
			"and every NIC of each is held at drop. lv firewall tag set on one of them gives it its own identity", r.SharedIdentity))
	s.setFirewallCondition(ctx, CondFirewallTagIdentityLost, len(r.IdentityLost) > 0, corrosion.SeverityCritical,
		s.identityLostText(ctx, r.IdentityLost))
}

// tagRefsText names each group or rule reference, the handling, and the
// command that removes the rule.
func tagRefsText(lead string, refs []firewall.TagGroupRef) string {
	if len(refs) == 0 {
		return ""
	}
	var parts []string
	for i, r := range refs {
		if i == conditionListMax {
			parts = append(parts, fmt.Sprintf("and %d more", len(refs)-conditionListMax))
			break
		}
		if r.ID == "" {
			parts = append(parts, fmt.Sprintf("group %s: %s; %s", r.Group, r.Reason, r.Handling))
			continue
		}
		row := firewall.InvalidRow{Table: r.Table, ID: r.ID}
		parts = append(parts, fmt.Sprintf("%s %s (tag:%s, action %q): %s; remove it with `%s`",
			r.Table, r.ID, r.Group, shownAction(r.Action), r.Handling, removeRowCmd(row)))
	}
	return lead + ": " + strings.Join(parts, "; ")
}

// tagHoldsText names each workload, its identity, the other holders and the
// NICs held here.
func tagHoldsText(lead string, holds []firewall.TagWorkloadHold) string {
	if len(holds) == 0 {
		return ""
	}
	var parts []string
	for i, h := range holds {
		if i == conditionListMax {
			parts = append(parts, fmt.Sprintf("and %d more", len(holds)-conditionListMax))
			break
		}
		p := fmt.Sprintf("%s (fw_id %s", fwTagWhoText(h.Kind, h.Host, h.Name), h.FWID)
		if len(h.Holders) > 0 {
			p += "; held by " + strings.Join(h.Holders, ", ")
		}
		if len(h.NICs) > 0 {
			p += "; NICs held at drop here: " + strings.Join(h.NICs, " ")
		} else {
			p += "; no NIC held here"
		}
		parts = append(parts, p+")")
	}
	return lead + ": " + strings.Join(parts, "; ")
}

// identityLostText names each workload whose identity was likely lost, the
// row it was matched to (for a container, the host that row was recorded
// on) and its tags, then the commands: tag rm first, which releases the hold
// and admits the workload to nothing, and tag set with the row's tags, which
// admits it to the groups they match and fits only the same workload.
func (s *Server) identityLostText(ctx context.Context, lost []firewall.TagWorkloadHold) string {
	if len(lost) == 0 {
		return ""
	}
	var parts []string
	for i, w := range lost {
		if i == conditionListMax {
			parts = append(parts, fmt.Sprintf("and %d more", len(lost)-conditionListMax))
			break
		}
		parts = append(parts, s.identityLostNote(ctx, w))
	}
	return "workloads that are members of no tag group although a tags row of an earlier incarnation of their name remains " +
		"(a relocation, a restore or a spec write that did not carry the identity). Their NICs are held at drop on the networks " +
		"a tag group binds security groups on (all of them while a drop or reject rule names a tag group, or every network while " +
		"a tag group cannot be read), and the row is kept until the identity is restored. lv firewall tag rm on the workload " +
		"gives it a new identity with no tags and releases the hold; lv firewall tag set with the row's tags does too, and " +
		"admits it to the groups they match, so run it only when the workload is the one the row was recorded for: " +
		strings.Join(parts, "; ")
}

// identityLostNote is one workload's part of identityLostText.
func (s *Server) identityLostNote(ctx context.Context, w firewall.TagWorkloadHold) string {
	who := fwTagWhoText(w.Kind, w.Host, w.Name)
	recorded := fwTagWhoText(w.Kind, w.RowHost, w.Name)
	note := fmt.Sprintf("%s has no firewall identity; the row of identity %s was recorded for %s", who, w.FWID, recorded)
	var pairs, keys []string
	if rec, ok, err := corrosion.ResolveFirewallTags(ctx, s.db, w.Kind, w.FWID); err != nil {
		slog.Warn("could not read the firewall tags left behind", "kind", w.Kind, "name", w.Name, "fw_id", w.FWID, "error", err)
	} else if ok && !rec.Unreadable {
		for _, k := range slices.Sorted(maps.Keys(rec.Tags)) {
			if corrosion.ValidFirewallTagWord(k) && corrosion.ValidFirewallTagWord(rec.Tags[k]) {
				pairs = append(pairs, k+"="+rec.Tags[k])
				keys = append(keys, k)
			}
		}
	}
	if len(pairs) > 0 {
		target := w.Name
		if w.Kind == corrosion.TagMemberCT {
			target += " --container --host " + w.Host
		}
		note += fmt.Sprintf(" and holds %s. To release the hold (sg.write): lv firewall tag rm %s %s. "+
			"Only if it is that workload: lv firewall tag set %s %s",
			strings.Join(pairs, " "), target, keys[0], target, strings.Join(pairs, " "))
	}
	if len(w.NICs) > 0 {
		note += " (NICs held at drop here: " + strings.Join(w.NICs, " ") + ")"
	} else {
		note += " (no NIC held here)"
	}
	return note
}

// fwTagWhoText names a workload in a condition.
func fwTagWhoText(kind, host, name string) string {
	if kind == corrosion.TagMemberCT {
		return "container " + host + "/" + name
	}
	return "VM " + name
}

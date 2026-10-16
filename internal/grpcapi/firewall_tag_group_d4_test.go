package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// The tag-group conditions follow each pass's report: each is raised with
// its severity and evidence naming what it holds, and resolved once the pass
// reports nothing.
//
// Mutations: drop the shared-identity condition — red; name no holder —
// red; raise the lost identity without the re-apply command — red.
func TestRecordFirewallState_TagGroupConditions(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := context.Background()
	seedTagsFor(t, s, corrosion.TagMemberCT, fwB, map[string]string{"role": "web"}, "web", "node-1")
	cond := func(code string) (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		return row, err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{TagGroups: firewall.TagGroupReport{
		Missing: []firewall.TagGroupRef{{Table: "cluster_firewall_rules", ID: "c1", Group: "gone", Action: "drop",
			Handling: firewall.TagHandlingNoAddress}},
		Unreadable: []firewall.TagGroupRef{{Group: "bad", Reason: "its row cannot be read", Handling: firewall.TagHandlingHeldTagged},
			{Table: "sg_rules", ID: "r2", Group: "bad", Action: "accept", Handling: firewall.TagHandlingEmptySet}},
		TagsUnreadable:  []firewall.TagWorkloadHold{{Kind: "vm", Name: "u", FWID: fwA, NICs: []string{"tap1"}}},
		UnreadableHolds: []firewall.TagWorkloadHold{{Kind: "vm", Name: "t1", FWID: fwB, NICs: []string{"tap7"}}},
		SharedIdentity: []firewall.TagWorkloadHold{{Kind: "vm", Name: "a", FWID: fwA, Holders: []string{"VM a", "VM b"},
			NICs: []string{"tap1", "tap2"}}},
		IdentityLost: []firewall.TagWorkloadHold{{Kind: "ct", Name: "web", Host: s.hostName, FWID: fwB}},
	}})
	for _, c := range []struct {
		code, severity string
		want           []string
	}{
		{CondFirewallTagGroupMissing, corrosion.SeverityCritical,
			[]string{"cluster_firewall_rules c1 (tag:gone", firewall.TagHandlingNoAddress, "lv firewall cluster-rule rm c1"}},
		{CondFirewallTagGroupUnreadable, corrosion.SeverityCritical,
			[]string{"group bad: its row cannot be read; " + firewall.TagHandlingHeldTagged, "sg_rules r2 (tag:bad", "lv sg rule-rm r2",
				"VM t1 (fw_id " + fwB, "NICs held at drop here: tap7"}},
		{CondFirewallTagsUnreadable, corrosion.SeverityCritical,
			[]string{"VM u (fw_id " + fwA, "NICs held at drop here: tap1", "lv firewall tag set",
				"every network while a tag group cannot be read"}},
		{CondFirewallTagIdentityShared, corrosion.SeverityCritical,
			[]string{"VM a (fw_id " + fwA, "held by VM a, VM b", "tap1 tap2"}},
		{CondFirewallTagIdentityLost, corrosion.SeverityWarning,
			[]string{"container " + s.hostName + "/web has no firewall identity", fwB,
				"lv firewall tag set web --container --host " + s.hostName + " role=web"}},
	} {
		row, active := cond(c.code)
		if !active {
			t.Errorf("%s not raised", c.code)
			continue
		}
		if row.Severity != c.severity {
			t.Errorf("%s severity %q, want %q", c.code, row.Severity, c.severity)
		}
		for _, w := range c.want {
			if !strings.Contains(row.Evidence, w) {
				t.Errorf("%s evidence %q lacks %q", c.code, row.Evidence, w)
			}
		}
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{})
	for _, code := range []string{CondFirewallTagGroupMissing, CondFirewallTagGroupUnreadable, CondFirewallTagsUnreadable,
		CondFirewallTagIdentityShared, CondFirewallTagIdentityLost} {
		if _, active := cond(code); active {
			t.Errorf("%s still active once the pass reports nothing", code)
		}
	}
}

// A workload whose tags row cannot be read is listed as unreadable, not as
// having no tags (D3 review m-3): in the list of every tagged workload too.
//
// Mutations: leave Unreadable unset — red; skip unreadable rows in the full
// list — red.
func TestListFirewallTags_AnUnreadableRowIsShownAsUnreadable(t *testing.T) {
	s, _ := tagsServer(t)
	insertTestVM(t, adminCtx(), s.db, "u", s.hostName, "running")
	setVMSpec(t, s, "u", `{"name":"u","firewall_id":"`+fwA+`"}`)
	if err := s.db.Execute(context.Background(), `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'x', 't')`,
		corrosion.FirewallTagsKeyPrefix+"vm/"+fwA, `{"tags":{"role":null}}`); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.GetTags()) != 1 || all.Tags[0].GetWorkload() != "u" || !all.Tags[0].GetUnreadable() {
		t.Fatalf("list all = %v, want u, unreadable", all.GetTags())
	}
	one, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{Kind: "vm", Workload: "u"})
	if err != nil || len(one.GetTags()) != 1 || !one.Tags[0].GetUnreadable() || len(one.Tags[0].GetTags()) != 0 {
		t.Fatalf("list u = %v %v, want it unreadable with no tags", one.GetTags(), err)
	}
}

// A tag set whose copied identity appears only after the check, and whose
// post-mint clear then fails, has committed the mint: it leaves an error
// audit row naming the identity replaced, though no tags were dropped (D3
// re-review 2).
//
// Mutation: audit the error exit only when tags were dropped — red.
func TestSetFirewallTags_AFailedPostMintClearIsAudited(t *testing.T) {
	s, _ := tagsServer(t)
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
	insertTestVM(t, adminCtx(), s.db, "copy", s.hostName, "running")
	first, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	f := first.GetFwId()
	s.testFirewallTagsBeforeMint = func() { setVMSpec(t, s, "copy", `{"name":"copy","firewall_id":"`+f+`"}`) }
	s.testClearFirewallTags = func(context.Context, string, string) error { return errors.New("disk full") }
	_, err = s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"env": "prod"}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("premise: the post-mint clear failed: %v", err)
	}
	got := lastAuditRow(t, s, "firewall.tag.set")
	if !got.found || got.result != "error" || !strings.Contains(got.detail, "replaced_copied_fw_id="+f) ||
		!strings.Contains(got.detail, "fw_id="+vmFWID(t, s, "web")) {
		t.Fatalf("the failed set's audit row: %+v", got)
	}
}

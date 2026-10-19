package firewall

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// C2: a stored "<verdict>+log" action parses into the verdict plus Log;
// nothing else does.
//
// Mutations: parse any "+" suffix — drop+foo reads as a logged drop, red;
// leave the suffix on the action — the action is not Drop, red.
func TestFromCorrosionRule_LogSuffix(t *testing.T) {
	for action, want := range map[string]struct {
		act Action
		log bool
	}{
		"drop+log":   {Drop, true},
		"Accept+LOG": {Accept, true},
		"reject+log": {Reject, true},
		"drop":       {Drop, false},
		"":           {Accept, false},
		"drop+foo":   {Action("drop+foo"), false},
		"+log":       {Action("+log"), false},
	} {
		r := FromCorrosionRule("ingress", "tcp", "22", "", action)
		if r.Action != want.act || r.Log != want.log {
			t.Errorf("FromCorrosionRule(action %q) = %q log=%v, want %q log=%v", action, r.Action, r.Log, want.act, want.log)
		}
	}
}

// C2: the loader hands the renderer a logged row of every tier as its plain
// verdict with Log set and the row's id (the log prefix names it); a bare
// "+log" or another suffix is unreadable and left out (never read as an
// accept).
//
// Mutations: drop the ID — the id is empty, red; judge the stored action
// rather than the verdict — every logged row is left out, red; parse a bare
// "+log" as a logged accept — it is rendered, red.
func TestLoader_LoggedRowsCarryLogAndID(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	const now = "2026-10-15T00:00:00Z"
	for _, r := range []struct{ id, action string }{{"c-log", "drop+log"}, {"c-bare", "+log"}, {"c-foo", "drop+foo"}} {
		rawRow(t, db, `INSERT INTO cluster_firewall_rules
			(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
			VALUES (?, 'ingress', 'tcp', '22', '10.0.0.0/8', ?, 100, '', '', ?, 1)`, r.id, r.action, now)
	}
	rawRow(t, db, `INSERT INTO host_firewall_rules
		(id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('h-log', 'host-a', 'egress', 'udp', '53', '', 'accept+log', 100, '', '', ?, 1)`, now)
	rawRow(t, db, `INSERT INTO security_groups (id, name, stack_name, created_at, updated_at) VALUES ('sg1', 'web', '', ?, 1)`, now)
	rawRow(t, db, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		VALUES ('s-log', 'sg1', 'ingress', 'tcp', '80', '', 'reject+log', 100, ?, 1)`, now)

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ClusterRules) != 1 {
		t.Fatalf("cluster rules = %+v, want only the logged drop", plan.ClusterRules)
	}
	if r := plan.ClusterRules[0]; r.Action != Drop || !r.Log || r.ID != "c-log" {
		t.Errorf("cluster rule = %+v, want a logged drop with id c-log", r)
	}
	if len(plan.HostRules) != 1 || plan.HostRules[0].Action != Accept || !plan.HostRules[0].Log || plan.HostRules[0].ID != "h-log" {
		t.Errorf("host rules = %+v, want a logged accept with id h-log", plan.HostRules)
	}
	var sgRules []Rule
	for _, sg := range plan.SecurityGroups {
		sgRules = append(sgRules, sg.Rules...)
	}
	if len(sgRules) != 1 || sgRules[0].Action != Reject || !sgRules[0].Log || sgRules[0].ID != "s-log" {
		t.Errorf("sg rules = %+v, want a logged reject with id s-log", sgRules)
	}
	left := map[string]bool{}
	for _, inv := range plan.InvalidRows {
		left[inv.ID] = inv.Handling == HandlingLeftOut
	}
	for _, id := range []string{"c-bare", "c-foo"} {
		if !left[id] {
			t.Errorf("row %s: invalid rows %+v, want it left out", id, plan.InvalidRows)
		}
	}
	if _, err := Render(plan); err != nil {
		t.Errorf("render: %v", err)
	}
}

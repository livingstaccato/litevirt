package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

// The teardown record crosses a rolling upgrade both ways. A previous
// release reads it into {teardown, keep_disks} with encoding/json, which
// ignores the firewall field, so it reads this build's disk choice as before.
// A teardown without the firewall authority writes exactly the record a
// previous release writes, and a previous release's record reads here as a
// teardown without it.
//
// Mutations: drop omitempty from the firewall field — the record of a
// teardown without the authority differs from a previous release's, red.
// Read a previous release's record as authorized — red.
func TestStackTeardownRecord_CrossesARollingUpgrade(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	if err := UpsertStack(ctx, c, StackRecord{Name: "app", State: "active"}); err != nil {
		t.Fatal(err)
	}
	// previousRelease is the record as a previous release declares it.
	type previousRelease struct {
		Teardown  string `json:"teardown"`
		KeepDisks bool   `json:"keep_disks"`
	}
	read := func() (string, StackRecord) {
		t.Helper()
		rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = 'stack_teardown/app'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("teardown record: %v %v", rows, err)
		}
		st, err := GetStack(ctx, c, "app")
		if err != nil || st == nil {
			t.Fatalf("stack: %+v %v", st, err)
		}
		return rows[0].String("value"), *st
	}

	for _, removes := range []bool{false, true} {
		if err := MarkStackDeleting(ctx, c, "app", true, removes, "node-0"); err != nil {
			t.Fatal(err)
		}
		v, st := read()
		var old previousRelease
		if err := json.Unmarshal([]byte(v), &old); err != nil {
			t.Fatalf("a previous release cannot read %s: %v", v, err)
		}
		if old.Teardown != st.UpdatedAt || !old.KeepDisks {
			t.Errorf("a previous release reads %s as %+v, want this teardown keeping its disks", v, old)
		}
		if !removes {
			want, _ := json.Marshal(previousRelease{Teardown: st.UpdatedAt, KeepDisks: true})
			if v != string(want) {
				t.Errorf("the record of a teardown without sg.write is %s, want a previous release's %s", v, want)
			}
		}
		if got, _ := StackTeardownRemovesFirewall(ctx, c, st); got != removes {
			t.Errorf("removes firewall = %v for a teardown recorded with %v", got, removes)
		}
	}

	// A previous release's record of this teardown: no authority.
	_, st := read()
	old, _ := json.Marshal(previousRelease{Teardown: st.UpdatedAt})
	if _, err := c.DB().ExecContext(ctx, `UPDATE cluster_policies SET value = ? WHERE key = 'stack_teardown/app'`, string(old)); err != nil {
		t.Fatal(err)
	}
	if got, why := StackTeardownRemovesFirewall(ctx, c, st); got || why == "" {
		t.Errorf("a previous release's record reads as removes firewall = %v (%q)", got, why)
	}
	if deletes, proven, _ := StackTeardownDeletesDisks(ctx, c, st); !deletes || !proven {
		t.Errorf("a previous release's disk choice reads as deletes %v proven %v", deletes, proven)
	}
}

// A stack whose file no longer asks for the default-deny, but whose last
// deploy with sg.write did, is still an heir of the deny: a stale deploy
// does not withdraw the ask. An intent this build cannot read asks for it.
//
// Mutation: drop the intent from otherStackWants — the deny is removed, red.
func TestStackFirewallIntent_KeepsADefaultDenyAsk(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, value string }{
		{"recorded", ""},
		{"unreadable", `not json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewTestClientT(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			c.SetClusterPolicyGate(func() bool { return true })
			for _, st := range []StackRecord{{Name: "base", ComposeYAML: "deny", State: "active"}, {Name: "edge", ComposeYAML: "", State: "active"}} {
				if err := UpsertStack(ctx, c, st); err != nil {
					t.Fatal(err)
				}
			}
			if err := SetFirewallDefault(ctx, c, "cluster", true, "base"); err != nil {
				t.Fatal(err)
			}
			if tc.value == "" {
				edge, _ := GetStack(ctx, c, "edge")
				if err := SetStackFirewallIntent(ctx, c, edge, true, true, "node-0"); err != nil {
					t.Fatal(err)
				}
			} else if err := c.Execute(ctx, clusterPolicyUpsertSQL, stackFirewallKeyPrefix+"edge", tc.value, "node-0", c.NowTS()); err != nil {
				t.Fatal(err)
			}
			read := func(y string) (bool, map[string]bool, error) { return y == "deny", nil, nil }
			if err := DeleteStackFirewallDefaults(ctx, c, "base", read); err != nil {
				t.Fatal(err)
			}
			if d, _ := GetFirewallDefault(ctx, c, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "edge" {
				t.Fatalf("the cluster default after base went = %+v, want deny handed to edge", d)
			}
		})
	}
}

// A firewall intent stands for the stack's name until a caller with
// sg.write at the root changes it: a teardown without that authority, which
// a node whose replica holds an older file may begin, leaves it, while the
// stack is being torn down and after it is tombstoned, and so does a
// teardown record this build cannot read; a teardown with it clears it, in
// its own batch; an Admin redeploy after that records anew.
//
// Mutations: clear the intent on every teardown — "without sg.write", red.
// Never clear it — "with sg.write", red. Leave a torn-down stack out of
// StackFirewallIntents — "tombstoned", red.
func TestStackFirewallIntent_StandsUntilAnAdminChangesIt(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	if err := UpsertStack(ctx, c, StackRecord{Name: "s", State: "active"}); err != nil {
		t.Fatal(err)
	}
	st, _ := GetStack(ctx, c, "s")
	stands := func(what string, want bool) {
		t.Helper()
		got, err := standingDenyAsk(ctx, c, "s")
		if err != nil {
			t.Fatal(err)
		}
		all, err := StackFirewallIntents(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, listed := all["s"]; got != want || listed != want {
			t.Errorf("%s: the deny ask stands = %v (listed %v), want %v", what, got, listed, want)
		}
	}
	if err := SetStackFirewallIntent(ctx, c, st, true, true, "node-0"); err != nil {
		t.Fatal(err)
	}
	stands("recorded", true)
	if err := MarkStackDeleting(ctx, c, "s", false, false, "node-1"); err != nil {
		t.Fatal(err)
	}
	stands("without sg.write, deleting", true)
	if err := DeleteStackRecord(ctx, c, "s"); err != nil {
		t.Fatal(err)
	}
	stands("without sg.write, tombstoned", true)
	if _, err := c.DB().ExecContext(ctx, `UPDATE cluster_policies SET value = 'garbled' WHERE key = 'stack_teardown/s'`); err != nil {
		t.Fatal(err)
	}
	stands("an unreadable teardown record", true)
	if err := MarkStackDeleting(ctx, c, "s", false, true, "node-0"); err != nil {
		t.Fatal(err)
	}
	stands("with sg.write", false)
	if err := UpsertStack(ctx, c, StackRecord{Name: "s", State: "active"}); err != nil {
		t.Fatal(err)
	}
	st, _ = GetStack(ctx, c, "s")
	if err := SetStackFirewallIntent(ctx, c, st, false, true, "node-0"); err != nil {
		t.Fatal(err)
	}
	stands("an Admin redeploy after the teardown", true)
}

// A cluster default-deny owned by a torn-down stack whose standing intent
// asks for it stays with that stack: handing it to another torn-down stack
// with a standing ask would hand it back on the next pass, a write each time.
//
// Mutation: drop the standing-owner check from SweepOrphanStackRows — the
// owner moves, red.
func TestSweepOrphanStackRows_KeepsADenyWithAStandingOwner(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	for _, name := range []string{"a", "b"} {
		if err := UpsertStack(ctx, c, StackRecord{Name: name, State: "active"}); err != nil {
			t.Fatal(err)
		}
		st, _ := GetStack(ctx, c, name)
		if err := SetStackFirewallIntent(ctx, c, st, false, true, "node-0"); err != nil {
			t.Fatal(err)
		}
		if err := MarkStackDeleting(ctx, c, name, false, false, "node-1"); err != nil {
			t.Fatal(err)
		}
		if err := DeleteStackRecord(ctx, c, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetFirewallDefault(ctx, c, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	read := func(string) (bool, map[string]bool, error) { return false, nil, nil }
	for pass := 0; pass < 2; pass++ {
		orphan, err := SweepOrphanStackRows(ctx, c, read)
		if err != nil {
			t.Fatal(err)
		}
		if d, _ := GetFirewallDefault(ctx, c, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "a" || orphan != "" {
			t.Fatalf("pass %d: the cluster default is %+v (orphan %q), want deny kept by a", pass+1, d, orphan)
		}
	}
}

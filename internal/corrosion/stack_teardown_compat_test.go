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
		{"recorded", `{"firewall":true,"default_deny":true}`},
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
			if err := c.Execute(ctx, clusterPolicyUpsertSQL, stackFirewallKeyPrefix+"edge", tc.value, "node-0", c.NowTS()); err != nil {
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

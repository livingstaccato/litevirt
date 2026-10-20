package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The teardown of a stack whose firewall this host holds, begun by a caller
// without sg.write at the cluster root, or by one this host cannot tell held
// it, keeps that firewall: an entry node whose replica lags may see no
// firewall for the stack (an older record without one) and authorize a
// teardown that every peer applies by name. The stack stays "deleting" and
// stack.firewall_teardown_held names who can finish it. Every marker this
// host may receive is covered: a teardown's record written by this build
// (with and without the authority), a previous release's record (no
// authority field), none at all (a previous release before cluster_policies
// could be written, or the gate closed), and another teardown's record.
//
// Mutations: remove the firewall whatever the teardown's authority
// (stackFirewallHold returns "") — every held case, red. Hold whatever the
// authority (ignore StackTeardownRemovesFirewall) — "authorized", red.
// Accept another teardown's record (drop the stamp check in stackTeardown) —
// "authorized, another teardown's record", red. Treat a missing record as
// authorized — "no record", red. Treat a record this build cannot read as
// authorized — "an unreadable record", red. Ignore the stored file (rows only) —
// "file declares a default-deny, no rows", red.
func TestStackReconciler_KeepsAFirewallTheTeardownMayNotRemove(t *testing.T) {
	const denyFile = "name: app\nfirewall:\n  default-deny: true\n"
	for _, tc := range []struct {
		name string
		file string
		sg   bool
		// mark writes the teardown's marker over the seeded "deleting" row.
		mark func(t *testing.T, db *corrosion.Client)
		held bool
	}{
		{"authorized", "", true, markTeardown(true, true), false},
		{"without sg.write", "", true, markTeardown(true, false), true},
		{"no record", "", true, markTeardown(false, true), true},
		{"an unreadable record", "", true, func(t *testing.T, db *corrosion.Client) {
			markTeardown(true, true)(t, db)
			if _, err := db.DB().ExecContext(context.Background(),
				`UPDATE cluster_policies SET value = 'garbled' WHERE key = 'stack_teardown/app'`); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a previous release's record", "", true, markPreviousRelease, true},
		{"authorized, another teardown's record", "", true, func(t *testing.T, db *corrosion.Client) {
			markTeardown(true, true)(t, db)
			// Re-stamped since by another write of the row: the record speaks
			// for a teardown that is not this one.
			setStackUpdatedAt(t, db, "app", time.Now().Add(-time.Hour))
		}, true},
		{"file declares a default-deny, no rows", denyFile, false, markTeardown(true, false), true},
		{"unreadable file, no rows", "vms: [a, b]\n", false, markTeardown(true, false), true},
		{"no firewall anywhere, without sg.write", "name: app\n", false, markTeardown(true, false), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := seedDeletingStack(t, false, false)
			if tc.file != "" {
				if _, err := db.DB().ExecContext(ctx, `UPDATE stacks SET compose_yaml = ? WHERE name = 'app'`, tc.file); err != nil {
					t.Fatal(err)
				}
			}
			if tc.sg {
				if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg1", Name: "web", StackName: "app"}); err != nil {
					t.Fatal(err)
				}
				if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, "app"); err != nil {
					t.Fatal(err)
				}
			}
			tc.mark(t, db)
			r := NewStackReconciler("node-0", db)
			r.SetCleaner(&failingStackCleaner{})
			r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
			r.ReconcileOnce(ctx)

			st, _ := corrosion.GetStack(ctx, db, "app")
			row, found, err := corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, "app")
			if err != nil {
				t.Fatal(err)
			}
			open := found && row.Lifecycle != corrosion.ConditionResolved
			if !tc.held {
				if st != nil {
					t.Fatalf("the teardown was not finished: %+v", st)
				}
				if sgs, _ := corrosion.ListSecurityGroups(ctx, db, "app"); len(sgs) != 0 {
					t.Errorf("an authorized teardown left the security groups: %+v", sgs)
				}
				if d, _ := corrosion.GetFirewallDefault(ctx, db, "cluster"); d != nil && d.DefaultDeny {
					t.Errorf("an authorized teardown left the default-deny: %+v", d)
				}
				if open {
					t.Errorf("the held-firewall condition is open for a teardown that finished: %+v", row)
				}
				return
			}
			if st == nil || st.State != "deleting" {
				t.Fatalf("stack = %+v, want it kept \"deleting\" with its firewall", st)
			}
			if tc.sg {
				if sgs, _ := corrosion.ListSecurityGroups(ctx, db, "app"); len(sgs) != 1 {
					t.Errorf("the teardown removed the security group it may not: %+v", sgs)
				}
				if d, _ := corrosion.GetFirewallDefault(ctx, db, "cluster"); d == nil || !d.DefaultDeny {
					t.Errorf("the teardown removed the default-deny it may not: %+v", d)
				}
			}
			if !open {
				t.Fatalf("no open %s condition for a held teardown", firewallHoldCode)
			}
			if !strings.Contains(row.Evidence, "lv compose down --name app") || !strings.Contains(row.Evidence, "sg.write") {
				t.Errorf("the condition does not name the remedy: %s", row.Evidence)
			}
		})
	}
}

// An Admin's compose down finishes a held teardown: a new marker with the
// authority, which the next pass acts on, and the condition resolves.
//
// Mutation: never resolve the condition — red.
func TestStackReconciler_AnAdminDownFinishesAHeldTeardown(t *testing.T) {
	ctx := context.Background()
	db := seedDeletingStack(t, false, false)
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg1", Name: "web", StackName: "app"}); err != nil {
		t.Fatal(err)
	}
	markTeardown(true, false)(t, db)
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(&failingStackCleaner{})
	r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
	r.ReconcileOnce(ctx)
	if st, _ := corrosion.GetStack(ctx, db, "app"); st == nil {
		t.Fatal("setup: the teardown was not held")
	}

	markTeardown(true, true)(t, db)
	r.ReconcileOnce(ctx)
	if st, _ := corrosion.GetStack(ctx, db, "app"); st != nil {
		t.Fatalf("the Admin's teardown was not finished: %+v", st)
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, db, "app"); len(sgs) != 0 {
		t.Errorf("the Admin's teardown left the security group: %+v", sgs)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, "app")
	if err != nil || !found || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the held-firewall condition = %+v (found %v, err %v), want resolved", row, found, err)
	}
}

// markTeardown marks app "deleting" as DeleteStack does, with the record
// when cluster_policies may be written (gate), and the caller's authority.
func markTeardown(gate, removesFirewall bool) func(t *testing.T, db *corrosion.Client) {
	return func(t *testing.T, db *corrosion.Client) {
		t.Helper()
		db.SetClusterPolicyGate(func() bool { return gate })
		if err := corrosion.MarkStackDeleting(context.Background(), db, "app", false, removesFirewall, "node-0"); err != nil {
			t.Fatal(err)
		}
	}
}

// markPreviousRelease marks app "deleting" with the record a previous
// release's DeleteStack writes: its disk choice, no firewall authority.
func markPreviousRelease(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	now := db.NowTS()
	if _, err := db.DB().ExecContext(ctx, `UPDATE stacks SET state = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`, "deleting", now, "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at) VALUES (?, ?, ?, ?, NULL)`,
		"stack_teardown/app", `{"teardown":"`+now+`","keep_disks":false}`, "node-0", now); err != nil {
		t.Fatal(err)
	}
}

// A stack torn down while this host holds a security group it owns, written
// before the tombstone, is reported; one written after it (a new deploy of
// the name, which writes its rows before its record) is not. The condition
// resolves once the rows are gone.
//
// Mutations: drop the "written before the tombstone" check — the new
// deploy's row is reported, red. Never report — red.
func TestStackReconciler_ReportsTheFirewallATornDownStackLeft(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old", "redeploying"} {
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: name, ComposeYAML: "name: " + name + "\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-old", Name: "old-web", StackName: "old"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old", "redeploying"} {
		if err := corrosion.DeleteStackRecord(ctx, db, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-new", Name: "new-web", StackName: "redeploying"}); err != nil {
		t.Fatal(err)
	}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(&failingStackCleaner{})
	r.ReconcileOnce(ctx)
	open := func(stack string) (bool, string) {
		row, found, err := corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, stack)
		if err != nil {
			t.Fatal(err)
		}
		return found && row.Lifecycle != corrosion.ConditionResolved, row.Evidence
	}
	if ok, ev := open("old"); !ok || !strings.Contains(ev, "lv compose down --name old") {
		t.Fatalf("the torn-down stack's group is not reported: open %v, %s", ok, ev)
	}
	if ok, ev := open("redeploying"); ok {
		t.Errorf("a new deploy's group is reported as a torn-down stack's: %s", ev)
	}
	if err := corrosion.DeleteStackFirewallRows(ctx, db, "old"); err != nil {
		t.Fatal(err)
	}
	r.ReconcileOnce(ctx)
	if ok, ev := open("old"); ok {
		t.Errorf("the condition stayed open once the group was removed: %s", ev)
	}
}

// A live stack whose file no longer declares what its last deploy with
// sg.write declared (StackFirewallIntent) is reported, and resolves once the
// file declares it again; a teardown without sg.write holds a firewall the
// intent alone declares, and one with it clears the intent.
//
// A later deployment of the name does not inherit it, and a stored file this
// build cannot read keeps the condition open.
//
// Mutations: never report a withdrawn firewall — red. Drop the intent from
// stackFirewallHold — "held by the intent alone", red. Drop the deployment
// binding (stackFirewallIntentApplies true) — "a later deployment", red.
// Skip an unreadable file — "an unreadable file", red.
func TestStackReconciler_TheFirewallIntentOutlivesAStaleFile(t *testing.T) {
	ctx := context.Background()
	newDB := func() *corrosion.Client {
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetClusterPolicyGate(func() bool { return true })
		return db
	}
	open := func(db *corrosion.Client, stack string) (bool, string) {
		row, found, err := corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, stack)
		if err != nil {
			t.Fatal(err)
		}
		return found && row.Lifecycle != corrosion.ConditionResolved, row.Evidence
	}
	t.Run("withdrawn", func(t *testing.T) {
		db := newDB()
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		setIntent(t, db, "edge", true, true)
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&failingStackCleaner{})
		r.ReconcileOnce(ctx)
		if ok, ev := open(db, "edge"); !ok || !strings.Contains(ev, "lv compose up") || !strings.Contains(ev, "lv compose down --name edge") {
			t.Fatalf("a withdrawn default-deny is not reported: open %v, %s", ok, ev)
		} else if !strings.Contains(ev, "failed after writing its firewall") {
			// An Admin redeploy that failed after its persist leaves the
			// same state: nothing replaced the file.
			t.Errorf("the condition does not name a recorded deploy that failed: %s", ev)
		}
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\nfirewall:\n  default-deny: true\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		r.ReconcileOnce(ctx)
		if ok, ev := open(db, "edge"); ok {
			t.Errorf("the condition stayed open once the file declared the deny again: %s", ev)
		}
	})
	t.Run("held by the intent alone", func(t *testing.T) {
		db := seedDeletingStack(t, false, false)
		db.SetClusterPolicyGate(func() bool { return true })
		setIntent(t, db, "app", false, true)
		markTeardown(true, false)(t, db)
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&failingStackCleaner{})
		r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
		r.ReconcileOnce(ctx)
		if st, _ := corrosion.GetStack(ctx, db, "app"); st == nil || st.State != "deleting" {
			t.Fatalf("stack = %+v, want it kept \"deleting\"", st)
		}
		if ok, _ := open(db, "app"); !ok {
			t.Fatal("no condition for a teardown the intent holds")
		}
	})
	t.Run("a later deployment does not inherit it", func(t *testing.T) {
		db := seedDeletingStack(t, false, false)
		db.SetClusterPolicyGate(func() bool { return true })
		setIntent(t, db, "app", true, false)
		markTeardown(true, true)(t, db)
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&failingStackCleaner{})
		r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
		r.ReconcileOnce(ctx)
		if st, _ := corrosion.GetStack(ctx, db, "app"); st != nil {
			t.Fatalf("the authorized teardown did not finish: %+v", st)
		}
		// The name is deployed again: another deployment.
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "app", ComposeYAML: "name: app\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		st, _ := corrosion.GetStack(ctx, db, "app")
		if in, applies, err := corrosion.StackFirewallIntentOf(ctx, db, *st); err != nil || applies {
			t.Errorf("the torn-down deployment's intent %+v applies to the next one (err %v)", in, err)
		}
		r.ReconcileOnce(ctx)
		if ok, ev := open(db, "app"); ok {
			t.Errorf("the next deployment is reported for the last one's intent: %s", ev)
		}
	})
	t.Run("an unreadable file keeps the condition open", func(t *testing.T) {
		db := newDB()
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		setIntent(t, db, "edge", true, true)
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&failingStackCleaner{})
		r.ReconcileOnce(ctx)
		if ok, _ := open(db, "edge"); !ok {
			t.Fatal("setup: no condition for the withdrawn intent")
		}
		if _, err := db.DB().ExecContext(ctx, `UPDATE stacks SET compose_yaml = ? WHERE name = 'edge'`, "vms: [a, b]\n"); err != nil {
			t.Fatal(err)
		}
		r.ReconcileOnce(ctx)
		if ok, ev := open(db, "edge"); !ok || !strings.Contains(ev, "cannot be read") {
			t.Errorf("an unreadable file resolved the condition, or it does not say why: open %v, %s", ok, ev)
		}
	})
}

// setIntent records the firewall intent of stack's current deployment, as an
// Admin's deploy does.
func setIntent(t *testing.T, db *corrosion.Client, stack string, firewall, deny bool) {
	t.Helper()
	db.SetClusterPolicyGate(func() bool { return true })
	st, err := corrosion.GetStack(context.Background(), db, stack)
	if err != nil || st == nil {
		t.Fatalf("stack %s: %+v %v", stack, st, err)
	}
	if err := corrosion.SetStackFirewallIntent(context.Background(), db, st, firewall, deny, "node-0"); err != nil {
		t.Fatal(err)
	}
}

// A pass that cannot read the stacks' firewall intents leaves an open
// condition as it is: it does not know the stack is no longer held, and a
// resolve on one failed read would raise the condition again on the next
// pass with a new FirstSeen.
//
// Mutation: resolve whatever the reports could read — both cases, red.
func TestStackReconciler_AFailedReadLeavesTheConditionOpen(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, db *corrosion.Client)
	}{
		{"withdrawn", func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
				t.Fatal(err)
			}
			setIntent(t, db, "edge", true, true)
		}},
		{"torn down", func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
				t.Fatal(err)
			}
			setIntent(t, db, "edge", true, true)
			if err := corrosion.DeleteStackRecord(ctx, db, "edge"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatal(err)
			}
			db.SetClusterPolicyGate(func() bool { return true })
			tc.setup(t, db)
			r := NewStackReconciler("node-0", db)
			r.SetCleaner(&failingStackCleaner{})
			r.ReconcileOnce(ctx)
			row, found, err := corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, "edge")
			if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
				t.Fatalf("setup: condition = %+v (found %v, err %v), want open", row, found, err)
			}
			// The intent may stand after a teardown with sg.write too (a
			// previous release's, or one an Admin redeploy's intent won):
			// the condition does not say who tore it down.
			if strings.Contains(row.Evidence, "teardown without sg.write") {
				t.Errorf("the condition blames a teardown without sg.write: %s", row.Evidence)
			}
			first := row.FirstSeen
			if _, err := db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies RENAME TO cluster_policies_away`); err != nil {
				t.Fatal(err)
			}
			r.ReconcileOnce(ctx)
			if _, err := db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies_away RENAME TO cluster_policies`); err != nil {
				t.Fatal(err)
			}
			row, found, err = corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, "edge")
			if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
				t.Errorf("a pass that could not read the intents resolved the condition: %+v (found %v, err %v)", row, found, err)
			}
			r.ReconcileOnce(ctx)
			row, _, _ = corrosion.GetHealthCondition(ctx, db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, "edge")
			if row.FirstSeen != first {
				t.Errorf("FirstSeen = %q after the failed read, want %q", row.FirstSeen, first)
			}
		})
	}
}

// No stack reconciler pass removes the cluster default-deny on its own: a
// removal decided on one replica's view can outrank a newer ask it has not
// seen. A deny a live stack owns that nothing asks for any more is kept and
// reported (stack.firewall_deny_unasked, naming the stack and
// `lv firewall default-deny off`), as one a torn-down stack owns is
// (firewall.default_deny_orphaned). The condition resolves once an operator
// settles the deny.
//
// Mutations: remove an unasked deny in the reconcile pass — "live owner",
// red. Never raise the condition — red.
func TestStackReconciler_NeverWithdrawsADenyOnItsOwn(t *testing.T) {
	ctx := context.Background()
	newDB := func(t *testing.T) *corrosion.Client {
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetClusterPolicyGate(func() bool { return true })
		return db
	}
	pass := func(t *testing.T, db *corrosion.Client) *corrosion.FirewallDefault {
		t.Helper()
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&failingStackCleaner{})
		for i := 0; i < 3; i++ {
			r.ReconcileOnce(ctx)
		}
		d, err := corrosion.GetFirewallDefault(ctx, db, "cluster")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Run("live owner", func(t *testing.T) {
		db := newDB(t)
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, "edge"); err != nil {
			t.Fatal(err)
		}
		setIntent(t, db, "edge", false, false)
		if d := pass(t, db); d == nil || !d.DefaultDeny || d.StackName != "edge" {
			t.Fatalf("the cluster default after the passes = %+v, want edge's deny kept", d)
		}
		row, found, err := corrosion.GetHealthCondition(ctx, db, unaskedDenyEvaluator, unaskedDenyCode, unaskedDenyKind, unaskedDenySubject)
		if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved ||
			!strings.Contains(row.Evidence, `edge`) || !strings.Contains(row.Evidence, "lv firewall default-deny off") {
			t.Fatalf("condition = %+v (found %v, err %v), want it open naming edge and the exit", row, found, err)
		}
		if err := corrosion.SetFirewallDefault(ctx, db, "cluster", false, ""); err != nil {
			t.Fatal(err)
		}
		if d := pass(t, db); d == nil || d.DefaultDeny {
			t.Fatalf("the operator's allow = %+v after the passes", d)
		}
		row, _, _ = corrosion.GetHealthCondition(ctx, db, unaskedDenyEvaluator, unaskedDenyCode, unaskedDenyKind, unaskedDenySubject)
		if row.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("the condition stayed open after `lv firewall default-deny off`: %+v", row)
		}
	})
	t.Run("torn-down owner", func(t *testing.T) {
		db := newDB(t)
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "gone", ComposeYAML: "name: gone\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, "gone"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, db, "gone"); err != nil {
			t.Fatal(err)
		}
		if d := pass(t, db); d == nil || !d.DefaultDeny {
			t.Fatalf("the cluster default after the passes = %+v, want the deny kept", d)
		}
	})
}

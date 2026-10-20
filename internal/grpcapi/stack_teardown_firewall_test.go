package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A compose down without sg.write at the root runs only where the entry node
// sees no firewall for the stack, and records that its caller lacked the
// authority, so a peer's reconciler leaves the firewall it holds. The rows
// of a newer deploy can also reach the entry node during the teardown: it
// then leaves them too, says so, and keeps the stack "deleting". An Admin's
// down records the authority and removes them.
//
// Mutations: record every teardown with the authority — the Operator's
// record says it may remove the firewall, red. Drop the check before the
// entry node removes the firewall rows itself — the group the Operator's
// down met goes, red.
func TestDeleteStack_ATeardownWithoutSGWriteLeavesAFirewallThatArrivesDuringIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin bool
	}{{"operator", false}, {"admin", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, opal, ada := stackFirewallFixture(t)
			s.virt = libvirtfake.New()
			s.db.SetClusterPolicyGate(func() bool { return true })
			if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "plain", ComposeYAML: "name: plain\n", State: "active"}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "plain-web-1", StackName: "plain",
				HostName: s.hostName, State: "stopped", Spec: "{}"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			caller := opal
			if tc.admin {
				caller = ada
			}
			// A newer deploy's group reaches this node while the down runs;
			// the teardown's record is read there, while it is "deleting".
			removes := false
			s.SetStackMemberDeleteHookForTest(func(string) {
				if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg-plain", Name: "plain-web", StackName: "plain"}); err != nil {
					t.Error(err)
				}
				st, _ := corrosion.GetStack(ctx, s.db, "plain")
				if st != nil {
					removes, _ = corrosion.StackTeardownRemovesFirewall(ctx, s.db, *st)
				}
			})
			stream := &mockDeleteStream{ctx: caller}
			if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "plain"}, stream); err != nil {
				t.Fatalf("compose down of a stack with no firewall here: %v", err)
			}
			if removes != tc.admin {
				t.Errorf("the teardown records it may remove the firewall = %v, want %v", removes, tc.admin)
			}
			g, _ := corrosion.GetSecurityGroup(ctx, s.db, "sg-plain")
			st, _ := corrosion.GetStack(ctx, s.db, "plain")
			if tc.admin {
				if g != nil || st != nil {
					t.Fatalf("the Admin's down left group %+v, stack %+v", g, st)
				}
				return
			}
			if g == nil {
				t.Fatal("the down of a caller without sg.write removed a firewall row that arrived during it")
			}
			if st == nil || st.State != stackStateDeleting {
				t.Fatalf("stack = %+v, want it kept %q", st, stackStateDeleting)
			}
			said := false
			for _, p := range stream.sent {
				said = said || (p.GetStatus() == "error" && strings.Contains(p.GetError(), "sg.write"))
			}
			if !said {
				t.Errorf("the down did not say why the firewall stays: %+v", stream.sent)
			}
		})
	}
}

// A deploy of a stack whose teardown keeps its firewall
// (stack.firewall_teardown_held) is refused naming the condition and the
// Admin's exit: that teardown does not finish by itself, so "wait until it
// is gone" would be a wait without end. Any other teardown keeps the wait.
//
// Mutation: drop the held branch — the refusal says to wait, red.
func TestDeployStack_ARefusalOverAHeldTeardownNamesTheAdminExit(t *testing.T) {
	ctx := context.Background()
	s, _, ada := stackFirewallFixture(t)
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "held", ComposeYAML: "name: held\n", State: stackStateDeleting}); err != nil {
		t.Fatal(err)
	}
	deploy := func() error {
		return s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: held\n"}, &mockDeployStreamR2{ctx: ada})
	}
	if err := deploy(); err == nil || !strings.Contains(err.Error(), "wait until") {
		t.Fatalf("a deploy over a teardown in progress: %v, want the wait", err)
	}
	ts := "2026-10-19T00:00:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: corrosion.StackFirewallHoldEvaluator, Code: corrosion.StackFirewallHoldCode,
		SubjectKind: corrosion.StackFirewallHoldKind, SubjectID: "held", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, FirstSeen: ts, ConfirmedAt: ts, LastSeen: ts, Evidence: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	err := deploy()
	if err == nil || !strings.Contains(err.Error(), corrosion.StackFirewallHoldCode) ||
		!strings.Contains(err.Error(), "`lv compose down --name held`") || strings.Contains(err.Error(), "wait until") {
		t.Fatalf("a deploy over a held teardown: %v, want the condition and the Admin's exit", err)
	}
}

// What a stack's firewall is, as its last deploy by a caller with sg.write
// at the root declared it, is recorded by that deploy only; a deploy without
// it is refused when the record declares a firewall, even where neither the
// stack's rows nor its file here do (a node whose replica holds an older
// file). An Admin's teardown clears it.
//
// Mutations: record the intent for any caller — the Operator's deploy
// records it, red. Drop the intent from stackFirewallRefusal — the
// Operator's redeploy is allowed, red. Never clear it on an Admin's
// teardown — the Operator's deploys after that teardown are refused, red.
func TestDeployStack_TheFirewallIntentIsTheAdminsToChange(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: fw\nfirewall:\n  default-deny: true\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("the Admin deploys: %v", err)
	}
	if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "fw"); !found || !in.DefaultDeny || !in.Firewall {
		t.Fatalf("the Admin's deploy recorded intent %+v (found %v), want the default-deny", in, found)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: plain\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
		t.Fatalf("the Operator deploys a stack with no firewall: %v", err)
	}
	if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "plain"); found {
		t.Fatalf("a deploy without sg.write recorded intent %+v", in)
	}

	// As a node holding an older file sees fw: no firewall in the file and
	// no row here; the intent is all that says it has one.
	if err := corrosion.DeleteStackFirewall(ctx, s.db, "fw", nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fw", ComposeYAML: "name: fw\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: fw\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator redeploys over the Admin's intent", err)
	if !strings.Contains(err.Error(), "last deploy by a caller with sg.write") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// Once an Admin tears fw down, the name is the Operator's to deploy
	// again: the teardown cleared the intent.
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fw"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("the Admin tears fw down: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: fw\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
			t.Fatalf("the Operator's deploy %d of fw after the Admin's teardown: %v", i+1, err)
		}
	}
}

// What a teardown leaves of a stack's intent decides who may deploy the name
// next. A first Admin deploy that failed before it recorded the stack leaves
// none, and an Admin's teardown on another host of this release clears it:
// neither blocks a later Operator stack of the same name. One a
// previous-release teardown left (it clears nothing) stays in force for the
// name, a first deploy without sg.write included, until an Admin's down.
//
// Mutations: write the intent before a first deploy's record exists — the
// failed deploy leaves one, red. Never clear it on an Admin's teardown —
// "this release", red. Drop the standing intent from stackFirewallRefusal
// for a name with no record — the Operator's first deploy in the
// previous-release case is allowed, red.
func TestDeployStack_WhatATeardownLeavesOfTheIntent(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })

	t.Run("a failed first deploy", func(t *testing.T) {
		if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg-taken", Name: "taken"}); err != nil {
			t.Fatal(err)
		}
		yaml := "name: clash\nsecurity-groups:\n  taken:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"80\", action: accept}\n"
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStreamR2{ctx: ada}); err == nil {
			t.Fatal("setup: the Admin's deploy of a taken group name succeeded")
		}
		if st, _ := corrosion.GetStack(ctx, s.db, "clash"); st != nil {
			t.Fatalf("setup: the failed first deploy recorded the stack: %+v", st)
		}
		if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "clash"); found {
			t.Errorf("a first deploy that failed before it recorded the stack left intent %+v", in)
		}
		for i := 0; i < 2; i++ {
			if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: clash\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
				t.Fatalf("the Operator's deploy %d of clash: %v", i+1, err)
			}
		}
	})
	// tearDownGone deploys name with a default-deny as an Admin and tears it
	// down on another host: as an Admin of this release does (stamped,
	// which clears the intent), or as the released previous version does,
	// which writes no teardown record and leaves the intent.
	tearDownGone := func(t *testing.T, name string, stamped bool) {
		t.Helper()
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: " + name + "\nfirewall:\n  default-deny: true\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
			t.Fatal(err)
		}
		if stamped {
			if err := corrosion.MarkStackDeleting(ctx, s.db, name, false, true, "other-host"); err != nil {
				t.Fatal(err)
			}
		} else if err := corrosion.SetStackState(ctx, s.db, name, stackStateDeleting); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackFirewall(ctx, s.db, name, nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, name); err != nil {
			t.Fatal(err)
		}
		in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, name)
		if stamped && (!found || in.Declares()) {
			t.Fatalf("setup: the Admin's teardown left intent %+v (found %v), want it cleared", in, found)
		}
		if !stamped && !in.DefaultDeny {
			t.Fatalf("setup: the previous release's teardown left intent %+v (found %v), want the deny", in, found)
		}
	}
	operatorDeploys := func(name string) error {
		return s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: " + name + "\n"}, &mockDeployStreamR2{ctx: opal})
	}
	t.Run("a deployment this release tore down elsewhere", func(t *testing.T) {
		tearDownGone(t, "gone", true)
		for i := 0; i < 2; i++ {
			if err := operatorDeploys("gone"); err != nil {
				t.Fatalf("the Operator's deploy %d of gone after its teardown: %v", i+1, err)
			}
		}
	})
	// The released previous version clears nothing at a teardown: the
	// intent stays in force for the name (fail closed, docs/upgrades.md),
	// and an Admin's down from this release clears it. A first deploy of the
	// name without sg.write is refused too
	// (TestDeployStack_AnOperatorFirstDeployOverAStandingIntentIsRefused).
	t.Run("a deployment the previous release tore down", func(t *testing.T) {
		tearDownGone(t, "old", false)
		err := operatorDeploys("old")
		wantGrantHint(t, "an Operator's first deploy of a name a previous-release teardown left the intent of", err)
		if !strings.Contains(err.Error(), "`lv compose down --name old`") {
			t.Errorf("the refusal does not name the Admin's exit: %v", err)
		}
		if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "old"}, &mockDeleteStream{ctx: ada}); err != nil {
			t.Fatalf("the Admin's compose down of old: %v", err)
		}
		for i := 0; i < 2; i++ {
			if err := operatorDeploys("old"); err != nil {
				t.Fatalf("the Operator's deploy %d of old after the Admin's down: %v", i+1, err)
			}
		}
	})
}

// A teardown without sg.write at the root leaves the firewall intent as it
// is: begun on a node the intent has not reached, a write of it would
// overwrite the Admin's intent everywhere. A teardown with sg.write clears
// it at the teardown's own stamp, at its start: an Admin redeploy of the
// name that a peer ran while the teardown was under way (here: replicated in
// during it) is newer, and stands.
//
// Mutations: write an empty intent at the firewall-rows step of a teardown,
// for every caller or for an Operator only — "operator", red. Clear it when
// the teardown finishes rather than in MarkStackDeleting's batch — "a
// redeploy during an Admin's teardown", red. That subtest guards the
// mutation only: it passes on 8d30aa6a9 too.
func TestDeleteStack_OnlyAnAdminTeardownChangesTheFirewallIntent(t *testing.T) {
	ctx := context.Background()
	t.Run("operator", func(t *testing.T) {
		s, opal, _ := stackFirewallFixture(t)
		s.db.SetClusterPolicyGate(func() bool { return true })
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "plain", ComposeYAML: "name: plain\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		stream := &mockDeleteStream{ctx: opal}
		if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "plain"}, stream); err != nil {
			t.Fatalf("compose down: %v", err)
		}
		if st, _ := corrosion.GetStack(ctx, s.db, "plain"); st != nil {
			t.Fatalf("setup: the down did not reach the firewall-rows step and finish: %+v, %+v", st, stream.sent)
		}
		if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "plain"); found {
			t.Errorf("an Operator's teardown wrote firewall intent %+v", in)
		}
	})
	t.Run("a redeploy during an Admin's teardown", func(t *testing.T) {
		s, _, ada := stackFirewallFixture(t)
		s.virt = libvirtfake.New()
		s.db.SetClusterPolicyGate(func() bool { return true })
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "plain", ComposeYAML: "name: plain\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "plain-web-1", StackName: "plain",
			HostName: s.hostName, State: "stopped", Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		s.SetStackMemberDeleteHookForTest(func(string) {
			st, _ := corrosion.GetStack(ctx, s.db, "plain")
			if err := corrosion.SetStackFirewallIntent(ctx, s.db, st, false, true, "peer"); err != nil {
				t.Error(err)
			}
		})
		if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "plain"}, &mockDeleteStream{ctx: ada}); err != nil {
			t.Fatalf("the Admin's compose down: %v", err)
		}
		if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "plain"); !found || !in.DefaultDeny {
			t.Errorf("the Admin's teardown overwrote the intent of a redeploy newer than it: %+v (found %v)", in, found)
		}
	})
}

// A name an Admin tore down and then deployed again with a firewall keeps
// the protection: the redeploy's intent is newer than the teardown, so a
// stale Operator deploy of the name is refused.
//
// A guard against a mutation, not a regression test: it passes on 8d30aa6a9
// too. Mutation: skip recording the intent for a name that has a teardown
// record — red.
func TestDeployStack_ARedeployAfterATeardownKeepsItsIntent(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	deny := "name: again\nfirewall:\n  default-deny: true\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: deny}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "again"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: deny}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	// As a node holding the file from before the redeploy sees it.
	if err := corrosion.DeleteStackFirewall(ctx, s.db, "again", nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "again", ComposeYAML: "name: again\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: again\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator redeploys a name an Admin tore down and deployed again", err)
}

// An Admin redeploy that persistStackFirewall refuses (here: a security-group
// name another owner holds) leaves everything as it was, the stack's firewall
// intent included. A refused file's default-deny ask, recorded, would make
// the stack reconciler turn the cluster default-deny on for a deploy that
// failed, and lock an Operator out of the stack.
//
// Mutation: record the intent before the persist validates the file — red.
func TestDeployStack_ARefusedAdminRedeployRecordsNoIntent(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	// The fixture's stack owns the deny; an Admin tears it down so the
	// cluster is default-allow.
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("Admin down fwonly: %v", err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Fatalf("setup: cluster still denies: %+v", d)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: p\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("Admin deploys p: %v", err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg-taken", Name: "taken"}); err != nil {
		t.Fatal(err)
	}
	bad := "name: p\nsecurity-groups:\n  taken:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"80\", action: accept}\nfirewall:\n  default-deny: true\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: bad}, &mockDeployStreamR2{ctx: ada}); err == nil {
		t.Fatal("setup: the Admin's redeploy with a taken group name succeeded")
	}
	if in, _, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "p"); in.Declares() {
		t.Errorf("the refused redeploy recorded intent %+v", in)
	}
	if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
		t.Fatal(err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Errorf("a refused Admin redeploy turned the cluster default-deny on (via the reconciler): %+v", d)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: p\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
		t.Errorf("an Operator's redeploy of p (no firewall anywhere) is refused after a refused Admin deploy: %v", err)
	}
}

// An Admin redeploy records its intent before its first firewall row
// changes, not only once it ends: one that fails after its rows are written
// (here: a backup repo with no path) still asks for the default-deny it
// asked for. The deny another stack owns then passes to it when that stack
// goes, rather than being removed.
//
// A redeploy that drops its firewall records that before it removes the
// rows, too.
//
// A guard against mutations, not a regression test: it passes on e6f4403a9
// too. Mutations: drop the intent write before the rows (V7) — both, red.
// Drop it from the persist of a file with no firewall only — "dropping the
// firewall", red.
func TestDeployStack_AnAdminRedeployRecordsItsIntentBeforeItsRows(t *testing.T) {
	ctx := context.Background()
	const noRepoPath = "backup-repos:\n  r:\n    path: \"\"\n"
	t.Run("asking for the deny", func(t *testing.T) {
		s, _, ada := stackFirewallFixture(t)
		s.db.SetClusterPolicyGate(func() bool { return true })
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: p\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
			t.Fatalf("Admin deploys p: %v", err)
		}
		failing := "name: p\n" + noRepoPath + "firewall:\n  default-deny: true\n"
		err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: failing}, &mockDeployStreamR2{ctx: ada})
		if err == nil || !strings.Contains(err.Error(), "path required") {
			t.Fatalf("setup: the Admin's redeploy = %v, want it to fail at the backup repo", err)
		}
		if in, _, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "p"); !in.DefaultDeny {
			t.Errorf("a redeploy that wrote its rows and then failed recorded intent %+v, want the deny", in)
		}
		if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
			t.Fatalf("Admin down fwonly: %v", err)
		}
		if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "p" {
			t.Errorf("the cluster default after fwonly went = %+v, want deny owned by p", d)
		}
	})
	t.Run("dropping the firewall", func(t *testing.T) {
		s, _, ada := stackFirewallFixture(t)
		s.db.SetClusterPolicyGate(func() bool { return true })
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: fwStackYAML}, &mockDeployStreamR2{ctx: ada}); err != nil {
			t.Fatalf("the Admin redeploys fwonly: %v", err)
		}
		if in, _, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "fwonly"); !in.Declares() {
			t.Fatalf("setup: the Admin's redeploy recorded intent %+v", in)
		}
		err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: fwonly\n" + noRepoPath}, &mockDeployStreamR2{ctx: ada})
		if err == nil || !strings.Contains(err.Error(), "path required") {
			t.Fatalf("setup: the Admin's redeploy = %v, want it to fail at the backup repo", err)
		}
		if g, _ := corrosion.ListSecurityGroups(ctx, s.db, "fwonly"); len(g) != 0 {
			t.Fatalf("setup: the redeploy left the stack's groups %+v", g)
		}
		if in, _, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "fwonly"); in.Declares() {
			t.Errorf("a redeploy that removed its rows and then failed left intent %+v, want none declared", in)
		}
	})
}

// A previous-release teardown removes a stack's deny and clears nothing, so
// the intent its last Admin deploy recorded stands for the name, and the
// stack reconciler turns the deny back on for it (fail closed: it cannot be
// told from a stale teardown without sg.write). An Operator's first deploy
// of the name is refused like a redeploy: allowed, it would take over the
// name, and the deny with it, as an Operator's stack. An Admin's down of the
// name, record or not, clears the intent and the deny, and they stay off.
//
// Mutation: drop the standing intent from stackFirewallRefusal for a name
// with no record — red.
func TestDeployStack_AnOperatorFirstDeployOverAStandingIntentIsRefused(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: old\nfirewall:\n  default-deny: true\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	// As the previous release tears it down: state, rows, record; no record
	// in cluster_policies, no intent clear.
	if err := corrosion.SetStackState(ctx, s.db, "old", stackStateDeleting); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteStackFirewall(ctx, s.db, "old", nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteStackRecord(ctx, s.db, "old"); err != nil {
		t.Fatal(err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Fatalf("setup: cluster still denies: %+v", d)
	}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: old\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator's first deploy of a name whose intent stands", err)
	if st, _ := corrosion.GetStack(ctx, s.db, "old"); st != nil {
		t.Fatalf("the refused deploy recorded the stack: %+v", st)
	}
	if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
		t.Fatal(err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "old" {
		t.Fatalf("the cluster default = %+v, want the standing ask's deny, owned by the torn-down name", d)
	}
	// An Admin's down of the name, with no record, clears it.
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "old"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("the Admin's compose down --name old: %v", err)
	}
	if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
		t.Fatal(err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Errorf("the deny stays after the Admin's down of the name: %+v", d)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: old\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
		t.Errorf("the Operator's deploy of old after the Admin's down: %v", err)
	}
	if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
		t.Fatal(err)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Errorf("the Operator's deploy after the Admin's down brought the deny back: %+v", d)
	}
}

// A cluster default-deny re-asserted for a stack in the moment its record
// was newer than the clear of its intent (here: an Admin's first deploy,
// without a deny, of a name whose intent stood asking for one; a reconciler
// pass between the record and the intent) is withdrawn once the clear lands
// and nothing asks for it, and passes to another stack that still asks.
// One whose intent is no newer than the deny (a replica that has not caught
// up) keeps it.
//
// Mutations: never withdraw a live stack's deny — "nothing asks", red.
// Withdraw whatever the intent's age — "an intent older than the deny", red.
// Remove it rather than hand it on — "another stack asks", red.
func TestReassertStackDefaultDeny_WithdrawsADenyNothingAsksFor(t *testing.T) {
	ctx := context.Background()
	// standing leaves name old torn down by a previous release, its intent
	// asking for the deny, then writes old's first deploy without a deny as
	// two writes with a re-assert between them, as recordStackDeploy did:
	// the deny is old's.
	standing := func(t *testing.T) *Server {
		s, _, ada := stackFirewallFixture(t)
		s.db.SetClusterPolicyGate(func() bool { return true })
		if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: old\nfirewall:\n  default-deny: true\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.SetStackState(ctx, s.db, "old", stackStateDeleting); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackFirewall(ctx, s.db, "old", nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteStackRecord(ctx, s.db, "old"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "old", ComposeYAML: "name: old\n", ComposeHash: "h", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
			t.Fatal(err)
		}
		if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "old" {
			t.Fatalf("setup: the cluster default between the record and the intent = %+v, want old's deny", d)
		}
		return s
	}
	clear := func(t *testing.T, s *Server) {
		t.Helper()
		st, _ := corrosion.GetStack(ctx, s.db, "old")
		if err := corrosion.SetStackFirewallIntent(ctx, s.db, st, false, false, "h"); err != nil {
			t.Fatal(err)
		}
	}
	settle := func(t *testing.T, s *Server) *corrosion.FirewallDefault {
		t.Helper()
		for i := 0; i < 2; i++ {
			if err := corrosion.ReassertStackDefaultDeny(ctx, s.db, compose.StoredStackWants); err != nil {
				t.Fatal(err)
			}
			if _, err := corrosion.SweepOrphanStackRows(ctx, s.db, compose.StoredStackWants); err != nil {
				t.Fatal(err)
			}
		}
		d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster")
		return d
	}
	t.Run("nothing asks", func(t *testing.T) {
		s := standing(t)
		clear(t, s)
		if d := settle(t, s); d != nil && d.DefaultDeny {
			t.Errorf("a deny nothing asks for stays in force, owned by live stack old: %+v", d)
		}
	})
	t.Run("another stack asks", func(t *testing.T) {
		s := standing(t)
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "edge", ComposeYAML: "name: edge\nfirewall:\n  default-deny: true\n", State: "active"}); err != nil {
			t.Fatal(err)
		}
		clear(t, s)
		if d := settle(t, s); d == nil || !d.DefaultDeny || d.StackName != "edge" {
			t.Errorf("the cluster default = %+v, want the deny handed to edge, which asks for it", d)
		}
	})
	t.Run("an intent older than the deny", func(t *testing.T) {
		s := standing(t)
		clear(t, s)
		// The deny is written again after the clear, as by a replica whose
		// re-assert had not seen it: this replica keeps it until an intent
		// newer than it says otherwise.
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "old"); err != nil {
			t.Fatal(err)
		}
		if d := settle(t, s); d == nil || !d.DefaultDeny {
			t.Errorf("a deny newer than the intent was withdrawn: %+v", d)
		}
	})
}

// An Admin's first deploy records its stack and the firewall intent of its
// file in one write, the intent first: no pass, here or on a replica, sees
// the new record with the intent its name had before.
//
// Mutation: write the record and then the intent, apart, again — red.
func TestDeployStack_TheRecordAndTheIntentAreOneWrite(t *testing.T) {
	ctx := context.Background()
	s, _, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	// What the record's insert finds of the intent, as it is written.
	r6Exec(t, s, `CREATE TABLE seen (value TEXT)`)
	r6Exec(t, s, `CREATE TRIGGER seen_intent AFTER INSERT ON stacks WHEN NEW.name = 'q'
		BEGIN INSERT INTO seen SELECT coalesce((SELECT value FROM cluster_policies
		  WHERE key = 'stack_firewall/q' AND deleted_at IS NULL), 'none'); END`)
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: q\nfirewall:\n  default-deny: true\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	var seen string
	if err := s.db.DB().QueryRowContext(ctx, `SELECT value FROM seen`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen, `"default_deny":true`) {
		t.Errorf("the record of q was written before its intent: the intent then was %s", seen)
	}
}

// The intent write before the persist's first row change refuses the deploy
// with nothing changed when it fails: no deny and no group is written.
//
// Mutations: run the hook after the rows (M9) — red. Drop the hook's error
// — red.
func TestDeployStack_AFailedIntentWriteChangesNothing(t *testing.T) {
	ctx := context.Background()
	s, _, ada := stackFirewallFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: p\n"}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatal(err)
	}
	r6Exec(t, s, `CREATE TRIGGER block_intent BEFORE INSERT ON cluster_policies WHEN NEW.key = 'stack_firewall/p' BEGIN SELECT RAISE(ABORT, 'injected'); END`)
	r6Exec(t, s, `CREATE TRIGGER block_intent2 BEFORE UPDATE ON cluster_policies WHEN NEW.key = 'stack_firewall/p' BEGIN SELECT RAISE(ABORT, 'injected'); END`)
	add := "name: p\nsecurity-groups:\n  pg:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"80\", action: accept}\nfirewall:\n  default-deny: true\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: add}, &mockDeployStreamR2{ctx: ada}); err == nil {
		t.Fatal("the deploy succeeded although its intent could not be written")
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d != nil && d.DefaultDeny {
		t.Errorf("the refused deploy wrote the deny: %+v", d)
	}
	if g, _ := corrosion.ListSecurityGroups(ctx, s.db, "p"); len(g) != 0 {
		t.Errorf("the refused deploy wrote groups: %+v", g)
	}
}

// r6Exec runs q on the test database directly, outside replication.
func r6Exec(t *testing.T, s *Server, q string) {
	t.Helper()
	if _, err := s.db.DB().ExecContext(context.Background(), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

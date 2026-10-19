package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// file). It does not outlive the deployment it was written for.
//
// Mutations: record the intent for any caller — the Operator's deploy
// records it, red. Drop the intent from stackFirewallRefusal — the
// Operator's redeploy is allowed, red. Drop the deployment binding — the
// Operator's deploys after the Admin's teardown are refused, red.
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
	// again: the intent spoke for the deployment that went.
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fw"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("the Admin tears fw down: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: fw\n"}, &mockDeployStreamR2{ctx: opal}); err != nil {
			t.Fatalf("the Operator's deploy %d of fw after the Admin's teardown: %v", i+1, err)
		}
	}
}

// A recorded intent speaks for one deployment of the stack. One left by
// another — a first Admin deploy that failed before it recorded the stack,
// or a deployment this release tore down on another host — does not block a
// later Operator stack of the same name. One a previous-release teardown
// left (no teardown record) stays in force until an Admin's down.
//
// Mutations: write the intent before a first deploy's record exists — the
// failed deploy leaves one, red. Ignore the teardown stamp — the Operator's
// redeploy after this release's teardown is refused, red. Let the Admin's
// down not re-stamp (no teardown record) — the previous-release case, red.
func TestDeployStack_AnIntentLeftByAnotherDeploymentDoesNotApply(t *testing.T) {
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
	// tearDownGone deploys gone with a default-deny as an Admin and tears it
	// down on another host, leaving the intent: with this release's
	// teardown record (stamped), or as the released previous version does,
	// which writes no teardown record at all.
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
		if _, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, name); !found {
			t.Fatal("setup: no intent left behind")
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
	// The released previous version writes no teardown record, so nothing
	// says its teardown began another deployment: the intent stays in force
	// for the name (fail closed, docs/upgrades.md), and an Admin's down from
	// this release clears it.
	t.Run("a deployment the previous release tore down", func(t *testing.T) {
		tearDownGone(t, "old", false)
		if err := operatorDeploys("old"); err != nil {
			t.Fatalf("the Operator's first deploy of old (no record here yet): %v", err)
		}
		err := operatorDeploys("old")
		wantGrantHint(t, "an Operator redeploys a name a previous-release teardown left the intent of", err)
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
// redeploy during an Admin's teardown", red.
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
// Mutation: skip recording the intent for a name that has a teardown
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

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
// file). An Admin's teardown clears it.
//
// Mutations: record the intent for any caller — the Operator's deploy
// records it, red. Drop the intent from stackFirewallRefusal — the
// Operator's redeploy is allowed, red. Keep the intent on an Admin's
// teardown — red.
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

	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fw"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("the Admin tears fw down: %v", err)
	}
	if in, found, _ := corrosion.GetStackFirewallIntent(ctx, s.db, "fw"); !found || in.Firewall || in.DefaultDeny {
		t.Fatalf("the Admin's teardown left intent %+v (found %v), want it cleared", in, found)
	}
}

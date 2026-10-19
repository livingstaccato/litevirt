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

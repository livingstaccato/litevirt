package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// stackFWFailingYAML persists its firewall and then fails the deploy: the
// backup repo without a path is refused after the security groups are
// written.
const stackFWFailingYAML = `
name: fwfail
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
backup-repos:
  broken: {}
`

// A first deploy of a stack that fails after its firewall was written leaves
// no security group behind: no stack record exists to tear it down, and the
// group held its name against the next deploy of the same file.
//
// Mutation: drop the rollback — the group outlives the failed deploy.
func TestDeployStack_FailedFirstDeployTakesItsFirewallBack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "keep", Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: stackFWFailingYAML}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded; the test needs it to fail after the firewall is written")
	}
	sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sgs) != 1 || sgs[0].Name != "admin" {
		t.Errorf("security groups after the failed first deploy = %+v, want only the pre-existing admin", sgs)
	}
}

// A redeploy of an existing stack that fails keeps the stack's firewall: the
// stack is still there, and its rows are its current config.
func TestDeployStack_FailedRedeployKeepsTheStacksFirewall(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fwfail", ComposeYAML: "name: fwfail\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: stackFWFailingYAML}, &mockDeployStream{ctx: context.Context(ctx)}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "fwfail"); len(sgs) != 1 {
		t.Errorf("the existing stack's security groups after a failed redeploy = %+v, want web kept", sgs)
	}
}

// A failed first deploy that left a workload of the stack keeps the groups:
// its NICs may be bound to them, and `compose down` finds the stack by it.
//
// Mutation: take the rows back whatever exists — the group goes from under
// the VM.
func TestDeployStack_FailedFirstDeployWithAWorkloadKeepsItsFirewall(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "fwfail-web", StackName: "fwfail", HostName: "node-1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: stackFWFailingYAML}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "fwfail"); len(sgs) != 1 {
		t.Errorf("security groups of a failed first deploy with a VM of the stack = %+v, want web kept", sgs)
	}
}

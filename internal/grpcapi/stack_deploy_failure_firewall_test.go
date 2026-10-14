package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// Review C1. A failing first deploy whose file asks for default-deny, on a
// cluster an operator already set to default-deny, leaves the cluster
// denying, and the operator's row keeps its owner: the deploy neither takes
// the row over nor removes it.
//
// Mutations: let the rollback tombstone the stack's firewall_defaults (the
// cluster goes default-allow); let the deploy re-stamp the existing row with
// its stack name (the owner changes).
func TestDeployStack_FailedFirstDeployKeepsAnOperatorsDefaultDeny(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	yaml := stackFWFailingYAML + "firewall:\n  default-deny: true\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	d, err := corrosion.GetFirewallDefault(ctx, s.db, "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || !d.DefaultDeny {
		t.Fatalf("cluster default after a failed first deploy = %+v, want the operator's deny kept", d)
	}
	if d.StackName != "" {
		t.Errorf("the operator's cluster default-deny is now owned by stack %q; a stack must not take over a row it did not write", d.StackName)
	}
}

// Review I1. A repo another stack registered, named by a failing first
// deploy, is still registered afterwards.
//
// Mutation: tombstone the failed stack's repos in the rollback — the taken
// over repo goes.
func TestDeployStack_FailedFirstDeployKeepsAnotherStacksRepo(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "other"}); err != nil {
		t.Fatal(err)
	}
	yaml := `
name: fwfail
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
backup-repos:
  nightly: {path: /srv/nightly}
  zz-broken: {}
`
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if p, _ := corrosion.GetBackupRepoPath(ctx, s.db, "nightly"); p == "" {
		t.Error("the repo another stack registered is gone after a failed first deploy that named it")
	}
}

// failAfterCreateStream is a client that goes away once the deploy has
// created its first workload. Its onDone hook removes the workload's row from
// the entry node's replica first, which is how a create on a peer looks to
// the entry node before it replicates.
type failAfterCreateStream struct {
	mockDeployStream
	onDone func()
}

func (m *failAfterCreateStream) Send(p *pb.DeployProgress) error {
	if p.Phase == "done" && p.VmName != "" {
		if m.onDone != nil {
			m.onDone()
		}
		return errors.New("client went away")
	}
	return m.mockDeployStream.Send(p)
}

// Review I2. A first deploy that created a workload and then failed keeps
// its security groups, even though the entry node's replica does not show
// the workload yet: the deploy itself knows it issued the create.
//
// Mutation: judge "no workload" on the local replica — the groups go from
// under the created workload.
func TestDeployStack_FailedFirstDeployAfterACreateKeepsItsFirewall(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	if err := corrosion.SetHostLabel(ctx, s.db, "test-host", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	s.SetContainerRuntime(&fakeCTRuntime{})
	yaml := `name: ctfw
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
workloads:
  web:
    kind: lxc
    image: alpine:3.21
    cpu: 1
    memory: 256
`
	stream := &failAfterCreateStream{mockDeployStream: mockDeployStream{ctx: ctx}}
	stream.onDone = func() {
		if err := s.db.Execute(ctx, `DELETE FROM containers`); err != nil {
			t.Error(err)
		}
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream); err == nil {
		t.Fatal("the deploy succeeded although its client went away")
	}
	if sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "ctfw"); len(sgs) != 1 {
		t.Errorf("security groups of a first deploy that created a workload and then failed = %+v, want web kept", sgs)
	}
}

// The rollback never touches the default-deny row, even one this failed
// deploy wrote itself: a lingering deny fails closed, a removed one open.
//
// Mutation: tombstone the stack's firewall_defaults in the rollback — the
// cluster is left with no default-deny.
func TestDeployStack_FailedFirstDeployLeavesItsOwnDefaultDeny(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	yaml := stackFWFailingYAML + "firewall:\n  default-deny: true\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if deny, err := corrosion.ResolveDefaultDeny(ctx, s.db, ""); err != nil || !deny {
		t.Errorf("cluster default-deny after a failed first deploy that asked for it = %v (%v), want deny kept", deny, err)
	}
}

// Code review [2]. A first deploy whose firewall persist fails part way takes
// back the rows it had already inserted: the security group written before
// the ip set write failed does not outlive the failed deploy.
//
// Mutation: install the rollback only once the persist has succeeded — the
// group stays, holding its name.
func TestDeployStack_FailedFirstPersistTakesBackWhatItWrote(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if _, err := s.db.DB().ExecContext(ctx, `CREATE TRIGGER cr7_fail_ipset BEFORE INSERT ON ip_sets
		BEGIN SELECT RAISE(ABORT, 'injected write failure'); END`); err != nil {
		t.Fatal(err)
	}
	yaml := `
name: fwpart
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
ipsets:
  office:
    cidrs: ["10.0.0.0/8"]
`
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("fixture: the deploy succeeded although its ip set write failed")
	}
	if sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "fwpart"); err != nil || len(sgs) != 0 {
		t.Errorf("security groups after a first deploy whose persist failed part way = %+v (%v), want none", sgs, err)
	}
}

// Code review [2]. Rows a failed earlier attempt left behind, owned by a
// stack that has no record, do not turn the rollback off for the next
// attempt: a stack with no record has never been deployed.
//
// Mutation: keep the rollback only when the stack had no security groups
// before the deploy — the second failed attempt leaves its group.
func TestDeployStack_FailedFirstDeployAfterLeftoversTakesItsFirewallBack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "leftover", Name: "web", StackName: "fwfail"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: stackFWFailingYAML}, &mockDeployStream{ctx: ctx}); err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "fwfail"); err != nil || len(sgs) != 0 {
		t.Errorf("security groups after a second failed first deploy = %+v (%v), want none", sgs, err)
	}
}

// Rereview r1-m2. A failed first deploy that left the cluster default-deny on
// (its own row) says so in its error, and how to take it off.
//
// Mutation: drop the note — the error does not mention the default-deny.
func TestDeployStack_FailedFirstDeploySaysItsDefaultDenyStays(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	yaml := stackFWFailingYAML + "firewall:\n  default-deny: true\n"
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx})
	if err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if msg := err.Error(); !strings.Contains(msg, "default-deny") || !strings.Contains(msg, "stays on") ||
		!strings.Contains(msg, "lv firewall default-deny off") {
		t.Errorf("error of a failed first deploy that left its default-deny on = %q, want it to say the deny stays on and how to remove it", msg)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want the deploy's own InvalidArgument kept", status.Code(err))
	}
}

// The note is only for a default-deny the failed deploy left in force as its
// own: an operator's deny is not this stack's to explain.
func TestDeployStack_FailedFirstDeployDoesNotClaimAnOperatorsDeny(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	yaml := stackFWFailingYAML + "firewall:\n  default-deny: true\n"
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx})
	if err == nil {
		t.Fatal("the deploy with a path-less backup repo succeeded")
	}
	if strings.Contains(err.Error(), "stays on") {
		t.Errorf("error = %q, claims an operator's default-deny as the deploy's", err)
	}
}

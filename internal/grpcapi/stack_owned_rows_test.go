package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// putStack records a deployed stack with its compose file, as a deploy that
// got to the end leaves it.
func putStack(t *testing.T, ctx context.Context, s *Server, name, yaml string) {
	t.Helper()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: name, ComposeYAML: yaml, State: "active"}); err != nil {
		t.Fatal(err)
	}
}

func downStack(t *testing.T, ctx context.Context, s *Server, name string) {
	t.Helper()
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: name}, &mockDeleteStream{ctx: ctx}); err != nil {
		t.Fatalf("DeleteStack %s: %v", name, err)
	}
}

func repoOwner(t *testing.T, ctx context.Context, s *Server, name string) (path, owner string, ok bool) {
	t.Helper()
	repos, err := corrosion.ListBackupRepos(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range repos {
		if r.Name == name {
			return r.Path, r.StackName, true
		}
	}
	return "", "", false
}

const nightlyOwnerYAML = "name: owner\nbackup-repos:\n  nightly: {path: /srv/nightly}\n"

// Deferred (a). A deploy naming a repo another stack registered uses it as
// it is: the repo keeps its owner, and the naming stack's `compose down`
// leaves it registered.
//
// Mutation: upsert every named repo as before — the deploy takes the repo
// over, and its down removes the other stack's repo.
func TestDeployStack_DoesNotTakeOverAnotherStacksRepo(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "owner", nightlyOwnerYAML)
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	yaml := "name: user\nbackup-repos:\n  nightly: {path: /srv/nightly}\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err != nil {
		t.Fatalf("deploy of a stack naming another stack's repo: %v", err)
	}
	if _, owner, ok := repoOwner(t, ctx, s, "nightly"); !ok || owner != "owner" {
		t.Fatalf("repo nightly after another stack's deploy named it: registered=%v owner=%q, want owner kept", ok, owner)
	}
	downStack(t, ctx, s, "user")
	if _, owner, ok := repoOwner(t, ctx, s, "nightly"); !ok || owner != "owner" {
		t.Errorf("repo nightly after the down of a stack that only used it: registered=%v owner=%q, want it kept by its owner", ok, owner)
	}
}

// A deploy naming another stack's repo at a different path does not move the
// repo; it uses the registered path and says so.
//
// Mutation: upsert the file's path — the owner's backups go elsewhere.
func TestDeployStack_AnotherStacksRepoKeepsItsPath(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "owner", nightlyOwnerYAML)
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	yaml := "name: user\nbackup-repos:\n  nightly: {path: /srv/elsewhere}\n"
	stream := &mockDeployStream{ctx: ctx}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if path, owner, _ := repoOwner(t, ctx, s, "nightly"); path != "/srv/nightly" || owner != "owner" {
		t.Errorf("repo nightly = %s owned by %q, want /srv/nightly owned by owner", path, owner)
	}
	said := false
	for _, p := range stream.sent {
		if p.Phase == "warning" && strings.Contains(p.Detail, `"owner"`) && strings.Contains(p.Detail, "/srv/nightly") {
			said = true
		}
	}
	if !said {
		t.Error("no warning said the repo is another stack's, at its registered path")
	}
}

// The owner redeploying its own repo at a new path still moves it.
func TestDeployStack_OwnerStillUpdatesItsRepo(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	yaml := "name: owner\nbackup-repos:\n  nightly: {path: /srv/moved}\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if path, owner, _ := repoOwner(t, ctx, s, "nightly"); path != "/srv/moved" || owner != "owner" {
		t.Errorf("repo nightly = %s owned by %q, want /srv/moved owned by owner", path, owner)
	}
}

// Deferred (a). When the owner goes down while another live stack's file
// names the repo, the repo is handed to that stack, at the path it has, and
// goes only with the last stack that names it.
//
// Mutation: tombstone every owned repo on down — the other stack's backups
// lose their repo.
func TestDeleteStack_HandsARepoToAnotherStackThatNamesIt(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "owner", nightlyOwnerYAML)
	putStack(t, ctx, s, "user", "name: user\nbackup-repos:\n  nightly: {path: /srv/elsewhere}\n")
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	downStack(t, ctx, s, "owner")
	if path, owner, ok := repoOwner(t, ctx, s, "nightly"); !ok || owner != "user" || path != "/srv/nightly" {
		t.Fatalf("repo nightly after its owner's down = %v %s owned by %q, want /srv/nightly handed to user", ok, path, owner)
	}
	downStack(t, ctx, s, "user")
	if _, _, ok := repoOwner(t, ctx, s, "nightly"); ok {
		t.Error("repo nightly is still registered after the last stack naming it went down")
	}
}

const denyYAML = "name: %s\nfirewall:\n  default-deny: true\n"

func denyFile(name string) string { return strings.Replace(denyYAML, "%s", name, 1) }

func clusterDefault(t *testing.T, ctx context.Context, s *Server) *corrosion.FirewallDefault {
	t.Helper()
	d, err := corrosion.GetFirewallDefault(ctx, s.db, "cluster")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Deferred (b). Stack A owns the cluster default-deny and stack B asked for
// it too. A's down hands the deny to B instead of removing it; B's down then
// removes it.
//
// Mutation: tombstone the owner's row whatever other stacks ask — the
// cluster goes default-allow while B still asks for deny.
func TestDeleteStack_HandsTheDefaultDenyToAnotherStackThatAsked(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", denyFile("a"))
	putStack(t, ctx, s, "b", denyFile("b"))
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	downStack(t, ctx, s, "a")
	if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "b" {
		t.Fatalf("cluster default after a's down = %+v, want deny handed to b", d)
	}
	downStack(t, ctx, s, "b")
	if d := clusterDefault(t, ctx, s); d != nil && d.DefaultDeny {
		t.Errorf("cluster default after the last stack asking for deny went down = %+v, want removed", d)
	}
}

// Deferred (b). A redeploy that drops default-deny hands the row to another
// stack that still asks for it, as a down does.
//
// Mutation: tombstone the row on the redeploy — the cluster goes
// default-allow while b asks for deny.
func TestDeployStack_DroppingDenyHandsItToAnotherStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", denyFile("a"))
	putStack(t, ctx, s, "b", denyFile("b"))
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	yaml := "name: a\nsecurity-groups:\n  web:\n    rules:\n      - {direction: ingress, proto: tcp, port: \"80\", action: accept}\n"
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStream{ctx: ctx}); err != nil {
		t.Fatalf("redeploy of a without default-deny: %v", err)
	}
	if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "b" {
		t.Errorf("cluster default after a dropped deny = %+v, want deny handed to b", d)
	}
}

// Rereview r1-m1. A stack that asked for default-deny while an operator owned
// the row leaves the operator's deny on its down; a stack that owns the row
// removes it on its down.
//
// Mutations: tombstone the cluster row whatever its owner (the operator's
// deny goes); never tombstone it (the owning stack's deny outlives it).
func TestDeleteStack_DefaultDenyGoesOnlyWithItsOwner(t *testing.T) {
	t.Run("operator owns", func(t *testing.T) {
		s := testServer(t)
		ctx := adminCtx()
		putStack(t, ctx, s, "s", denyFile("s"))
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, ""); err != nil {
			t.Fatal(err)
		}
		downStack(t, ctx, s, "s")
		if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "" {
			t.Errorf("cluster default after the down of a stack that asked for deny = %+v, want the operator's deny kept", d)
		}
	})
	t.Run("stack owns", func(t *testing.T) {
		s := testServer(t)
		ctx := adminCtx()
		putStack(t, ctx, s, "s", denyFile("s"))
		if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "s"); err != nil {
			t.Fatal(err)
		}
		downStack(t, ctx, s, "s")
		if d := clusterDefault(t, ctx, s); d != nil && d.DefaultDeny {
			t.Errorf("cluster default after its owning stack went down = %+v, want removed", d)
		}
	})
}

// A stack whose stored file cannot be read might ask for default-deny, so a
// down does not remove the deny while one exists: it fails closed.
//
// Mutation: skip an unreadable file as asking for nothing — the deny goes.
func TestDeleteStack_KeepsTheDenyWhileAnotherStacksFileIsUnreadable(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", denyFile("a"))
	putStack(t, ctx, s, "bad", "vms: [a, b]\n")
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	downStack(t, ctx, s, "a")
	if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny {
		t.Errorf("cluster default after a's down with an unreadable stack file = %+v, want deny kept", d)
	}
}

// hookDeployStream runs onSend for every progress line before recording it.
type hookDeployStream struct {
	mockDeployStream
	onSend func(*pb.DeployProgress)
}

func (m *hookDeployStream) Send(p *pb.DeployProgress) error {
	if m.onSend != nil {
		m.onSend(p)
	}
	return m.mockDeployStream.Send(p)
}

// cr7 round 1, I1. Stack C's deploy asks for default-deny while stack A owns
// it, so C's persist leaves A's row alone. A goes down while C's deploy is in
// flight, and sees no record of C asking. C's deploy must not end with the
// cluster default-allow.
//
// Mutation: drop the re-assert after the stack record is written — the
// cluster is left default-allow.
func TestDeployStack_DenyOwnerDownMidDeployLeavesTheClusterDenying(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "a", denyFile("a"))
	if err := corrosion.SetFirewallDefault(ctx, s.db, "cluster", true, "a"); err != nil {
		t.Fatal(err)
	}
	// The warning about another stack's repo is sent after C's persist: the
	// point at which A goes down.
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "z"}); err != nil {
		t.Fatal(err)
	}
	yaml := "name: c\nfirewall:\n  default-deny: true\nbackup-repos:\n  nightly: {path: /srv/other}\n"
	downed := false
	stream := &hookDeployStream{mockDeployStream: mockDeployStream{ctx: ctx}}
	stream.onSend = func(p *pb.DeployProgress) {
		if !downed && p.Phase == "warning" && strings.Contains(p.Detail, "nightly") {
			downed = true
			downStack(t, ctx, s, "a")
			if d := clusterDefault(t, ctx, s); d != nil && d.DefaultDeny {
				t.Errorf("fixture: a's down mid-deploy left the deny %+v; the test needs it gone", d)
			}
		}
	}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream); err != nil {
		t.Fatalf("deploy of c: %v", err)
	}
	if !downed {
		t.Fatal("fixture: a was never taken down mid-deploy")
	}
	if d := clusterDefault(t, ctx, s); d == nil || !d.DefaultDeny || d.StackName != "c" {
		t.Errorf("cluster default after c's deploy = %+v, want deny owned by c", d)
	}
}

// cr7 round 1, m3. A repo a stack's workload backs up to without defining it
// is handed to that stack on its owner's down, not unregistered.
//
// Mutation: hand a repo only to a stack that defines it — the
// registration goes.
func TestDeleteStack_HandsARepoToAStackThatBacksUpToIt(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "owner", nightlyOwnerYAML)
	putStack(t, ctx, s, "user", "name: user\nvms:\n  web:\n    image: ubuntu\n    backup: {repo: nightly, schedule: \"0 2 * * *\"}\n")
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	downStack(t, ctx, s, "owner")
	if path, owner, ok := repoOwner(t, ctx, s, "nightly"); !ok || owner != "user" || path != "/srv/nightly" {
		t.Errorf("repo nightly after its owner's down = %v %s owned by %q, want /srv/nightly handed to user", ok, path, owner)
	}
}

// cr7 round 1, m3. While another stack's stored file cannot be read, a down
// keeps its repos registered: that stack may back up to them.
//
// Mutation: tombstone whatever is unreadable — the registration goes.
func TestDeleteStack_KeepsReposWhileAnotherStacksFileIsUnreadable(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	putStack(t, ctx, s, "owner", nightlyOwnerYAML)
	putStack(t, ctx, s, "bad", "vms: [a, b]\n")
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "nightly", Path: "/srv/nightly", StackName: "owner"}); err != nil {
		t.Fatal(err)
	}
	downStack(t, ctx, s, "owner")
	if _, _, ok := repoOwner(t, ctx, s, "nightly"); !ok {
		t.Error("repo nightly was unregistered while another stack's file could not be read")
	}
}

package grpcapi

import (
	"context"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
)

const (
	fwA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fwB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// tagsServer is a test server with the cluster-policy gate open and the
// release gate latched (open).
func tagsServer(t *testing.T) (*Server, *relGate) {
	t.Helper()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.db.SetRepointReady(func(context.Context) bool { return true })
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	return s, g
}

func tagsGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups)
}

// markTagsUsed records firewall_tag_groups as used on s's replica, as the
// gate does at the first tag set.
func markTagsUsed(t *testing.T, s *Server) {
	t.Helper()
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, info.Token,
		string(capabilities.FeatureFirewallTagGroups), s.hostName, true); err != nil {
		t.Fatal(err)
	}
}

// tagsRowValue is the raw value of identity id's tags row; ok false for no row.
func tagsRowValue(t *testing.T, s *Server, kind, id string) (string, bool) {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT value FROM cluster_policies WHERE key = ?`,
		corrosion.FirewallTagsKeyPrefix+kind+"/"+id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("value"), true
}

func seedTagsFor(t *testing.T, s *Server, kind, id string, tags map[string]string, name, host string) {
	t.Helper()
	if err := corrosion.SetFirewallTags(context.Background(), s.db, tagsGrant(t), corrosion.FWTagAuthorityForTest(t),
		kind, id, tags, name, host, "seed"); err != nil {
		t.Fatal(err)
	}
}

func vmFWID(t *testing.T, s *Server, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("VM %s: %v %v", name, vm, err)
	}
	return corrosion.FirewallIDOf(corrosion.TagMemberVM, vm.Spec)
}

func setVMSpec(t *testing.T, s *Server, name, spec string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`, spec, s.db.NowTS(), name); err != nil {
		t.Fatal(err)
	}
}

// `tag set` needs sg.write at the cluster root (Operator is refused, and
// nothing is minted or written), and is audited with the tags before and
// after; `tag rm` too.
//
// Mutations: mint the authority without sg.write — Operator writes: red;
// drop the audit — red.
func TestSetFirewallTags_NeedsSGWriteAndIsAudited(t *testing.T) {
	s, _ := tagsServer(t)
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")

	op := boundCtx(t, s, "olga", "admin", "Operator")
	if _, err := s.SetFirewallTags(op, &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Operator tag set: %v, want PermissionDenied", err)
	}
	if id := vmFWID(t, s, "web"); id != "" {
		t.Fatalf("a refused tag set minted %q", id)
	}

	ctx := boundCtx(t, s, "nina", "viewer", "NetworkAdmin")
	out, err := s.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web", "env": "prod"}})
	if err != nil {
		t.Fatalf("NetworkAdmin tag set: %v", err)
	}
	id := vmFWID(t, s, "web")
	if !corrosion.ValidFirewallID(id) || out.GetFwId() != id || !maps.Equal(out.GetTags(), map[string]string{"role": "web", "env": "prod"}) {
		t.Fatalf("tag set answered %+v; the VM holds identity %q", out, id)
	}
	wantAudit(t, s, "firewall.tag.set", "nina", "web", "fw_id="+id+" before=none after={env=prod role=web}")

	if _, err := s.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Remove: []string{"env"}}); err != nil {
		t.Fatalf("tag rm: %v", err)
	}
	wantAudit(t, s, "firewall.tag.rm", "nina", "web", "fw_id="+id+" before={env=prod role=web} after={role=web}")
	rec, ok, _ := corrosion.ResolveFirewallTags(context.Background(), s.db, corrosion.TagMemberVM, id)
	if !ok || !maps.Equal(rec.Tags, map[string]string{"role": "web"}) || rec.Name != "web" {
		t.Fatalf("tags row after rm: %+v", rec)
	}
}

// Refused until the release latch, with the release text, minting nothing.
//
// Mutation: drop the entry check (and the gate) — red.
func TestSetFirewallTags_RefusedBeforeTheLatch(t *testing.T) {
	s, g := tagsServer(t)
	g.open = false
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
	_, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web"}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(capabilities.FeatureFirewallTagGroups)) {
		t.Fatalf("tag set before the latch: %v", err)
	}
	if id := vmFWID(t, s, "web"); id != "" {
		t.Fatalf("a tag set before the latch minted %q", id)
	}
}

// Every tag set mints (D2a review I-3): an identity a second live VM also
// holds was copied, so the VM tagged gets a fresh one, the copied id's tags
// row is cleared (the copy inherits nothing), and the other VM keeps its id.
// A second tag set keeps the identity it minted.
//
// Mutations: mint only when the VM has no identity — the copy keeps the
// shared id and the old tags: red; skip the abandoned clear — red.
func TestSetFirewallTags_MintsOnEveryCallAndClearsACopiedID(t *testing.T) {
	s, _ := tagsServer(t)
	for _, n := range []string{"web", "copy"} {
		insertTestVM(t, adminCtx(), s.db, n, s.hostName, "running")
		setVMSpec(t, s, n, `{"name":"`+n+`","firewall_id":"`+fwA+`"}`)
	}
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "db"}, "copy", "")

	out, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	id := vmFWID(t, s, "web")
	if id == fwA || id != out.GetFwId() {
		t.Fatalf("the tagged VM kept the copied identity: %q (answer %q)", id, out.GetFwId())
	}
	if got := vmFWID(t, s, "copy"); got != fwA {
		t.Fatalf("the other holder's identity changed to %q", got)
	}
	if v, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA); v != "" {
		t.Fatalf("the copied identity's tags row still holds %q", v)
	}
	wantAudit(t, s, "firewall.tag.set", "admin", "web", "fw_id="+id+" replaced_copied_fw_id="+fwA+" before=none after={role=web}")
	if _, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"env": "prod"}}); err != nil {
		t.Fatal(err)
	}
	if again := vmFWID(t, s, "web"); again != id {
		t.Fatalf("a second tag set changed the identity %q -> %q", id, again)
	}
}

// fwTagsPeer records SetFirewallTags forwards.
type fwTagsPeer struct {
	pb.LiteVirtClient
	mu    sync.Mutex
	req   *pb.SetFirewallTagsRequest
	actor []string
}

func (p *fwTagsPeer) SetFirewallTags(ctx context.Context, req *pb.SetFirewallTagsRequest, _ ...grpc.CallOption) (*pb.FirewallTags, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.req = req
	md, _ := metadata.FromOutgoingContext(ctx)
	p.actor = md.Get(repairActorMDKey)
	return &pb.FirewallTags{Kind: req.GetKind(), Workload: req.GetWorkload(), FwId: fwB}, nil
}

// The mint runs on the workload's owner (D2a review I-3): a VM owned by
// another host, and a container on another host, are forwarded there, with
// the caller named for the owner's audit row; nothing is minted here.
//
// Mutation: mint on the entry node — red.
func TestSetFirewallTags_RoutedToTheOwner(t *testing.T) {
	s, _ := tagsServer(t)
	peer := &fwTagsPeer{}
	var dialled []string
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		dialled = append(dialled, host)
		return peer, func() {}, nil
	}
	insertTestVM(t, adminCtx(), s.db, "remote", "other-host", "running")
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "node-2", Name: "cache", State: "running", CreateSpec: `{"template":"debian"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "remote", Set: map[string]string{"role": "web"}}); err != nil {
		t.Fatal(err)
	}
	if id := vmFWID(t, s, "remote"); id != "" {
		t.Fatalf("the entry node minted %q for a VM another host owns", id)
	}
	if _, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "container", Workload: "cache", Set: map[string]string{"role": "web"}}); err != nil {
		t.Fatal(err)
	}
	ct, _ := corrosion.GetContainer(context.Background(), s.db, "node-2", "cache")
	if id := corrosion.FirewallIDOf(corrosion.TagMemberCT, ct.CreateSpec); id != "" {
		t.Fatalf("the entry node minted %q for a container on another host", id)
	}
	if len(dialled) != 2 || dialled[0] != "other-host" || dialled[1] != "node-2" {
		t.Fatalf("forwards went to %v, want other-host then node-2", dialled)
	}
	if peer.req.GetHost() != "node-2" || peer.req.GetWorkload() != "cache" || len(peer.actor) != 1 || peer.actor[0] != "admin" {
		t.Fatalf("container forward = %+v actor %v", peer.req, peer.actor)
	}
}

// A container on this host is minted and tagged here; one with no create
// spec (an earlier build's) is refused with the remedy.
func TestSetFirewallTags_ContainerOnThisHost(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: s.hostName, Name: "cache", State: "running", CreateSpec: `{"template":"debian"}`,
	}); err != nil {
		t.Fatal(err)
	}
	out, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "container", Workload: "cache", Host: s.hostName, Set: map[string]string{"role": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := corrosion.GetContainer(ctx, s.db, s.hostName, "cache")
	if id := corrosion.FirewallIDOf(corrosion.TagMemberCT, ct.CreateSpec); id == "" || id != out.GetFwId() {
		t.Fatalf("container identity %q, answer %q", id, out.GetFwId())
	}
	rec, _, _ := corrosion.ResolveFirewallTags(ctx, s.db, corrosion.TagMemberCT, out.GetFwId())
	if rec.Host != s.hostName || rec.Name != "cache" {
		t.Fatalf("tags row display fields %+v", rec)
	}
	wantAudit(t, s, "firewall.tag.set", "admin", s.hostName+"/cache", "fw_id="+out.GetFwId()+" before=none after={role=web}")

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: s.hostName, Name: "old", State: "running"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "container", Workload: "old", Host: s.hostName, Set: map[string]string{"role": "web"}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "recreate the container") {
		t.Fatalf("a container with no create spec: %v", err)
	}
}

func TestSetFirewallTags_RejectsBadRequests(t *testing.T) {
	s, _ := tagsServer(t)
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
	for name, req := range map[string]*pb.SetFirewallTagsRequest{
		"no kind":     {Workload: "web", Set: map[string]string{"a": "b"}},
		"no workload": {Kind: "vm", Set: map[string]string{"a": "b"}},
		"nothing":     {Kind: "vm", Workload: "web"},
		"bad key":     {Kind: "vm", Workload: "web", Set: map[string]string{"A": "b"}},
		"bad value":   {Kind: "vm", Workload: "web", Set: map[string]string{"a": "b c"}},
		"bad rm":      {Kind: "vm", Workload: "web", Remove: []string{"-x"}},
	} {
		if _, err := s.SetFirewallTags(adminCtx(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "nope", Set: map[string]string{"a": "b"}}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown VM: %v", err)
	}
	if id := vmFWID(t, s, "web"); id != "" {
		t.Fatalf("a refused request minted %q", id)
	}
}

// SetVMLabels and UpdateVM, with any label, leave the tags row and the
// identity as they are: membership never lives in the spec (R1-I1).
func TestFirewallTags_LabelAndUpdateWritesDoNotTouchThem(t *testing.T) {
	s := reconfigServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	seedStoppedQ35VM(t, s, "web")
	if _, _, err := corrosion.MintFirewallID(context.Background(), s.db, tagsGrant(t), corrosion.TagMemberVM, "", "web"); err != nil {
		t.Fatal(err)
	}
	id := vmFWID(t, s, "web")
	seedTagsFor(t, s, corrosion.TagMemberVM, id, map[string]string{"role": "web"}, "web", "")
	before, _ := tagsRowValue(t, s, corrosion.TagMemberVM, id)
	rec0, _, _ := corrosion.ResolveFirewallTags(context.Background(), s.db, corrosion.TagMemberVM, id)

	if _, err := s.SetVMLabels(adminCtx(), &pb.SetVMLabelsRequest{Name: "web", Labels: map[string]string{"role": "db", "fw.role": "db"}}); err != nil {
		t.Fatalf("SetVMLabels: %v", err)
	}
	if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "web", Cpu: 4}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	after, _ := tagsRowValue(t, s, corrosion.TagMemberVM, id)
	rec1, _, _ := corrosion.ResolveFirewallTags(context.Background(), s.db, corrosion.TagMemberVM, id)
	if after != before || rec1.UpdatedAt != rec0.UpdatedAt {
		t.Fatalf("a label or update write touched the tags row: %q@%s -> %q@%s", before, rec0.UpdatedAt, after, rec1.UpdatedAt)
	}
	if got := vmFWID(t, s, "web"); got != id {
		t.Fatalf("a label or update write changed the identity %q -> %q", id, got)
	}
}

// deleteSeededVM is a VM s owns, minted an identity (returned), the feature
// recorded used as asked, and nothing in this replica's tags row for it.
func deleteSeededVM(t *testing.T, used bool) (*Server, string) {
	t.Helper()
	s := hotplugDiskServer(t)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	seedForceVM(t, s, "vm1")
	id, _, err := corrosion.MintFirewallID(context.Background(), s.db, tagsGrant(t), corrosion.TagMemberVM, "", "vm1")
	if err != nil || id == "" {
		t.Fatalf("mint: %q %v", id, err)
	}
	if used {
		markTagsUsed(t, s)
	}
	return s, id
}

// A plain delete clears the VM's tags row UNCONDITIONALLY once the feature is
// used — this replica holds no row for it, yet "" is written — and not at
// all before the first use.
//
// Mutation: clear only when this replica holds a non-empty row — red.
func TestDeleteVM_ClearsTheTagsUnconditionallyOnceUsed(t *testing.T) {
	s, id := deleteSeededVM(t, true)
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if v, ok := tagsRowValue(t, s, corrosion.TagMemberVM, id); !ok || v != "" {
		t.Fatalf("after the delete the tags row is %q (present %v), want a written \"\"", v, ok)
	}

	unused, id2 := deleteSeededVM(t, false)
	if _, err := unused.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if _, ok := tagsRowValue(t, unused, corrosion.TagMemberVM, id2); ok {
		t.Fatal("a delete before the feature's first use wrote a tags row")
	}
}

// A failing clear does not fail the delete.
//
// Mutation: return the clear's error from DeleteVM — red.
func TestDeleteVM_AFailingClearDoesNotFailTheDelete(t *testing.T) {
	s, _ := deleteSeededVM(t, true)
	called := false
	s.testClearFirewallTags = func(context.Context, string, string) error { called = true; return errors.New("disk full") }
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("DeleteVM with a failing clear: %v", err)
	}
	if !called {
		t.Fatal("the delete did not try to clear the tags")
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); vm != nil {
		t.Fatal("the VM is still there")
	}
}

// A rebuild's or recreate's delete — its context carries a deleted-VM sink
// of either kind (the rolling recreate's, the inline recreate's report-only
// one) — keeps the tags: the VM re-created keeps the identity (D2b review
// I-4). So does the owner of a delete an entry node forwarded (the entry
// clears a plain one itself).
//
// Mutations: clear whatever the sink (drop hasDeletedVMSink) — red; clear
// on the owner of a forwarded delete — red.
func TestDeleteVM_ARecreatesDeleteKeepsTheTags(t *testing.T) {
	for what, mk := range map[string]func(t *testing.T, s *Server) context.Context{
		"recreate sink": func(t *testing.T, s *Server) context.Context {
			ctx, _ := withDeletedVMSink(adminCtx(), "vm1", mustGetVM(t, s, "vm1").CreatedAt)
			return ctx
		},
		"inline report": func(t *testing.T, s *Server) context.Context {
			ctx, _ := withDeletedVMReport(adminCtx(), "vm1", mustGetVM(t, s, "vm1").CreatedAt)
			return ctx
		},
		"forwarded by the entry": func(t *testing.T, s *Server) context.Context {
			ctx := context.WithValue(peerCtxFor(t, s, "entry-host"), ctxKeyUsername, "admin")
			ctx = context.WithValue(ctx, ctxKeyRole, "admin")
			return metadata.NewIncomingContext(ctx, metadata.Pairs(entryClearsFirewallTagsMD, "1"))
		},
	} {
		t.Run(what, func(t *testing.T) {
			s, id := deleteSeededVM(t, true)
			seedTagsFor(t, s, corrosion.TagMemberVM, id, map[string]string{"role": "web"}, "vm1", "")
			if _, err := s.DeleteVM(mk(t, s), &pb.DeleteVMRequest{Name: "vm1", Force: true}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			if vm, _ := corrosion.GetVM(adminCtx(), s.db, "vm1"); vm != nil {
				t.Fatal("premise: the delete did not happen")
			}
			if v, _ := tagsRowValue(t, s, corrosion.TagMemberVM, id); v == "" {
				t.Fatalf("the %s delete cleared the tags", what)
			}
		})
	}
}

// fwDeletePeer records the metadata of a forwarded DeleteVM.
type fwDeletePeer struct {
	pb.LiteVirtClient
	md metadata.MD
}

func (p *fwDeletePeer) DeleteVM(ctx context.Context, _ *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.md, _ = metadata.FromOutgoingContext(ctx)
	return &emptypb.Empty{}, nil
}

// The entry node of a plain delete of a VM another host owns clears the tags
// itself, and tells the owner it does.
func TestDeleteVM_TheEntryClearsAForwardedDelete(t *testing.T) {
	s := hotplugDiskServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	markTagsUsed(t, s)
	insertTestVM(t, adminCtx(), s.db, "remote", "other-host", "running")
	setVMSpec(t, s, "remote", `{"name":"remote","firewall_id":"`+fwA+`"}`)
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "remote", "")
	peer := &fwDeletePeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "remote"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if len(peer.md.Get(entryClearsFirewallTagsMD)) != 1 {
		t.Fatalf("the forward does not tell the owner the entry clears: %v", peer.md)
	}
	if v, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA); v != "" {
		t.Fatalf("the entry did not clear the tags: %q", v)
	}
}

// A container delete clears its tags row too; a failing clear does not fail
// it.
func TestDeleteContainer_ClearsTheTags(t *testing.T) {
	s, _ := tagsServer(t)
	markTagsUsed(t, s)
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := context.Background()
	for _, n := range []string{"c1", "c2"} {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: s.hostName, Name: n, State: "stopped", CreateSpec: `{"template":"debian"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	id, _, err := corrosion.MintFirewallID(ctx, s.db, tagsGrant(t), corrosion.TagMemberCT, s.hostName, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "c1", HostName: s.hostName, Force: true}); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if v, ok := tagsRowValue(t, s, corrosion.TagMemberCT, id); !ok || v != "" {
		t.Fatalf("container delete left the tags row %q (present %v)", v, ok)
	}
	id2, _, err := corrosion.MintFirewallID(ctx, s.db, tagsGrant(t), corrosion.TagMemberCT, s.hostName, "c2")
	if err != nil {
		t.Fatal(err)
	}
	s.testClearFirewallTags = func(context.Context, string, string) error { return errors.New("boom") }
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "c2", HostName: s.hostName, Force: true}); err != nil {
		t.Fatalf("DeleteContainer with a failing clear: %v", err)
	}
	if _, ok := tagsRowValue(t, s, corrosion.TagMemberCT, id2); ok {
		t.Fatal("premise: the failing clear wrote")
	}
}

// ListFirewallTags: every tagged workload; one named workload with its
// identity (none included) and an earlier incarnation's orphan row of its
// name (m-3). Viewer may read; an unknown name is NotFound.
func TestListFirewallTags(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := context.Background()
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
	insertTestVM(t, adminCtx(), s.db, "bare", s.hostName, "running")
	setVMSpec(t, s, "web", `{"name":"web","firewall_id":"`+fwA+`"}`)
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "web", "")
	// An orphan row named web (an earlier incarnation's), and one named bare.
	seedTagsFor(t, s, corrosion.TagMemberVM, fwB, map[string]string{"role": "db"}, "bare", "")
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "node-2", Name: "web", State: "running",
		CreateSpec: `{"fw_id":"cccccccccccccccccccccccccccccccc"}`}); err != nil {
		t.Fatal(err)
	}

	all, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{})
	if err != nil {
		t.Fatalf("list as viewer: %v", err)
	}
	if len(all.GetTags()) != 1 || all.Tags[0].GetWorkload() != "web" || all.Tags[0].GetFwId() != fwA || all.Tags[0].GetOrphan() {
		t.Fatalf("list all = %v, want only web", all.GetTags())
	}

	one, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{Kind: "vm", Workload: "bare"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.GetTags()) != 2 || one.Tags[0].GetFwId() != "" || one.Tags[0].GetOrphan() ||
		!one.Tags[1].GetOrphan() || one.Tags[1].GetFwId() != fwB {
		t.Fatalf("list bare = %v, want the VM (no identity) then the orphan row", one.GetTags())
	}

	both, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{Workload: "web"})
	if err != nil || len(both.GetTags()) != 2 || both.Tags[0].GetKind() != "vm" || both.Tags[1].GetKind() != "container" {
		t.Fatalf("list web, both kinds = %v %v", both.GetTags(), err)
	}
	if _, err := s.ListFirewallTags(viewerCtx(), &pb.ListFirewallTagsRequest{Workload: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown workload: %v", err)
	}
}

// A cutover leaves the replaced VM's tags with it (T-8) and says so, with
// the command that sets them on the VM now named so.
//
// Mutation: drop the note — red.
func TestCutoverVM_SaysWhichTagsStayWithTheReplacedVM(t *testing.T) {
	s, _, _, _ := cutoverFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	setVMSpec(t, s, "app", `{"name":"app","firewall_id":"`+fwA+`"}`)
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "app", "")
	st := &trailerStream{}
	if _, err := s.CutoverVM(grpc.NewContextWithServerTransportStream(adminCtx(), st), &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	notes := st.hdr.Get(firewallTagsLeftMD)
	if len(notes) != 1 || !strings.Contains(notes[0], "fw_id "+fwA) || !strings.Contains(notes[0], "role=web") ||
		!strings.Contains(notes[0], "lv firewall tag set app role=web") {
		t.Fatalf("cutover notes = %q", notes)
	}
	if got := vmFWID(t, s, "app"); got == fwA {
		t.Fatal("the replacement took the replaced VM's identity")
	}
}

// A rebuild or recreate that fails after its teardown names the tags the
// torn-down VM left (D2b review M-5).
//
// Mutation: drop the note — red.
func TestRecreateFailedAfterTeardown_NamesTheTagsLeft(t *testing.T) {
	s, _ := tagsServer(t)
	insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
	setVMSpec(t, s, "web", `{"name":"web","firewall_id":"`+fwA+`"}`)
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "web", "")
	if err := corrosion.DeleteVM(context.Background(), s.db, "web"); err != nil {
		t.Fatal(err)
	}
	err := s.recreateFailedAfterTeardown(adminCtx(), "rebuild", "web", s.hostName, &pb.VMSpec{Name: "web"}, status.Error(codes.Internal, "no space"), false)
	if !strings.Contains(err.Error(), "fw_id "+fwA) || !strings.Contains(err.Error(), "lv firewall tag set web role=web") {
		t.Fatalf("recreate failure: %v", err)
	}
}

// The orphan sweep: on the failover lease holder only, once the feature is
// used, it clears a row whose identity no live workload holds only past the
// grace (fake clock).
//
// Mutations: sweep without the grace — red; sweep on a non-holder — red.
func TestSweepFirewallTagOrphans(t *testing.T) {
	s, _, _, _ := sweepServer(t, "")
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	markTagsUsed(t, s)
	ctx := context.Background()
	if err := s.db.Execute(ctx, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at, deleted_at) VALUES ('gone', 'h', ?, 'stopped', 't', 't', ?)`,
		`{"firewall_id":"`+fwA+`"}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "gone", "")

	s.sweepFirewallTagOrphans(ctx, time.Now().Add(time.Hour))
	if v, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA); v == "" {
		t.Fatal("swept inside the grace")
	}
	other, _, _, _ := sweepServer(t, "someone-else")
	other.SetReleaseFeatureGate(&relGate{t: t, open: true})
	markTagsUsed(t, other)
	seedTagsFor(t, other, corrosion.TagMemberVM, fwA, map[string]string{"role": "web"}, "gone", "")
	other.sweepFirewallTagOrphans(ctx, time.Now().Add(48*time.Hour))
	if v, _ := tagsRowValue(t, other, corrosion.TagMemberVM, fwA); v == "" {
		t.Fatal("a host that does not hold the failover lease swept")
	}

	s.sweepFirewallTagOrphans(ctx, time.Now().Add(25*time.Hour))
	if v, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA); v != "" {
		t.Fatalf("an orphan past the grace was not cleared: %q", v)
	}
}

// Fleet scenarios for the rules that treat a cluster PEER's call differently
// from anyone else's. Until the harness presented a peer's connection as a
// peer's (peer_identity.go) every one of these branches was unreachable here,
// and forcing each away (isRemotePeer → false, the forwarded clone refusal
// off, forwardedImportCaller off) left the whole fleet suite green. Each
// scenario below goes red when its branch is removed; the mutation is named
// on it.

package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// userOn creates user with role on n and returns a token for it. Callers on a
// non-shared cluster wait for it to replicate themselves.
func userOn(t *testing.T, c *Cluster, n *Node, user, role string) string {
	t.Helper()
	ctx := context.Background()
	admin := c.SelfClient(n)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: user, Password: user + "-password-0123456789", Role: role}); err != nil {
		t.Fatalf("CreateUser %s: %v", user, err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: user})
	if err != nil || tok.GetToken() == "" {
		t.Fatalf("CreateToken %s: %s %v", user, credState(tok), err)
	}
	return tok.GetToken()
}

// latchForwardedIdentity turns auth.forwarded_identity on everywhere and waits
// for forwarded_identity_v1 to latch on every node.
func latchForwardedIdentity(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		n.Server.SetForwardedIdentity(true)
	}
	for _, n := range c.Nodes {
		g := gates[n.Name]
		eventually(t, 10*time.Second, n.Name+" to latch forwarded_identity_v1", func() bool {
			return g.Enforced(ctx, capabilities.ForwardedIdentityV1)
		})
	}
}

// startedContainer creates name on n and starts it.
func startedContainer(t *testing.T, c *Cluster, n *Node, name, project string) {
	t.Helper()
	createSizedContainer(t, c, n, name, project, 1, 256)
	if _, err := c.SelfClient(n).StartContainer(context.Background(), &pb.StartContainerRequest{HostName: n.Name, Name: name}); err != nil {
		t.Fatalf("StartContainer %s: %v", name, err)
	}
	if st := n.CT.State(name); !strings.EqualFold(st, "running") {
		t.Fatalf("%s is %q after its start", name, st)
	}
}

// A container delete without force refuses a running container — except from
// a peer: a current entry node judged it before forwarding, and an older one
// (a rolling upgrade) drives compose and relocation deletes that never
// carried the flag (containers.go, DeleteContainer).
//
// Mutation: drop `&& !s.isRemotePeer(ctx)` from the running check — the
// peer's delete is refused.
func TestFleet_PeerBranch_APeersDeleteOfARunningContainerIsExempt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	owner, peer := c.Nodes[0], c.Nodes[1]
	startedContainer(t, c, owner, "ct-run", "")

	// Control: the on-node root, which no entry node judged, is refused.
	if _, err := c.SelfClient(owner).DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: owner.Name, Name: "ct-run"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("on-node delete of a running container without force: err = %v, want FailedPrecondition", err)
	}
	if !owner.CT.Exists("ct-run") {
		t.Fatal("the refused delete removed the container")
	}

	if _, err := c.PeerClient(peer, owner).DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: owner.Name, Name: "ct-run"}); err != nil {
		t.Fatalf("%s's delete of a running container on %s: %v (a peer's delete is exempt from the running check)", peer.Name, owner.Name, err)
	}
	if owner.CT.Exists("ct-run") {
		t.Fatal("the peer's delete left the container")
	}
}

// The owner rules bind a forwarded call when the entry node marks it as made
// for a caller without the admin role (ownerStrict). An operator listing a
// container's snapshots through another node does not see the one an earlier
// container of the name, in another project, took; an admin through the same
// node does.
//
// Mutation: in ownerStrict, ignore the peer's marker (return false for every
// peer) — the operator sees the other project's snapshot.
func TestFleet_PeerBranch_TheOwnerRulesBindAForwardMadeForANonAdmin(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	for _, p := range []string{"/acme", "/beta"} {
		if err := corrosion.InsertProject(ctx, owner.DB, corrosion.ProjectRecord{Name: p}); err != nil {
			t.Fatalf("InsertProject %s: %v", p, err)
		}
	}
	createSizedContainer(t, c, owner, "ct1", "/acme", 1, 256)
	if _, err := c.SelfClient(owner).SnapshotContainer(ctx, &pb.SnapshotContainerRequest{Name: "ct1", HostName: owner.Name, Snapshot: "s1"}); err != nil {
		t.Fatalf("SnapshotContainer: %v", err)
	}
	// ct1 is deleted and the name taken by a container in project beta.
	if err := corrosion.DeleteContainer(ctx, owner.DB, owner.Name, "ct1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, owner.DB, corrosion.ContainerRecord{
		HostName: owner.Name, Name: "ct1", State: "stopped", Project: "/beta",
	}); err != nil {
		t.Fatal(err)
	}

	list := func(cl pb.LiteVirtClient) int {
		t.Helper()
		resp, err := cl.ListContainerSnapshots(ctx, &pb.ListContainerSnapshotsRequest{Name: "ct1", HostName: owner.Name})
		if err != nil {
			t.Fatalf("ListContainerSnapshots through %s: %v", entry.Name, err)
		}
		return len(resp.GetSnapshots())
	}
	if n := list(c.SelfClient(entry)); n != 1 {
		t.Fatalf("an admin through %s sees %d snapshots, want acme's one (the escape hatch)", entry.Name, n)
	}
	if n := list(operatorOn(t, c, entry)); n != 0 {
		t.Fatalf("an operator through %s sees %d snapshots of beta's ct1; acme's earlier container took it", entry.Name, n)
	}
}

// A compose recreate's delete forwarded from another entry node carries the
// recreate's template, and the member's host judges the create on its own
// disk before it deletes: a template in a protected place is refused there,
// and the member is kept. Only a peer's delete carries it; a client's is the
// plain delete it always was.
//
// Mutations: recreatePreflightIncoming ignores a peer (returns nil) — the
// peer's delete goes ahead; it accepts anyone (drop the isRemotePeer test) —
// the client's delete is refused.
func TestFleet_PeerBranch_AForwardedRecreatesDeleteIsJudgedOnTheMembersHost(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	protected := filepath.Join(c.tmpRoot, owner.Name, "data", "images", "ct-root")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	preflight := metadata.AppendToOutgoingContext(ctx,
		"x-litevirt-recreate-template-bin", protected, "x-litevirt-recreate-project-bin", "")

	createSizedContainer(t, c, owner, "web", "", 1, 256)
	_, err := c.PeerClient(entry, owner).DeleteContainer(preflight, &pb.DeleteContainerRequest{HostName: owner.Name, Name: "web", Force: true})
	if err == nil || !strings.Contains(err.Error(), "left as it is") {
		t.Fatalf("a forwarded recreate delete whose create would be refused: err = %v, want the member's host to refuse it", err)
	}
	if !owner.CT.Exists("web") {
		t.Fatal("the member was deleted although its recreate would be refused")
	}

	// A client cannot send the preflight: its delete is a plain delete.
	op := operatorOn(t, c, owner)
	if _, err := op.DeleteContainer(preflight, &pb.DeleteContainerRequest{HostName: owner.Name, Name: "web", Force: true}); err != nil {
		t.Fatalf("a client's delete carrying recreate metadata: %v (only a peer's carries a preflight)", err)
	}
	if owner.CT.Exists("web") {
		t.Fatal("the client's plain delete left the container")
	}
}

// With forwarded identity, the member's host judges a forwarded create as the
// deployer, and a compose recreate's create carries what the entry decided
// for it: a privileged member kept by an operator's redeploy stays privileged.
// The decision is honoured from a peer only; an operator sending it straight
// to the host is refused, as any operator asking for privilege is.
//
// Mutations: acceptRecreateInherit ignores a peer (isRemotePeer → false) —
// the forwarded create is refused; it accepts anyone — the operator's own
// create lands privileged.
func TestFleet_PeerBranch_AForwardedRecreateKeepsTheModeItWasJudgedFor(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 3301})
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	latchForwardedIdentity(t, c)
	tok := userOn(t, c, entry, "deployer", "operator")
	c.WaitConverged(t, convergeTimeout)

	req := func(name string) *pb.CreateContainerRequest {
		return &pb.CreateContainerRequest{HostName: owner.Name, Name: name, Template: "download",
			Distro: "debian", Release: "bookworm", Arch: "amd64", Cpu: 1, MemoryMib: 256, Privileged: true}
	}
	inherit := func(name string) string {
		b, _ := json.Marshal(map[string]any{"name": name, "host": owner.Name, "image": "", "template": "download",
			"privileged": true, "confinement": "", "inherited": true})
		return string(b)
	}
	fwd := metadata.AppendToOutgoingContext(ctx, "x-litevirt-fwd-bearer", "Bearer "+tok)

	// Control: the forwarded create without the decision is the operator's,
	// and an operator may not ask for privilege.
	if _, err := c.PeerClient(entry, owner).CreateContainer(fwd, req("plain")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a forwarded privileged create for an operator, no recreate decision: err = %v, want PermissionDenied", err)
	}
	decided := metadata.AppendToOutgoingContext(fwd, "x-litevirt-recreate-inherit-bin", inherit("kept"))
	if _, err := c.PeerClient(entry, owner).CreateContainer(decided, req("kept")); err != nil {
		t.Fatalf("a forwarded recreate's create carrying its decision: %v", err)
	}
	if rec, _ := corrosion.GetContainer(ctx, owner.DB, owner.Name, "kept"); rec == nil {
		t.Fatal("the recreate's create left no row")
	}

	// The decision from a client is ignored.
	own := metadata.AppendToOutgoingContext(ctx, "x-litevirt-recreate-inherit-bin", inherit("forged"))
	if _, err := c.bearerClient(owner, tok).CreateContainer(own, req("forged")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator sending a recreate decision itself: err = %v, want PermissionDenied", err)
	}
}

// A forwarded plain delete is recorded on its iSCSI LUNs by the ENTRY host,
// which knows what the delete is for; the member's host does not record the
// forward it serves. A compose recreate's delete is no plain delete: entered
// on one node for a VM on another, it must leave no record, or it voids the
// LUN allocation the recreate keeps for the new incarnation.
//
// Mutation: drop `!s.isRemotePeer(ctx)` from DeleteVM's record condition —
// the member's host records the recreate's forwarded delete as a plain one.
func TestFleet_PeerBranch_AForwardedRecreateDeleteRecordsNoPlainDeleteOnItsLUN(t *testing.T) {
	c, web, stack := lunWebStack(t, "")
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	lun := fleetLUNKey(0)
	recorded := func() string {
		t.Helper()
		for _, n := range c.Nodes {
			if v, err := corrosion.GetLUNPlainDelete(ctx, n.DB, lun); err != nil {
				t.Fatalf("GetLUNPlainDelete on %s: %v", n.Name, err)
			} else if v != "" {
				return n.Name + ": " + v
			}
		}
		return ""
	}
	// An inline recreate (a disk-topology change), entered on node-0, of web
	// on node-1.
	before, err := corrosion.GetVM(ctx, n0.DB, web)
	if err != nil || before == nil {
		t.Fatalf("%s before its recreate: %v", web, err)
	}
	deployCollect(t, ctx, c.SelfClient(n0), stack(n1.Name, "      scratch: 1G\n"))
	eventually(t, convergeTimeout, web+"'s new incarnation to reach every node", func() bool {
		for _, n := range c.Nodes {
			if r, _ := corrosion.GetVM(ctx, n.DB, web); r == nil || r.CreatedAt == before.CreatedAt {
				return false
			}
		}
		return true
	})
	waitVMAgreed(t, c, web)
	if r := recorded(); r != "" {
		t.Fatalf("a recreate entered on %s for %s's VM recorded a plain delete on the LUN (%s)", n0.Name, n1.Name, r)
	}

	// Control: a plain delete entered on node-0 is recorded, by node-0.
	var rec *corrosion.VMRecord
	rec, err = corrosion.GetVM(ctx, n0.DB, web)
	if err != nil || rec == nil {
		t.Fatalf("%s after its recreate: %v", web, err)
	}
	if _, err := c.SelfClient(n0).DeleteVM(ctx, &pb.DeleteVMRequest{Name: web}); err != nil {
		t.Fatalf("DeleteVM %s: %v", web, err)
	}
	eventually(t, convergeTimeout, "the plain delete's record", func() bool {
		v, _ := corrosion.GetLUNPlainDelete(ctx, n0.DB, lun)
		return v == rec.CreatedAt
	})
}

// Under split-brain enforcement a coordinator's restore — another node's
// daemon restoring a container here — must carry a proof. The on-node root's
// restore is an operator restore and needs none.
//
// Mutation: drop the proofless-coordinator refusal (or force isRemotePeer to
// false) — the peer's proofless restore lays the container down.
func TestFleet_PeerBranch_AProoflessCoordinatorRestoreIsRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	enforceGate(t, c)
	createSizedContainer(t, c, src, "ct-coord", "", 1, 256)
	repo, ts := backupContainer(t, c, src, "ct-coord")

	restore := func(cl pb.LiteVirtClient) error {
		st, err := cl.RestoreContainer(context.Background(), &pb.RestoreContainerRequest{
			RepoPath: repo, Name: "ct-coord", Timestamp: ts, HostName: dst.Name,
		})
		if err != nil {
			return err
		}
		for {
			if _, err := st.Recv(); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
	err := restore(c.PeerClient(src, dst))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "requires a proof") {
		t.Fatalf("%s's proofless restore on %s: err = %v, want the coordinator-proof refusal", src.Name, dst.Name, err)
	}
	if dst.CT.Exists("ct-coord") {
		t.Fatal("the refused restore laid the container down")
	}
	// Control: the operator's own restore on the host is not a coordinator's.
	if err := restore(c.SelfClient(dst)); err != nil && strings.Contains(err.Error(), "requires a proof") {
		t.Fatalf("the on-node root's restore was refused as a coordinator's: %v", err)
	}
}

// A clone onto another host made where the source is, entered at another
// node for a user, would run its move as the forwarding peer (an admin) where
// forwarded identity is not enforced. The source host refuses it, naming the
// way out; the same user's clone sent to the source host itself is judged as
// that user.
//
// Mutation: drop the forwarded cross-host clone refusal in CloneVM — the
// forwarded clone is made.
func TestFleet_PeerBranch_AForwardedCrossHostCloneIsRefusedWithoutForwardedIdentity(t *testing.T) {
	f := newCloneFleet(t)
	ctx := context.Background()
	tok := userOn(t, f.c, f.entry, "cloner", "operator")

	_, err := f.c.bearerClient(f.entry, tok).CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "c-fwd", DestinationHost: f.dst.Name})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "as a cluster peer, not as you") {
		t.Fatalf("an operator's cross-host clone entered at %s: err = %v, want the source host's refusal", f.entry.Name, err)
	}
	if rec, _ := corrosion.GetVM(ctx, f.entry.DB, "c-fwd"); rec != nil {
		t.Fatalf("the refused clone left a row: %+v", rec)
	}
	// Control: sent to the source host, the clone is the operator's own.
	if _, err := f.c.bearerClient(f.src, tok).CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "c-direct", DestinationHost: f.dst.Name}); err != nil &&
		strings.Contains(err.Error(), "as a cluster peer") {
		t.Fatalf("the operator's clone sent to the source host was refused as a forward: %v", err)
	}
}

// A forwarded import (--target-host) of a host path outside the import
// staging root is judged on the target as the entry node's caller, by the
// bearer the entry relays — never as the forwarding peer, an admin. An
// operator is refused; an admin through the same entry node is not.
//
// Mutation: drop the forwardedImportCaller step in resolveStagedPath — the
// operator's forwarded import reads the host path as the peer.
func TestFleet_PeerBranch_AForwardedImportIsJudgedAsItsCaller(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, target := c.Nodes[0], c.Nodes[1]
	tok := userOn(t, c, entry, "importer", "operator")
	outside := t.TempDir()

	importVia := func(cl pb.LiteVirtClient, name string) error {
		st, err := cl.ImportVM(context.Background())
		if err != nil {
			return err
		}
		if err := st.Send(&pb.ImportVMRequest{Name: name, TargetHost: target.Name, SourcePath: outside, Inspect: true, Final: true}); err != nil {
			return err
		}
		_ = st.CloseSend()
		for {
			if _, err := st.Recv(); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
	err := importVia(c.bearerClient(entry, tok), "imp-op")
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "outside the import staging root") {
		t.Fatalf("an operator's forwarded import of a host path: err = %v, want the staging-root refusal", err)
	}
	// Control: an admin's forwarded import gets past the path check.
	if err := importVia(c.SelfClient(entry), "imp-admin"); err != nil && strings.Contains(err.Error(), "outside the import staging root") {
		t.Fatalf("an admin's forwarded import was refused the host path: %v", err)
	}
}

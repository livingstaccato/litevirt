// Fleet scenarios for the firewall identity's carry tokens (firewall extras
// spec §4.3, D2b): a path that puts the SAME workload back under a new row —
// a rebuild or rolling recreate, a container's cold migrate or relocation —
// keeps its fw_id, read from the row its own operation retires; a new
// workload — a clone, a template instantiate, an operator restore, a replica
// restore into a freed name — gets none; and a client can never hand one in,
// through the re-create's peer-only metadata or a spec field.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// fwIDIn is the identity doc holds under key, read exactly, as the members
// query reads it.
func fwIDIn(doc, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(doc), &m) != nil {
		return ""
	}
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}

// mintFWID mints the firewall identity of workload name on n, as tag set
// will, and waits until every replica has it.
func mintFWID(t *testing.T, c *Cluster, n *Node, kind, host, name string) string {
	t.Helper()
	n.DB.SetRepointReady(func(context.Context) bool { return true })
	id, _, err := corrosion.MintFirewallID(context.Background(), n.DB,
		capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups), kind, host, name)
	if err != nil || id == "" {
		t.Fatalf("mint the firewall identity of %s %s on %s: %q %v", kind, name, n.Name, id, err)
	}
	c.WaitConverged(t, convergeTimeout)
	return id
}

// vmFWIDOn is the identity n's replica holds for VM name ("" for no row).
func vmFWIDOn(t *testing.T, n *Node, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil {
		t.Fatal(err)
	}
	if vm == nil {
		return ""
	}
	return fwIDIn(vm.Spec, "firewall_id")
}

// ctFWIDOn is the identity n's replica holds for container (host, name).
func ctFWIDOn(t *testing.T, n *Node, host, name string) string {
	t.Helper()
	ct, err := corrosion.GetContainer(context.Background(), n.DB, host, name)
	if err != nil || ct == nil {
		t.Fatalf("container %s on %s in %s's replica: %v %v", name, host, n.Name, ct, err)
	}
	return fwIDIn(ct.CreateSpec, "fw_id")
}

// seedTagsRow writes a firewall-tags row into n's replica alone: what a
// restore into a freed name reads to say what the deleted incarnation left.
func seedTagsRow(t *testing.T, n *Node, kind, id, value string) {
	t.Helper()
	if err := localExec(context.Background(), n.DB,
		`INSERT OR REPLACE INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'test', ?)`,
		corrosion.FirewallTagsKeyPrefix+kind+"/"+id, value, n.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
}

// A rebuild whose create is forwarded to a host behind on the tombstone keeps
// the VM's identity on every replica: the create carries it from the row its
// own delete tombstoned, across the forward in the peer-only metadata
// (R3-I1, R4-I1).
//
// Mutation: drop the token on rebuild (createVM's insert carries none) — the
// rebuilt VM has no identity: red.
func TestFirewallIDCarry_ARebuildForwardedToAHostBehindKeepsIt(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	id := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "web")
	lagFrom(c, n0, c.Nodes[1:]...)

	if _, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
	for _, n := range c.Nodes {
		if got := vmFWIDOn(t, n, "web"); got != id {
			t.Errorf("the rebuilt VM's identity on %s's replica = %q, want %q (membership lost)", n.Name, got, id)
		}
	}
}

// A stack's rolling recreate, run from a third node, of a VM whose delete
// runs on its owner and whose create lands on another host: the identity the
// owner's delete reported travels with the create.
func TestFirewallIDCarry_ARollingRecreateKeepsIt(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	id := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "web")
	lagFrom(c, n0, n1, n2)

	desired := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
	for _, n := range c.Nodes {
		if got := vmFWIDOn(t, n, "web"); got != id {
			t.Errorf("the recreated VM's identity on %s's replica = %q, want %q", n.Name, got, id)
		}
	}
}

// adminToken mints an admin's bearer token on n, for a CLIENT: no peer
// certificate stands behind its calls.
func adminToken(t *testing.T, c *Cluster, n *Node) string {
	t.Helper()
	ctx := context.Background()
	admin := c.SelfClient(n)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "ops", Password: "p4ssw0rd-ops", Role: "admin"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "ops", Name: "fw"})
	if err != nil || tok.GetToken() == "" {
		t.Fatalf("CreateToken: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	return tok.GetToken()
}

// R4-I1: a client cannot hand a create an identity. It sends the re-create's
// metadata naming a tagged VM's fw_id, and the same fw_id in its spec; the
// create gets none, forwarded to another host or served where it lands.
//
// Mutation: honour the replaced-VM metadata from a non-peer
// (acceptReplacedVMMD without its peer check) — both creates carry the
// victim's identity: red.
func TestFirewallIDCarry_AClientCannotHandACreateAnIdentity(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	seedVM(t, c, n0, &pb.VMSpec{Name: "victim", Cpu: 1, MemoryMib: 256})
	victim := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "victim")
	token := adminToken(t, c, n0)

	claim := func(name string) context.Context {
		b, err := json.Marshal(map[string]any{
			"name": name, "created_at": "2026-10-15T00:00:00Z", "host_name": n0.Name,
			"identity_hash": "forged", "firewall_id": victim,
		})
		if err != nil {
			t.Fatal(err)
		}
		return metadata.AppendToOutgoingContext(context.Background(), "x-litevirt-recreate-replaces", string(b))
	}
	for _, tc := range []struct {
		what, name string
		entry      *Node
	}{
		{"forwarded to another host", "intruder", n0},
		{"served where it lands", "intruder2", n1},
	} {
		client := c.bearerClient(tc.entry, token)
		if _, err := client.CreateVM(claim(tc.name), &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: tc.name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}, FirewallId: victim,
		}}); err != nil {
			t.Fatalf("%s: CreateVM: %v", tc.what, err)
		}
		c.WaitConverged(t, convergeTimeout)
		for _, n := range c.Nodes {
			if got := vmFWIDOn(t, n, tc.name); got != "" {
				t.Errorf("%s: %s holds identity %q on %s's replica; a client's create gets none", tc.what, tc.name, got, n.Name)
			}
		}
	}
	if got := vmFWIDOn(t, n1, "victim"); got != victim {
		t.Errorf("the victim's identity = %q, want %q", got, victim)
	}
}

// A clone, and a template instantiate (a clone of a template), are new
// workloads: neither inherits the source's identity, on the source's host or
// on another (spec §4.3, R2-I1).
//
// Mutation: carry the source's identity on clone — red.
func TestFirewallIDCarry_ACloneGetsNone(t *testing.T) {
	f := newCloneFleet(t)
	id := mintFWID(t, f.c, f.entry, corrosion.TagMemberVM, "", "tpl")
	for _, req := range []*pb.CloneVMRequest{
		{Target: "c-here"},
		{Target: "c-there", DestinationHost: f.dst.Name},
	} {
		if _, err := f.clone(t, req); err != nil {
			t.Fatalf("clone %s: %v", req.Target, err)
		}
		if got := fwIDIn(f.vm(t, req.Target).Spec, "firewall_id"); got != "" {
			t.Errorf("clone %s inherited identity %q", req.Target, got)
		}
	}
	if got := fwIDIn(f.vm(t, "tpl").Spec, "firewall_id"); got != id {
		t.Errorf("the template's identity = %q, want %q", got, id)
	}
}

// A container clone, and a container template's instantiate (a clone of the
// template), are new containers: neither inherits the source's identity. The
// in-place conversion to a template is an update of the same container, and
// keeps it.
func TestFirewallIDCarry_AContainerCloneGetsNone(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	createContainer(t, c, n, "src")
	id := mintFWID(t, c, n, corrosion.TagMemberCT, n.Name, "src")
	cl := c.SelfClient(n)
	if _, err := cl.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "src", Target: "c-clone", HostName: n.Name}); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err := cl.ConvertContainerToTemplate(ctx, &pb.ConvertContainerToTemplateRequest{Name: "src", HostName: n.Name}); err != nil {
		t.Fatalf("convert to a template: %v", err)
	}
	if _, err := cl.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "src", Target: "c-inst", HostName: n.Name}); err != nil {
		t.Fatalf("instantiate the template: %v", err)
	}
	for _, name := range []string{"c-clone", "c-inst"} {
		if got := ctFWIDOn(t, n, n.Name, name); got != "" {
			t.Errorf("%s inherited identity %q", name, got)
		}
	}
	if got := ctFWIDOn(t, n, n.Name, "src"); got != id {
		t.Errorf("the template's identity = %q, want %q", got, id)
	}
}

// A container's cold migrate moves the same container: the target's row keeps
// the identity of the live source row the migrate then deletes.
//
// Mutation: drop the carry from RestoreContainer — red.
func TestFirewallIDCarry_AContainerMigrateKeepsIt(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-move"
	createContainer(t, c, src, name)
	id := mintFWID(t, c, src, corrosion.TagMemberCT, src.Name, name)
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := ctFWIDOn(t, dst, dst.Name, name); got != id {
		t.Fatalf("the migrated container's identity = %q, want %q", got, id)
	}
}

// A failover promotes a container's replica on the host that holds it, under
// the coordinator's relocation token: the same container, keeping the
// identity of the row the coordinator marked relocating.
func TestFirewallIDCarry_AReplicaPromotionKeepsIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dead, target, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, dead, name)
	id := mintFWID(t, c, dead, corrosion.TagMemberCT, dead.Name, name)
	drRepo(t, target)
	sched := ctSchedule(t, c, dead, name, target.Name, 3, true)
	dead.CT.Seed(name, "replicated")
	if err := dead.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if outcome, err := promoteVia(t, coord, dead, target, name, "tok-fw"); err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("promotion: (%v, %v)", outcome, err)
	}
	if got := ctFWIDOn(t, target, target.Name, name); got != id {
		t.Fatalf("the promoted container's identity = %q, want %q", got, id)
	}
}

// An operator's restore of a container backup into its freed name is a new
// container, whatever the archived create spec held (spec §4.3).
func TestFirewallIDCarry_AnOperatorRestoreGetsNone(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	const name = "ct-back"
	createContainer(t, c, n, name)
	id := mintFWID(t, c, n, corrosion.TagMemberCT, n.Name, name)
	repo, ts := backupContainer(t, c, n, name)
	if err := n.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, n.DB, n.Name, name); err != nil {
		t.Fatal(err)
	}
	st, err := c.SelfClient(n).RestoreContainer(ctx, &pb.RestoreContainerRequest{
		RepoPath: repo, Name: name, Timestamp: ts, HostName: n.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("restore: %v", rerr)
		}
	}
	if got := ctFWIDOn(t, n, n.Name, name); got != "" {
		t.Errorf("the restored container holds identity %q (the backup's was %q); a restore is a new container", got, id)
	}
}

// R3-I1: a replica restored into a freed name is a new container. The
// deleted one's tags row is still there (its clear failed); the restore gets
// no identity, so it is a member of nothing, and it says which tags the
// deleted container left and how to set them again.
//
// Mutation: mint a carry token from the delete's tombstone — red.
func TestFirewallIDCarry_AReplicaRestoreIntoAFreedNameGetsNone(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, tg := c.Nodes[0], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, tg)
	c.WaitConverged(t, convergeTimeout)
	id := mintFWID(t, c, a, corrosion.TagMemberCT, a.Name, name)
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}
	seedTagsRow(t, tg, corrosion.TagMemberCT, id, `{"tags":{"role":"web","env":"prod"},"name":"web"}`)
	if err := a.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, a.DB, a.Name, name); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		waitForRepl(t, n.Name+" to apply the tombstone", func() bool { return containerHostOn(t, n, name) == "" })
	}

	var hdr metadata.MD
	if _, err := c.SelfClient(tg).RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp,
	}, grpc.Header(&hdr)); err != nil {
		t.Fatalf("restore the replica into the freed name: %v", err)
	}
	if got := ctFWIDOn(t, tg, tg.Name, name); got != "" {
		t.Fatalf("the restored container holds identity %q (the deleted one's was %q)", got, id)
	}
	note := strings.Join(hdr.Get("x-litevirt-firewall-tags-left"), "\n")
	for _, want := range []string{"env=prod", "role=web",
		"lv firewall tag set " + name + " --container --host " + tg.Name + " env=prod role=web"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the restore's note %q does not say %q", note, want)
		}
	}
}

// D2b review I-1: a rolling recreate run from node-2, whose replica still
// holds incarnation A of web (fw_id X, tagged) after web was deleted and
// re-created on node-0 as B. The delete runs on node-0 and tombstones B; its
// report names B, which is not the incarnation node-2 meant, so node-2 has no
// report it may accept and falls back to its own copy, A. A was ended by
// another delete: its identity must not come back on the re-created VM.
//
// Mutation: carry from the fallback copy (drop the strip in recreateAs) — the
// re-created VM holds X: red.
func TestFirewallIDCarry_ARecreateFromAStaleCopyCarriesNoForeignIdentity(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	x := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "web")
	n1.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	n2.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	// node-2 hears nothing from here on: it keeps A.
	c.SetLinkFault(n0, n2, LinkFault{Block: true})
	c.SetLinkFault(n1, n2, LinkFault{Block: true})

	// A is deleted, and B created in its name, on node-0.
	if err := corrosion.DeleteVM(ctx, n0.DB, "web"); err != nil {
		t.Fatal(err)
	}
	if err := n0.Virt.UndefineDomain("web", false); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Uuid: "6a1f3c2e-0d4b-4e8a-9c7d-1b2a3c4d5e6f"})
	if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
		Name: "web", HostName: n0.Name, State: "stopped", Spec: string(b), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := n0.Virt.DefineDomain(`<domain><name>web</name></domain>`); err != nil {
		t.Fatal(err)
	}
	waitForRepl(t, n1.Name+" to see B", func() bool {
		vm, _ := corrosion.GetVM(ctx, n1.DB, "web")
		return vm != nil && fwIDIn(vm.Spec, "firewall_id") == ""
	})
	if got := vmFWIDOn(t, n2, "web"); got != x {
		t.Fatalf("premise: %s still holds A with %q, got %q", n2.Name, x, got)
	}

	desired := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate: %v; %s", err, whereIs(c, "web"))
	}
	if got := vmFWIDOn(t, n1, "web"); got != "" {
		t.Fatalf("the re-created VM holds identity %q; A's was %q and B had none", got, x)
	}
}

// gatedMigrateCluster is ctMigrateCluster with the release latched and the
// split-brain gate at quorum: a migrate then mints its relocation proof.
func gatedMigrateCluster(t *testing.T) *Cluster {
	t.Helper()
	c := ctMigrateCluster(t)
	gates := latchRelease(t, c)
	qctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, n := range c.Nodes {
		go gates[n.Name].Start(qctx)
	}
	for _, n := range c.Nodes {
		eventually(t, 20*time.Second, "quorum on "+n.Name, func() bool {
			state, _, _ := gates[n.Name].QuorumProof(context.Background())
			return state == health.QuorumYes
		})
	}
	return c
}

// D2b review I-2: a cold migrate whose target landed and whose source is then
// parked (its runtime delete failed) leaves two live rows holding one fw_id,
// for as long as an operator takes. With a tag group present, the pair is
// recognised from the migrate's own proof: the target is the member, neither
// row is held at drop. A third live holder of the id is still held, and
// minting the id refuses while the move is open.
//
// Mutation: drop the move exemption — both rows are held: red.
func TestFirewallIDCarry_AParkedMigrateIsNotHeldAndRefusesAMint(t *testing.T) {
	c := gatedMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-park"
	createContainer(t, c, src, name)
	id := mintFWID(t, c, src, corrosion.TagMemberCT, src.Name, name)
	if err := corrosion.SetFirewallTagGroup(ctx, src.DB, capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups),
		"web", &corrosion.FirewallTagGroupDef{Match: map[string]string{"role": "web"}}, "test"); err != nil {
		t.Fatal(err)
	}
	seedTagsRow(t, src, corrosion.TagMemberCT, id, `{"tags":{"role":"web"}}`)

	src.CT.FailDelete(errors.New("simulated source runtime delete failure"))
	merr := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if merr == nil || !strings.Contains(merr.Error(), "source runtime cleanup failed") {
		t.Fatalf("premise: the migrate was to land and park its source, got %v", merr)
	}
	if got := ctFWIDOn(t, dst, dst.Name, name); got != id {
		t.Fatalf("premise: the target landed with %q, want %q", got, id)
	}
	if got := ctFWIDOn(t, src, src.Name, name); got != id {
		t.Fatalf("premise: the parked source holds %q, want %q", got, id)
	}

	m, err := corrosion.ListTagGroupMembers(ctx, dst.DB)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.SharedFWID) != 0 {
		t.Fatalf("the migrate's own pair is held at drop: %+v", m.SharedFWID)
	}
	var members []string
	for _, g := range m.Groups {
		for _, mb := range g.Members {
			members = append(members, mb.Host+"/"+mb.Name)
		}
	}
	if !slices.Equal(members, []string{dst.Name + "/" + name}) {
		t.Fatalf("members %v, want the target alone", members)
	}

	dst.DB.SetRepointReady(func(context.Context) bool { return true })
	_, _, err = corrosion.MintFirewallID(ctx, dst.DB, capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups),
		corrosion.TagMemberCT, dst.Name, name)
	if !errors.Is(err, corrosion.ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "migration of container "+name) {
		t.Fatalf("a mint during the open migrate: %v, want refused naming it", err)
	}

	// A third live holder of the id is no part of the move: all are held.
	if err := localExec(ctx, dst.DB, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at)
		VALUES ('node-9', ?, 'running', ?, 't', 't')`, name, `{"fw_id":"`+id+`"}`); err != nil {
		t.Fatal(err)
	}
	if m, err = corrosion.ListTagGroupMembers(ctx, dst.DB); err != nil {
		t.Fatal(err)
	}
	if len(m.SharedFWID) != 3 {
		t.Fatalf("with a third holder, held: %+v, want all three", m.SharedFWID)
	}
}

// D2b review I-5: a CLIENT cannot hand a container restore an identity
// either. It sends a victim's fw_id in source_create_spec, with the migrate
// marker naming the victim's host — and, separately, a relocation token too.
// The token without a peer certificate is refused outright; the migrate
// marker is ignored, so the restore is an operator's and keeps no identity.
//
// Mutation: honour the migrate marker from a non-peer (drop the transport and
// CN checks in migrateSourceFromPeer) — the restore carries the victim's
// identity: red.
func TestFirewallIDCarry_AClientCannotHandARestoreAnIdentity(t *testing.T) {
	c := ctMigrateCluster(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	createContainer(t, c, n0, "victim")
	victim := mintFWID(t, c, n0, corrosion.TagMemberCT, n0.Name, "victim")
	const name = "ct-client"
	createContainer(t, c, n1, name)
	repo, ts := backupContainer(t, c, n1, name)
	if err := n1.CT.DeleteContainer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, n1.DB, n1.Name, name); err != nil {
		t.Fatal(err)
	}
	client := c.bearerClient(n1, adminToken(t, c, n0))
	restore := func(md ...string) error {
		st, err := client.RestoreContainer(metadata.AppendToOutgoingContext(ctx, md...), &pb.RestoreContainerRequest{
			RepoPath: repo, Name: name, Timestamp: ts, HostName: n1.Name,
			SourceCreateSpec: `{"template":"debian","fw_id":"` + victim + `"}`,
		})
		if err != nil {
			return err
		}
		for {
			if _, err := st.Recv(); err == io.EOF {
				return nil
			} else if err != nil {
				return err
			}
		}
	}

	if err := restore("x-litevirt-migrate-from-host", n0.Name, "x-litevirt-relocate-token", "tok-forged"); err == nil {
		t.Fatal("a client's restore carrying a relocation token was accepted")
	}
	if rec, _ := corrosion.GetContainer(ctx, n1.DB, n1.Name, name); rec != nil {
		t.Fatalf("a refused restore left a row: %+v", rec)
	}
	if err := restore("x-litevirt-migrate-from-host", n0.Name); err != nil {
		t.Fatalf("a client's restore with the migrate marker (ignored): %v", err)
	}
	if got := ctFWIDOn(t, n1, n1.Name, name); got != "" {
		t.Fatalf("a client's restore holds identity %q (the victim's is %q)", got, victim)
	}
}

// D2b review M-2: a compose deploy entered on a node that does not host web
// re-creates web inline (a stack's recreate: it keeps web's identity, from
// the row its owner's delete reported) and creates api in the same run (a
// new workload: none).
//
// Mutation: drop the token on the create (as N1) — web loses its identity:
// red. (api's create runs on a context of its own that names no replaced VM,
// so it cannot pick up web's.)
func TestFirewallIDCarry_AComposeInlineRecreateKeepsItAndACreateGetsNone(t *testing.T) {
	c, before := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	id := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "web")
	lagFrom(c, n0, n1, n2)

	yaml := recreateRemoteYAML("node-0", "second") + `  api:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
`
	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), yaml)
	for _, vm := range []string{"web", "api"} {
		if p := errorPhaseFor(msgs, vm); p != nil {
			t.Fatalf("deploy of %s: %s; %s", vm, p.Error, whereIs(c, vm))
		}
	}
	assertReCreated(t, c, "web", before, n0)
	if api, err := corrosion.GetVM(context.Background(), n0.DB, "api"); err != nil || api == nil {
		t.Fatalf("premise: api was created: %v %v", api, err)
	}
	for _, n := range c.Nodes {
		if got := vmFWIDOn(t, n, "web"); got != id {
			t.Errorf("web's identity on %s's replica = %q, want %q", n.Name, got, id)
		}
		if got := vmFWIDOn(t, n, "api"); got != "" {
			t.Errorf("api, created in the same deploy, holds identity %q on %s's replica", got, n.Name)
		}
	}
}

// D2b re-review N-1: a container migrated A -> B, then back B -> A, where the
// way back parks its source on B. Both proofs bind a direction between the
// two live rows (the first one A -> B, the second B -> A); the newer one
// decides, so the live target on A is the member and B is left out. Never
// "in no group and not held".
//
// Mutation: take the first direction that matches — red when the target's
// row is scanned first.
func TestFirewallIDCarry_AMigrateThereAndBackParkedKeepsTheTargetTheMember(t *testing.T) {
	c := gatedMigrateCluster(t)
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-back"
	createContainer(t, c, a, name)
	id := mintFWID(t, c, a, corrosion.TagMemberCT, a.Name, name)
	if err := corrosion.SetFirewallTagGroup(ctx, a.DB, capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups),
		"web", &corrosion.FirewallTagGroupDef{Match: map[string]string{"role": "web"}}, "test"); err != nil {
		t.Fatal(err)
	}
	seedTagsRow(t, a, corrosion.TagMemberCT, id, `{"tags":{"role":"web"}}`)
	if err := runMigrate(t, c, a, b, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate there: %v", err)
	}
	b.CT.FailDelete(errors.New("simulated source runtime delete failure"))
	if err := runMigrate(t, c, b, a, name, stagingRepo(t)); err == nil || !strings.Contains(err.Error(), "source runtime cleanup failed") {
		t.Fatalf("premise: the way back was to land and park its source on %s, got %v", b.Name, err)
	}
	for _, n := range []*Node{a, b} {
		if got := ctFWIDOn(t, a, n.Name, name); got != id {
			t.Fatalf("premise: the row on %s holds %q, want %q", n.Name, got, id)
		}
	}
	m, err := corrosion.ListTagGroupMembers(ctx, a.DB)
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, g := range m.Groups {
		for _, mb := range g.Members {
			members = append(members, mb.Host+"/"+mb.Name)
		}
	}
	if len(m.SharedFWID) != 0 || !slices.Equal(members, []string{a.Name + "/" + name}) {
		t.Fatalf("members %v, held %+v; want the live target on %s the only member", members, m.SharedFWID, a.Name)
	}
}

// D2b re-review M-b: I-1 scenario A on the inline compose recreate. node-2
// is cut off and still holds incarnation A of web (fw_id X); on node-0, A was
// deleted and B created in its name. A deploy entered on node-2 re-creates
// web inline: the owner's delete tombstones B and reports B, which node-2
// does not accept, so the create names node-2's copy of A for its existence
// check only — never A's identity.
//
// Mutation: drop the strip on the row-only fallback in recreateInline — the
// re-created web holds X: red.
func TestFirewallIDCarry_AnInlineRecreateFromAStaleCopyCarriesNoForeignIdentity(t *testing.T) {
	c, _ := newRecreateRemoteFleet(t, 2, "node-0")
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	x := mintFWID(t, c, n0, corrosion.TagMemberVM, "", "web")
	c.SetLinkFault(n0, n2, LinkFault{Block: true})
	c.SetLinkFault(n1, n2, LinkFault{Block: true})
	a, err := corrosion.GetVM(ctx, n0.DB, "web")
	if err != nil || a == nil {
		t.Fatalf("web on %s: %v", n0.Name, err)
	}
	if err := corrosion.DeleteVM(ctx, n0.DB, "web"); err != nil {
		t.Fatal(err)
	}
	b := *a
	b.CreatedAt, b.OwnerEpoch, b.SpecGeneration = "", 0, 0
	if err := corrosion.InsertVM(ctx, n0.DB, b, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := vmFWIDOn(t, n0, "web"); got != "" {
		t.Fatalf("premise: B holds no identity, got %q", got)
	}
	if got := vmFWIDOn(t, n2, "web"); got != x {
		t.Fatalf("premise: %s still holds A with %q, got %q", n2.Name, x, got)
	}

	msgs := deployCollect(t, ctx, c.SelfClient(n2), recreateRemoteYAML("node-0", "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("inline recreate from a stale copy: %s; %s", p.Error, whereIs(c, "web"))
	}
	assertUserdata(t, n0, "second")
	if got := vmFWIDOn(t, n0, "web"); got != "" {
		t.Fatalf("the re-created web holds identity %q; A's was %q and B had none", got, x)
	}
}

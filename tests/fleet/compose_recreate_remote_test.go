// Fleet scenarios: an inline (default-strategy) compose re-create entered on
// a node that does not host the VM.
//
// Observed on lab 1, 2026-10-13 (lab1-composeguard-3f3a2917.md, F1; 5 of 5
// runs, two builds): `lv compose up` on node-1 of a stack whose VM runs on
// node-4, with a cloud-init change. recreateInline forwarded the delete to
// node-4, which tore the VM down, then ran the create on node-1, whose
// replica had not applied the tombstone yet (11 ms later). node-1's existence
// check saw the old row and refused AlreadyExists: the VM and its disks were
// gone. From the owner it never happened — the owner's own replica has the
// tombstone. The inline path named the VM it replaces only for a VM on an
// iSCSI LUN, so the create could not tell that row from another VM's.
//
// Replication from the deleting host is delayed (or cut off) so the create
// always gets to a stale replica first.
package fleet

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeRecreateRemote = `name: rr

images:
  test:
    source: file:///dev/null

vms:
  web:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: HOST
    cloud-init:
      userdata: |
        #cloud-config
        hostname: USERDATA
`

func recreateRemoteYAML(host, userdata string) string {
	return strings.NewReplacer("HOST", host, "USERDATA", userdata).Replace(composeRecreateRemote)
}

// newRecreateRemoteFleet is three independent replicas, each able to create
// web from image test, with web deployed onto host through deployer.
func newRecreateRemoteFleet(t *testing.T, deployer int, host string) (*Cluster, *corrosion.VMRecord) {
	t.Helper()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, c.Nodes[0].DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatal(err)
		}
	}
	c.WaitConverged(t, 20*time.Second)
	d := c.Nodes[deployer]
	deployClean(t, ctx, c.SelfClient(d), recreateRemoteYAML(host, "first"))
	// Every replica holds web as its host wrote it (vms is compared apart:
	// waitHistoryApplied).
	waitHistoryApplied(t, c, 20*time.Second)
	var owner *Node
	for _, n := range c.Nodes {
		if n.Name == host {
			owner = n
		}
	}
	before, err := corrosion.GetVM(ctx, owner.DB, "web")
	if err != nil || before == nil || before.HostName != host {
		t.Fatalf("web after the first deploy: %+v (%v), want it on %s", before, err, host)
	}
	return c, before
}

// assertUserdata checks web's stored spec on n carries the second deploy's
// cloud-init: the re-create applied the file.
func assertUserdata(t *testing.T, n *Node, want string) {
	t.Helper()
	rec, _ := corrosion.GetVM(context.Background(), n.DB, "web")
	if rec == nil || !strings.Contains(rec.Spec, want) {
		t.Errorf("web's spec on %s does not carry the new cloud-init %q", n.Name, want)
	}
}

// The lab's case. web runs on node-0; the deploy enters on node-1, whose
// replica is behind node-0 on the tombstone. The delete runs on node-0 and
// the create's existence check on node-1 sees the old row.
//
// Red against 029413eb: "AlreadyExists: VM "web" already exists", and web is
// gone on every node.
func TestFleet_AComposeRecreateEnteredOnANonOwnerKeepsTheVM(t *testing.T) {
	c, before := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	lagFrom(c, n0, n1, n2)

	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteYAML("node-0", "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create entered on %s of a VM on %s: %s; %s", n1.Name, n0.Name, p.Error, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n0)
	assertOnlyDeleterTombstoned(t, c, n0)
	assertUserdata(t, n0, "second")
}

// The entry node is cut off from the tombstone: the deploy enters on node-1,
// which hears nothing from node-0, directly or relayed through node-2. It
// waits, bounded, for the tombstone of the row it names, then retires its
// stale copy of exactly that row itself and creates; when the link heals, the
// late tombstones kill nothing.
//
// The forwarded create always targets the VM's owner here: the planner pins
// a VM update to its current host (planner.go, PinHost), and the owner holds
// its own tombstone. That the row survives the forward is pinned by
// TestReplacedRow_IsNotAReCreate and TestReplacedRow_TheRowItDeletedIsSettled.
//
// Red against 029413eb, as the lab's case.
func TestFleet_AComposeRecreateEnteredOnANodeCutOffFromTheTombstoneKeepsTheVM(t *testing.T) {
	c, before := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	n1.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	c.SetLinkFault(n0, n1, LinkFault{Block: true})
	c.SetLinkFault(n2, n1, LinkFault{Block: true})

	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteYAML("node-0", "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create entered on %s, cut off from %s's tombstone: %s; %s", n1.Name, n0.Name, p.Error, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n0)
	assertUserdata(t, n0, "second")
	assertUserdata(t, n1, "second")
}

// The entry's copy of the row is behind the owner's: an ownership write on
// node-0 (owner epoch +1, as a migration makes) is still on its way to the
// entry node-1 when the deploy runs there. The delete tombstones node-0's
// row; node-1 then applies that write, and only later the tombstone. The row
// the create names must be the one node-0 reports it deleted: named by
// node-1's stale copy, the row ahead of it is refused and the VM is lost.
//
// Mutation: name node-1's own copy (withReplacedRow(cur)) — red.
func TestFleet_AComposeRecreateEnteredOnANodeBehindTheOwnerKeepsTheVM(t *testing.T) {
	c, before := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	lagFrom(c, n0, n1, n2)
	if err := corrosion.TransferVMOwnerFresh(ctx, n0.DB, "web", n0.Name, before.State); err != nil {
		t.Fatalf("ownership write on %s: %v", n0.Name, err)
	}
	// The ownership write reaches node-1 well before the tombstone does.
	time.Sleep(raceLag / 2)
	if stale, _ := corrosion.GetVM(ctx, n1.DB, "web"); stale == nil || stale.OwnerEpoch != before.OwnerEpoch {
		t.Fatalf("%s is not behind the owner: %+v", n1.Name, stale)
	}

	msgs := deployCollect(t, ctx, c.SelfClient(n1), recreateRemoteYAML("node-0", "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create entered on %s, behind %s's row: %s; %s", n1.Name, n0.Name, p.Error, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n0)
	assertOnlyDeleterTombstoned(t, c, n0)
	assertUserdata(t, n0, "second")
}

var keptSpecRE = regexp.MustCompile(`Its spec is kept on (\S+) at (\S+\.json)`)

// A create that fails after the teardown says the VM was torn down and keeps
// the spec it was given, as a rebuild and a rolling recreate do. Another VM
// of the name appears between the delete and the create, so the create is
// refused AlreadyExists.
//
// Mutation: drop the recreateFailedAfterTeardown wrap in recreateInline — red.
func TestFleet_AComposeRecreateWhoseCreateFailsAfterTheTeardownKeepsTheSpec(t *testing.T) {
	c, _ := newRecreateRemoteFleet(t, 0, "node-0")
	n0 := c.Nodes[0]
	ctx := context.Background()
	n0.Server.SetRecreateTornDownHookForTest(func(name string) {
		if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
			Name: name, HostName: n0.Name, State: "stopped",
			Spec: `{"name":"web","uuid":"7e1f0c2d-3b4a-4c5d-8e6f-9a0b1c2d3e4f"}`,
		}, nil, nil); err != nil {
			t.Errorf("insert another web: %v", err)
		}
	})
	t.Cleanup(func() { n0.Server.SetRecreateTornDownHookForTest(nil) })

	msgs := deployCollect(t, ctx, c.SelfClient(n0), recreateRemoteYAML("node-0", "second"))
	p := errorPhaseFor(msgs, "web")
	if p == nil {
		t.Fatal("the re-create succeeded over another VM of the same name")
	}
	if !strings.Contains(p.Error, "already exists") || !strings.Contains(p.Error, "torn down on node-0") {
		t.Fatalf("error %q: want the AlreadyExists cause and that the VM was torn down on node-0", p.Error)
	}
	m := keptSpecRE.FindStringSubmatch(p.Error)
	if m == nil || m[1] != n0.Name {
		t.Fatalf("error %q does not name the spec kept on %s", p.Error, n0.Name)
	}
	b, err := os.ReadFile(m[2])
	if err != nil || !strings.Contains(string(b), "second") {
		t.Fatalf("kept spec %s: %v; want the file's new cloud-init in it (%d bytes)", m[2], err, len(b))
	}
}

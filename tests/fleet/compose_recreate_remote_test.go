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

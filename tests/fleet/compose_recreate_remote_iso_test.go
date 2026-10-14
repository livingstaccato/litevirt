// Fleet scenarios: an inline (default-strategy) compose re-create of a VM
// with an installer ISO, entered on a node that does not host it.
//
// The entry node judges the create before it deletes the VM, but it cannot
// see another host's files: a library ISO that does not resolve on the VM's
// host was found only by the create there, after the delete had torn the VM
// down (compose-guard re-review 5, M1). The host the create is pinned to is
// now asked first, as a rebuild and a rolling recreate ask it
// (judgeRecreateOn).
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeRecreateRemoteISO = `name: rri

images:
  test:
    source: file:///dev/null

vms:
  web:
    image: test
    iso: media/win.iso
    cpu: 1
    memory: 256
    placement:
      host: HOST
    cloud-init:
      userdata: |
        #cloud-config
        hostname: USERDATA
`

func recreateRemoteISOYAML(host, userdata string) string {
	return strings.NewReplacer("HOST", host, "USERDATA", userdata).Replace(composeRecreateRemoteISO)
}

// newRecreateRemoteISOFleet is three nodes, each with a `media` pool of its
// own directory and able to create web from image test. win.iso is in every
// node's pool; web is deployed onto node-0 from node-1. It returns the
// cluster, web's row and node-0's ISO file.
func newRecreateRemoteISOFleet(t *testing.T) (*Cluster, *corrosion.VMRecord, string) {
	t.Helper()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	n0 := c.Nodes[0]
	if err := corrosion.InsertImage(ctx, n0.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	var isoOn0 string
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(c.tmpRoot, n.Name, "media-pool")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStoragePool(ctx, n0.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "media", Driver: "dir", Target: dir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		iso := filepath.Join(dir, "win.iso")
		writeOptical(t, iso)
		if n == n0 {
			isoOn0 = iso
		}
	}
	deployClean(t, ctx, c.SelfClient(c.Nodes[1]), recreateRemoteISOYAML(n0.Name, "first"))
	before, err := corrosion.GetVM(ctx, n0.DB, "web")
	if err != nil || before == nil || before.HostName != n0.Name {
		t.Fatalf("web after the first deploy: %+v (%v), want it on %s", before, err, n0.Name)
	}
	return c, before, isoOn0
}

// web's installer ISO no longer resolves on node-0, its host; the deploy
// enters on node-1, where it still does. node-0 refuses the re-create before
// anything is deleted, and web is left as it was.
//
// Red against c7b052a0: node-1 judged the ISO only for itself, deleted web,
// and node-0's create refused the ISO — web was gone.
func TestFleet_AComposeRecreateIsRefusedBeforeTheDeleteWhenTheVMsHostLacksTheISO(t *testing.T) {
	c, before, isoOn0 := newRecreateRemoteISOFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	if err := os.Remove(isoOn0); err != nil {
		t.Fatal(err)
	}
	xml := n0.Virt.DefinedXML("web")

	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteISOYAML(n0.Name, "second"))
	p := errorPhaseFor(msgs, "web")
	if p == nil {
		t.Fatalf("the re-create went ahead on %s without its ISO; %s", n0.Name, whereIs(c, "web"))
	}
	if !strings.Contains(p.Error, n0.Name) || !strings.Contains(p.Error, "nothing was deleted") {
		t.Errorf("error %q: want it to name %s and say nothing was deleted", p.Error, n0.Name)
	}
	rec, _ := corrosion.GetVM(context.Background(), n0.DB, "web")
	if rec == nil || rec.CreatedAt != before.CreatedAt || rec.HostName != n0.Name {
		t.Fatalf("web after the refused re-create: %+v; want the row it had (%s)", rec, whereIs(c, "web"))
	}
	if xml == "" || n0.Virt.DefinedXML("web") != xml {
		t.Fatalf("web's domain on %s changed under a refused re-create", n0.Name)
	}
	if strings.Contains(rec.Spec, "second") {
		t.Errorf("web's row carries the refused deploy's cloud-init")
	}
}

// The ISO resolves on node-0: the re-create entered on node-1 goes ahead
// there, judged by node-0 first.
func TestFleet_AComposeRecreateOfAnISOVMEnteredOnANonOwnerGoesAhead(t *testing.T) {
	c, before, _ := newRecreateRemoteISOFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	var asked atomic.Bool
	n0.HookUnary("PreflightRecreateVM", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		asked.Store(true)
		return handler(ctx, req)
	})

	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteISOYAML(n0.Name, "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create of an ISO VM entered on %s: %s; %s", n1.Name, p.Error, whereIs(c, "web"))
	}
	if !asked.Load() {
		t.Errorf("%s was not asked to judge the re-create", n0.Name)
	}
	waitReCreatedOn(t, c, before, n0)
}

// node-0 is on an older build, with no PreflightRecreateVM: its create
// judges no installer ISO (main had no ISO gate), so the re-create goes
// ahead as on main.
//
// Mutation: treat Unimplemented as a refusal — red.
func TestFleet_AComposeRecreateOfAnISOVMOnAnOlderHostGoesAheadAsOnMain(t *testing.T) {
	c, before, _ := newRecreateRemoteISOFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	defer n0.DoNotImplement("PreflightRecreateVM")()

	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteISOYAML(n0.Name, "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("compose re-create onto a host on an older build: %s; %s", p.Error, whereIs(c, "web"))
	}
	waitReCreatedOn(t, c, before, n0)
}

// waitReCreatedOn waits for web to be a new incarnation on host carrying the
// second deploy's cloud-init.
func waitReCreatedOn(t *testing.T, c *Cluster, before *corrosion.VMRecord, host *Node) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec, _ := corrosion.GetVM(context.Background(), host.DB, "web")
		if rec != nil && rec.CreatedAt != before.CreatedAt && rec.HostName == host.Name &&
			strings.Contains(rec.Spec, "second") && host.Virt.DomainExists("web") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("web was not re-created on %s: %+v; %s", host.Name, rec, whereIs(c, "web"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

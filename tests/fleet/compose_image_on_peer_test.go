package fleet

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeImageOnPeer = `name: peerimg

vms:
  box:
    image: IMG
    cpu: 1
    memory: 512
    placement:
      host: node-1
`

// An image held by a peer (imported there; `lv image ls` shows it with that
// host) is available to a deploy served by any node: the pre-deploy check
// looks at the cluster catalogue, not the serving node's own store. The lab
// failure: an image on node-2 was refused as "not found on any host" when
// `lv compose up` ran on node-1.
func TestFleet_ComposeImageOnAPeerIsAccepted(t *testing.T) {
	// One shared catalogue (the replication path is not what is under test);
	// the image FILE is in the holder's store only.
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	serving, holder := c.Nodes[0], c.Nodes[1]

	if err := holder.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('peeronly', 'qcow2', '', 'deadbeef', 0, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := corrosion.InsertImageHost(ctx, holder.DB, corrosion.ImageHostRecord{
		ImageName: "peeronly", HostName: holder.Name, Path: holder.Server.ImagePathForTests("peeronly"), Status: "ready",
	}); err != nil {
		t.Fatalf("seed image host: %v", err)
	}
	if err := writeEmptyImageFile(holder.Server.ImagePathForTests("peeronly")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	if _, err := os.Stat(serving.Server.ImagePathForTests("peeronly")); err == nil {
		t.Fatal("the serving node has the image file; the test needs it on the peer only")
	}

	msgs := deployCollect(t, ctx, c.SelfClient(serving), strings.Replace(composeImageOnPeer, "IMG", "peeronly", 1))
	if p := errorPhaseFor(msgs, "box"); p != nil {
		t.Fatalf("deploy of an image held by %s failed: %s", holder.Name, p.Error)
	}
	eventually(t, 10*time.Second, "box to be created on "+holder.Name, func() bool {
		vm, err := corrosion.GetVM(ctx, holder.DB, "box")
		return err == nil && vm != nil && vm.HostName == holder.Name
	})
}

// An image no host holds is still refused before anything is created.
func TestFleet_ComposeImageOnNoHostIsRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	serving := c.Nodes[0]
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := c.SelfClient(serving).DeployStack(dctx, &pb.DeployStackRequest{
		ComposeYaml: strings.Replace(composeImageOnPeer, "IMG", "nowhere", 1)})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), `image "nowhere" not found on any host`) {
		t.Fatalf("deploy of an image no host has: err=%v, want the not-found refusal", err)
	}
	if vm, _ := corrosion.GetVM(ctx, serving.DB, "box"); vm != nil {
		t.Errorf("box was created from an image no host has")
	}
}

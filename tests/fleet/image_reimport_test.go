package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
	"google.golang.org/protobuf/types/known/emptypb"
)

// An image deleted (lv image rm) and imported again under the same name is a
// live image again on every host. Lab 2 (lab2-dnr-7e6e8625, F-1): the import's
// row reached each peer as a column-preserving upsert that kept the peer's
// tombstone, anti-entropy then tombstoned the importing host's own row, the
// image vanished from `lv image ls` everywhere, and a prune removed its
// current file as a deleted image's.

// importImageSizedOn is importImageOn with a virtual size of its own, so a
// re-import under the same name publishes different content.
func importImageSizedOn(t *testing.T, c *Cluster, n *Node, name string, size uint64) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(src, size, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.SelfClient(n).ImportImage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.ImportImageRequest{Name: name, Format: "qcow2", Chunk: b}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatalf("import %s on %s: %v", name, n.Name, err)
	}
	f := n.Server.ImagePathForTests(name)
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("import left no file on %s: %v", n.Name, err)
	}
	return f
}

// antiEntropyEverywhere runs one full anti-entropy pass on every node, as the
// daemons' own schedule does within a minute: the pass that, in the lab, took
// the importing host's row back to the peers' tombstone.
func antiEntropyEverywhere(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		if !corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(context.Background()) {
			t.Fatalf("anti-entropy did not run on %s", n.Name)
		}
	}
}

// listedImage is image name as n's lv image ls lists it (nil when it is not).
func listedImage(t *testing.T, c *Cluster, n *Node, name string) *pb.Image {
	t.Helper()
	resp, err := c.SelfClient(n).ListImages(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("list images on %s: %v", n.Name, err)
	}
	for _, img := range resp.GetImages() {
		if img.GetName() == name {
			return img
		}
	}
	return nil
}

// The catalog row comes back on every host through a statement every build
// applies, and the file is safe.
func TestFleet_ImageReimport_SameNameIsLiveOnEveryHost(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	reimportScenario(t, c)
}

// reimportScenario imports imgr on node-0, removes it with lv image rm,
// imports it again with other content, lets replication and anti-entropy
// run, and checks every host.
func reimportScenario(t *testing.T, c *Cluster) {
	t.Helper()
	imageRmFleet(c)
	n0 := c.Nodes[0]
	ctx := context.Background()

	importImageSizedOn(t, c, n0, "imgr", 64<<20)
	c.WaitConverged(t, convergeTimeout)
	if _, err := c.SelfClient(n0).RemoveImage(ctx, &pb.RemoveImageRequest{Name: "imgr"}); err != nil {
		t.Fatalf("lv image rm imgr: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if img := listedImage(t, c, n, "imgr"); img != nil {
			t.Fatalf("precondition: %s still lists imgr after lv image rm", n.Name)
		}
	}

	// The same name again, different content.
	f := importImageSizedOn(t, c, n0, "imgr", 96<<20)
	digest, ok := image.RecordedDigest(f)
	if !ok {
		t.Fatalf("the re-imported file %s has no recorded digest", f)
	}
	want := "sha256:" + digest
	// The import's own write reaches every peer first; anti-entropy runs
	// after it, as it does within a minute in production.
	for _, n := range c.Nodes[1:] {
		eventually(t, convergeTimeout, n.Name+" to apply the re-import's row", func() bool {
			rows, err := n.DB.Query(ctx, `SELECT checksum FROM images WHERE name = 'imgr'`)
			return err == nil && len(rows) == 1 && rows[0].String("checksum") == want
		})
	}
	antiEntropyEverywhere(t, c)
	c.WaitConverged(t, convergeTimeout)
	antiEntropyEverywhere(t, c)

	for _, n := range c.Nodes {
		img := listedImage(t, c, n, "imgr")
		if img == nil {
			var deletedAt string
			if rows, err := n.DB.Query(ctx, `SELECT COALESCE(deleted_at, '') AS d FROM images WHERE name = 'imgr'`); err == nil && len(rows) == 1 {
				deletedAt = rows[0].String("d")
			}
			t.Errorf("%s does not list the re-imported imgr (its row's deleted_at=%q): the old delete outlived the import", n.Name, deletedAt)
			continue
		}
		if img.GetChecksum() != want {
			t.Errorf("%s lists imgr with checksum %q, want the re-import's %q", n.Name, img.GetChecksum(), want)
		}
	}

	// The prune: the image's current file is never a deleted image's file.
	for _, req := range []*pb.PruneImagesRequest{
		{Name: "imgr", Version: filepath.Base(f)},
		{Name: "imgr"},
		{},
	} {
		resp, err := c.SelfClient(n0).PruneImages(ctx, req)
		if err != nil {
			t.Fatalf("prune %v: %v", req, err)
		}
		for _, r := range resp.GetRemoved() {
			if r == f {
				t.Errorf("prune %v removed the re-imported image's current file %s", req, f)
			}
		}
	}
	if !fileThere(f) {
		t.Fatal("the re-imported image's current file is gone")
	}
	if got, err := image.FileDigest(f); err != nil || got != digest {
		t.Errorf("the re-imported file reads sha256 %s (err %v), want %s", got, err, digest)
	}
}

// The prune's own guard. Whatever the replicas say, a delete is older than a
// file published after it, and that file is not the delete's to remove. The
// stale tombstone is written here directly, as anti-entropy left it on every
// host in the lab — over a row an older build re-imported, which no fix to
// this build's writer can prevent.
func TestFleet_ImageReimport_PruneKeepsAFilePublishedAfterTheDelete(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	ctx := context.Background()

	f := importImageSizedOn(t, c, n0, "imgq", 64<<20)
	staleDelete := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if err := localExec(ctx, n0.DB, `UPDATE images SET deleted_at = ? WHERE name = ?`, staleDelete, "imgq"); err != nil {
		t.Fatal(err)
	}

	resp, err := c.SelfClient(n0).PruneImages(ctx, &pb.PruneImagesRequest{Name: "imgq", Version: filepath.Base(f)})
	if err != nil {
		t.Fatalf("prune --version current: %v", err)
	}
	if len(resp.GetRemoved()) != 0 || !fileThere(f) {
		t.Fatalf("lv image prune imgq --version <current> removed %v under a delete an hour older than the file", resp.GetRemoved())
	}
	reason := ""
	for _, k := range resp.GetKept() {
		if k.GetPath() == f {
			reason = k.GetReason()
		}
	}
	if !strings.Contains(reason, "after its image was deleted") {
		t.Errorf("kept reason for %s = %q, want it to say the file was published after the delete", f, reason)
	}
	for _, req := range []*pb.PruneImagesRequest{{Name: "imgq"}, {}} {
		resp, err := c.SelfClient(n0).PruneImages(ctx, req)
		if err != nil {
			t.Fatalf("prune %v: %v", req, err)
		}
		if len(resp.GetRemoved()) != 0 {
			t.Errorf("prune %v removed %v under the stale delete", req, resp.GetRemoved())
		}
	}
	if !fileThere(f) {
		t.Fatal("the current file is gone")
	}
}

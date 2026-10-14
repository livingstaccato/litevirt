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
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// lv image rm removes the image's files on every host, each host judging only
// its own files from its own disks — and a file any VM in the cluster may
// still need is kept on every host, with the reason reported.

// importImageOn imports a small standalone qcow2 as image name on n, through
// the real ImportImage stream, and returns the file it was published at.
func importImageOn(t *testing.T, c *Cluster, n *Node, name string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(src, 64<<20, nil); err != nil {
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

// imageRmFleet limits every node's open-file check to this process: the
// fleet runs without root, and the full read of /proc fails closed on every
// other user's process, keeping every file. Every node runs in this process,
// so a file any node holds open is still seen.
//
// It also sets the margin a prune keeps a deleted image's file within to one
// nanosecond: these scenarios remove an image moments after importing it, and
// the clock-skew floor (5 minutes) would keep every such file. The margin's
// own fleet test sets it back.
func imageRmFleet(c *Cluster) {
	for _, n := range c.Nodes {
		n.Server.SetImageOpenFilesForTest(grpcapi.OpenFilesOfThisProcessForTest)
		n.Server.SetImageDeleteMarginForTest(time.Nanosecond)
	}
}

func fileThere(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// hostResult is host's part of resp (nil when it has none).
func hostResult(resp *pb.RemoveImageResponse, host string) *pb.PruneImagesResponse {
	for _, h := range resp.GetHosts() {
		if h.HostName == host {
			return h
		}
	}
	return nil
}

// An image nothing uses: lv image rm removes its file on every host, and
// reports each host's removal.
func TestFleet_ImageRm_RemovesTheFileOnEveryHost(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	files := map[string]string{}
	for _, n := range c.Nodes {
		files[n.Name] = importImageOn(t, c, n, "ubuntu")
	}
	resp, err := c.SelfClient(c.Nodes[0]).RemoveImage(context.Background(), &pb.RemoveImageRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Failed) != 0 {
		t.Fatalf("hosts not asked: %v", resp.Failed)
	}
	for _, n := range c.Nodes {
		h := hostResult(resp, n.Name)
		if h == nil || len(h.Removed) != 1 || h.Removed[0] != files[n.Name] || len(h.Kept) != 0 {
			t.Errorf("%s reported %v, want %s removed and nothing kept", n.Name, h, files[n.Name])
		}
		if fileThere(files[n.Name]) {
			t.Errorf("%s still has %s", n.Name, files[n.Name])
		}
	}
	eventually(t, 10*time.Second, "every host's catalog to show the delete", func() bool {
		for _, n := range c.Nodes {
			if img, err := corrosion.GetImage(context.Background(), n.DB, "ubuntu"); err != nil || img != nil {
				return false
			}
		}
		return true
	})
}

// A VM built on the image, on one host, keeps the image's file on every host:
// its own host's disk is built on its copy, and a failover or recreate onto
// another host may need that host's copy. Once the VM is gone, lv image prune
// removes each copy.
func TestFleet_ImageRm_KeepsEveryCopyWhileAVMIsBuiltOnIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	ctx := context.Background()
	owner := c.Nodes[1]
	files := map[string]string{}
	for _, n := range c.Nodes {
		files[n.Name] = importImageOn(t, c, n, "ubuntu")
	}
	if _, err := c.SelfClient(owner).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: owner.Name}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "every host to see web's disk row", func() bool {
		for _, n := range c.Nodes {
			if ds, err := corrosion.GetVMDisks(ctx, n.DB, "web"); err != nil || len(ds) == 0 {
				return false
			}
		}
		return true
	})

	resp, err := c.SelfClient(c.Nodes[0]).RemoveImage(ctx, &pb.RemoveImageRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Failed) != 0 {
		t.Fatalf("hosts not asked: %v", resp.Failed)
	}
	for _, n := range c.Nodes {
		if !fileThere(files[n.Name]) {
			t.Fatalf("%s removed %s while VM web on %s is built on the image", n.Name, files[n.Name], owner.Name)
		}
		h := hostResult(resp, n.Name)
		if h == nil || len(h.Removed) != 0 || len(h.Kept) != 1 || !strings.Contains(h.Kept[0].Reason, "web") {
			t.Errorf("%s reported %v, want its file kept naming VM web", n.Name, h)
		}
	}

	if _, err := c.SelfClient(owner).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	// A deleted VM records its image for a grace (a rebuild creates it again);
	// this one is gone for good.
	for _, n := range c.Nodes {
		n.Server.SetImageRecreateGraceForTest(-1)
	}
	for _, n := range c.Nodes {
		eventually(t, 15*time.Second, "lv image prune on "+n.Name+" to remove its copy", func() bool {
			_, err := c.SelfClient(c.Nodes[0]).PruneImages(ctx, &pb.PruneImagesRequest{Name: "ubuntu", HostName: n.Name})
			return err == nil && !fileThere(files[n.Name])
		})
	}
}

// A host on an older build, with no image prune, keeps its file; the others
// remove theirs, and the delete itself is never refused.
func TestFleet_ImageRm_AnOlderHostKeepsItsFile(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	files := map[string]string{}
	for _, n := range c.Nodes {
		files[n.Name] = importImageOn(t, c, n, "ubuntu")
	}
	old := c.Nodes[2]
	defer old.DoNotImplement("PruneImages")()
	resp, err := c.SelfClient(c.Nodes[0]).RemoveImage(context.Background(), &pb.RemoveImageRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Failed) != 1 || resp.Failed[0].HostName != old.Name || !strings.Contains(resp.Failed[0].Error, "older build") {
		t.Errorf("failed %v, want %s reported as an older build", resp.Failed, old.Name)
	}
	if !fileThere(files[old.Name]) {
		t.Errorf("the older host's file is gone")
	}
	for _, n := range c.Nodes[:2] {
		if fileThere(files[n.Name]) {
			t.Errorf("%s still has %s", n.Name, files[n.Name])
		}
	}
}

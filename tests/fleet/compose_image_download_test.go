package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// imageServer counts every download of the compose images: source URL.
func imageServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("fake-qcow2"))
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

func composeWithSource(image, source, checksum, host string) string {
	cs := ""
	if checksum != "" {
		cs = "\n    checksum: " + checksum
	}
	return "name: dl\n\nimages:\n  " + image + ":\n    source: " + source + cs + `

vms:
  box:
    image: ` + image + `
    cpu: 1
    memory: 512
    placement:
      host: ` + host + "\n"
}

// seedPeerImage records a ready copy of image on holder, with the catalogue
// checksum given, and stages its file there only.
func seedPeerImage(t *testing.T, holder *Node, image, checksum string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, holder.DB, corrosion.ImageRecord{Name: image, Format: "qcow2", Checksum: checksum}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImageHost(ctx, holder.DB, corrosion.ImageHostRecord{
		ImageName: image, HostName: holder.Name, Path: holder.Server.ImagePathForTests(image), Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := writeEmptyImageFile(holder.Server.ImagePathForTests(image)); err != nil {
		t.Fatal(err)
	}
}

// A peer's ready copy is used: the VM's host pulls it from the peer at create
// time, and the compose source URL is not downloaded.
func TestFleet_ComposeImageSourceNotDownloadedWhenAPeerHasIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	serving, holder := c.Nodes[0], c.Nodes[1]
	ts, hits := imageServer(t)
	seedPeerImage(t, holder, "peerimg", "")

	msgs := deployCollect(t, context.Background(), c.SelfClient(serving), composeWithSource("peerimg", ts.URL+"/peerimg.qcow2", "", holder.Name))
	if p := errorPhaseFor(msgs, "box"); p != nil {
		t.Fatalf("deploy failed: %s", p.Error)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the source URL was downloaded %d time(s) although %s holds a ready copy", n, holder.Name)
	}
}

// With no ready copy anywhere, the source URL is downloaded (once) and the
// copy recorded.
func TestFleet_ComposeImageSourceDownloadedWhenNobodyHasIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	serving := c.Nodes[0]
	ts, hits := imageServer(t)

	msgs := deployCollect(t, context.Background(), c.SelfClient(serving), composeWithSource("newimg", ts.URL+"/newimg.qcow2", "", serving.Name))
	if p := errorPhaseFor(msgs, "box"); p != nil {
		t.Fatalf("deploy failed: %s", p.Error)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the source URL was downloaded %d time(s), want 1", n)
	}
	hs, err := corrosion.GetImageHosts(context.Background(), serving.DB, "newimg")
	if err != nil || len(hs) != 1 || hs[0].HostName != serving.Name || hs[0].Status != "ready" {
		t.Errorf("image hosts = %+v, %v; want a ready copy on %s", hs, err, serving.Name)
	}
}

// A declared checksum that differs from the one recorded for the cluster's
// copy is an error naming both — never a silent re-download over it.
func TestFleet_ComposeImageChecksumMismatchIsAnError(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	serving, holder := c.Nodes[0], c.Nodes[1]
	ts, hits := imageServer(t)
	seedPeerImage(t, holder, "sumimg", "sha256:aaaa")

	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := c.SelfClient(serving).DeployStack(dctx, &pb.DeployStackRequest{
		ComposeYaml: composeWithSource("sumimg", ts.URL+"/sumimg.qcow2", "sha256:bbbb", holder.Name)})
	if err == nil {
		for {
			if _, err = stream.Recv(); err != nil {
				break
			}
		}
	}
	if err == nil || !strings.Contains(err.Error(), "sha256:aaaa") || !strings.Contains(err.Error(), "sha256:bbbb") {
		t.Fatalf("deploy with a mismatched checksum: err=%v, want an error naming both checksums", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the source URL was downloaded %d time(s) over a checksum mismatch", n)
	}
	if vm, _ := corrosion.GetVM(context.Background(), serving.DB, "box"); vm != nil {
		t.Error("box was created from an image whose checksum does not match")
	}
}

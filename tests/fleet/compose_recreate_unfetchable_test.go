// Fleet scenarios: a compose recreate of a container member to an image the
// member's host cannot fetch.
//
// A recreate deletes the member and then creates it again. The create is
// where the new image was fetched (lxc-create's download template, or the
// copy of a rootfs path), so an image the host could not fetch — a release
// the image server does not have, an image server the host cannot reach —
// failed the create after the delete: the member was gone. The image is fetched and verified on the member's host
// before anything is deleted, whichever host the deploy entered on.
package fleet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeFetchCT = `name: fetchct

workloads:
  web-ct:
    kind: lxc
    image: IMAGE
    cpu: 1
    memory: 256
    placement:
      host: node-0
`

func fetchCTYAML(image string) string { return strings.Replace(composeFetchCT, "IMAGE", image, 1) }

// newFetchCTFleet deploys web-ct on node-0 of a two-node cluster from
// alpine:3.21, and marks its rootfs so a test can tell the member from a
// replacement.
func newFetchCTFleet(t *testing.T) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	owner := c.Nodes[0]
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := corrosion.SetHostLabel(ctx, n.DB, owner.Name, corrosion.LabelLXCCapable, "true"); err != nil {
			t.Fatalf("label %s lxc-capable on %s: %v", owner.Name, n.Name, err)
		}
	}
	deployClean(t, ctx, c.SelfClient(owner), fetchCTYAML("alpine:3.21"))
	rootfs, err := owner.CT.ContainerRootFSPath("web-ct")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "payload"), []byte("the member's data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Every node holds the member as its host wrote it.
	waitHistoryApplied(t, c, 20*time.Second)
	return c, owner
}

// assertMemberKept checks web-ct is on owner as it was: its runtime
// container running with its own data, never deleted, and its row naming
// the image it runs.
func assertMemberKept(t *testing.T, owner *Node) {
	t.Helper()
	if st := owner.CT.State("web-ct"); st != "running" {
		t.Errorf("web-ct on %s is %q, want running as it was", owner.Name, st)
	}
	if got := owner.CT.Payload("web-ct"); got != "the member's data" {
		t.Errorf("web-ct's rootfs on %s holds %q, want the member's own data", owner.Name, got)
	}
	if d := owner.CT.DeleteCalls(); len(d) != 0 {
		t.Errorf("the member was deleted on %s: %v", owner.Name, d)
	}
	rec, err := corrosion.GetContainer(context.Background(), owner.DB, owner.Name, "web-ct")
	if err != nil || rec == nil || rec.Image != "alpine:3.21" || rec.State != "running" {
		t.Errorf("web-ct's row on %s = %+v (%v), want it running alpine:3.21", owner.Name, rec, err)
	}
}

func TestFleet_ARecreateToAnUnfetchableImageKeepsTheMember(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry int
		image string
	}{
		{"entered on the owner, download", 0, "alpine:3.99"},
		{"entered on a peer, download", 1, "alpine:3.99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, owner := newFetchCTFleet(t)
			owner.CT.Unfetchable("alpine:3.99", errors.New("download: no image alpine 3.99 amd64 on the image server"))
			entry := c.Nodes[tc.entry]

			msgs := deployCollect(t, context.Background(), c.SelfClient(entry), fetchCTYAML(tc.image))
			p := errorPhaseFor(msgs, "web-ct")
			if p == nil {
				t.Fatalf("a recreate to an image %s cannot fetch reported no error; %s", owner.Name, whereIs(c, "web-ct"))
			}
			if !strings.Contains(p.Error, "left as it is") {
				t.Errorf("the refusal does not say the member was kept: %s", p.Error)
			}
			assertMemberKept(t, owner)
			if len(owner.CT.FetchCalls()) == 0 {
				t.Errorf("%s never fetched the new image", owner.Name)
			}
		})
	}
}

// A recreate to an image the host can fetch still replaces the member, and
// the image was fetched before the delete.
func TestFleet_ARecreateToAFetchableImageReplacesTheMember(t *testing.T) {
	c, owner := newFetchCTFleet(t)
	deployClean(t, context.Background(), c.SelfClient(c.Nodes[1]), fetchCTYAML("alpine:3.22"))
	rec, err := corrosion.GetContainer(context.Background(), owner.DB, owner.Name, "web-ct")
	if err != nil || rec == nil || rec.Image != "alpine:3.22" {
		t.Fatalf("web-ct's row on %s = %+v (%v), want it recreated from alpine:3.22", owner.Name, rec, err)
	}
	if got := owner.CT.Payload("web-ct"); got == "the member's data" {
		t.Errorf("web-ct was not replaced: its rootfs still holds the old data")
	}
	var fetched bool
	for _, f := range owner.CT.FetchCalls() {
		if f.Template == "download" && f.Distro == "alpine" && f.Release == "3.22" {
			fetched = true
		}
	}
	if !fetched {
		t.Errorf("%s did not fetch alpine:3.22 before the recreate: %+v", owner.Name, owner.CT.FetchCalls())
	}
}

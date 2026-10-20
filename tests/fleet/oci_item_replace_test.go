// Fleet scenarios: an Admin's pull over an existing OCI library item (a
// claim, lv ct pull --project), against the containers built from it.
//
// A replacing pull changes the image every container built from the item
// is recreated from. A privileged member recreated from the same item path
// by a deployer without ContainerRoot would run that new image as root on
// the host, so the member's host refuses the recreate when the item is no
// longer the generation the member was built from — whichever host the
// deploy entered on. A container an earlier release created from the item
// uses its rootfs in place, so the item is not replaced while one exists.
package fleet

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeOCIBuild = `name: ocist

workloads:
  build:
    kind: oci
    image: IMAGE
    privileged: true
    cpu: CPU
    memory: 256
    placement:
      host: node-0
`

func ociBuildYAML(image, cpu string) string {
	return strings.NewReplacer("IMAGE", image, "CPU", cpu).Replace(composeOCIBuild)
}

// newOCIItemFleet pulls library item "build" (no owner) on node-0 of a
// two-node cluster and returns its rootfs path, and an Operator's client on
// each node.
func newOCIItemFleet(t *testing.T) (*Cluster, string, []pb.LiteVirtClient) {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	owner := c.Nodes[0]
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := corrosion.SetHostLabel(ctx, n.DB, owner.Name, corrosion.LabelLXCCapable, "true"); err != nil {
			t.Fatal(err)
		}
	}
	admin := c.SelfClient(owner)
	if _, err := admin.PullOCIImage(ctx, &pb.PullOCIImageRequest{Image: "ghcr.io/acme/build:1", Dest: "build", HostName: owner.Name}); err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "pat", Password: "p4ssw0rd-long", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "pat", Name: "ops"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	waitHistoryApplied(t, c, 20*time.Second)
	ops := []pb.LiteVirtClient{c.bearerClient(c.Nodes[0], tok.Token), c.bearerClient(c.Nodes[1], tok.Token)}
	return c, filepath.Join(owner.Server.DataDir(), "oci", "build", "rootfs"), ops
}

func buildImage(t *testing.T, n *Node) string {
	t.Helper()
	return n.CT.Payload("build")
}

func TestFleet_AnOperatorCannotRecreateAPrivilegedMemberFromAReplacedItem(t *testing.T) {
	for _, entry := range []int{0, 1} {
		t.Run([]string{"entered on the owner", "entered on a peer"}[entry], func(t *testing.T) {
			c, rootfs, ops := newOCIItemFleet(t)
			owner := c.Nodes[0]
			ctx := context.Background()
			// An Admin deploys the privileged member.
			deployClean(t, ctx, c.SelfClient(owner), ociBuildYAML(rootfs, "1"))
			if got := buildImage(t, owner); got != "image ghcr.io/acme/build:1" {
				t.Fatalf("the member runs %q", got)
			}
			waitHistoryApplied(t, c, 20*time.Second)
			// The item unchanged, an Operator's cpu change keeps the member
			// privileged, as before.
			deployClean(t, ctx, ops[entry], ociBuildYAML(rootfs, "2"))
			// An Admin claims the item for a project: its content is replaced.
			if _, err := c.SelfClient(c.Nodes[1]).PullOCIImage(ctx, &pb.PullOCIImageRequest{
				Image: "ghcr.io/other/root:9", Dest: "build", HostName: owner.Name, Project: "_default"}); err != nil {
				t.Fatalf("the Admin's claim, through %s: %v", c.Nodes[1].Name, err)
			}
			waitHistoryApplied(t, c, 20*time.Second)
			deletesBefore := len(owner.CT.DeleteCalls())
			msgs := deployCollect(t, ctx, ops[entry], ociBuildYAML(rootfs, "3"))
			p := errorPhaseFor(msgs, "build")
			if p == nil || !strings.Contains(p.Error, "ContainerRoot") || !strings.Contains(p.Error, "replaced") {
				t.Fatalf("an Operator's recreate from the replaced item: %+v, want a refusal naming ContainerRoot", p)
			}
			if got := buildImage(t, owner); got != "image ghcr.io/acme/build:1" {
				t.Errorf("the member now runs %q, want the image it was built from", got)
			}
			if d := owner.CT.DeleteCalls(); len(d) != deletesBefore {
				t.Errorf("the member was deleted: %v", d)
			}
			// An Admin may: the member is rebuilt from the new content.
			deployClean(t, ctx, c.SelfClient(c.Nodes[entry]), ociBuildYAML(rootfs, "3"))
			if got := buildImage(t, owner); got != "image ghcr.io/other/root:9" {
				t.Errorf("after the Admin's recreate the member runs %q", got)
			}
		})
	}
}

// An Admin's claim of the item between the member host's last judgment of
// an Operator's recreate (its generation check) and the create does not
// reach the member: the member's host copied the judged generation aside
// before the delete, the claim goes ahead, and the member is rebuilt from
// the image it was judged on.
func TestFleet_AClaimDuringAnOperatorsRecreateDoesNotReachTheMember(t *testing.T) {
	for _, entry := range []int{0, 1} {
		t.Run([]string{"entered on the owner", "entered on a peer"}[entry], func(t *testing.T) {
			c, rootfs, ops := newOCIItemFleet(t)
			owner := c.Nodes[0]
			ctx := context.Background()
			deployClean(t, ctx, c.SelfClient(owner), ociBuildYAML(rootfs, "1"))
			waitHistoryApplied(t, c, 20*time.Second)
			claim := func() error {
				_, err := c.SelfClient(c.Nodes[1]).PullOCIImage(ctx, &pb.PullOCIImageRequest{
					Image: "ghcr.io/other/root:9", Dest: "build", HostName: owner.Name, Project: "_default"})
				return err
			}
			var claimErr error
			var claimed bool
			owner.CT.OnDelete(func(name string) {
				if name == "build" && !claimed {
					claimed = true
					claimErr = claim()
				}
			})
			deployClean(t, ctx, ops[entry], ociBuildYAML(rootfs, "2"))
			owner.CT.OnDelete(nil)
			if !claimed {
				t.Fatal("the member was not recreated")
			}
			if claimErr != nil {
				t.Fatalf("the Admin's claim during the recreate: %v", claimErr)
			}
			if got := buildImage(t, owner); got != "image ghcr.io/acme/build:1" {
				t.Fatalf("the member runs %q, want the image it was judged on", got)
			}
		})
	}
}

// An Operator's pull over the item is refused, through any node; the item
// is left as it was.
func TestFleet_AnOperatorCannotPullOverAnExistingItem(t *testing.T) {
	c, rootfs, ops := newOCIItemFleet(t)
	for i, op := range ops {
		_, err := op.PullOCIImage(context.Background(), &pb.PullOCIImageRequest{
			Image: "ghcr.io/other/root:9", Dest: "build", HostName: c.Nodes[0].Name})
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("an Operator's pull over the item through %s: %v, want FailedPrecondition", c.Nodes[i].Name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(rootfs, "etc", "image")); string(b) != "ghcr.io/acme/build:1" {
		t.Errorf("the item now holds %q", b)
	}
}

// A container created from the item by an earlier release uses its rootfs
// in place: an Admin's claim is refused, naming it, and the item is kept.
func TestFleet_AnItemAContainerUsesInPlaceIsNotReplaced(t *testing.T) {
	c, rootfs, _ := newOCIItemFleet(t)
	owner := c.Nodes[0]
	owner.CT.SeedByReference("legacy-web", rootfs)
	_, err := c.SelfClient(c.Nodes[1]).PullOCIImage(context.Background(), &pb.PullOCIImageRequest{
		Image: "ghcr.io/other/root:9", Dest: "build", HostName: owner.Name, Project: "_default"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "legacy-web") {
		t.Fatalf("an Admin's claim of an item legacy-web uses in place: %v, want a refusal naming it", err)
	}
	if b, _ := os.ReadFile(filepath.Join(rootfs, "etc", "image")); string(b) != "ghcr.io/acme/build:1" {
		t.Errorf("the item now holds %q", b)
	}
}

// A deploy entered on a peer whose caller gives up while the member's host
// is still fetching the new image leaves the member as it is: the fetch runs
// on the caller's context, before anything is detached or deleted.
func TestFleet_ACallerWhoGivesUpDuringAPeerFetchKeepsTheMember(t *testing.T) {
	c, owner := newFetchCTFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	owner.CT.OnFetch(func(fctx context.Context) error {
		calls++
		if calls > 1 {
			return nil
		}
		cancel()
		select {
		case <-fctx.Done():
			return fctx.Err()
		case <-time.After(3 * time.Second):
			return nil // the fetch was not cancelled: it completes
		}
	})
	stream, err := c.SelfClient(c.Nodes[1]).DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: fetchCTYAML("alpine:3.22")})
	if err == nil {
		for {
			if _, rerr := stream.Recv(); rerr != nil {
				if !errors.Is(rerr, io.EOF) && status.Code(rerr) != codes.Canceled {
					t.Logf("deploy stream ended: %v", rerr)
				}
				break
			}
		}
	}
	// Whatever the entry host still runs after the cancel has had time to.
	time.Sleep(4 * time.Second)
	assertMemberKept(t, owner)
}

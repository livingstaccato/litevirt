package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/gitops"
)

// The gitops deployer used to return on the first "error" progress message
// and close its connection. A deploy's per-action failures are reported
// in-band and the deploy carries on to the next action — but only while its
// client is listening: the server's stream context is cancelled by the
// disconnect, its next Send fails, and the deploy stops there. So a single
// failed VM also cancelled every action planned after it, and the stack record
// was never written.

const composeFailThree = composeFailTwo + `  hb-3:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
`

// injectFirstFailsSecondWaits makes hb-1's define fail and holds hb-2's
// define until release is closed, so the client can act on hb-1's error while
// the server is still busy with hb-2 — the moment an abandoning client left.
func injectFirstFailsSecondWaits(node *Node, release <-chan struct{}) {
	var once sync.Once
	node.Virt.FailDefineDomain = func(xml string) error {
		switch {
		case strings.Contains(xml, "<name>hb-1</name>"):
			return errors.New("injected: define refused")
		case strings.Contains(xml, "<name>hb-2</name>"):
			once.Do(func() { <-release })
		}
		return nil
	}
}

// A client that stops reading at the first error cancels the rest of the
// deploy. This pins the server behaviour the gitops fix has to work with.
func TestFleet_ComposeAbandonedDeployStreamCancelsTheRestOfTheDeploy(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	release := make(chan struct{})
	injectFirstFailsSecondWaits(node, release)

	dctx, cancel := context.WithCancel(ctx)
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: composeFailThree})
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	for {
		p, err := stream.Recv()
		if err != nil {
			t.Fatalf("stream ended before any error phase: %v", err)
		}
		if p.Error != "" {
			break // what the old deployer did: return, closing the connection
		}
	}
	cancel()
	time.Sleep(200 * time.Millisecond) // let the cancellation reach the server
	close(release)

	// hb-3 is planned after hb-2; the server never gets to it.
	time.Sleep(time.Second)
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-3"); vm != nil {
		t.Fatal("hb-3 was created although the client abandoned the deploy — the server did not cancel")
	}
	if st, _ := corrosion.GetStack(ctx, node.DB, "hb"); st != nil {
		t.Errorf("stack record written (state %q) by a deploy its client abandoned", st.State)
	}
}

// The gitops deployer now reads the stream to its end: the deploy runs every
// action, and the deployer reports every failure.
func TestFleet_GitopsDeployerDrainsTheStreamAndReportsEveryFailure(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	release := make(chan struct{})
	close(release)
	injectFirstFailsSecondWaits(node, release)

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: composeFailThree})
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	derr := gitops.DrainDeploy(stream)
	if derr == nil {
		t.Fatal("DrainDeploy reported success for a deploy with a failed VM")
	}
	if !strings.Contains(derr.Error(), "hb-1") || !strings.Contains(derr.Error(), "injected") {
		t.Errorf("DrainDeploy error %q does not name hb-1 and its failure", derr)
	}
	for _, vm := range []string{"hb-2", "hb-3"} {
		if rec, _ := corrosion.GetVM(ctx, node.DB, vm); rec == nil {
			t.Errorf("%s was not created — the deploy stopped at hb-1's failure", vm)
		}
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state = %q, want degraded", got)
	}
}

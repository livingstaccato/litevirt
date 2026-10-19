// A compose up run again while its first run's create is still in flight on
// the owner (lab 2 delcancel r5, item 4: rc-1..3), over two nodes.

package fleet

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeRerun = `name: rr

images:
  test:
    source: file:///dev/null

vms:
  rr-1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
`

// TestFleet_ComposeUpRunAgainWhileItsCreateIsInFlightLeavesTheVMWhole: the
// first compose up's create of rr-1 is held on its owner (node-0) between its
// domain's define and its row; a second compose up, entered on node-1, plans
// rr-1 absent and creates it again. That second create is refused on the
// owner, saying a create is in progress, and touches nothing: the first
// finishes with one domain, persistent and running, whose uuid its row
// records, and its disk where its row says. A third compose up converges.
//
// It used to be the second create's orphan sweep that undefined the first's
// domain, and its debris sweep and failed-create cleanup that unlinked the
// first's disk and seed under a running qemu.
//
// Mutation: drop the owner's in-flight refusal and the orphan sweep's
// live-create refusal (grpcapi beginCreate, refuseLiveDomainOfName) — the
// second deploy creates rr-1 over the first, red.
func TestFleet_ComposeUpRunAgainWhileItsCreateIsInFlightLeavesTheVMWhole(t *testing.T) {
	// The writes travel as in production: the entry node plans each deploy
	// from what has reached it.
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	owner, entry := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range c.Nodes {
		if err := corrosion.InsertImage(ctx, n.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
			SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
			t.Fatalf("seed image on %s: %v", n.Name, err)
		}
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatalf("stage image file on %s: %v", n.Name, err)
		}
	}
	client := c.SelfClient(entry)

	held, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	owner.Virt.FailStartDomain = func(name string) error {
		if name == "rr-1" && first.CompareAndSwap(false, true) {
			close(held)
			// Bounded: a test that never releases fails rather than hangs.
			select {
			case <-release:
			case <-time.After(60 * time.Second):
			}
		}
		return nil
	}
	released := false
	releaseOnce := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer releaseOnce()

	type result struct {
		msgs []*pb.DeployProgress
		err  error
	}
	deploy := func() result {
		dctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: composeRerun})
		if err != nil {
			return result{err: err}
		}
		var out []*pb.DeployProgress
		for {
			p, err := stream.Recv()
			if err == io.EOF {
				return result{msgs: out}
			}
			if err != nil {
				return result{msgs: out, err: err}
			}
			out = append(out, p)
		}
	}
	firstDone := make(chan result, 1)
	go func() { firstDone <- deploy() }()
	select {
	case <-held:
	case <-time.After(30 * time.Second):
		t.Fatal("the first deploy's create of rr-1 never reached its domain start on node-0")
	}

	second := deploy()
	if second.err != nil {
		t.Fatalf("second deploy: %v", second.err)
	}
	ep := errorPhaseFor(second.msgs, "rr-1")
	if ep == nil {
		t.Error("the second deploy created rr-1 while the first's create was in flight")
	} else if !strings.Contains(ep.GetError(), "in progress") {
		t.Errorf("the second deploy's rr-1 error does not say a create is in progress: %q", ep.GetError())
	}

	releaseOnce()
	var r1 result
	select {
	case r1 = <-firstDone:
	case <-time.After(60 * time.Second):
		t.Fatal("the first deploy had not returned 60s after its create was released")
	}
	if r1.err != nil {
		t.Fatalf("first deploy: %v", r1.err)
	}
	if ep := errorPhaseFor(r1.msgs, "rr-1"); ep != nil {
		t.Fatalf("the first deploy's create of rr-1 failed: %q", ep.GetError())
	}

	row, err := corrosion.GetVM(ctx, owner.DB, "rr-1")
	if err != nil || row == nil {
		t.Fatalf("rr-1's row on its owner: %v %v", row, err)
	}
	for _, e := range owner.Virt.EventLog() {
		if e.Domain == "rr-1" && (e.Op == "undefine" || e.Op == "destroy") {
			t.Errorf("rr-1's domain saw %s (%s)", e.Op, e.Note)
		}
	}
	if active, aerr := owner.Virt.DomainIsActive("rr-1"); aerr != nil || !active {
		t.Errorf("rr-1's domain is not running: %v %v", active, aerr)
	}
	x, xerr := owner.Virt.DumpXMLInactive("rr-1")
	if xerr != nil {
		t.Errorf("rr-1's domain has no persistent definition: %v", xerr)
	} else {
		u := ""
		if _, rest, ok := strings.Cut(x, "<uuid>"); ok {
			u, _, _ = strings.Cut(rest, "</uuid>")
		}
		if u == "" || !strings.Contains(row.Spec, u) {
			t.Errorf("rr-1's domain (uuid %q) is not the one its row records", u)
		}
	}
	disks, err := corrosion.GetVMDisks(ctx, owner.DB, "rr-1")
	if err != nil || len(disks) == 0 {
		t.Fatalf("rr-1's disk rows: %v %v", disks, err)
	}
	for _, d := range disks {
		if _, err := os.Stat(d.Path); err != nil {
			t.Errorf("rr-1's disk %s is gone: %v", d.Path, err)
		}
	}

	// Run again, it converges: rr-1 is there and nothing fails — once the
	// entry node, which plans the deploy, has the owner's row.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if vm, _ := corrosion.GetVM(ctx, entry.DB, "rr-1"); vm != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rr-1's row never reached node-1")
		}
		time.Sleep(20 * time.Millisecond)
	}
	third := deploy()
	if third.err != nil {
		t.Fatalf("third deploy: %v", third.err)
	}
	if ep := errorPhaseFor(third.msgs, "rr-1"); ep != nil {
		t.Errorf("the third deploy failed rr-1: %q", ep.GetError())
	}
	if got := stackState(t, ctx, entry.DB, "rr"); got != "active" {
		t.Errorf("stack rr is %q after the third deploy, want active", got)
	}
}

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An image-recreate relocation is one replicated write from the coordinator,
// and every receiver validates the entry it arrives in before applying it. The
// relocation used to put the source's guarded tombstone in the MIDDLE of its
// entry, with the unguarded target row after it, which the receiver's
// apply-safety check refuses outright ("guarded workload transition/delete must
// be the unique final statement"). The refusal back-pressures, so it was not one
// lost row: the sender's whole stream stopped at that entry, and every later
// write it made — however unrelated — never reached a peer.
//
// Independent replicas are the only harness that can see this: with a shared
// database nothing is ever validated on the way in.
func TestFleet_IndependentReplicas_ContainerRelocationDoesNotStallTheStream(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// The container lives on victim; a is the coordinator that relocates it.
	if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
		HostName: victim.Name, Name: "ct-moved", Image: "docker.io/library/alpine:3.19",
		State: "running", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)

	if err := corrosion.RelocateContainerWithToken(ctx, a.DB, victim.Name, "ct-moved", b.Name, "tok-stream"); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	// An unrelated write from the same sender, strictly after the relocation.
	insertVM(t, a, "vm-after-relocate", a.Name)

	deadline := time.Now().Add(convergeTimeout)
	for {
		stalled := ""
		for _, n := range []*Node{b, victim} {
			if vmOn(t, n, "vm-after-relocate") == nil {
				stalled = n.Name
				break
			}
		}
		if stalled == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never received a write a made after the relocation: a's replication "+
				"stream is stalled behind the relocation entry", stalled)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// And the relocation itself arrived intact everywhere: source tombstoned,
	// target pending recreate with its token.
	for _, n := range c.Nodes {
		if src, err := corrosion.GetContainer(ctx, n.DB, victim.Name, "ct-moved"); err != nil || src != nil {
			t.Errorf("%s: source row still live after relocation: %+v err=%v", n.Name, src, err)
		}
		dst, err := corrosion.GetContainer(ctx, n.DB, b.Name, "ct-moved")
		if err != nil || dst == nil {
			t.Errorf("%s: target row missing: err=%v", n.Name, err)
			continue
		}
		if dst.StateDetail != corrosion.ContainerRelocateRecreateDetail || dst.RelocateToken != "tok-stream" {
			t.Errorf("%s: target = detail %q token %q, want %q / tok-stream",
				n.Name, dst.StateDetail, dst.RelocateToken, corrosion.ContainerRelocateRecreateDetail)
		}
	}
	c.WaitConverged(t, convergeTimeout)
}

// A restarted node must catch its replica up within seconds, not one
// anti-entropy interval later.
//
// Observed on the kvm003-f3 lab during a rolling upgrade (lab1-reltok,
// 2026-10-10): for about 70 s after every daemon restart, `lv stop`, `lv start`
// and `lv migrate` served by that node were refused with "this node's replica
// has not caught up with the cluster yet (no anti-entropy exchange with a peer
// has completed since this process started)". node-1 restarted at 21:07:48 and
// its first exchange completed at 21:09:00.
//
// The refusal is right: until one exchange completes, the node's replica can
// still name it the owner of a workload that moved while it was away. What was
// wrong is how long it waited for nothing: the anti-entropy loop's first pass
// ran only after one full jittered interval (60 s ±20 %) — nothing tried to
// catch up before then — and a node that lost every peer and got them back
// waited for the next scheduled tick the same way.
//
// These scenarios run the real loop (AntiEntropy.Start) at its default
// interval over the fleet's real gRPC + mTLS, so a loop that only catches up
// on its scheduled tick cannot pass.

package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// catchUpBound is how long a restarted node with reachable peers may stay
// not-caught-up. Well under the default 48 s minimum of one jittered interval,
// and loose enough for a loaded CI host.
const catchUpBound = 20 * time.Second

func waitCaughtUp(t *testing.T, n *Node, within time.Duration, phase string) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		if ok, _ := n.DB.ReplicaCaughtUp(); ok {
			return time.Since(start)
		}
		if time.Since(start) > within {
			_, why := n.DB.ReplicaCaughtUp()
			t.Fatalf("%s: %s's replica still not caught up after %s (%s) — the anti-entropy loop "+
				"waits for its scheduled interval instead of catching up", phase, n.Name, within, why)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFleet_RestartedNode_CatchesUpWithinSeconds(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	n := c.Nodes[0]
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
		Name: "rvm", HostName: n.Name, State: "running", Spec: `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	n.Virt.SetState("rvm", "running")

	// The daemon restarts: a fresh process has not caught up.
	n.DB.MarkReplicaStale("process restarted (fleet: modelled daemon restart)")
	_, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "rvm"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a just-restarted node must refuse StopVM Unavailable until it catches up, got %v", err)
	}
	// The refusal says what it is waiting for and that it is retrying, not
	// "retry in a minute".
	msg := status.Convert(err).Message()
	for _, want := range []string{"not caught up", "retries the exchange"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "Retry in a minute") {
		t.Errorf("refusal %q still tells the operator to wait a minute", msg)
	}

	// The daemon's loop, at the default interval (0 → 60 s).
	ae := corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0)
	lctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); ae.Start(lctx) }()
	defer func() { stop(); <-done }()

	took := waitCaughtUp(t, n, catchUpBound, "after a restart")
	t.Logf("caught up %s after the loop started", took.Round(time.Millisecond))
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "rvm"}); err != nil {
		t.Fatalf("once caught up, StopVM must be served: %v", err)
	}

	// Later the node loses sight of every peer (memberlist's last leave) and
	// gets them back. It must catch up again without waiting out the 60 s
	// interval the loop is now sleeping in.
	n.DB.MarkReplicaStale("lost sight of every gossip peer (fleet: modelled partition)")
	took = waitCaughtUp(t, n, catchUpBound, "after losing every peer")
	t.Logf("caught up again %s after the reset", took.Round(time.Millisecond))
}

// Every peer leaves and comes back a few seconds later (a host suspend, a
// switch flap). memberlist's last leave marks the replica stale and wakes the
// loop, whose pass finds no peers. That empty pass must not start the 12 s
// cooldown: once the peers are back the node catches up within about one
// catch-up retry, not a cooldown later.
func TestFleet_AllPeersBlip_CatchesUpSoonAfterReturn(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	n := c.Nodes[0]
	ctx := context.Background()
	peers := n.DB.Members()
	if len(peers) == 0 {
		t.Fatal("setup: the node must see its peers")
	}
	var gone atomic.Bool
	n.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		if gone.Load() {
			return nil
		}
		return peers
	})

	n.DB.MarkReplicaStale("process restarted (fleet: modelled daemon restart)")
	ae := corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0)
	lctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); ae.Start(lctx) }()
	defer func() { stop(); <-done }()
	waitCaughtUp(t, n, catchUpBound, "after a restart")

	// Let the cooldown of that catch-up pass run out, so only the blip itself
	// can hold the next pass back.
	time.Sleep(13 * time.Second)

	gone.Store(true)
	n.DB.MarkReplicaStale("lost sight of every gossip peer (fleet: modelled blip)")
	time.Sleep(time.Second) // the woken pass runs and finds nobody
	gone.Store(false)

	took := waitCaughtUp(t, n, 6*time.Second, "after every peer came back")
	t.Logf("caught up %s after the peers returned", took.Round(time.Millisecond))
}

package fleet

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestFleet_FenceConfirmRefusesAHostOthersSeeAnswering: on the lab an operator
// ran `lv host fence-confirm node-4` while node-4 was alive and answering, and
// the cluster recorded it fenced, ready to recover its workloads beside the
// running copies. Here b has just seen d answer; an operator on a confirms d
// off. a reads b's verdict from its own replica and refuses, and neither
// replica records anything. Once d is down — every observer's latest verdict
// is a failure — the same confirmation is accepted.
//
// Mutation: drop the liveness precondition in FenceHost — the first
// confirmation records d fenced and this goes red.
func TestFleet_FenceConfirmRefusesAHostOthersSeeAnswering(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// The statement PublishHealth replicates, with a healthy verdict.
	if err := b.DB.Execute(ctx,
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		b.Name, d.Name, "healthy", 0, nil, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)

	_, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{Name: d.Name, Confirmed: true, ConfirmManualOnly: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("fence-confirm of %s while %s sees it answer = %v, want FailedPrecondition", d.Name, b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		if st := hostStateOn(t, n, d.Name); st != "active" {
			t.Fatalf("%s holds %s %q after a refused confirmation", n.Name, d.Name, st)
		}
		if f := fencesOf(t, n, d.Name); len(f) != 0 {
			t.Fatalf("%s holds fencing_log rows for %s after a refused confirmation: %+v", n.Name, d.Name, f)
		}
	}

	// d goes down: every observer's newest verdict is a failure.
	c.Kill(d)
	at := time.Now()
	for _, o := range []*Node{a, b} {
		PublishHealth(t, o, d.Name, 5, at)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	if _, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{Name: d.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
		t.Fatalf("fence-confirm of %s once it is down: %v", d.Name, err)
	}
	if st := hostStateOn(t, a, d.Name); st != "fenced" {
		t.Fatalf("%s holds %s %q after the confirmation, want fenced", a.Name, d.Name, st)
	}
}

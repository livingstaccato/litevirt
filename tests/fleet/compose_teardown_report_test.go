package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// DeleteStack leaves a stack "deleting" when any part of its teardown fails,
// and records what was not removed in the audit row. A failed network
// deprovision or container listing used to be recorded ONLY there: the stream
// carried no error for it, so `lv compose down` printed "torn down." and exited
// 0 while the stack stayed "deleting". Every failure that keeps the stack
// "deleting" must reach the stream.

func deleteStackCollect(t *testing.T, ctx context.Context, client pb.LiteVirtClient, name string) []*pb.DeleteProgress {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeleteStack(dctx, &pb.DeleteStackRequest{Name: name})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	var out []*pb.DeleteProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("DeleteStack stream: %v", err)
		}
		out = append(out, p)
	}
}

func deleteErrors(msgs []*pb.DeleteProgress) []*pb.DeleteProgress {
	var out []*pb.DeleteProgress
	for _, p := range msgs {
		if p.Status == "error" {
			out = append(out, p)
		}
	}
	return out
}

func TestFleet_ComposeTeardownReportsFailedNetworkDeprovision(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	msgs := deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}

	// A stack network whose record cannot be removed.
	if err := corrosion.UpsertNetwork(ctx, node.DB, corrosion.NetworkRecord{
		Name: "hb_back", StackName: "hb", Type: "bridge", Config: `{"type":"bridge"}`,
	}); err != nil {
		t.Fatalf("seed stack network: %v", err)
	}
	if err := node.DB.Execute(ctx, `CREATE TRIGGER test_hb_back_undeletable BEFORE UPDATE OF deleted_at ON networks
		WHEN OLD.name = 'hb_back' AND NEW.deleted_at IS NOT NULL
		BEGIN SELECT RAISE(ABORT, 'injected: network row locked'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}

	got := deleteStackCollect(t, ctx, client, "hb")
	if got := stackState(t, ctx, node.DB, "hb"); got != "deleting" {
		t.Fatalf("stack state = %q, want deleting (the injection did not hold)", got)
	}
	errs := deleteErrors(got)
	if len(errs) != 1 {
		t.Fatalf("got %d error statuses, want 1 for the network; stream: %v", len(errs), got)
	}
	if !strings.Contains(errs[0].VmName, "hb_back") || !strings.Contains(errs[0].Error, "injected") {
		t.Errorf("error status %v does not name the network and its failure", errs[0])
	}
}

func TestFleet_ComposeTeardownReportsFailedContainerListing(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	msgs := deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}

	// The containers table is unreadable, so the stack's containers cannot be
	// enumerated — let alone deleted.
	if err := node.DB.Execute(ctx, `ALTER TABLE containers RENAME TO containers_hidden_by_test`); err != nil {
		t.Fatalf("hide containers table: %v", err)
	}
	t.Cleanup(func() {
		_ = node.DB.Execute(context.Background(), `ALTER TABLE containers_hidden_by_test RENAME TO containers`)
	})

	got := deleteStackCollect(t, ctx, client, "hb")
	if got := stackState(t, ctx, node.DB, "hb"); got != "deleting" {
		t.Fatalf("stack state = %q, want deleting (the injection did not hold)", got)
	}
	errs := deleteErrors(got)
	if len(errs) != 1 {
		t.Fatalf("got %d error statuses, want 1 for the container listing; stream: %v", len(errs), got)
	}
	if !strings.Contains(errs[0].VmName, "containers") || errs[0].Error == "" {
		t.Errorf("error status %v does not say the containers could not be listed", errs[0])
	}
}

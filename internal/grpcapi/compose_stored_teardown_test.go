package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stack whose stored compose cannot be read cannot say which of its
// networks are external (pre-existing, not the stack's to delete). The
// teardown deprovisions none of them, says why, and leaves the stack in
// "deleting" — never guesses that none is external.
func TestDeleteStack_UnreadableStoredComposeKeepsNetworks(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "bad", ComposeYAML: "vms: [a, b]\n", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "bad_lan", StackName: "bad", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStream{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "bad"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if nr, _ := corrosion.GetNetwork(ctx, s.db, "bad_lan"); nr == nil {
		t.Error("a network of a stack whose stored compose cannot be read was deprovisioned")
	}
	said := false
	for _, p := range stream.sent {
		if p.Status == "error" && strings.Contains(p.Error, "cannot be read") {
			said = true
		}
	}
	if !said {
		t.Errorf("no error progress says the stored compose cannot be read: %+v", stream.sent)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "bad"); st == nil || st.State != "deleting" {
		t.Errorf("stack = %+v, want it left in deleting for the reconciler", st)
	}
}

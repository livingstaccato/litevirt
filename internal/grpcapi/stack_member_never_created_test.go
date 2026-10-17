package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A degraded stack whose member's create failed is torn down in one compose
// down: the member no host has is reported absent, not an error, and the
// stack does not linger "deleting" (lab 2, O4). A stack recorded "active"
// keeps the rule TestDeleteStack_AMemberWithNoRecordIsNotTakenAsGone pins.
//
// Mutation: drop the never-created case — the member is an error and the
// stack stays "deleting", red.
func TestDeleteStack_AMemberWhoseCreateFailedIsAbsent(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fbm", State: "degraded", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	absent := false
	for _, p := range stream.sent {
		if p.Status == "error" {
			t.Errorf("compose down reported an error: %+v", p)
		}
		absent = absent || (p.VmName == "lbfbm" && p.Status == "absent")
	}
	if !absent {
		t.Errorf("lbfbm was not reported absent: %+v", stream.sent)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st != nil {
		t.Errorf("the stack was not torn down in the one call: %+v", st)
	}
}

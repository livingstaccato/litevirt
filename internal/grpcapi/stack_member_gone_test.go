package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const goneStackYAML = `name: fbm
vms:
  lbfbm:
    image: tiny
    cpu: 1
    memory: 256
`

// Lab 2 run b, finding 5: `lv compose down --name <stack> -y` on a stack whose
// only VM was already deleted (`lv rm --force`) failed with NotFound and left
// the stack "deleting" until the reconciler removed it minutes later. A member
// whose row here is a tombstone, and which no peer has, was deleted: it is
// reported deleted, and the stack is torn down in the one call.
//
// Mutation: drop the tombstone check — the member is an error and the stack
// stays, red.
func TestDeleteStack_AMemberAlreadyDeletedIsRemoved(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fbm", State: "active", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "lbfbm", StackName: "fbm", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	// lv rm --force: the row is a tombstone.
	if err := corrosion.DeleteVM(ctx, s.db, "lbfbm"); err != nil {
		t.Fatal(err)
	}

	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	for _, p := range stream.sent {
		if p.Status == "error" {
			t.Errorf("compose down reported an error for a member that was already deleted: %+v", p)
		}
	}
	deleted := false
	for _, p := range stream.sent {
		if p.VmName == "lbfbm" && p.Status == "deleted" {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("no progress reports lbfbm deleted: %+v", stream.sent)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st != nil {
		t.Errorf("the stack was not torn down in the one call: %+v", st)
	}
}

// A member the stack's file names that has no row here at all — never made,
// or made on a peer and not replicated yet — is not proven gone: it stays an
// error and the stack stays "deleting" for the reconciler, as before.
func TestDeleteStack_AMemberWithNoRecordIsNotTakenAsGone(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fbm", State: "active", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	failed := false
	for _, p := range stream.sent {
		if p.VmName == "lbfbm" && p.Status == "error" {
			failed = true
		}
	}
	if !failed {
		t.Errorf("a member with no record anywhere was reported removed: %+v", stream.sent)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st == nil || st.State != "deleting" {
		t.Errorf("the stack = %+v, want it kept \"deleting\" for the reconciler", st)
	}
}

// A tombstone here is not proof while a peer could not be asked: that peer
// may hold a newer VM of the name the stack made and this host has not heard
// of. The member stays an error and the stack "deleting", as before.
//
// Mutation: take the member as gone whatever peers were asked — red.
func TestDeleteStack_AnAlreadyDeletedMemberWaitsForAnUnaskedPeer(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fbm", State: "active", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "lbfbm", StackName: "fbm", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "lbfbm"); err != nil {
		t.Fatal(err)
	}
	// An active peer this host cannot dial (no peer credentials here).
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.peerClient(ctx, "peer-1"); err == nil {
		t.Fatal("setup: peer-1 is reachable, so it would be asked")
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st == nil || st.State != "deleting" {
		t.Errorf("the stack = %+v, want it kept \"deleting\" while a peer was not asked", st)
	}
}

// A peer that is draining, in maintenance, fenced or unknown is never asked —
// and a draining host still runs VMs — so it counts as unasked: compose down
// errors and leaves the stack "deleting", as on main, rather than report a
// member gone that such a peer may still run.
//
// Mutation: skip non-active peers without counting them — red.
func TestDeleteStack_AnAlreadyDeletedMemberWaitsForAPeerNotActive(t *testing.T) {
	for _, state := range []string{"draining", "maintenance", "fenced", "unknown"} {
		t.Run(state, func(t *testing.T) {
			s := testServerR2(t)
			s.virt = libvirtfake.New()
			ctx := adminContext(context.Background())
			goneMemberStack(t, s, ctx, "fbm")
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: state}); err != nil {
				t.Fatal(err)
			}
			stream := &mockDeleteStreamR2{ctx: ctx}
			if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
				t.Fatalf("DeleteStack: %v", err)
			}
			if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st == nil || st.State != "deleting" {
				t.Errorf("the stack = %+v, want it kept \"deleting\" while a %s peer was not asked", st, state)
			}
		})
	}
	// A witness never runs a VM, and a removed host is gone: neither holds it.
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	goneMemberStack(t, s, ctx, "fbm")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "w-1", Address: "10.0.0.8", State: "maintenance", Role: "witness"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "gone-1", Address: "10.0.0.7", State: "removed"}); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st != nil {
		t.Errorf("a witness or a removed host held the teardown: %+v", st)
	}
}

// The tombstone has to be this stack's member: a tombstone of the name left
// by a VM of another stack (or none) proves nothing about this stack's.
//
// Mutation: accept any tombstone of the name — red.
func TestDeleteStack_ATombstoneOfAnotherStacksVMIsNotProof(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "fbm", State: "active", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "lbfbm", StackName: "other", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "lbfbm"); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fbm"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if st, _ := corrosion.GetStack(ctx, s.db, "fbm"); st == nil || st.State != "deleting" {
		t.Errorf("the stack = %+v, want it kept \"deleting\": the tombstone is another stack's VM", st)
	}
}

// goneMemberStack makes stack fbm whose one member, lbfbm, was deleted here.
func goneMemberStack(t *testing.T, s *Server, ctx context.Context, stack string) {
	t.Helper()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: stack, State: "active", ComposeYAML: goneStackYAML}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "lbfbm", StackName: stack, HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "lbfbm"); err != nil {
		t.Fatal(err)
	}
}

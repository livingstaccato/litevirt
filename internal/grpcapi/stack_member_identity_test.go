package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lab-recheck-5 11:28:45: a compose up of stack rc5iso failed and left the
// stack record, naming its members. A VM later created on its own (through
// the UI) under one of those names was deleted, with its disk, by
// `lv compose down --name rc5iso`: the teardown took every instance name
// the stored compose file lists as the stack's, without asking whether the
// VM of that name was the stack's. A VM's row records the stack that
// created it (stack_name); a VM whose row names another stack, or none, is
// not the stack's and is left alone.
func TestDeleteStack_LeavesASameNamedVMTheStackDidNotCreate(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())

	composeYAML := `name: rc5iso
vms:
  rc5-isosym:
    image: tiny
    cpu: 1
    memory: 256
  rc5-isohome:
    image: tiny
    cpu: 1
    memory: 256
`
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name: "rc5iso", State: "active", ComposeYAML: composeYAML,
	}); err != nil {
		t.Fatal(err)
	}
	// Created by the UI, not by the stack: no stack_name.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "rc5-isosym", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	// The stack's own member.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "rc5-isohome", StackName: "rc5iso", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}

	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "rc5iso"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}

	if vm, _ := corrosion.GetVM(ctx, s.db, "rc5-isosym"); vm == nil {
		t.Fatal("compose down deleted rc5-isosym, a VM the stack did not create (its row names no stack)")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "rc5-isohome"); vm != nil {
		t.Errorf("the stack's own member was not deleted: %+v", vm)
	}
	for _, p := range stream.sent {
		if p.VmName == "rc5-isosym" && (p.Status == "deleting" || p.Status == "deleted") {
			t.Errorf("progress reports deleting a VM the stack did not create: %+v", p)
		}
	}
	said := false
	for _, p := range stream.sent {
		if p.VmName == "rc5-isosym" && p.Status == "kept" && strings.Contains(p.Error, "not created by stack") {
			said = true
		}
	}
	if !said {
		t.Errorf("no progress says why rc5-isosym was kept: %+v", stream.sent)
	}
}

// A VM of that name created by ANOTHER stack is not this stack's either.
func TestDeleteStack_LeavesASameNamedVMOfAnotherStack(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name: "old", State: "deleting", ComposeYAML: "name: old\nvms:\n  web:\n    image: tiny\n    cpu: 1\n    memory: 256\n",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "new", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "old"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("tearing down stack old deleted web, which stack new created")
	}
}

// The member check is made again right before each delete, by the delete
// itself: a row of the name that appears (replicates) after the stack's VMs
// were listed, and names another stack, is still not deleted.
func TestDeleteVMWithFanout_RefusesAVMOfAnotherStack(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	err := s.deleteVMWithFanout(ctx, stackMember{Name: "web", Stack: "old"}, false)
	if !errors.Is(err, errNotStackMember) {
		t.Fatalf("deleteVMWithFanout = %v, want errNotStackMember", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("a VM the stack did not create was deleted")
	}
}

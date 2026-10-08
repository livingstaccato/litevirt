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

// Review M-2: a VM the stack did not create but that sits on one of the
// stack's networks keeps that network: deprovisioning it would tear the
// network down under the kept VM. The teardown says so and is complete.
func TestDeleteStack_KeepsANetworkAKeptVMUses(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminContext(context.Background())
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name: "rc5iso", State: "active",
		ComposeYAML: "name: rc5iso\nvms:\n  rc5-isosym:\n    image: tiny\n    cpu: 1\n    memory: 256\n",
	}); err != nil {
		t.Fatal(err)
	}
	for _, nr := range []corrosion.NetworkRecord{
		{Name: "rc5iso_lan", StackName: "rc5iso", Type: "bridge", Config: "{}"},
		{Name: "rc5iso_back", StackName: "rc5iso", Type: "bridge", Config: "{}"},
	} {
		if err := corrosion.UpsertNetwork(ctx, s.db, nr); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "rc5-isosym", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		[]corrosion.InterfaceRecord{{VMName: "rc5-isosym", NetworkName: "rc5iso_lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	stream := &mockDeleteStreamR2{ctx: ctx}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "rc5iso"}, stream); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if nr, _ := corrosion.GetNetwork(ctx, s.db, "rc5iso_lan"); nr == nil {
		t.Fatal("the stack network a kept VM uses was deprovisioned under it")
	}
	if nr, _ := corrosion.GetNetwork(ctx, s.db, "rc5iso_back"); nr != nil {
		t.Error("an unused stack network was kept")
	}
	said := false
	for _, p := range stream.sent {
		if p.VmName == "network rc5iso_lan" && p.Status == "kept" && strings.Contains(p.Error, "rc5-isosym") {
			said = true
		}
		if p.Status == "error" {
			t.Errorf("a kept network is not a failure: %+v", p)
		}
	}
	if !said {
		t.Errorf("no progress says the network was kept for rc5-isosym: %+v", stream.sent)
	}
}

// Review M-6: a VM DeleteStack keeps at delete time — a member's name whose
// row is another incarnation (errNotStackMember from the owner's binding
// check) — records the same stack, so "a workload of another stack" does
// not see it. It still keeps the networks it uses.
func TestStackNetworkUsers_AVMKeptAtDeleteTimeKeepsItsNetwork(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", StackName: "st", HostName: "test-host", State: "stopped", CPUActual: 1, MemActual: 256},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "st_lan", MAC: "52:54:00:00:00:02"}}, nil); err != nil {
		t.Fatal(err)
	}
	if users, err := s.stackNetworkUsers(ctx, "st_lan", "st", nil); err != nil || len(users) != 0 {
		t.Fatalf("no VM kept: users = %v, %v; want none (web is the stack's own and being deleted)", users, err)
	}
	users, err := s.stackNetworkUsers(ctx, "st_lan", "st", []string{"web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0] != "web" {
		t.Fatalf("users = %v, want the kept VM web", users)
	}
}

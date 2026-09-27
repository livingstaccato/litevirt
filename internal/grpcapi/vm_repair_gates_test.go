package grpcapi

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A compose retry repairs a VM a previous deploy left in error or mid-
// transition through UpdateVM with allow_restart: redefine over its disks,
// then start it. That start is a start like any other, so it passes every
// gate StartVM applies — split-brain quorum, host capacity for the whole VM
// (an error VM is counted nowhere), the linked-clone guard, hardware adoption
// — and a repair never touches a VM another operation is working on.

// repairFixture is a VM "hb" in state on test-host, whose domain is defined
// and in domState, on a host with room for one 1024 MiB VM.
func repairFixture(t *testing.T, state string, memMiB int32, domState libvirtfake.State) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := reconfigServer(t)
	admissionHost(t, s)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hb", "test-host", state,
		seedSpecJSON(t, &pb.VMSpec{Name: "hb", Cpu: 1, MemoryMib: memMiB}))
	fake := s.virt.(*libvirtfake.Fake)
	if err := fake.DefineDomain(`<domain type='kvm'><name>hb</name><memory unit='KiB'>1048576</memory><vcpu>1</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	fake.SetState("hb", domState)
	return s, fake
}

func repairHB(s *Server) error {
	_, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "hb", Cpu: 1, AllowRestart: proto.Bool(true)})
	return err
}

// domainOps lists the fake's lifecycle ops on hb from index from.
func domainOps(f *libvirtfake.Fake, from int) []string {
	var ops []string
	for _, e := range f.EventLog()[from:] {
		if e.Domain == "hb" {
			ops = append(ops, e.Op)
		}
	}
	return ops
}

func assertUntouched(t *testing.T, s *Server, f *libvirtfake.Fake, from int, wantState string) {
	t.Helper()
	if ops := domainOps(f, from); len(ops) != 0 {
		t.Errorf("the refused repair acted on the domain: %v", ops)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "hb"); vm == nil || vm.State != wantState {
		t.Errorf("hb = %+v, want it left in %s", vm, wantState)
	}
}

// The baseline the refusals below are measured against: nothing in the way,
// the repair redefines and starts the VM.
func TestUpdateVM_RepairStartsAVMNothingBlocks(t *testing.T) {
	s, _ := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	if err := repairHB(s); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "hb"); vm == nil || vm.State != "running" {
		t.Fatalf("hb = %+v after the repair, want running", vm)
	}
}

func TestUpdateVM_RepairRefusedWithoutQuorum(t *testing.T) {
	s, f := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	s.SetGate(fakeServerGate{enforced: true, execOK: false})
	from := len(f.EventLog())
	err := repairHB(s)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "start refused") {
		t.Fatalf("repair without quorum = %v, want FailedPrecondition 'start refused'", err)
	}
	assertUntouched(t, s, f, from, "error")
}

// The whole VM is admitted as new to the host: an error VM consumes nothing,
// so starting it adds its full size — not the zero a desired-minus-stored
// grow computes.
func TestUpdateVM_RepairRefusedOnAFullHost(t *testing.T) {
	s, f := repairFixture(t, "error", 2048, libvirtfake.StateDefined) // > 1536 allocatable
	from := len(f.EventLog())
	err := repairHB(s)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("repair of a VM the host has no room for = %v, want ResourceExhausted", err)
	}
	assertUntouched(t, s, f, from, "error")
}

func TestUpdateVM_RepairRefusedWhileBackingLinkedClones(t *testing.T) {
	s, f := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	ctx := adminCtx()
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "hb", DiskName: "root", HostName: "test-host", Path: "/var/lib/litevirt/disks/hb-root.qcow2", StorageType: "local",
	}); err != nil {
		t.Fatal(err)
	}
	insertTestVM(t, ctx, s.db, "clone1", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "clone1", DiskName: "root", HostName: "test-host", Path: "/var/lib/litevirt/disks/clone1-root.qcow2",
		StorageType: "local", BackingDisk: "/var/lib/litevirt/disks/hb-root.qcow2",
	}); err != nil {
		t.Fatal(err)
	}
	from := len(f.EventLog())
	err := repairHB(s)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "linked clone") {
		t.Fatalf("repair of a VM backing a linked clone = %v, want FailedPrecondition naming the clones", err)
	}
	assertUntouched(t, s, f, from, "error")
}

// A VM mid-start by the failover path is held by a vm_locks lease, not by
// this process's VM lock. The repair must not destroy the domain that start
// just brought up.
func TestUpdateVM_RepairLeavesAVMMidFailoverStart(t *testing.T) {
	s, f := repairFixture(t, "starting", 1024, libvirtfake.StateRunning)
	ctx := adminCtx()
	now := time.Now().UTC()
	if err := s.db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES ('hb', 'node-2', ?, ?)`,
		now.Add(10*time.Minute).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	from := len(f.EventLog())
	err := repairHB(s)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "start lease") {
		t.Fatalf("repair of a VM a failover start holds = %v, want FailedPrecondition naming the start lease", err)
	}
	assertUntouched(t, s, f, from, "starting")
	if active, _ := f.DomainIsActive("hb"); !active {
		t.Error("the failover start's domain is no longer running")
	}
}

// An expired lease is no one's: it does not hold the repair off.
func TestUpdateVM_RepairIgnoresAnExpiredVMLock(t *testing.T) {
	s, _ := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	ctx := adminCtx()
	old := time.Now().UTC().Add(-time.Hour)
	if err := s.db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES ('hb', 'node-2', ?, ?)`,
		old.Format(time.RFC3339), old.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := repairHB(s); err != nil {
		t.Fatalf("repair with an expired vm_locks row: %v", err)
	}
}

// A row carrying a pending action is another operation's transition.
func TestUpdateVM_RepairRefusedWithAPendingAction(t *testing.T) {
	s, f := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	if err := s.db.Execute(adminCtx(), `UPDATE vms SET pending_action_id = 'act-1' WHERE name = 'hb'`); err != nil {
		t.Fatal(err)
	}
	from := len(f.EventLog())
	if err := repairHB(s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("repair of a VM with a pending action = %v, want FailedPrecondition", err)
	}
	assertUntouched(t, s, f, from, "error")
}

// Whether the domain runs is unknown: the repair cannot know it is not
// destroying a live guest, so it refuses.
func TestUpdateVM_RepairRefusedWhenDomainActivityIsUnknown(t *testing.T) {
	s, f := repairFixture(t, "error", 1024, libvirtfake.StateDefined)
	s.virt = activityUnknownVirt{f}
	from := len(f.EventLog())
	err := repairHB(s)
	if status.Code(err) == codes.OK || !strings.Contains(err.Error(), "whether its domain runs is unknown") {
		t.Fatalf("repair with its domain's activity unknown = %v, want a refusal saying so", err)
	}
	assertUntouched(t, s, f, from, "error")
}

// activityUnknownVirt fails only the activity question, so every other step
// the repair takes sees a healthy libvirt.
type activityUnknownVirt struct{ *libvirtfake.Fake }

func (activityUnknownVirt) DomainIsActive(string) (bool, error) {
	return false, errors.New("injected: libvirt connection lost")
}

package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A row the start guard cannot read refuses the start as retryable: whether
// a move of the VM is in flight is then unknown, and a start on an unknown
// row could be the second copy.
//
// Mutation: a read error taken as "no move" — the start goes ahead, red.
func TestMovingVMStartRefusal_UnreadableRowRefusesAsRetryable(t *testing.T) {
	s, _ := provableCreateServer(t)
	insertTestVMWithSpec(t, adminCtx(), s.db, "web", s.hostName, "stopped", `{"name":"web"}`)
	vm, err := corrosion.GetVM(adminCtx(), s.db, "web")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	gone, cancel := context.WithCancel(adminCtx())
	cancel() // every read on it fails
	err = s.movingVMStartRefusal(gone, vm)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "retry") {
		t.Fatalf("start guard with the row unreadable = %v; want Unavailable, retryable", err)
	}
}

// A cutover's runtime handoff starts the replaced VM under its name outside
// the start primitive: a row recorded migrating is not started there either.
//
// Mutation: the guard dropped from finishVMReplaceRuntime — x boots, red.
func TestFinishVMReplaceRuntime_DoesNotStartAReplacedVMRecordedMigrating(t *testing.T) {
	s, fake := provableCreateServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "x", HostName: s.hostName, State: "migrating", StateDetail: "→ peer",
		CPUActual: 1, MemActual: 512, Spec: `{"name":"x","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	dom := "<domain type='kvm'><name>x-next</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices></devices></domain>"
	cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
		Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
		Manifest: corrosion.VMReplaceManifest{
			HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
			ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
		}}
	err = s.finishVMReplaceRuntime(adminCtx(), cl)
	if err == nil || !strings.Contains(err.Error(), "migrating") {
		t.Fatalf("handoff start of a replaced VM recorded migrating = %v; want it refused naming the move", err)
	}
	if st, _ := fake.RawState("x"); st == libvirtfake.StateRunning {
		t.Fatal("x was started")
	}
}

// replacedVMHandoffAtStart runs the runtime handoff of a replaced VM x whose
// row is state, running act on the database at the moment the handoff reads
// x's domain state, just before its start. It returns the handoff's error and
// whether x was started.
func replacedVMHandoffAtStart(t *testing.T, state, detail, act string) (error, bool) {
	t.Helper()
	s, fake := provableCreateServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "x", HostName: s.hostName, State: state, StateDetail: detail,
		CPUActual: 1, MemActual: 512, Spec: `{"name":"x","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	acted := false
	fake.FailDomainState = func(name string) error {
		if name == "x" && !acted {
			acted = true
			if err := s.db.Execute(adminCtx(), act); err != nil {
				t.Errorf("%s: %v", act, err)
			}
		}
		return nil
	}
	dom := "<domain type='kvm'><name>x-next</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices></devices></domain>"
	cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
		Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
		Manifest: corrosion.VMReplaceManifest{
			HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
			ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
		}}
	err = s.finishVMReplaceRuntime(adminCtx(), cl)
	if !acted {
		t.Fatal("the handoff never read x's domain state; the scenario did not run")
	}
	st, _ := fake.RawState("x")
	return err, st == libvirtfake.StateRunning
}

// The handoff's start reads the row again for the start guard: a read that
// fails there refuses the start as retryable, as the guard itself does,
// rather than skipping the guard. Here the row says migrating, so a start
// would be a second copy of a guest that may run on the move's target.
//
// Mutation: the read error taken as "no row to check" (the guard run only on
// a successful read) — x boots, red.
func TestFinishVMReplaceRuntime_UnreadableRowAtStartRefusesTheStart(t *testing.T) {
	err, started := replacedVMHandoffAtStart(t, "migrating", "→ peer", `ALTER TABLE vms RENAME TO vms_hidden`)
	if started {
		t.Fatal("x was started with its row unreadable")
	}
	if status.Code(errors.Unwrap(err)) != codes.Unavailable || !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), "retry") {
		t.Fatalf("handoff start with the row unreadable = %v; want Unavailable, naming the read error, retryable", err)
	}
}

// A row gone between the handoff's first read and its start is not started
// under its name: nothing records the guest that would run.
//
// Mutation: a missing row taken as "nothing to check" — x boots, red.
func TestFinishVMReplaceRuntime_RowGoneAtStartRefusesTheStart(t *testing.T) {
	err, started := replacedVMHandoffAtStart(t, "stopped", "", `DELETE FROM vms WHERE name = 'x'`)
	if started {
		t.Fatal("x was started with its row gone")
	}
	if err == nil || !strings.Contains(err.Error(), "row is gone") {
		t.Fatalf("handoff start with the row gone = %v; want it refused naming the missing row", err)
	}
}

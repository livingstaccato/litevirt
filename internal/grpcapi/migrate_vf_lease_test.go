package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// withLeaseJournal gives the rig's server a host-local operation journal, the
// one the daemon wires at startup, and returns it.
func (r *vfRig) withLeaseJournal(t *testing.T) *opjournal.Journal {
	t.Helper()
	j, err := opjournal.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	r.s.SetOpJournal(j)
	return j
}

// migrationLease reads the VM's device lease, failing the test on a read error.
func migrationLease(t *testing.T, j *opjournal.Journal, vm string) (*opjournal.Entry, bool) {
	t.Helper()
	e, found, err := j.Read(deviceLeaseOpID(vm))
	if err != nil {
		t.Fatalf("read device lease: %v", err)
	}
	return e, found
}

// assertVFsHeldInTheWindow checks what must hold while a VF is out of the guest
// for a migration: the VM still owns it, no other allocation can claim it, and
// a durable lease names it for restart recovery. It runs inside libvirt's
// migrate call, on MigrateVM's goroutine, so it never calls t.Fatal: that would
// end the goroutine without answering MigrateVM, which then waits forever.
func (r *vfRig) assertVFsHeldInTheWindow(t *testing.T, j *opjournal.Journal) {
	t.Helper()
	ctx := adminCtx()
	for _, a := range r.vfs {
		if guestHasHostdev(t, r.s, "vf-vm", a) {
			t.Errorf("VF %s still in the guest when libvirt was asked to migrate it", a)
		}
		if o := pciOwnerOf(t, ctx, r.s, a); o != "vf-vm" {
			t.Errorf("VF %s is owned by %q in the migration window, want vf-vm — released, any VM can claim it", a, o)
		}
		ok, err := corrosion.ClaimPCIDevice(ctx, r.s.db, "test-host", a, "other-vm")
		if err != nil {
			t.Errorf("ClaimPCIDevice: %v", err)
		}
		if ok {
			t.Errorf("another VM claimed VF %s while it was detached for the migration", a)
		}
		avail, err := corrosion.GetAvailableDevicesByType(ctx, r.s.db, "test-host", "net")
		if err != nil {
			t.Errorf("GetAvailableDevicesByType: %v", err)
		}
		for _, d := range avail {
			if d.Address == a {
				t.Errorf("VF %s is offered to allocators while detached for the migration", a)
			}
		}
	}
	e, found, err := j.Read(deviceLeaseOpID("vf-vm"))
	if err != nil || !found {
		t.Errorf("no durable device lease names the detached VFs — a crash now loses them (err %v)", err)
		return
	}
	if e.Stage != deviceLeaseStageMigrationDetached {
		t.Errorf("lease stage %q, want %q", e.Stage, deviceLeaseStageMigrationDetached)
	}
	if got, want := e.Artifacts["addresses"], strings.Join(r.vfs, ","); got != want {
		t.Errorf("lease addresses %q, want %q", got, want)
	}
}

// TestMigrateVM_AConcurrentAllocatorCannotTakeADetachedVF: between the VF
// leaving the guest and the migration's outcome, another VM's allocation must
// not be able to take it. The VF used to be released for the whole window.
func TestMigrateVM_AConcurrentAllocatorCannotTakeADetachedVF(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0", "0000:41:10.1")
	j := r.withLeaseJournal(t)
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.assertVFsHeldInTheWindow(t, j)
		return errors.New("injected libvirt migration failure")
	}

	if err := r.migrate(t); err == nil {
		t.Fatal("the migration succeeded; the scenario needs libvirt to fail it")
	}
	r.assertVFsHome(t, "after libvirt failed the migration")
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived a migration whose VFs all went back")
	}
}

// TestMigrateVM_ARestartInTheWindowReattachesTheVFs: the daemon dies while the
// VFs are out of the guest. On restart RecoverDeviceLeases — the startup pass —
// finds the lease and puts them back into the guest still running here.
//
// The hook stands for the crash point: the request's in-memory abort is
// disarmed by then, so only the durable lease, the ownership rows and libvirt
// are there for the restarted daemon to work from.
func TestMigrateVM_ARestartInTheWindowReattachesTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0", "0000:41:10.1")
	j := r.withLeaseJournal(t)
	recovered := false
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.s.RecoverDeviceLeases(context.Background())
		recovered = true
		for _, a := range r.vfs {
			if o := pciOwnerOf(t, adminCtx(), r.s, a); o != "vf-vm" {
				t.Errorf("after restart recovery VF %s is owned by %q, want vf-vm", a, o)
			}
			if !r.fs.isBound(a) {
				t.Errorf("after restart recovery VF %s is not bound to vfio-pci", a)
			}
			if !guestHasHostdev(t, r.s, "vf-vm", a) {
				t.Errorf("after restart recovery VF %s is not back in the guest", a)
			}
		}
		if _, found, err := j.Read(deviceLeaseOpID("vf-vm")); err != nil || found {
			t.Errorf("restart recovery reattached the VFs but kept the lease (err %v)", err)
		}
		return errors.New("daemon died mid-migration")
	}

	_ = r.migrate(t)
	if !recovered {
		t.Fatal("the migration never reached libvirt")
	}
}

// TestRecoverDeviceLeases_AfterACutoverReleasesTheSourceVFs: the daemon dies
// after the cutover committed but before the source VFs were given up. The
// guest runs on the target with its own VFs; on restart the source's are
// unbound and released, never left owned by a VM that is not here.
func TestRecoverDeviceLeases_AfterACutoverReleasesTheSourceVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	ctx := adminCtx()
	for _, a := range r.vfs {
		if err := r.s.detachHostdevIfPresent("vf-vm", a); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.s.beginMigrationVFLease("vf-vm", []string{r.vfs[0]}); err != nil {
		t.Fatal(err)
	}
	// The cutover: libvirt undefined the source domain, the row names the target.
	if err := corrosion.UpdateVMState(ctx, r.s.db, "vf-vm", "migrating", "→ target-host"); err != nil {
		t.Fatal(err)
	}
	if err := r.fake.UndefineDomain("vf-vm", false); err != nil {
		t.Fatal(err)
	}
	if ok, err := corrosion.CommitMigrationOwnership(ctx, r.s.db, "vf-vm", "test-host", "target-host", "running", nil); err != nil || !ok {
		t.Fatalf("CommitMigrationOwnership: %v %v", ok, err)
	}

	r.s.RecoverDeviceLeases(context.Background())

	for _, a := range r.vfs {
		if o := pciOwnerOf(t, ctx, r.s, a); o != "" {
			t.Errorf("VF %s still owned by %q on the source after the guest moved away", a, o)
		}
		if r.fs.isBound(a) {
			t.Errorf("VF %s still bound to vfio-pci on the source after release", a)
		}
	}
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived the release")
	}
}

// TestRecoverDeviceLeases_AMigrationLeaseIsKeptWhenTheGuestCannotBeRead: with
// the domain's state unreadable, recovery touches nothing and keeps the lease —
// the VFs stay owned by the VM, never released into a guest still using them.
func TestRecoverDeviceLeases_AMigrationLeaseIsKeptWhenTheGuestCannotBeRead(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	for _, a := range r.vfs {
		if err := r.s.detachHostdevIfPresent("vf-vm", a); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.s.beginMigrationVFLease("vf-vm", r.vfs); err != nil {
		t.Fatal(err)
	}
	r.fake.FailDomainStateReason = func(string) error { return errors.New("libvirt unreachable") }

	r.s.RecoverDeviceLeases(context.Background())

	if o := pciOwnerOf(t, adminCtx(), r.s, r.vfs[0]); o != "vf-vm" {
		t.Errorf("VF owned by %q, want vf-vm", o)
	}
	if !r.fs.isBound(r.vfs[0]) {
		t.Error("VF unbound while the guest's state was unknown")
	}
	if _, found := migrationLease(t, j, "vf-vm"); !found {
		t.Error("the lease was dropped although nothing was recovered")
	}
}

// TestMigrateVM_ACutoverReleasesTheSourceVFs: a migration that cuts over gives
// the source's VFs up — unbound, unowned, the lease cleared — once ownership has
// moved, and not before.
func TestMigrateVM_ACutoverReleasesTheSourceVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.assertVFsHeldInTheWindow(t, j)
		return nil
	}

	if err := r.migrate(t); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, a := range r.vfs {
		if o := pciOwnerOf(t, adminCtx(), r.s, a); o != "" {
			t.Errorf("VF %s still owned by %q on the source after the cutover", a, o)
		}
		if r.fs.isBound(a) {
			t.Errorf("VF %s still bound to vfio-pci on the source after the cutover", a)
		}
	}
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived a completed migration")
	}
}

// TestMigrateVM_ARecoveryRequiredDeviceLeaseRefusesTheMove: a device lease left
// recovery-required by a failed attach is that attach's only crash anchor.
// Overwriting it with the migration's lease would lose it, so the move is
// refused before any VF is touched.
func TestMigrateVM_ARecoveryRequiredDeviceLeaseRefusesTheMove(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	prior := opjournal.Entry{
		OperationID: deviceLeaseOpID("vf-vm"), ResourceID: "vf-vm", Kind: deviceLeaseKind,
		Stage: deviceLeaseStageRollbackIncomplete, Artifacts: map[string]string{"addresses": "0000:42:00.0"},
	}
	if err := j.Write(prior); err != nil {
		t.Fatal(err)
	}

	err := r.migrate(t)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	r.assertVFsHome(t, "after the refusal")
	e, found := migrationLease(t, j, "vf-vm")
	if !found || e.Stage != deviceLeaseStageRollbackIncomplete || e.Artifacts["addresses"] != "0000:42:00.0" {
		t.Errorf("the recovery-required lease was changed: %+v found=%v", e, found)
	}
}

// TestMigrateVM_AFailureWithTheGuestStoppedReleasesTheVFs: libvirt fails and the
// guest is no longer running, so there is nothing to put the VFs back into. The
// VM held them through the move; they go back to the pool, as a stopped guest's
// devices are allocated again when it starts, and the lease is cleared.
func TestMigrateVM_AFailureWithTheGuestStoppedReleasesTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.fake.SetState("vf-vm", "shutoff")
		return errors.New("injected libvirt migration failure")
	}

	if err := r.migrate(t); err == nil {
		t.Fatal("the migration succeeded; the scenario needs libvirt to fail it")
	}
	for _, a := range r.vfs {
		if o := pciOwnerOf(t, adminCtx(), r.s, a); o != "" {
			t.Errorf("VF %s still owned by %q although the guest it was held for is not running", a, o)
		}
		if r.fs.isBound(a) {
			t.Errorf("VF %s still bound to vfio-pci after its release", a)
		}
	}
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived the release")
	}
}

// TestAdoptAbandonedMigration_ACutoverReleasesTheSourceVFs: the client stopped
// watching and the adopted migration then cut over. The adopter commits the
// move and gives up the source's VFs, as a watched cutover does.
func TestAdoptAbandonedMigration_ACutoverReleasesTheSourceVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	ctx := adminCtx()
	// Where MigrateVM leaves things when libvirt takes over: VFs out of the
	// guest, still the VM's, named by the lease; the row `migrating`.
	if err := r.s.beginMigrationVFLease("vf-vm", r.vfs); err != nil {
		t.Fatal(err)
	}
	var detached []corrosion.PCIDeviceRecord
	for _, a := range r.vfs {
		if err := r.s.detachHostdevIfPresent("vf-vm", a); err != nil {
			t.Fatal(err)
		}
		detached = append(detached, corrosion.PCIDeviceRecord{HostName: "test-host", Address: a, Type: "net", VendorID: "8086", VMName: "vf-vm"})
	}
	if err := corrosion.UpdateVMState(ctx, r.s.db, "vf-vm", "migrating", "→ target-host"); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, r.s.db, "vf-vm")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}

	done := make(chan error, 1)
	unlocked := make(chan struct{})
	r.s.adoptAbandonedMigration(context.Background(), vm, "target-host", false, nil, done,
		func() { close(unlocked) }, migrationFinish{
			target:      &corrosion.HostRecord{Name: "target-host", Address: "10.0.0.1", GRPCPort: 7443},
			detachedVFs: detached,
		})
	done <- nil
	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted migration never finished")
	}
	for _, a := range r.vfs {
		if o := pciOwnerOf(t, ctx, r.s, a); o != "" {
			t.Errorf("VF %s still owned by %q on the source after the adopted cutover", a, o)
		}
		if r.fs.isBound(a) {
			t.Errorf("VF %s still bound to vfio-pci on the source after the adopted cutover", a)
		}
	}
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived the adopted cutover")
	}
}

// TestMigrateVM_AFirstDetachFailureClearsTheLease: the lease is written before
// the first detach, and that detach fails. No VF left the guest, so the lease
// names nothing to recover and must not linger.
func TestMigrateVM_AFirstDetachFailureClearsTheLease(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	r.fake.FailDetachHostdev = func(string, string) error { return errors.New("injected detach failure") }

	if err := r.migrate(t); err == nil || !strings.Contains(err.Error(), "detach VF 0000:41:10.0") {
		t.Fatalf("got %v, want the VF's detach failure", err)
	}
	r.assertVFsHome(t, "after the detach failed")
	if _, found := migrationLease(t, j, "vf-vm"); found {
		t.Error("the lease outlived a migration in which no VF left the guest")
	}
}

// TestMigrateVM_AFailureWithTheGuestPausedKeepsTheVFs: libvirt fails and leaves
// the guest paused. A paused guest is still active and resumes in place, so its
// VFs must not go back to the pool: they stay owned and bound, the lease stays
// for recovery, and a VM event says they are out of the guest.
func TestMigrateVM_AFailureWithTheGuestPausedKeepsTheVFs(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.fake.SetState("vf-vm", libvirtfake.StatePaused)
		return errors.New("injected libvirt migration failure")
	}

	if err := r.migrate(t); err == nil {
		t.Fatal("the migration succeeded; the scenario needs libvirt to fail it")
	}
	ctx := adminCtx()
	for _, a := range r.vfs {
		if o := pciOwnerOf(t, ctx, r.s, a); o != "vf-vm" {
			t.Errorf("VF %s owned by %q after a failure that left the guest paused, want vf-vm — released from a guest that will resume", a, o)
		}
		if !r.fs.isBound(a) {
			t.Errorf("VF %s unbound from a paused guest's reservation", a)
		}
	}
	if e, found := migrationLease(t, j, "vf-vm"); !found || e.Stage != deviceLeaseStageMigrationDetached {
		t.Errorf("the lease must be kept for recovery: %+v found=%v", e, found)
	}
	evs, err := corrosion.ListVMEvents(ctx, r.s.db, "vf-vm", 50, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	seen := false
	for _, ev := range evs {
		if ev.Result == "error" && strings.Contains(ev.Detail, "0000:41:10.0") {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no error VM event names the VF left out of the paused guest; events: %+v", evs)
	}
}

// TestMigrateVM_TheVFLeaseAndItsRecoveryWorkWithTheProtocolOff pins a decision:
// a migration's VF lease and its restart recovery are NOT gated on
// operation_protocol (TestAttachDevice_ProtocolInactiveRejected pins the
// opposite for operator hotplug). The migration's detach and reattach do not
// change the VM's replicated hardware, which is the thing the protocol
// journals. The lease is host-local and no peer relies on it, so a gate would
// buy no safety. It would only turn restart recovery off on every cluster that
// keeps the default enforcement.operation_protocol=false.
func TestMigrateVM_TheVFLeaseAndItsRecoveryWorkWithTheProtocolOff(t *testing.T) {
	r := vfMigrationRig(t, "0000:41:10.0")
	j := r.withLeaseJournal(t)
	r.s.SetOperationProtocol(false) // flag off, and the rig's gate latches nothing
	if r.s.operationProtocolActive(adminCtx()) {
		t.Fatal("precondition: operation_protocol must be inactive")
	}
	recovered := false
	r.fake.FailMigrateToTarget = func(string, string) error {
		r.assertVFsHeldInTheWindow(t, j) // the lease is written
		r.s.RecoverDeviceLeases(context.Background())
		recovered = true
		for _, a := range r.vfs {
			if !guestHasHostdev(t, r.s, "vf-vm", a) {
				t.Errorf("with the protocol off, restart recovery did not put VF %s back", a)
			}
		}
		if _, found, err := j.Read(deviceLeaseOpID("vf-vm")); err != nil || found {
			t.Errorf("with the protocol off, restart recovery kept the lease (err %v)", err)
		}
		return errors.New("daemon died mid-migration")
	}

	_ = r.migrate(t)
	if !recovered {
		t.Fatal("the migration never reached libvirt")
	}
}

package health

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Kernel boot IDs: the boot onboot last ran in, and this one.
const (
	bootBefore = "11111111-1111-4111-8111-111111111111"
	bootNow    = "22222222-2222-4222-8222-222222222222"
)

// onbootVM inserts an onboot VM stopped by its operator, its domain defined
// and shut off (as `lv stop` leaves it).
func onbootVM(t *testing.T, db *corrosion.Client, fake *libvirtfake.Fake, name, spec string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: name, HostName: "node-a", State: "stopped", StateDetail: operatorStopDetail, Spec: spec,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain><name>` + name + `</name></domain>`); err != nil {
		t.Fatal(err)
	}
}

// writeRecord writes the onboot record: boot ID and owed VMs.
func writeRecord(t *testing.T, dataDir, boot string, owed ...onbootStop) {
	t.Helper()
	if err := writeOnbootRecord(dataDir, onbootRecord{BootID: boot, Owed: owed}); err != nil {
		t.Fatal(err)
	}
}

// onbootFixture is node-a with one onboot VM "ob", stopped by its operator,
// and the boot ID onboot last ran under (recorded; "" for no record). The
// kernel reports boot.
func onbootFixture(t *testing.T, recorded, boot string) (*corrosion.Client, *libvirtfake.Fake, *Reconciler, string) {
	t.Helper()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	onbootVM(t, db, fake, "ob", `{"name":"ob","onboot":true}`)
	dataDir := t.TempDir()
	if recorded != "" {
		writeRecord(t, dataDir, recorded)
	}
	return db, fake, restartedReconciler(db, fake, dataDir, boot), dataDir
}

// restartedReconciler is a fresh daemon's reconciler on dataDir: a daemon
// (re)start, in the boot the kernel reports as boot.
func restartedReconciler(db *corrosion.Client, fake *libvirtfake.Fake, dataDir, boot string) *Reconciler {
	r := NewReconciler("node-a", dataDir, db, fake)
	r.bootID = func() (string, error) { return boot, nil }
	return r
}

// record reads the onboot record: its boot ID and owed VM names ("" and nil
// for no record).
func record(t *testing.T, dataDir string) (string, []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, onbootBootFile))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var rec onbootRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("record %q: %v", b, err)
	}
	var owed []string
	for _, s := range rec.Owed {
		owed = append(owed, s.VM)
	}
	sort.Strings(owed)
	return rec.BootID, owed
}

func requireRecord(t *testing.T, dataDir, boot string, owed ...string) {
	t.Helper()
	gotBoot, gotOwed := record(t, dataDir)
	if gotBoot != boot || len(gotOwed) != len(owed) {
		t.Fatalf("record = %q owing %v, want %q owing %v", gotBoot, gotOwed, boot, owed)
	}
	for i := range owed {
		if gotOwed[i] != owed[i] {
			t.Fatalf("record = %q owing %v, want %q owing %v", gotBoot, gotOwed, boot, owed)
		}
	}
}

func starts(fake *libvirtfake.Fake, name string) int {
	n := 0
	for _, e := range fake.EventLog() {
		if e.Domain == name && e.Op == "start" {
			n++
		}
	}
	return n
}

// stopByOperator is `lv stop` of a running VM: the domain shut off and the
// row stopped/operator-stop.
func stopByOperator(t *testing.T, db *corrosion.Client, fake *libvirtfake.Fake, name string) {
	t.Helper()
	fake.SetState(name, libvirtfake.StateShutdown)
	if err := corrosion.UpdateVMState(context.Background(), db, name, "stopped", operatorStopDetail); err != nil {
		t.Fatal(err)
	}
}

// Lab 2 F-4. onboot starts a VM when its host boots, including one its
// operator stopped before the reboot (docs/compose.md: started "when their
// host boots"). The boot-time attempt always meets the split-brain gate's
// warm-up refusal, and the retry then dropped the VM as "operator intent
// changed" — an intent that had not changed since the boot decided to start
// it. The VM never started.
//
// Now the retry keeps a VM the host boot starts despite its operator stop,
// for as long as that stop is the one the boot saw, and starts it once the
// gate opens. The boot is recorded at once, owing the VM until it starts.
//
// Mutation "the retry drops every operator stop" (the old rule): red.
// Mutation "a host boot does not override an operator stop": red.
func TestOnboot_AHostBootStartsAVMItsOperatorStopped(t *testing.T) {
	db, fake, r, dataDir := onbootFixture(t, bootBefore, bootNow)
	ctx := context.Background()
	gate := &mutableGate{active: true, execOK: false} // warm-up: the gate refuses
	r.SetGate(gate)

	r.StartOnbootVMs(ctx)
	if hwStarted(fake, "ob") {
		t.Fatal("ob started while the gate refused")
	}
	requireRecord(t, dataDir, bootNow, "ob")
	// Passes while the gate still refuses keep it owed.
	r.reconcile(ctx)
	r.onbootMu.Lock()
	_, owed := r.onbootPending["ob"]
	r.onbootMu.Unlock()
	if !owed {
		t.Fatal("the onboot retry dropped ob, which the host boot owes a start, while the gate refused")
	}

	gate.setExecOK(true)
	r.reconcile(ctx)
	if !hwStarted(fake, "ob") {
		t.Fatal("ob, onboot and stopped by its operator before the host booted, did not start at boot")
	}
	requireState(t, db, "ob", "running")
	requireRecord(t, dataDir, bootNow)
}

// A plain daemon restart (the same boot, nothing owed) is a no-op for an
// onboot VM its operator stopped (docs/compose.md: "a plain daemon restart
// is a no-op"), with or without the gate. With no record of an earlier boot
// (the first start of this build), or a record that cannot be trusted
// (review M-3: empty, garbage, a boot ID of the wrong form), it is not taken
// for a host boot either, and this boot is recorded.
//
// Mutation "every start is a host boot": red. Mutation "a corrupt record
// is a host boot": red.
func TestOnboot_ADaemonRestartLeavesAnOperatorStoppedVMStopped(t *testing.T) {
	for _, tc := range []struct {
		name string
		// raw, when set, is written as the record verbatim.
		raw      string
		recorded string
		gate     *mutableGate // nil: no gate (a cluster with the gate not enforced)
	}{
		{name: "same boot, gate refuses then opens", recorded: bootNow, gate: &mutableGate{active: true}},
		{name: "same boot, no gate", recorded: bootNow},
		{name: "no record of a boot, gate refuses then opens", gate: &mutableGate{active: true}},
		{name: "no record of a boot, no gate"},
		{name: "empty record", raw: "\n"},
		{name: "garbage record", raw: "not a record"},
		{name: "a boot ID of the wrong form", raw: `{"boot_id":"boot-before"}`},
		{name: "the old plain form", raw: bootBefore + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, fake, r, dataDir := onbootFixture(t, tc.recorded, bootNow)
			ctx := context.Background()
			if tc.raw != "" {
				if err := os.WriteFile(filepath.Join(dataDir, onbootBootFile), []byte(tc.raw), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.gate != nil {
				r.SetGate(tc.gate)
			}
			r.StartOnbootVMs(ctx)
			if tc.gate != nil {
				tc.gate.setExecOK(true)
			}
			r.reconcile(ctx)
			if hwStarted(fake, "ob") {
				t.Fatal("a daemon restart started an onboot VM its operator stopped")
			}
			vm := requireState(t, db, "ob", "stopped")
			if vm.StateDetail != operatorStopDetail {
				t.Fatalf("state detail %q, want the operator stop kept", vm.StateDetail)
			}
			requireRecord(t, dataDir, bootNow)
		})
	}
}

// The host boot overrides the operator stop it found, not a cleared onboot:
// while the start waits for the gate, a VM whose onboot is turned off is
// dropped, and no longer owed.
//
// Mutation "the override ignores the onboot flag": red.
func TestOnboot_AHostBootStillHonoursOnbootTurnedOffWhileItWaits(t *testing.T) {
	db, fake, r, dataDir := onbootFixture(t, bootBefore, bootNow)
	ctx := context.Background()
	gate := &mutableGate{active: true}
	r.SetGate(gate)
	r.StartOnbootVMs(ctx)
	if err := db.Execute(ctx, `UPDATE vms SET spec='{"name":"ob","onboot":false}', updated_at=? WHERE name='ob'`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	gate.setExecOK(true)
	r.reconcile(ctx)
	if hwStarted(fake, "ob") {
		t.Fatal("ob started after its onboot was turned off")
	}
	requireRecord(t, dataDir, bootNow)
}

// A VM a host boot starts despite its operator stop, whose stop is replaced
// by a different one (here a drain's) while the start waits for the gate,
// is dropped: the boot overrides only the stop it found.
//
// Mutation "the override ignores a stop recorded since": red.
func TestOnboot_AHostBootDoesNotOverrideAStopRecordedSince(t *testing.T) {
	db, fake, r, _ := onbootFixture(t, bootBefore, bootNow)
	ctx := context.Background()
	gate := &mutableGate{active: true}
	r.SetGate(gate)
	r.StartOnbootVMs(ctx)
	if err := db.Execute(ctx, `UPDATE vms SET state_detail=?, updated_at=? WHERE name='ob'`,
		DrainStopDetail("op-1"), db.NowTS()); err != nil {
		t.Fatal(err)
	}
	gate.setExecOK(true)
	r.reconcile(ctx)
	if hwStarted(fake, "ob") {
		t.Fatal("ob started over a stop recorded after the host boot")
	}
}

// Once the row no longer carries the operator stop the boot overrode — here
// a start that failed into error, written by no step this process watched —
// the override ends and the VM is no longer owed a boot override, though it
// stays owed its onboot start as any onboot VM is.
//
// Mutation "the override ends only when the VM runs or is dropped": red.
func TestOnboot_TheOverrideEndsOnceTheOverriddenStopIsGone(t *testing.T) {
	db, _, r, dataDir := onbootFixture(t, bootBefore, bootNow)
	ctx := context.Background()
	r.SetGate(&mutableGate{active: true})
	r.StartOnbootVMs(ctx)
	if err := corrosion.UpdateVMState(ctx, db, "ob", "error", "define: boom"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	requireRecord(t, dataDir, bootNow)
	r.onbootMu.Lock()
	_, owed := r.onbootPending["ob"]
	r.onbootMu.Unlock()
	if !owed {
		t.Fatal("ob is no longer owed its onboot start")
	}
}

// Review I-1. Two VMs a host boot owes: ob1 starts, then its operator stops
// it; ob2's start is still held (its lock is another holder's). A daemon
// restart in the same boot must start neither ob1 — a stop made after the
// boot — nor forget ob2, which the boot still owes; ob2 starts once it can.
//
// Mutation "a restart in the same boot overrides every operator stop" (no
// owed set): red on ob1. Mutation "an override that ends is not taken out of
// the record": red on ob1.
func TestOnboot_ARestartInTheSameBootOverridesOnlyWhatTheBootStillOwes(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	onbootVM(t, db, fake, "ob1", `{"name":"ob1","onboot":true}`)
	onbootVM(t, db, fake, "ob2", `{"name":"ob2","onboot":true}`)
	dataDir := t.TempDir()
	writeRecord(t, dataDir, bootBefore)
	held := func(held bool) {
		t.Helper()
		if held {
			if !acquireVMLockFor(ctx, db, "node-b", "ob2", time.Now()) {
				t.Fatal("could not hold ob2's lock")
			}
			return
		}
		releaseVMLockFor(ctx, db, "node-b", "ob2")
	}
	held(true)

	r := restartedReconciler(db, fake, dataDir, bootNow)
	r.SetGate(&mutableGate{active: true, execOK: true})
	r.StartOnbootVMs(ctx)
	if starts(fake, "ob1") != 1 || starts(fake, "ob2") != 0 {
		t.Fatalf("after the host boot: ob1 started %d times, ob2 %d; want 1 and 0", starts(fake, "ob1"), starts(fake, "ob2"))
	}
	requireRecord(t, dataDir, bootNow, "ob2")
	stopByOperator(t, db, fake, "ob1")

	// The daemon restarts in the same boot.
	r2 := restartedReconciler(db, fake, dataDir, bootNow)
	r2.SetGate(&mutableGate{active: true, execOK: true})
	r2.StartOnbootVMs(ctx)
	r2.reconcile(ctx)
	if n := starts(fake, "ob1"); n != 1 {
		t.Fatalf("a daemon restart in the same boot started ob1 again (%d starts) over its operator's stop made after the boot", n)
	}
	requireRecord(t, dataDir, bootNow, "ob2")

	held(false)
	r2.reconcile(ctx)
	if starts(fake, "ob2") != 1 {
		t.Fatal("ob2, owed its boot start, was not started after the restart")
	}
	requireRecord(t, dataDir, bootNow)
}

// Review I-2. Every VM a host boot owes is recorded before the first start
// is tried and before any start-delay wait: the reconcile loop runs beside
// StartOnbootVMs, and the first VM's start completing while the second is
// not yet reached must not leave the record owing nothing. A daemon restart
// at that moment still starts the second.
//
// Mutation "overrides are registered as the start loop reaches each VM":
// red.
func TestOnboot_EveryVMTheBootOwesIsRecordedBeforeAnyStart(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	onbootVM(t, db, fake, "ob1", `{"name":"ob1","onboot":true,"startup_order":1,"start_delay_sec":3}`)
	onbootVM(t, db, fake, "ob2", `{"name":"ob2","onboot":true,"startup_order":2}`)
	dataDir := t.TempDir()
	writeRecord(t, dataDir, bootBefore)

	r := restartedReconciler(db, fake, dataDir, bootNow)
	r.SetGate(&mutableGate{active: true}) // warm-up
	bctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); r.StartOnbootVMs(bctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// In ob1's start-delay: the reconcile retry starts ob1.
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.onbootMu.Lock()
		_, reached := r.onbootPending["ob1"]
		r.onbootMu.Unlock()
		if reached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("StartOnbootVMs never reached ob1")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.clearOnbootPending("ob1")
	requireRecord(t, dataDir, bootNow, "ob2")

	// The daemon restarts now, before ob2 was reached.
	cancel()
	<-done
	r2 := restartedReconciler(db, fake, dataDir, bootNow)
	r2.StartOnbootVMs(ctx)
	if starts(fake, "ob2") != 1 {
		t.Fatal("ob2, owed its boot start, was left stopped by a daemon restart in the same boot")
	}
}

// Review M-1. Once the boot's start of a VM is past every gate (the row is
// written "starting"), the override is over: a stop the operator makes from
// then on is honoured even though it reads exactly like the stop the boot
// overrode — here the start was deferred on a disk that did not answer,
// and the operator stopped the VM before the next pass.
//
// Mutation "the override ends only when the retry next reads the row": red.
func TestOnboot_AStopAfterTheStartPassedTheGateIsHonoured(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	disk := filepath.Join(t.TempDir(), "ob-root.qcow2")
	if err := os.WriteFile(disk, []byte("the disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "ob", HostName: "node-a", State: "stopped", StateDetail: operatorStopDetail, Spec: `{"name":"ob","onboot":true}`,
	}, nil, []corrosion.DiskRecord{{VMName: "ob", DiskName: "root", HostName: "node-a", Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	writeRecord(t, dataDir, bootBefore)
	r := restartedReconciler(db, fake, dataDir, bootNow)
	s := stallStorage(t, disk)
	s.wire(r)

	r.StartOnbootVMs(ctx)
	requireState(t, db, "ob", "starting")
	requireRecord(t, dataDir, bootNow)
	stopByOperator(t, db, fake, "ob")

	s.answer()
	s.answered(t, disk)
	r.reconcile(ctx)
	if hwStarted(fake, "ob") {
		t.Fatal("ob was started over a stop its operator made after the boot's start passed the gate")
	}
}

// Review round 1, m-1. A record that could not be written must fail SAFE, as
// every other record that cannot be trusted does: here the host boot's
// up-front write fails, ob1 starts anyway, and its operator stops it. A
// daemon restart in the same boot must not read the previous boot's record
// (a host boot) and start ob1 over that stop: the record is removed, so the
// restart reads "no record" and honours the stop.
//
// Mutation "a failed write leaves the old record": red.
func TestOnboot_ARecordThatCannotBeWrittenFailsSafe(t *testing.T) {
	db, fake, r, dataDir := onbootFixture(t, bootBefore, bootNow)
	ctx := context.Background()
	r.writeRecord = func(string, onbootRecord) error { return os.ErrPermission }
	r.StartOnbootVMs(ctx)
	if !hwStarted(fake, "ob") {
		t.Fatal("the host boot did not start ob (a failed record write must not cost the boot's start)")
	}
	if boot, _ := record(t, dataDir); boot != "" {
		t.Fatalf("a record that could not be rewritten was left in place, naming %q", boot)
	}
	stopByOperator(t, db, fake, "ob")

	r2 := restartedReconciler(db, fake, dataDir, bootNow)
	r2.StartOnbootVMs(ctx)
	r2.reconcile(ctx)
	if n := starts(fake, "ob"); n != 1 {
		t.Fatalf("a daemon restart after a failed record write started ob again (%d starts) over its operator's stop", n)
	}
}

// Review round 1, m-2. The override ends at the start's "starting" write
// only when that write lands: a failed one leaves the row at the operator
// stop the boot overrides, and ending the override then made the next retry
// drop the VM as "operator intent changed" — the F-4 symptom. Here every
// "starting" write fails while the disk does not answer; once both clear,
// the boot's start is made.
//
// Mutation "the override ends whatever the write did": red.
func TestOnboot_AFailedStartingWriteKeepsTheOverride(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	disk := filepath.Join(t.TempDir(), "ob-root.qcow2")
	if err := os.WriteFile(disk, []byte("the disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "ob", HostName: "node-a", State: "stopped", StateDetail: operatorStopDetail, Spec: `{"name":"ob","onboot":true}`,
	}, nil, []corrosion.DiskRecord{{VMName: "ob", DiskName: "root", HostName: "node-a", Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `CREATE TRIGGER inject_starting_fail BEFORE UPDATE OF state ON vms
		WHEN NEW.name = 'ob' AND NEW.state = 'starting' BEGIN SELECT RAISE(ABORT, 'inject'); END;`); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	writeRecord(t, dataDir, bootBefore)
	r := restartedReconciler(db, fake, dataDir, bootNow)
	s := stallStorage(t, disk)
	s.wire(r)

	r.StartOnbootVMs(ctx)
	vm := requireState(t, db, "ob", "stopped")
	if vm.StateDetail != operatorStopDetail {
		t.Fatalf("state detail %q, want the stop the failed writes left", vm.StateDetail)
	}
	requireRecord(t, dataDir, bootNow, "ob")

	if err := db.Execute(ctx, `DROP TRIGGER inject_starting_fail`); err != nil {
		t.Fatal(err)
	}
	s.answer()
	s.answered(t, disk)
	r.reconcile(ctx)
	if !hwStarted(fake, "ob") {
		t.Fatal("the boot's start of ob was dropped after its \"starting\" write failed")
	}
}

// Review round 1, m-4. A daemon that died between writing the record's
// temp file and renaming it leaves the temp file behind; the next start
// removes it, and nothing else in the data dir.
//
// Mutation "no sweep": red.
func TestOnboot_LeftoverTempRecordsAreSwept(t *testing.T) {
	_, _, r, dataDir := onbootFixture(t, bootNow, bootNow)
	leftover := filepath.Join(dataDir, onbootBootFile+".tmp-123456")
	other := filepath.Join(dataDir, "onboot-boot-id-not-ours")
	for _, p := range []string{leftover, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.StartOnbootVMs(context.Background())
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the leftover temp record %s is still there (err %v)", leftover, err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the sweep removed a file that is not a temp record: %v", err)
	}
	requireRecord(t, dataDir, bootNow)
}

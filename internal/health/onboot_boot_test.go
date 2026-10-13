package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// onbootFixture is node-a with one onboot VM "ob", stopped by its operator
// (its domain defined and shut off, as `lv stop` leaves it), and the boot ID
// onboot last ran under (recorded; "" for none). The kernel reports boot.
func onbootFixture(t *testing.T, recorded, boot string) (*corrosion.Client, *libvirtfake.Fake, *Reconciler, string) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "ob", HostName: "node-a", State: "stopped", StateDetail: operatorStopDetail,
		Spec: `{"name":"ob","onboot":true}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain><name>ob</name></domain>`); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if recorded != "" {
		if err := os.WriteFile(filepath.Join(dataDir, onbootBootFile), []byte(recorded+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("node-a", dataDir, db, fake)
	r.bootID = func() (string, error) { return boot, nil }
	return db, fake, r, dataDir
}

func recordedBoot(t *testing.T, dataDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, onbootBootFile))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// Lab 2 F-4. onboot starts a VM when its host boots, including one its
// operator stopped before the reboot (docs/compose.md: started "when their
// host boots"; StartOnbootVMs: "deliberately-stopped VMs are only
// (re)started when the host actually boots"). The boot-time attempt always
// meets the split-brain gate's warm-up refusal, and the retry then dropped
// the VM as "operator intent changed" — an intent that had not changed since
// the boot decided to start it. The VM never started.
//
// Now the retry keeps a VM the host boot starts despite its operator stop,
// for as long as that stop is the one the boot saw, and starts it once the
// gate opens. The boot is recorded only then.
//
// Mutation "the retry drops every operator stop" (the old rule): red.
// Mutation "a host boot does not override an operator stop": red.
func TestOnboot_AHostBootStartsAVMItsOperatorStopped(t *testing.T) {
	db, fake, r, dataDir := onbootFixture(t, "boot-before", "boot-now")
	ctx := context.Background()
	gate := &mutableGate{active: true, execOK: false} // warm-up: the gate refuses
	r.SetGate(gate)

	r.StartOnbootVMs(ctx)
	if hwStarted(fake, "ob") {
		t.Fatal("ob started while the gate refused")
	}
	if got := recordedBoot(t, dataDir); got != "boot-before" {
		t.Fatalf("the boot was recorded (%q) while its onboot start is still owed", got)
	}
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
	if got := recordedBoot(t, dataDir); got != "boot-now" {
		t.Fatalf("recorded boot %q once the start was made, want boot-now", got)
	}
}

// A plain daemon restart (the same boot) is a no-op for an onboot VM its
// operator stopped (docs/compose.md: "a plain daemon restart is a no-op"),
// whether or not the gate lets the boot-time attempt through. With no record
// of an earlier boot (the first start of this build) it is not taken for a
// host boot either, and the boot is recorded so the next one is recognised.
//
// Mutation "every start is a host boot": red.
func TestOnboot_ADaemonRestartLeavesAnOperatorStoppedVMStopped(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorded string
		gate     *mutableGate // nil: no gate (a cluster with the gate not enforced)
	}{
		{"same boot, gate refuses then opens", "boot-now", &mutableGate{active: true}},
		{"same boot, no gate", "boot-now", nil},
		{"no record of a boot, gate refuses then opens", "", &mutableGate{active: true}},
		{"no record of a boot, no gate", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, fake, r, dataDir := onbootFixture(t, tc.recorded, "boot-now")
			ctx := context.Background()
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
			if got := recordedBoot(t, dataDir); got != "boot-now" {
				t.Fatalf("recorded boot %q, want boot-now", got)
			}
		})
	}
}

// The host boot overrides the operator stop it found, not one made after it,
// and not a cleared onboot: while the start waits for the gate, a VM whose
// onboot is turned off is dropped, and the boot is recorded once nothing is
// owed.
//
// Mutation "the override ignores the onboot flag": red.
func TestOnboot_AHostBootStillHonoursOnbootTurnedOffWhileItWaits(t *testing.T) {
	db, fake, r, dataDir := onbootFixture(t, "boot-before", "boot-now")
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
	if got := recordedBoot(t, dataDir); got != "boot-now" {
		t.Fatalf("recorded boot %q once nothing was owed, want boot-now", got)
	}
}

// A VM a host boot starts despite its operator stop, whose operator stops it
// AGAIN (a different stop: here a drain's) while the start waits for the
// gate, is dropped: the boot overrides only the stop it found.
//
// Mutation "the override ignores a stop recorded since": red.
func TestOnboot_AHostBootDoesNotOverrideAStopRecordedSince(t *testing.T) {
	db, fake, r, _ := onbootFixture(t, "boot-before", "boot-now")
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

// Once the boot's start of such a VM has got past the gate — its row no
// longer carries the operator stop, here because the start failed into
// error — the stop it overrode is gone, and the boot is recorded even though
// the VM is still owed its start. A daemon restart later in this boot then
// overrides no stop its operator makes from now on.
//
// Mutation "the override ends only when the VM runs or is dropped": red.
func TestOnboot_TheBootIsRecordedOnceTheOverriddenStopIsGone(t *testing.T) {
	db, _, r, dataDir := onbootFixture(t, "boot-before", "boot-now")
	ctx := context.Background()
	r.SetGate(&mutableGate{active: true})
	r.StartOnbootVMs(ctx)
	if err := corrosion.UpdateVMState(ctx, db, "ob", "error", "define: boom"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	if got := recordedBoot(t, dataDir); got != "boot-now" {
		t.Fatalf("recorded boot %q after the overridden stop was gone, want boot-now", got)
	}
	r.onbootMu.Lock()
	_, owed := r.onbootPending["ob"]
	r.onbootMu.Unlock()
	if !owed {
		t.Fatal("ob is no longer owed its onboot start")
	}
}

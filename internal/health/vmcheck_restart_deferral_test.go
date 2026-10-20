package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A restart-policy pass skipped because another operation holds the VM's
// lock (a backup, a snapshot, a replication) uses no restart attempt: it is
// a deferral, and the VM restarts on the first pass after the lock frees,
// with the attempt counted then — once, before the destroy, so a restart is
// never doubled. Before, each skipped pass counted, and a VM that crashed
// under a long backup had its policy exhausted by the time the lock freed.
//
// Mutation: the attempt counted before the lock is tried — three held passes
// use three attempts, red.
func TestMaybeRestartVM_APassSkippedForAHeldLockUsesNoAttempt(t *testing.T) {
	db := testStartDB(t)
	seedRestartPolicyVM(t, db, "web", "node1")
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain type='kvm'><name>web</name><uuid>44444444-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	v.SetBackend(fake)
	held := true
	v.SetVMLocker(func(string) (func(), bool) {
		if held {
			return nil, false
		}
		return func() {}, true
	})
	row := func() corrosion.VMRecord {
		r, err := corrosion.GetVM(context.Background(), db, "web")
		if err != nil || r == nil {
			t.Fatalf("GetVM: %+v %v", r, err)
		}
		return *r
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		v.maybeRestartVM(context.Background(), row(), now)
	}
	if got := restartAttempts(t, db, "web"); got != 0 {
		t.Fatalf("restart attempts after three passes skipped for a held lock = %d; want 0", got)
	}
	if st, _ := fake.RawState("web"); st == libvirtfake.StateRunning {
		t.Fatal("web was started while its lock was held")
	}
	held = false
	v.maybeRestartVM(context.Background(), row(), now)
	if st, _ := fake.RawState("web"); st != libvirtfake.StateRunning {
		t.Fatalf("web = %v once the lock freed; want it restarted at once", st)
	}
	if got := restartAttempts(t, db, "web"); got != 1 {
		t.Fatalf("restart attempts after the restart = %d; want exactly 1", got)
	}
}

package hostboot

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func hostIn(t *testing.T, state string) (*corrosion.Client, context.Context) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	if state != "active" {
		if err := corrosion.UpdateHostState(ctx, db, "h", state); err != nil {
			t.Fatal(err)
		}
	}
	return db, ctx
}

func stateOf(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v %+v", err, h)
	}
	return h.State
}

// A graceful stop of an active host records it 'upgrading' and leaves the
// marker; the boot keeps it 'upgrading' until it serves, and consumes the
// marker, so a daemon that dies before serving boots 'active' next time and
// cannot keep re-arming the coordinator's upgrading timeout.
//
// Mutation: leave the marker in place (takeMarker without os.Remove) — the
// second boot is 'upgrading' again.
func TestSIGTERMRestartBootsUpgradingOnce(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
		t.Fatal(err)
	}
	if got := stateOf(t, db); got != "upgrading" {
		t.Fatalf("after SIGTERM the host is %q, want upgrading", got)
	}
	b := BootState(ctx, db, "h", dir, false, now.Add(20*time.Second))
	if b.State != "upgrading" || !b.AwaitServing {
		t.Fatalf("boot after SIGTERM = %+v, want upgrading until serving", b)
	}
	if _, err := os.Stat(MarkerPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the boot left the marker in place: %v", err)
	}
	// The daemon died before serving; systemd starts it again.
	if b := BootState(ctx, db, "h", dir, false, now.Add(40*time.Second)); b.State != "active" || b.AwaitServing {
		t.Fatalf("second boot without a graceful stop = %+v, want active", b)
	}
}

// No graceful stop (a crash, a power cut): the boot is 'active' as before.
// A post-upgrade boot is 'upgrading', confirmed by the upgrade watchdog.
func TestBootWithoutMarker(t *testing.T) {
	db, ctx := hostIn(t, "active")
	if b := BootState(ctx, db, "h", t.TempDir(), false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot without a marker = %+v, want active", b)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), true, time.Now()); b.State != "upgrading" || b.AwaitServing {
		t.Fatalf("post-upgrade boot = %+v, want upgrading, confirmed by the upgrade watchdog", b)
	}
	if b := BootState(ctx, db, "h", "", false, time.Now()); b.State != "active" {
		t.Fatalf("boot with no data dir = %+v, want active", b)
	}
}

// A graceful stop older than the upgrading timeout boots 'active': the
// coordinator may have fenced the host while it was down, and this node's
// replica may not know yet. So does one whose record moved on while it was
// down.
//
// Mutations: drop the age check — the stale stop boots 'upgrading'; drop the
// state check — the fenced host boots 'upgrading'.
func TestBootAfterAStaleOrSupersededStop(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(UpgradingTimeout)); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot %s after the stop = %+v, want active", UpgradingTimeout, b)
	}

	for _, moved := range []string{"fenced", "offline", "maintenance"} {
		if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
			t.Fatal(err)
		}
		if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(MarkerPath(dir)); err != nil {
			t.Fatalf("fixture: no marker before the %s case: %v", moved, err)
		}
		if err := corrosion.UpdateHostState(ctx, db, "h", moved); err != nil {
			t.Fatal(err)
		}
		if b := BootState(ctx, db, "h", dir, false, now.Add(10*time.Second)); b.State != "active" || b.AwaitServing {
			t.Fatalf("boot of a host recorded %s while down = %+v, want the old boot (active)", moved, b)
		}
	}
}

// A graceful stop leaves the marker only for an active host. Fenced, offline
// and maintenance hosts keep their state; a draining host is marked
// 'upgrading' as before, so its restart is not fenced, but boots as before.
//
// Mutation: mark whatever the state — the maintenance host is 'upgrading'.
func TestMarkRestartingKeepsANonActiveState(t *testing.T) {
	for st, want := range map[string]string{"fenced": "fenced", "offline": "offline", "maintenance": "maintenance", "draining": "upgrading"} {
		t.Run(st, func(t *testing.T) {
			db, ctx := hostIn(t, st)
			dir := t.TempDir()
			if err := MarkRestarting(ctx, db, "h", dir, time.Now()); err != nil {
				t.Fatal(err)
			}
			if got := stateOf(t, db); got != want {
				t.Fatalf("SIGTERM moved a %s host to %q, want %q", st, got, want)
			}
			if _, err := os.Stat(MarkerPath(dir)); !os.IsNotExist(err) {
				t.Fatalf("SIGTERM of a %s host left a marker: %v", st, err)
			}
		})
	}
}

// Serving moves the host from 'upgrading' to 'active' and from nothing else,
// and keeps an isolation recorded while it was down.
//
// Mutation: write 'active' whatever the state — the fenced and maintenance
// hosts turn active.
func TestConfirmServing(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	if err := corrosion.IsolateHost(ctx, db, "observer", "h", "manual"); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	epoch, reason, err := corrosion.HostIsolation(ctx, db, "h")
	if err != nil || epoch == 0 {
		t.Fatalf("fixture: isolation epoch=%d err=%v", epoch, err)
	}
	flipped, state, err := ConfirmServing(ctx, db, "h")
	if err != nil || !flipped || state != "active" || stateOf(t, db) != "active" {
		t.Fatalf("confirm of an upgrading host: flipped=%v state=%q err=%v record=%q", flipped, state, err, stateOf(t, db))
	}
	if e2, r2, err := corrosion.HostIsolation(ctx, db, "h"); err != nil || e2 != epoch || r2 != reason {
		t.Fatalf("confirm changed the isolation: %d %q -> %d %q (%v)", epoch, reason, e2, r2, err)
	}

	for _, st := range []string{"fenced", "maintenance", "offline"} {
		db, ctx := hostIn(t, st)
		flipped, got, err := ConfirmServing(ctx, db, "h")
		if !errors.Is(err, ErrNotUpgrading) || flipped || got != st || stateOf(t, db) != st {
			t.Fatalf("confirm of a %s host: flipped=%v state=%q err=%v record=%q", st, flipped, got, err, stateOf(t, db))
		}
	}
}

package hostboot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// No graceful stop (a crash, a kill, a stop that could not be recorded): the
// boot of a host recorded active is 'upgrading' until this daemon serves, as
// after a graceful stop. Recorded 'active', it would be an active host that
// answers nothing for as long as startup takes, and its peers fence it once
// that passes their failure threshold (lab 1, 2026-10-14: ssh power-off 19 s
// after the boot, about 4 s before it would have served).
//
// The boot notes that it awaits serving (AwaitingPath); the next boot, if this
// daemon never served (Served), is 'active', so a daemon that crash-loops
// before serving cannot keep re-arming the coordinator's upgrading timeout.
//
// Mutations: return 'active' for a boot without the marker (the boot before
// this change) — the first boot is 'active'; drop the AwaitingPath check — the
// second boot is 'upgrading' again; drop the write of AwaitingPath — likewise;
// leave Served a no-op — the boot after a served one is 'active'.
func TestUncleanBootAwaitsServingOnce(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	b := BootState(ctx, db, "h", dir, false, now)
	if b.State != "upgrading" || !b.AwaitServing {
		t.Fatalf("boot of an active host without a graceful stop = %+v, want upgrading until serving", b)
	}
	if _, err := os.Stat(AwaitingPath(dir)); err != nil {
		t.Fatalf("the boot did not note that it awaits serving: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, db, "h", b.State); err != nil {
		t.Fatal(err)
	}
	// The daemon dies before serving; systemd starts it again.
	if b := BootState(ctx, db, "h", dir, false, now.Add(5*time.Second)); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot after a daemon that never served = %+v, want active", b)
	}
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	// That one serves; a later crash awaits serving again.
	Served(dir)
	if _, err := os.Stat(AwaitingPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("Served left the note in place: %v", err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(time.Minute)); b.State != "upgrading" || !b.AwaitServing {
		t.Fatalf("unclean boot after a daemon that served = %+v, want upgrading until serving", b)
	}
}

// A boot without the marker of a host recorded 'upgrading' — a graceful stop
// whose next boot never wrote (a WAL-quarantined one), or a draining host's
// SIGTERM — keeps it 'upgrading' while that state is younger than the
// coordinator's timeout, and is 'active' once it is older: the coordinator may
// be fencing it already. Any other state boots 'active' as before, and so does
// a boot with no data dir, which could not bound a crash loop.
//
// Mutations: drop the age check — the stale 'upgrading' boots 'upgrading';
// accept any state — the fenced, offline, maintenance, draining and joining
// hosts boot 'upgrading'.
func TestUncleanBootByRecordedState(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	since, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("fixture: HostStateSince ok=%v err=%v", ok, err)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(UpgradingTimeout/2)); b.State != "upgrading" || !b.AwaitServing {
		t.Fatalf("unclean boot of a host 'upgrading' for %s = %+v, want upgrading until serving", UpgradingTimeout/2, b)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(UpgradingTimeout+time.Second)); b.State != "active" || b.AwaitServing {
		t.Fatalf("unclean boot of a host 'upgrading' past the timeout = %+v, want active", b)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(-time.Minute)); b.State != "active" || b.AwaitServing {
		t.Fatalf("unclean boot dated before the 'upgrading' write = %+v, want active", b)
	}
	for _, st := range []string{"fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining} {
		db, ctx := hostIn(t, st)
		dir := t.TempDir()
		if b := BootState(ctx, db, "h", dir, false, time.Now()); b.State != "active" || b.AwaitServing {
			t.Fatalf("unclean boot of a host recorded %s = %+v, want active", st, b)
		}
		if _, err := os.Stat(AwaitingPath(dir)); !os.IsNotExist(err) {
			t.Fatalf("an active boot of a %s host noted that it awaits serving: %v", st, err)
		}
	}
	db, ctx = hostIn(t, "active")
	if b := BootState(ctx, db, "h", "", false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot with no data dir = %+v, want active", b)
	}
	if b := BootState(ctx, db, "nobody", t.TempDir(), false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot of a host with no record = %+v, want active", b)
	}
	// A post-upgrade boot is 'upgrading', confirmed by the upgrade watchdog.
	if b := BootState(ctx, db, "h", t.TempDir(), true, time.Now()); b.State != "upgrading" || b.AwaitServing {
		t.Fatalf("post-upgrade boot = %+v, want upgrading, confirmed by the upgrade watchdog", b)
	}
}

// A boot whose note cannot be written could not bound a crash loop, so it is
// 'active' as before.
//
// Mutation: ignore the write error — the boot is 'upgrading'.
func TestUncleanBootThatCannotNoteIsActive(t *testing.T) {
	db, ctx := hostIn(t, "active")
	// A data dir that is not there: no note to find, and none can be
	// written.
	dir := filepath.Join(t.TempDir(), "missing")
	if b := BootState(ctx, db, "h", dir, false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot that cannot note it awaits serving = %+v, want active", b)
	}
}

// A graceful stop older than the upgrading timeout boots 'active': the
// coordinator may have fenced the host while it was down, and this node's
// replica may not know yet. So does one whose record moved on while it was
// down.
//
// Mutations: drop the age check — the stale stop boots 'upgrading'; drop the
// negative-age arm — the stop dated after the boot boots 'upgrading'; drop the
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
	// The clock went back across the restart: the stop is dated in the
	// future, and its age says nothing.
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(-time.Second)); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot dated a second before the stop = %+v, want active", b)
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

// A daemon that serves briefly and crashes again clears the awaiting note
// each time; after FlapLimit unclean boots within FlapWindow the next one is
// 'active', so a flapping daemon is fenced on its failure count as before.
// Boots outside the window do not count.
//
// Mutation: drop the FlapLimit check — the fourth boot is 'upgrading'.
func TestUncleanBootsThatFlapBootActive(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < FlapLimit; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		if b := BootState(ctx, db, "h", dir, false, at); b.State != "upgrading" || !b.AwaitServing {
			t.Fatalf("unclean boot %d = %+v, want upgrading until serving", i+1, b)
		}
		Served(dir) // it serves, then crashes again
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute)); b.State != "active" || b.AwaitServing {
		t.Fatalf("unclean boot %d within %s = %+v, want active", FlapLimit+1, FlapWindow, b)
	}
	if _, err := os.Stat(AwaitingPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("an active boot noted that it awaits serving: %v", err)
	}
	// Quiet for longer than the window: the next crash awaits serving again.
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute+FlapWindow)); b.State != "upgrading" || !b.AwaitServing {
		t.Fatalf("unclean boot after a quiet %s = %+v, want upgrading until serving", FlapWindow, b)
	}
}

// A post-upgrade boot notes that it awaits serving like any other, so a crash
// of it before it serves boots 'active', not 'upgrading' with a fresh timeout.
//
// Mutation: drop writeAwaiting from the upgrade branch — the crash after it
// boots 'upgrading'.
func TestUpgradeBootNotesAwaitingServing(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	dir := t.TempDir()
	if b := BootState(ctx, db, "h", dir, true, time.Now()); b.State != "upgrading" || b.AwaitServing {
		t.Fatalf("post-upgrade boot = %+v, want upgrading, confirmed by the upgrade watchdog", b)
	}
	if b := BootState(ctx, db, "h", dir, false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("crash of a post-upgrade boot that never served = %+v, want active", b)
	}
}

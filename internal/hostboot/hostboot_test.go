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
// marker, so a daemon that dies before serving makes no boot write next time
// (Deferred): it cannot keep re-arming the coordinator's upgrading timeout,
// and it is not recorded 'active' before it serves.
//
// Mutation: leave the marker in place (takeMarker without os.Remove) — the
// second boot is a graceful one again, not deferred.
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
	if b := BootState(ctx, db, "h", dir, false, now.Add(40*time.Second)); b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("second boot without a graceful stop = %+v, want the recorded upgrading kept, no boot write", b)
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
// daemon never served (Served), makes no boot write (Deferred), so a daemon
// that crash-loops before serving cannot keep re-arming the coordinator's
// upgrading timeout, and is not recorded 'active' before it serves either.
//
// Mutations: return 'active' for a boot without the marker (the boot before
// this change) — the first boot is 'active'; drop the AwaitingPath check — the
// second boot is not deferred; drop the write of AwaitingPath — likewise;
// leave Served a no-op — the boot after a served one is deferred.
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
	if b := BootState(ctx, db, "h", dir, false, now.Add(5*time.Second)); b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("boot after a daemon that never served = %+v, want the recorded upgrading kept, no boot write", b)
	}
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	// That one serves; a later crash awaits serving again.
	Served(dir)
	if _, err := os.Stat(AwaitingPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("Served left the note in place: %v", err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(time.Minute)); b.State != "upgrading" || !b.AwaitServing || b.Deferred {
		t.Fatalf("unclean boot after a daemon that served = %+v, want upgrading until serving", b)
	}
}

// A boot without the marker of a host recorded 'upgrading' — a graceful stop
// whose next boot never wrote (a WAL-quarantined one), or a draining host's
// SIGTERM — keeps it 'upgrading' while that state is younger than the
// coordinator's timeout. Any other state boots 'active' as before, and so does
// a boot with no data dir, which could not bound a crash loop.
//
// A host recorded 'upgrading' for UpgradingTimeout or longer (or dated after
// this boot) is not recorded 'active' before it serves either: the boot
// writes a fresh 'upgrading' once, guarded on the state it read (From), so
// a fence, drain or offline recorded meanwhile is kept. With serving
// evidence that write is bounded by FlapLimit like any unclean boot's.
//
// Mutations: return 'active' for the stale 'upgrading' (the rule before) —
// the stale and back-dated cases fail; drop From — likewise; accept any
// state — the fenced, offline, maintenance, draining and joining hosts boot
// 'upgrading'.
func TestUncleanBootByRecordedState(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	since, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("fixture: HostStateSince ok=%v err=%v", ok, err)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(UpgradingTimeout/2)); b.State != "upgrading" || !b.AwaitServing || b.From != "upgrading" {
		t.Fatalf("unclean boot of a host 'upgrading' for %s = %+v, want upgrading until serving", UpgradingTimeout/2, b)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(UpgradingTimeout+time.Second)); b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "upgrading" {
		t.Fatalf("unclean boot of a host 'upgrading' past the timeout = %+v, want a fresh 'upgrading' written from upgrading", b)
	}
	if b := BootState(ctx, db, "h", t.TempDir(), false, since.Add(-time.Minute)); b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "upgrading" {
		t.Fatalf("unclean boot dated before the 'upgrading' write = %+v, want a fresh 'upgrading' written from upgrading", b)
	}
	db2, ctx2 := hostIn(t, "active")
	if b := BootState(ctx2, db2, "h", t.TempDir(), false, time.Now()); b.State != "upgrading" || !b.AwaitServing || b.From != "active" {
		t.Fatalf("unclean boot of an active host = %+v, want upgrading written from active", b)
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

// A graceful stop older than the upgrading timeout (or dated after the boot)
// of a host still recorded 'upgrading' writes a fresh 'upgrading' once,
// guarded on that state: a fence the coordinator records meanwhile is kept,
// and one this replica has not heard of yet is judged afresh from the write
// (failover's upgradingSinceHandled). A host whose record moved on to
// fenced, offline or maintenance while it was down boots 'active' as before.
// One still recorded 'active' (the SIGTERM's write did not land) is
// 'upgrading' until it serves.
//
// Mutations: return 'active' for the stale stop (the rule before) — the
// stale and back-dated stops fail; drop the state check — the fenced host
// boots 'upgrading'.
func TestBootAfterAStaleOrSupersededStop(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(UpgradingTimeout)); b.State != "upgrading" || !b.AwaitServing || b.From != "upgrading" {
		t.Fatalf("boot %s after the stop = %+v, want a fresh 'upgrading' written from upgrading", UpgradingTimeout, b)
	}
	// The clock went back across the restart: the stop is dated in the
	// future, and its age says nothing.
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	if err := MarkRestarting(ctx, db, "h", dir, now); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(-time.Second)); b.State != "upgrading" || !b.AwaitServing || b.From != "upgrading" {
		t.Fatalf("boot dated a second before the stop = %+v, want a fresh 'upgrading' written from upgrading", b)
	}
	// The marker was left, but the SIGTERM's 'upgrading' write did not land.
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(MarkerPath(dir), []byte(now.UTC().Format(time.RFC3339Nano)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(10*time.Second)); b.State != "upgrading" || !b.AwaitServing || b.From != "active" {
		t.Fatalf("boot after a stop whose 'upgrading' write did not land = %+v, want upgrading written from active", b)
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
// each time; after FlapLimit unclean boots within FlapWindow the next one
// makes no boot write (Deferred): it neither re-arms the 'upgrading' timeout
// nor records the host 'active' before it serves. A flapping host recorded
// 'active' is judged on its failure count as before; one recorded 'upgrading'
// keeps the timeout an earlier boot started. A host recorded as anything else
// (fenced, say) boots 'active' as before. Boots outside the window do not
// count.
//
// Mutations: drop the FlapLimit check — the fourth boot writes 'upgrading';
// return 'active' for it (the boot before this change) — not deferred; make
// the deferred boot write no note — the note check fails; take the flapping
// 'active' deferral before the never-served one — the I1 case is deferred.
func TestUncleanBootsThatFlapAreDeferred(t *testing.T) {
	db, ctx := hostIn(t, "active")
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < FlapLimit; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		if b := BootState(ctx, db, "h", dir, false, at); b.State != "upgrading" || !b.AwaitServing || b.Deferred {
			t.Fatalf("unclean boot %d = %+v, want upgrading until serving", i+1, b)
		}
		Served(dir) // it serves, then crashes again
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute)); b.State != "active" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("unclean boot %d within %s of a host recorded active = %+v, want active kept, no boot write", FlapLimit+1, FlapWindow, b)
	}
	if _, err := os.Stat(AwaitingPath(dir)); err != nil {
		t.Fatalf("a deferred boot did not note that it awaits serving: %v", err)
	}
	// Flapping, with the note: the last daemon never served, so the host's
	// 'active' is a write that did not land. It is 'upgrading' until it
	// serves, written once (I1).
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute+time.Second/2)); b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "active" {
		t.Fatalf("flapping boot of an active host after a never-served one = %+v, want upgrading written from active", b)
	}
	Served(dir)
	if err := corrosion.UpdateHostState(ctx, db, "h", "upgrading"); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute+time.Second)); b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("flapping boot of a host recorded upgrading = %+v, want upgrading kept, no boot write", b)
	}
	Served(dir)
	if err := corrosion.UpdateHostState(ctx, db, "h", "fenced"); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute+2*time.Second)); b.State != "active" || b.AwaitServing || b.Deferred {
		t.Fatalf("flapping boot of a fenced host = %+v, want active as before", b)
	}
	// Quiet for longer than the window: the next crash awaits serving again.
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	if b := BootState(ctx, db, "h", dir, false, now.Add(FlapLimit*time.Minute+FlapWindow+time.Minute)); b.State != "upgrading" || !b.AwaitServing || b.Deferred {
		t.Fatalf("unclean boot after a quiet %s = %+v, want upgrading until serving", FlapWindow, b)
	}
}

// A post-upgrade boot notes that it awaits serving like any other, so a crash
// of it before it serves makes no boot write: not 'upgrading' with a fresh
// timeout.
//
// Mutation: drop writeAwaiting from the upgrade branch — the crash after it
// writes 'upgrading' again.
func TestUpgradeBootNotesAwaitingServing(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	dir := t.TempDir()
	if b := BootState(ctx, db, "h", dir, true, time.Now()); b.State != "upgrading" || b.AwaitServing {
		t.Fatalf("post-upgrade boot = %+v, want upgrading, confirmed by the upgrade watchdog", b)
	}
	if b := BootState(ctx, db, "h", dir, false, time.Now()); b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("crash of a post-upgrade boot that never served = %+v, want upgrading kept, no boot write", b)
	}
}

// A fence that lands between ConfirmServing's read of 'upgrading' and its
// write is not overwritten with 'active': the write is conditional on the
// state it read, inside its own transaction.
//
// Mutation: write with corrosion.UpdateHostState (unconditional) — the
// fenced host turns active.
func TestConfirmServingDoesNotOverwriteAFenceThatLandsMeanwhile(t *testing.T) {
	db, ctx := hostIn(t, "upgrading")
	beforeConfirmWrite = func() {
		if err := corrosion.UpdateHostState(ctx, db, "h", "fenced"); err != nil {
			t.Errorf("the fence: %v", err)
		}
	}
	t.Cleanup(func() { beforeConfirmWrite = nil })
	flipped, state, err := ConfirmServing(ctx, db, "h")
	if !errors.Is(err, ErrNotUpgrading) || flipped || state != "fenced" {
		t.Fatalf("confirm with a fence landing meanwhile: flipped=%v state=%q err=%v, want ErrNotUpgrading, fenced", flipped, state, err)
	}
	if got := stateOf(t, db); got != "fenced" {
		t.Fatalf("the host is %q after the confirm, want the fence kept", got)
	}
}

// A boot without the marker after a daemon that never served — the lab 1
// ReleaseTokenRollbackRule cleanup boot (2026-10-16): a WAL-quarantined
// daemon's SIGTERM could write nothing, and it was stopped before it served —
// is judged by the recorded state, and is never recorded 'active' before it
// serves:
//
//   - 'upgrading' younger than the timeout: no boot write (Deferred). The
//     timeout the earlier write started is not re-armed, and the host turns
//     active once this daemon serves (ConfirmServingReport);
//   - 'upgrading' past the timeout: a fresh 'upgrading', written once;
//   - 'active' (the earlier boot's 'upgrading' write did not land): 'upgrading'
//     until it serves, written once — the next such boot finds 'upgrading';
//   - anything else: 'active' as before, which is how a fenced host returns.
//
// Mutations: return 'active' for the never-served boot (the boot before this
// change) — the upgrading and active cases fail; defer whatever the state —
// the fenced host is deferred.
func TestBootWithoutServingEvidenceByRecordedState(t *testing.T) {
	noted := func(t *testing.T) string {
		dir := t.TempDir()
		if err := writeAwaiting(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	db, ctx := hostIn(t, "upgrading")
	since, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("fixture: HostStateSince ok=%v err=%v", ok, err)
	}
	if b := BootState(ctx, db, "h", noted(t), false, since.Add(20*time.Second)); b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Fatalf("boot after a never-served one, host upgrading for 20s = %+v, want upgrading kept, no boot write", b)
	}
	// Past the timeout a deferred host would be fenced at once, before it
	// serves: it writes a fresh 'upgrading' once, guarded on the state read.
	if b := BootState(ctx, db, "h", noted(t), false, since.Add(UpgradingTimeout+time.Minute)); b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "upgrading" {
		t.Fatalf("boot after a never-served one, host upgrading past the timeout = %+v, want a fresh 'upgrading' written from upgrading", b)
	}
	db, ctx = hostIn(t, "active")
	if b := BootState(ctx, db, "h", noted(t), false, time.Now()); b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "active" {
		t.Fatalf("boot after a never-served one, host active = %+v, want upgrading until serving", b)
	}
	for _, st := range []string{"fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining} {
		db, ctx := hostIn(t, st)
		if b := BootState(ctx, db, "h", noted(t), false, time.Now()); b.State != "active" || b.AwaitServing || b.Deferred {
			t.Fatalf("boot after a never-served one, host %s = %+v, want active as before", st, b)
		}
	}
	if b := BootState(ctx, db, "nobody", noted(t), false, time.Now()); b.State != "active" || b.AwaitServing || b.Deferred {
		t.Fatalf("boot after a never-served one, no record = %+v, want active", b)
	}
}

// ConfirmServingReport is a deferred boot's write once its daemon serves: the
// boot report (version, resources) and 'active', in one write, only while the
// host is still recorded as the boot found it. A fence, maintenance or drain
// recorded meanwhile is kept, and so is a fence that lands between its read
// and its write. The isolation is kept.
//
// Mutations: write with corrosion.UpdateHostStartup (unconditional) — the
// fenced host turns active; write the state only (UpdateHostStateFrom) — the
// version is not reported; drop the moved-on report — the undrained,
// draining and maintenance hosts keep the old version; report whatever the
// state — the fenced host takes the new version.
func TestConfirmServingReport(t *testing.T) {
	r := Report{Version: "v-new", CPUs: 4, MemMiB: 8, DiskGiB: 16, HasResources: true}
	for _, from := range []string{"upgrading", "active"} {
		db, ctx := hostIn(t, from)
		if err := corrosion.IsolateHost(ctx, db, "observer", "h", "manual"); err != nil {
			t.Fatalf("isolate: %v", err)
		}
		epoch, reason, err := corrosion.HostIsolation(ctx, db, "h")
		if err != nil || epoch == 0 {
			t.Fatalf("fixture: isolation epoch=%d err=%v", epoch, err)
		}
		flipped, state, err := ConfirmServingReport(ctx, db, "h", from, r)
		h, _ := corrosion.GetHost(ctx, db, "h")
		if err != nil || !flipped || state != "active" || h.State != "active" || h.Version != "v-new" || h.CPUTotal != 4 {
			t.Fatalf("report from %s: flipped=%v state=%q err=%v host=%+v", from, flipped, state, err, h)
		}
		if e2, r2, err := corrosion.HostIsolation(ctx, db, "h"); err != nil || e2 != epoch || r2 != reason {
			t.Fatalf("report from %s changed the isolation: %d %q -> %d %q (%v)", from, epoch, reason, e2, r2, err)
		}
	}
	// Moved on meanwhile: the state is kept. A host that runs again
	// (undrained to active, draining, maintenance) still gets this boot's
	// report, so nothing judges it by the previous binary's version; a fenced
	// or offline one does not, so its fence's time is not re-dated.
	for st, reported := range map[string]bool{"active": true, "draining": true, "maintenance": true, "fenced": false, "offline": false} {
		db, ctx := hostIn(t, st)
		h0, _ := corrosion.GetHost(ctx, db, "h")
		flipped, got, err := ConfirmServingReport(ctx, db, "h", "upgrading", r)
		h, _ := corrosion.GetHost(ctx, db, "h")
		want := h0.Version
		if reported {
			want = r.Version
		}
		if !errors.Is(err, ErrMovedOn) || flipped || got != st || h.State != st || h.Version != want {
			t.Fatalf("report for a host now %s: flipped=%v state=%q err=%v host=%+v, want state kept and version %q", st, flipped, got, err, h, want)
		}
	}
	db, ctx := hostIn(t, "upgrading")
	beforeConfirmWrite = func() {
		if err := corrosion.UpdateHostState(ctx, db, "h", "fenced"); err != nil {
			t.Errorf("the fence: %v", err)
		}
	}
	t.Cleanup(func() { beforeConfirmWrite = nil })
	flipped, state, err := ConfirmServingReport(ctx, db, "h", "upgrading", r)
	if !errors.Is(err, ErrMovedOn) || flipped || state != "fenced" || stateOf(t, db) != "fenced" {
		t.Fatalf("report with a fence landing meanwhile: flipped=%v state=%q err=%v record=%q, want the fence kept", flipped, state, err, stateOf(t, db))
	}
}

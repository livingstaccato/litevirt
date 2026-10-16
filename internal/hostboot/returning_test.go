package hostboot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// returningStates are the recorded states a host returns to service from by
// booting: the boot ends them, as it always did, but records the host
// 'upgrading' until its daemon serves instead of 'active' at once.
var returningStates = []string{"fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining}

// A boot without the marker of a host recorded fenced, offline, maintenance,
// draining or joining is 'upgrading' until its daemon serves, and notes that
// it awaits serving. It still counts as an unclean boot.
//
// Mutation: have BootState skip returningBoot — every state boots 'active'.
func TestReturningHostBootsUpgradingUntilItServes(t *testing.T) {
	for _, st := range returningStates {
		t.Run(st, func(t *testing.T) {
			db, ctx := hostIn(t, st)
			dir := t.TempDir()
			b := BootState(ctx, db, "h", dir, false, time.Now())
			if b.State != "upgrading" || !b.AwaitServing {
				t.Fatalf("boot of a host recorded %s = %+v, want upgrading until serving", st, b)
			}
			if !strings.Contains(b.Reason, st) {
				t.Fatalf("boot reason %q does not name the recorded state %s", b.Reason, st)
			}
			if _, err := os.Stat(AwaitingPath(dir)); err != nil {
				t.Fatalf("the boot did not note that it awaits serving: %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, UncleanHistoryName))
			if err != nil || strings.Count(strings.TrimSpace(string(raw)), "\n") != 0 || strings.TrimSpace(string(raw)) == "" {
				t.Fatalf("the boot was not counted as one unclean boot: %q (%v)", raw, err)
			}
		})
	}
}

// The returning rule holds whatever else the boot finds: a graceful-stop
// marker (fresh or stale, the host fenced while it was down), a note that the
// daemon before it never served, a flapping history. Each of those makes an
// 'active' or 'upgrading' host's boot 'active' on this build; for a host the
// cluster recorded down or out of service, 'active' at once is what its peers
// fence before it serves, and the write is bounded without them: it is made
// only over a state the host's own daemon never writes, so the next boot finds
// 'upgrading' and the ordinary rules.
//
// Mutations: have BootState skip returningBoot — each case boots 'active';
// call returningBoot only for a boot without the marker — the marked cases
// boot 'active'.
func TestReturningHostBootsUpgradingWhateverItsHistory(t *testing.T) {
	now := time.Now()
	cases := map[string]func(t *testing.T, dir string) time.Time{
		"marker, host fenced while down": func(t *testing.T, dir string) time.Time {
			writeMarker(t, dir, now)
			return now.Add(10 * time.Second)
		},
		"stale marker": func(t *testing.T, dir string) time.Time {
			writeMarker(t, dir, now)
			return now.Add(UpgradingTimeout + time.Minute)
		},
		"last boot never served": func(t *testing.T, dir string) time.Time {
			if err := writeAwaiting(dir, now); err != nil {
				t.Fatal(err)
			}
			return now.Add(time.Minute)
		},
		"flapping": func(t *testing.T, dir string) time.Time {
			for i := 0; i < FlapLimit; i++ {
				if _, err := recordUncleanBoot(dir, now.Add(time.Duration(i)*time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			return now.Add(FlapLimit * time.Minute)
		},
	}
	for name, setup := range cases {
		for _, st := range []string{"fenced", "offline", "maintenance"} {
			t.Run(name+"/"+st, func(t *testing.T) {
				db, ctx := hostIn(t, st)
				dir := t.TempDir()
				at := setup(t, dir)
				b := BootState(ctx, db, "h", dir, false, at)
				if b.State != "upgrading" || !b.AwaitServing {
					t.Fatalf("boot of a host recorded %s (%s) = %+v, want upgrading until serving", st, name, b)
				}
				if _, err := os.Stat(MarkerPath(dir)); !os.IsNotExist(err) {
					t.Fatalf("the boot left the marker in place: %v", err)
				}
			})
		}
	}
}

// The rule reads only the recorded state, and applies to the returning states
// only: an 'active' or 'upgrading' host is decided by the restart rules, and a
// host with no record, or one whose state this node cannot know, boots as
// before.
//
// Mutation: apply the rule to every readable state — the active and upgrading
// hosts are taken by it (ok=true).
func TestReturningBootOnlyForReturningStates(t *testing.T) {
	for _, st := range []string{"active", "upgrading"} {
		db, ctx := hostIn(t, st)
		if b, ok := returningBoot(ctx, db, "h", t.TempDir(), false, time.Now()); ok {
			t.Fatalf("a host recorded %s was taken by the returning rule: %+v", st, b)
		}
	}
	db, ctx := hostIn(t, "fenced")
	if b, ok := returningBoot(ctx, db, "nobody", t.TempDir(), false, time.Now()); ok {
		t.Fatalf("a host with no record was taken by the returning rule: %+v", b)
	}
	if b := BootState(ctx, db, "nobody", t.TempDir(), false, time.Now()); b.State != "active" || b.AwaitServing {
		t.Fatalf("boot of a host with no record = %+v, want active as before", b)
	}
	if returning(corrosion.HostStateUnknown) {
		t.Fatalf("%q is taken as a returning state; a state this node cannot know must not be", corrosion.HostStateUnknown)
	}
}

// The returning write is made once per return: a crash of that boot before it
// serves finds the host 'upgrading', which the returning rule leaves to the
// restart rules, so a crash loop cannot re-arm the timeout through it.
//
// Mutation: treat 'upgrading' as a returning state — the second boot is
// taken by the rule.
func TestReturningBootIsOncePerReturn(t *testing.T) {
	db, ctx := hostIn(t, "fenced")
	dir := t.TempDir()
	now := time.Now()
	b := BootState(ctx, db, "h", dir, false, now)
	if b.State != "upgrading" {
		t.Fatalf("fixture: boot of the fenced host = %+v", b)
	}
	if err := corrosion.UpdateHostStartup(ctx, db, "h", b.State, "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	// It dies before serving and is started again.
	if b2, ok := returningBoot(ctx, db, "h", dir, false, now.Add(5*time.Second)); ok {
		t.Fatalf("the boot after the returning boot was taken by the returning rule again: %+v", b2)
	}
}

// The boot write and the serving confirm of a returning host keep an
// isolation recorded for it: the host is 'upgrading', then 'active', with its
// isolation epoch unchanged.
//
// Mutation: none in hostboot — this pins that the returning boot goes through
// the same writes (UpdateHostStartup, ConfirmServing) as a graceful restart.
func TestReturningBootKeepsIsolation(t *testing.T) {
	db, ctx := hostIn(t, "fenced")
	if err := corrosion.IsolateHost(ctx, db, "observer", "h", "manual"); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	epoch, reason, err := corrosion.HostIsolation(ctx, db, "h")
	if err != nil || epoch == 0 {
		t.Fatalf("fixture: isolation epoch=%d err=%v", epoch, err)
	}
	b := BootState(ctx, db, "h", t.TempDir(), false, time.Now())
	if err := corrosion.UpdateHostStartup(ctx, db, "h", b.State, "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := stateOf(t, db); got != "upgrading" {
		t.Fatalf("after the boot write the host is %q, want upgrading", got)
	}
	if flipped, state, err := ConfirmServing(ctx, db, "h"); err != nil || !flipped || state != "active" {
		t.Fatalf("confirm: flipped=%v state=%q err=%v", flipped, state, err)
	}
	if e2, r2, err := corrosion.HostIsolation(ctx, db, "h"); err != nil || e2 != epoch || r2 != reason {
		t.Fatalf("the return changed the isolation: %d %q -> %d %q (%v)", epoch, reason, e2, r2, err)
	}
}

func writeMarker(t *testing.T, dir string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(MarkerPath(dir), []byte(at.UTC().Format(time.RFC3339Nano)), 0o600); err != nil {
		t.Fatal(err)
	}
}

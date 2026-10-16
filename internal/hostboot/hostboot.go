// Package hostboot decides the state a daemon records for its own host across
// a graceful restart: 'upgrading' from the SIGTERM until it serves again,
// 'active' once it does.
//
// The boot write used to record the host 'active' as soon as the daemon had
// opened its database, seconds before its gRPC server listened. Its observers
// had counted it failing all through the restart, so the coordinator saw an
// active host that a quorum still could not reach. On lab 1 (2026-10-11) that
// SSH-powered node-5 off twice and node-2 once, about 3 s after the boot
// write. The coordinator now holds such a fence back for a whole run
// (failover.countedSinceActive), but only for 13 s. A restart that SIGTERM
// began instead boots 'upgrading', which the coordinator skips for
// UpgradingTimeout, and becomes 'active' once the daemon answers its own
// Ping, which closes the gap however long startup takes.
//
// A boot after a stop that left no marker (a crash, a kill, a stop whose
// write failed) is 'upgrading' until it serves too, for a host recorded
// 'active' (or 'upgrading' for less than UpgradingTimeout): recorded 'active'
// it answered nothing for as long as startup took, and on lab 1 (2026-10-14)
// its peers SSH-fenced it 19 s after the boot, before it served.
//
// Four rules keep that from hiding a host that should be fenced, or
// overwriting a decision made about it:
//
//   - only a SIGTERM of an ACTIVE host leaves the marker (MarkRestarting), and
//     the boot consumes it before its write (BootState);
//   - a boot that awaits serving leaves AwaitingPath until a daemon serves
//     (Served), and a boot without the marker that finds it makes no boot
//     write until it serves (Deferred): a daemon that crash-loops before it
//     serves is written 'upgrading' once, not on every boot, so it cannot keep
//     re-arming the 'upgrading' timeout, and it is not recorded 'active'
//     before it serves either;
//   - the boot writes 'upgrading' only while the host is still recorded
//     'upgrading' or 'active', checked in the write's own transaction
//     (Boot.From): a host the cluster has fenced, put in maintenance or
//     isolated while it was down keeps that, and one past its upgrading
//     timeout gets one fresh 'upgrading', not an 'active' its peers fence
//     before it serves;
//   - ConfirmServing moves the host from 'upgrading' to 'active' and from
//     nothing else, and leaves its isolation as it is.
//
// If the daemon never serves, the host stays 'upgrading' and the coordinator
// fences it once UpgradingTimeout has passed since the state write.
package hostboot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// UpgradingTimeout is how long the failover coordinator leaves a host recorded
// 'upgrading' before it treats the host as failed, counted from the state
// write (corrosion.HostStateSince). Long enough for a binary stream and a
// restart, short enough that a host that died mid-restart still fails over.
const UpgradingTimeout = 2 * time.Minute

// MarkerName is the file, in the daemon's data directory, a graceful stop
// leaves for the next boot: the SIGTERM's time, RFC 3339.
const MarkerName = "restart-pending"

// MarkerPath is the marker's path under dataDir.
func MarkerPath(dataDir string) string { return filepath.Join(dataDir, MarkerName) }

// Boot is the state the boot write records, and whether the daemon must
// confirm it serves (ConfirmServing) before the host is recorded active.
type Boot struct {
	State        string
	AwaitServing bool
	// Deferred: no boot write is made at boot. The host keeps the state the
	// cluster records (State, 'upgrading' or 'active'), so its 'upgrading'
	// timeout is not re-armed and it is not newly recorded 'active'; once
	// the daemon serves, the boot report and 'active' are written together,
	// only while the host is still recorded State (ConfirmServingReport).
	Deferred bool
	// From, when set, is the state the decision read: the boot write is made
	// only while the host is still recorded From (corrosion's
	// UpdateHostStartupFrom), so a fence, drain or offline recorded between
	// the read and the write is kept.
	From string
	// Reason says why, for the boot log.
	Reason string
}

// MarkRestarting is the graceful-stop write: it records host 'upgrading', so
// peers skip fencing it during the restart, and leaves the marker that lets
// the next boot keep it 'upgrading' until it serves.
//
// Only an ACTIVE host gets the marker. A host recorded fenced, offline or in
// maintenance keeps its state and is not written at all: the coordinator never
// fences those for being silent, and writing 'upgrading' over them is what
// lost them on the next boot. Any other state (draining, an unreadable record)
// is marked 'upgrading' as before, so the restart is still not fenced, but
// without the marker, so it boots as before.
func MarkRestarting(ctx context.Context, db *corrosion.Client, host, dataDir string, now time.Time) error {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return corrosion.UpdateHostState(ctx, db, host, "upgrading")
	}
	switch h.State {
	case "fenced", "offline", "maintenance":
		return nil
	case "active":
	default:
		return corrosion.UpdateHostState(ctx, db, host, "upgrading")
	}
	if dataDir != "" {
		// Before the state write: a marker without the write boots 'active'
		// (BootState checks the record), the write without a marker is the
		// old behaviour.
		_ = os.WriteFile(MarkerPath(dataDir), []byte(now.UTC().Format(time.RFC3339Nano)), 0o600)
	}
	return corrosion.UpdateHostState(ctx, db, host, "upgrading")
}

// BootState decides the state the boot write records, and consumes the
// marker. upgradePending is the post-upgrade watchdog's sentinel, whose boot
// is 'upgrading' as it always was and whose watchdog confirms it.
//
// No boot of a host recorded 'active' or 'upgrading' records it 'active'
// before its daemon serves: it writes 'upgrading' (guarded on the state it
// read, Boot.From) or nothing at all (Boot.Deferred), and the serving check
// records it active. Only a host recorded as something else (fenced,
// offline, maintenance, draining, joining), or one this boot cannot judge
// (no record, no data dir, an unclean boot it cannot count), boots 'active'
// as before.
func BootState(ctx context.Context, db *corrosion.Client, host, dataDir string, upgradePending bool, now time.Time) Boot {
	at, marked := takeMarker(dataDir)
	if upgradePending {
		// Noted like any boot that awaits serving, so a crash of this boot
		// before it serves is not 'upgrading' again with a fresh timeout. Best
		// effort: the watchdog, not the note, confirms this boot.
		_ = writeAwaiting(dataDir, now)
		return Boot{State: "upgrading", Reason: "post-upgrade boot; the upgrade watchdog confirms it"}
	}
	if !marked {
		return noteAwaiting(dataDir, uncleanBoot(ctx, db, host, dataDir, now), now)
	}
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return Boot{State: "active", Reason: "this host's record is unreadable"}
	}
	switch h.State {
	case "upgrading":
		if age := now.Sub(at); age < 0 || age >= UpgradingTimeout {
			// The coordinator may treat it as stuck 'upgrading' and fence it
			// at once; a fresh 'upgrading', written once (the marker is
			// consumed), gives it the timeout to serve. A fence recorded
			// meanwhile is kept by the write's guard.
			return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "upgrading",
				Reason: fmt.Sprintf("the graceful stop was %s ago; a fresh 'upgrading' until this daemon serves", age.Round(time.Second))}, now)
		}
		return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "upgrading", Reason: "graceful restart; active once this daemon serves"}, now)
	case "active":
		// The marker was left, but the SIGTERM's 'upgrading' write did not
		// land.
		return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "active",
			Reason: "graceful stop recorded, but its 'upgrading' write did not land; active once this daemon serves"}, now)
	}
	return Boot{State: "active", Reason: "recorded " + h.State + " since the graceful stop"}
}

// uncleanBoot is the boot after a stop that left no marker: a crash, a kill,
// or a stop whose 'upgrading' write failed (a WAL-quarantined daemon writes
// nothing). For a host recorded 'active' or 'upgrading' it is 'upgrading'
// until this daemon serves, written or kept:
//
//   - recorded 'active': 'upgrading' is written, guarded on 'active'. Only
//     when this boot is flapping (FlapLimit unclean boots within FlapWindow,
//     UncleanHistoryName) and the daemon before it served (no AwaitingPath)
//     is nothing written (Deferred): writing 'upgrading' after every crash of
//     a daemon that serves in between would keep re-arming the timeout, and
//     the host is judged on its failure count as recorded. After a daemon
//     that never served, the 'active' is a write that did not land, and
//     'upgrading' is written once: the next such boot finds 'upgrading';
//   - recorded 'upgrading' and flapping, or after a daemon that never served
//     while the state is younger than UpgradingTimeout (or its age is
//     unreadable): nothing is written (Deferred), so a crash loop cannot
//     re-arm the timeout the earlier write started;
//   - recorded 'upgrading' otherwise — younger than the timeout with serving
//     evidence, or past it (or dated after this boot): 'upgrading' is
//     written, guarded on 'upgrading'. Past the timeout the coordinator
//     treats the host as stuck and would fence it on its failure count
//     before it serves; the fresh write gives it the timeout to serve, once
//     per unclean boot, and FlapLimit bounds how often.
//
// Every other boot is 'active' as before: one with no data dir, or that
// cannot record itself, which could not bound a crash loop; a host recorded
// anything else (fenced, offline, maintenance, draining, joining) or not at
// all.
func uncleanBoot(ctx context.Context, db *corrosion.Client, host, dataDir string, now time.Time) Boot {
	if dataDir == "" {
		return Boot{State: "active", Reason: "no graceful stop recorded, and no data dir to bound a crash loop"}
	}
	prior, err := recordUncleanBoot(dataDir, now)
	if err != nil {
		return Boot{State: "active", Reason: "no graceful stop recorded, and recording this unclean boot failed (" + err.Error() + ")"}
	}
	flapping := prior >= FlapLimit
	_, nerr := os.Lstat(AwaitingPath(dataDir))
	neverServed := !os.IsNotExist(nerr)
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return Boot{State: "active", Reason: "no graceful stop recorded, and this host's record is unreadable"}
	}
	why := "no graceful stop recorded"
	if flapping {
		why += fmt.Sprintf(", this is unclean boot %d within %s", prior+1, FlapWindow)
	}
	if neverServed {
		why += ", and the last boot never served"
	}
	switch h.State {
	case "active":
		if flapping && !neverServed {
			return Boot{State: "active", AwaitServing: true, Deferred: true,
				Reason: why + "; a flapping daemon makes no boot write, and reports once it serves"}
		}
		return Boot{State: "upgrading", AwaitServing: true, From: "active", Reason: why + "; active once this daemon serves"}
	case "upgrading":
		if flapping {
			return Boot{State: "upgrading", AwaitServing: true, Deferred: true,
				Reason: why + "; the host stays 'upgrading' as recorded, without a boot write, until this daemon serves"}
		}
		since, ok, err := corrosion.HostStateSince(ctx, db, host)
		readable := err == nil && ok
		age := now.Sub(since)
		stale := readable && (age < 0 || age >= UpgradingTimeout)
		if neverServed && !stale {
			return Boot{State: "upgrading", AwaitServing: true, Deferred: true,
				Reason: why + "; the host stays 'upgrading' as recorded, without a boot write, until this daemon serves"}
		}
		if stale {
			return Boot{State: "upgrading", AwaitServing: true, From: "upgrading",
				Reason: fmt.Sprintf("%s; this host turned 'upgrading' %s ago, so a fresh 'upgrading' until this daemon serves", why, age.Round(time.Second))}
		}
		return Boot{State: "upgrading", AwaitServing: true, From: "upgrading", Reason: why + "; active once this daemon serves"}
	}
	return Boot{State: "active", Reason: why + "; recorded " + h.State}
}

// AwaitingName is the file, in the daemon's data directory, a boot that awaits
// serving leaves until a daemon serves (Served): while it is there, no daemon
// has served since that boot.
const AwaitingName = "boot-awaiting-serving"

// AwaitingPath is AwaitingName's path under dataDir.
func AwaitingPath(dataDir string) string { return filepath.Join(dataDir, AwaitingName) }

// noteAwaiting leaves AwaitingPath for a boot b that awaits serving, keeping
// one an earlier boot left. A boot that cannot leave it is 'active': the next
// boot could not tell that this daemon never served. A deferred boot writes
// nothing, so it re-arms nothing whatever the next boot can tell: its note is
// best effort.
func noteAwaiting(dataDir string, b Boot, now time.Time) Boot {
	if !b.AwaitServing {
		return b
	}
	if b.Deferred {
		_ = writeAwaiting(dataDir, now)
		return b
	}
	if err := writeAwaiting(dataDir, now); err != nil {
		return Boot{State: "active", Reason: b.Reason + "; but noting that it awaits serving failed (" + err.Error() + "), so active now"}
	}
	return b
}

// writeAwaiting leaves AwaitingPath, keeping one an earlier boot left.
func writeAwaiting(dataDir string, now time.Time) error {
	if dataDir == "" {
		return errors.New("no data dir")
	}
	p := AwaitingPath(dataDir)
	if _, err := os.Lstat(p); err == nil {
		return nil
	}
	return os.WriteFile(p, []byte(now.UTC().Format(time.RFC3339Nano)), 0o600)
}

// FlapLimit unclean boots within FlapWindow make the next one 'active'.
const (
	FlapLimit  = 3
	FlapWindow = 10 * time.Minute
)

// UncleanHistoryName is the file, in the daemon's data directory, that lists
// the times of the last unclean boots (boots without the graceful-stop
// marker), one RFC 3339 time per line.
const UncleanHistoryName = "boot-unclean-history"

// recordUncleanBoot adds now to UncleanHistoryName and returns how many
// unclean boots it already held within FlapWindow of now, either side (a clock
// that went back keeps counting them). It keeps only those, at most FlapLimit.
func recordUncleanBoot(dataDir string, now time.Time) (int, error) {
	p := filepath.Join(dataDir, UncleanHistoryName)
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	var recent []string
	for _, line := range strings.Split(string(b), "\n") {
		at, perr := time.Parse(time.RFC3339Nano, strings.TrimSpace(line))
		if perr != nil {
			continue
		}
		if d := now.Sub(at); d > -FlapWindow && d < FlapWindow {
			recent = append(recent, at.UTC().Format(time.RFC3339Nano))
		}
	}
	prior := len(recent)
	recent = append(recent, now.UTC().Format(time.RFC3339Nano))
	if len(recent) > FlapLimit {
		recent = recent[len(recent)-FlapLimit:]
	}
	if err := os.WriteFile(p, []byte(strings.Join(recent, "\n")+"\n"), 0o600); err != nil {
		return prior, err
	}
	return prior, nil
}

// Served records that this daemon answers its own Ping: the next boot is no
// longer one after a daemon that never served. Best effort.
func Served(dataDir string) {
	if dataDir == "" {
		return
	}
	_ = os.Remove(AwaitingPath(dataDir))
}

// takeMarker reads and removes the marker. Removed whatever it says, so a
// daemon that dies before it serves boots 'active' next time.
func takeMarker(dataDir string) (time.Time, bool) {
	if dataDir == "" {
		return time.Time{}, false
	}
	p := MarkerPath(dataDir)
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	_ = os.Remove(p)
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// ErrNotUpgrading is ConfirmServing's answer for a host recorded in some other
// state: nothing was written.
var ErrNotUpgrading = errors.New("host is not recorded upgrading")

// ConfirmServing records host 'active' once its daemon serves, if it is still
// recorded 'upgrading'. A host fenced, put in maintenance or otherwise moved
// on meanwhile keeps that state (flipped=false, ErrNotUpgrading), and the
// state write keeps the host's isolation as it is.
func ConfirmServing(ctx context.Context, db *corrosion.Client, host string) (bool, string, error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil {
		return false, "", err
	}
	if h == nil {
		return false, "", fmt.Errorf("host %q has no record", host)
	}
	if h.State != "upgrading" {
		return false, h.State, ErrNotUpgrading
	}
	if beforeConfirmWrite != nil {
		beforeConfirmWrite()
	}
	// Only from 'upgrading', checked in the write's own transaction: a fence
	// or drain recorded since the read above keeps its state.
	applied, err := corrosion.UpdateHostStateFrom(ctx, db, host, "upgrading", "active")
	if err != nil {
		return false, h.State, err
	}
	if !applied {
		now, err := corrosion.GetHost(ctx, db, host)
		if err != nil || now == nil {
			return false, "", ErrNotUpgrading
		}
		return false, now.State, ErrNotUpgrading
	}
	return true, "active", nil
}

// ErrMovedOn is ConfirmServingReport's answer for a host recorded in another
// state than the deferred boot found: nothing was written.
var ErrMovedOn = errors.New("host's recorded state changed since the boot")

// Report is the boot report a deferred boot writes once its daemon serves:
// what UpdateHostStartup writes at any other boot.
type Report struct {
	Version               string
	CPUs, MemMiB, DiskGiB int
	HasResources          bool
}

// ConfirmServingReport is ConfirmServing for a deferred boot (Boot.Deferred),
// or one whose guarded boot write found the host moved on: once its daemon
// serves, it records host 'active' with the boot report, in one write, only
// while the host is still recorded from, checked in the write's own
// transaction. A host fenced, drained or put in maintenance meanwhile keeps
// that state (flipped=false, ErrMovedOn); the isolation is kept as it is.
//
// A host that moved on and runs again — undrained to 'active', or
// 'draining' or 'maintenance' — still gets the report (reportKeepingState):
// it is the only writer of the running version and schema, and `lv host
// upgrade` skips a host by its recorded version.
func ConfirmServingReport(ctx context.Context, db *corrosion.Client, host, from string, r Report) (bool, string, error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil {
		return false, "", err
	}
	if h == nil {
		return false, "", fmt.Errorf("host %q has no record", host)
	}
	if h.State != from {
		return false, h.State, reportKeepingState(ctx, db, host, h.State, r)
	}
	if beforeConfirmWrite != nil {
		beforeConfirmWrite()
	}
	applied, err := corrosion.UpdateHostStartupFrom(ctx, db, host, from, "active", r.Version, r.CPUs, r.MemMiB, r.DiskGiB, r.HasResources)
	if err != nil {
		return false, h.State, err
	}
	if !applied {
		now, err := corrosion.GetHost(ctx, db, host)
		if err != nil || now == nil {
			return false, "", ErrMovedOn
		}
		return false, now.State, reportKeepingState(ctx, db, host, now.State, r)
	}
	return true, "active", nil
}

// reportKeepingState writes the boot report r of a host recorded state
// without moving the state, and returns ErrMovedOn (wrapped with a failed
// write's error). An 'active' host gets the whole report, guarded on
// 'active'; a 'draining' or 'maintenance' one its version and resources,
// which leave its membership row (and so its state's time) as it is; any
// other — fenced, offline, upgrading, joining — none, so neither a fence's
// time nor the upgrading timeout is re-dated.
func reportKeepingState(ctx context.Context, db *corrosion.Client, host, state string, r Report) error {
	var err error
	switch state {
	case "active":
		_, err = corrosion.UpdateHostStartupFrom(ctx, db, host, "active", "active", r.Version, r.CPUs, r.MemMiB, r.DiskGiB, r.HasResources)
	case "draining", "maintenance":
		if r.Version != "" {
			err = corrosion.UpdateHostVersion(ctx, db, host, r.Version)
		}
		if err == nil && r.HasResources {
			err = corrosion.UpdateHostResources(ctx, db, host, r.CPUs, r.MemMiB, r.DiskGiB)
		}
	}
	if err != nil {
		return fmt.Errorf("%w (reporting this boot failed: %v)", ErrMovedOn, err)
	}
	return ErrMovedOn
}

// beforeConfirmWrite, when set, runs between ConfirmServing's read and its
// write. Tests only.
var beforeConfirmWrite func()

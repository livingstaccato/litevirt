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
// These rules keep that from hiding a host that should be fenced, or
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
//   - a host recorded fenced, offline, maintenance, draining or joining is
//     returning to service, and boots 'upgrading' until it serves too
//     (returningBoot), once the returning_boot release feature is open, and
//     'active' as before until then: once per return, since its own daemon
//     never writes those states;
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
	// cluster records (State; empty when this boot could not read it), so
	// its 'upgrading' timeout is not re-armed and it is not newly recorded
	// 'active'; once the daemon serves, the boot report and 'active' are
	// written together, only while the host is still recorded State
	// (ConfirmServingReport; an empty State is read then).
	Deferred bool
	// From, when set, is the state the decision read: the boot write is made
	// only while the host is still recorded From (corrosion's
	// UpdateHostStartupFrom), so a fence, drain or offline recorded between
	// the read and the write is kept.
	From string
	// Returning: the host was recorded in a returning state (From), and its
	// 'upgrading' write is the returning_boot release feature's
	// (WriteReturningBoot). Until the feature opens, the boot is Fallback().
	Returning bool
	// KeptFence: a deferred boot of a host recorded fenced or offline that
	// could not record its unclean-boot history, which keeps the fence
	// (CondFenceKeptOnBoot); Cause is why.
	KeptFence bool
	Cause     string
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
// records it active. A host recorded fenced, offline, maintenance, draining
// or joining is returning to service (returningBoot). An unreadable record
// or an unclean boot whose history cannot be recorded defers writes or keeps
// its recorded fence; a boot with no record or data directory uses 'active'.
func BootState(ctx context.Context, db *corrosion.Client, host, dataDir string, upgradePending bool, now time.Time) Boot {
	at, marked := takeMarker(dataDir)
	if upgradePending {
		// Noted like any boot that awaits serving, so a crash of this boot
		// before it serves is not 'upgrading' again with a fresh timeout. Best
		// effort: the watchdog, not the note, confirms this boot.
		_ = writeAwaiting(dataDir, now)
		return Boot{State: "upgrading", Reason: "post-upgrade boot; the upgrade watchdog confirms it"}
	}
	// A host recorded down or out of service returns 'upgrading' until it
	// serves, whatever the marker or the history (returningBoot).
	if b, ok := returningBoot(ctx, db, host, dataDir, marked, now); ok {
		return b
	}
	if !marked {
		return noteAwaiting(dataDir, uncleanBoot(ctx, db, host, dataDir, now), now, false)
	}
	h, err := readHost(ctx, db, host)
	if err != nil || h == nil {
		// Noted, best effort, so a crash of this boot before it serves
		// leaves the next one its never-served signal. If the note cannot
		// be written either, that next boot reads as after a daemon that
		// served: for a host still 'upgrading' it may write one fresh
		// 'upgrading', the bounded re-arm of any unclean boot (FlapLimit).
		_ = writeAwaiting(dataDir, now)
		return unreadable("graceful stop recorded", err)
	}
	switch h.State {
	case "upgrading":
		if age := now.Sub(at); age < 0 || age >= UpgradingTimeout {
			// The coordinator may treat it as stuck 'upgrading' and fence it
			// at once; a fresh 'upgrading', written once (the marker is
			// consumed), gives it the timeout to serve. A fence recorded
			// meanwhile is kept by the write's guard.
			return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "upgrading",
				Reason: fmt.Sprintf("the graceful stop was %s ago; a fresh 'upgrading' until this daemon serves", age.Round(time.Second))}, now, true)
		}
		return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "upgrading", Reason: "graceful restart; active once this daemon serves"}, now, true)
	case "active":
		// The marker was left, but the SIGTERM's 'upgrading' write did not
		// land.
		return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: "active",
			Reason: "graceful stop recorded, but its 'upgrading' write did not land; active once this daemon serves"}, now, true)
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
// A boot that cannot record itself in UncleanHistoryName, which could not
// bound a crash loop, or cannot read the host's record, writes nothing until
// it serves (Deferred). Every other boot is 'active' as before: one with no
// data dir, and a host recorded anything else. (A host recorded fenced,
// offline, maintenance, draining or joining does not reach this:
// returningBoot.)
func uncleanBoot(ctx context.Context, db *corrosion.Client, host, dataDir string, now time.Time) Boot {
	if dataDir == "" {
		return Boot{State: "active", Reason: "no graceful stop recorded, and no data dir to bound a crash loop"}
	}
	prior, herr := recordUncleanBoot(dataDir, now)
	flapping := prior >= FlapLimit
	_, nerr := os.Lstat(AwaitingPath(dataDir))
	neverServed := !os.IsNotExist(nerr)
	h, err := readHost(ctx, db, host)
	if err != nil || h == nil {
		return unreadable("no graceful stop recorded", err)
	}
	if herr != nil {
		// It cannot bound a crash loop, so it writes nothing: no re-armed
		// timeout, and no 'active' before it serves.
		return Boot{State: h.State, AwaitServing: true, Deferred: true,
			Reason: "no graceful stop recorded, and recording this unclean boot failed (" + herr.Error() + "); no boot write until this daemon serves"}
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
// one an earlier boot left. An unclean boot that cannot leave it writes
// nothing until it serves (Deferred, the state it read): the next boot could
// not tell that this daemon never served, so a write now could be re-armed
// on every crash. A deferred boot, and a boot after a graceful stop (bounded:
// the marker is consumed), write what they decided whatever the next boot
// can tell: their note is best effort.
func noteAwaiting(dataDir string, b Boot, now time.Time, bounded bool) Boot {
	if !b.AwaitServing {
		return b
	}
	err := writeAwaiting(dataDir, now)
	if err == nil || b.Deferred || bounded {
		return b
	}
	return Boot{State: b.From, AwaitServing: true, Deferred: true,
		Reason: b.Reason + "; but noting that it awaits serving failed (" + err.Error() + "), so no boot write until this daemon serves"}
}

// readHost reads host's record, once more after a failed read.
func readHost(ctx context.Context, db *corrosion.Client, host string) (*corrosion.HostRecord, error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil {
		h, err = corrosion.GetHost(ctx, db, host)
	}
	return h, err
}

// unreadable is the boot of a host whose record cannot be read (or is not
// there): it writes nothing, and once the daemon serves the record is read
// again (Deferred with no State).
func unreadable(why string, err error) Boot {
	cause := "there is none"
	if err != nil {
		cause = err.Error()
	}
	return Boot{AwaitServing: true, Deferred: true,
		Reason: why + ", and this host's record is unreadable (" + cause + "); no boot write until this daemon serves"}
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
	return writeAwaitingFile(p, []byte(now.UTC().Format(time.RFC3339Nano)), 0o600)
}

// writeAwaitingFile writes AwaitingPath; a var so tests can fail it alone.
var writeAwaitingFile = os.WriteFile

// FlapLimit unclean boots within FlapWindow defer the next boot's write.
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
	// or drain recorded since the read above keeps its state. So is the
	// address (corrosion.ActivateHostFrom): a host that does not keep it is
	// refused, and retried.
	applied, lostTo, err := corrosion.ActivateHostFrom(ctx, db, host, "upgrading")
	if err != nil {
		return false, h.State, err
	}
	if lostTo != "" {
		return false, h.State, addressNotKept(host, lostTo)
	}
	if !applied {
		if afterConfirmDeclined != nil {
			afterConfirmDeclined()
		}
		now, err := corrosion.GetHost(ctx, db, host)
		if err != nil {
			return false, "", err
		}
		if now == nil {
			return false, "", ErrNotUpgrading
		}
		return false, now.State, ErrNotUpgrading
	}
	return true, "active", nil
}

// addressNotKept is the refusal to record host active while lostTo keeps
// its address (corrosion.AddressLostTo): a host already active there, or an
// earlier admission. The caller retries, so the host activates once lostTo is
// removed; until then it stays 'upgrading' and says why
// (upgrading_unconfirmed).
func addressNotKept(host, lostTo string) error {
	return fmt.Errorf("%s keeps this host's address (it is active there, or was admitted there first): a machine is "+
		"admitted under one name, and %s is not activated while %s holds it. Remove the one this machine does not "+
		"serve: `lv host rm %s` or `lv host rm %s`", lostTo, host, lostTo, host, lostTo)
}

// ErrMovedOn means ConfirmServingReport kept a host's moved-on state. An
// eligible running host may still have received version/resource reports.
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
		return false, "", ErrMovedOn // no record to write: the host is gone
	}
	if from == "" {
		// The boot could not read the record: confirm from what it is now.
		from = h.State
	}
	switch {
	case from != "upgrading" && from != "active":
		// A deferred boot of a host recorded fenced, offline, maintenance,
		// draining or joining wrote nothing: serving does not record it
		// active over that state. It gets its report as any moved-on host.
		return false, h.State, reportKeepingState(ctx, db, host, h.State, r)
	case h.State == "upgrading":
		// Recorded 'upgrading' since the boot: confirmed as ConfirmServing
		// would, rather than left unplaceable while it serves.
		from = "upgrading"
	case h.State != from:
		return false, h.State, reportKeepingState(ctx, db, host, h.State, r)
	}
	if beforeConfirmWrite != nil {
		beforeConfirmWrite()
	}
	applied, lostTo, err := corrosion.ActivateHostStartupFrom(ctx, db, host, from, r.Version, r.CPUs, r.MemMiB, r.DiskGiB, r.HasResources)
	if err != nil {
		return false, h.State, err
	}
	if lostTo != "" {
		return false, h.State, addressNotKept(host, lostTo)
	}
	if !applied {
		now, err := corrosion.GetHost(ctx, db, host)
		if err != nil {
			return false, "", err // retried
		}
		if now == nil {
			return false, "", ErrMovedOn
		}
		if now.State == "upgrading" {
			return false, now.State, errors.New("host turned 'upgrading' during the confirm; retried")
		}
		return false, now.State, reportKeepingState(ctx, db, host, now.State, r)
	}
	return true, "active", nil
}

// reportKeepingState writes the boot report r of a host recorded state,
// leaving the state as it is, and returns ErrMovedOn; a failed write returns
// its error instead, so the caller retries. An 'active' host gets the whole
// report, guarded on 'active': that rewrites 'active' and so re-dates when it
// became active (HostActiveSince, HostFenceLife) to the moment it serves. A
// 'draining' or 'maintenance' one gets its version and resources, which
// leave its membership row (and so its state's time) as it is; any other —
// fenced, offline, upgrading, joining — none at that observation. Eligibility
// for these version/resource writers is not guarded across their initial read:
// a concurrent fence can retain the report, while its membership state and
// timestamp remain untouched. This is separate from guarded activation above.
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
		return fmt.Errorf("reporting this boot to a host recorded %s: %w", state, err)
	}
	return ErrMovedOn
}

// beforeConfirmWrite, when set, runs between ConfirmServing's read and its
// write. Tests only.
var beforeConfirmWrite func()

// afterConfirmDeclined, when set, runs before the declined write's state read.
// Tests only; like beforeConfirmWrite, it must not be used by parallel tests.
var afterConfirmDeclined func()

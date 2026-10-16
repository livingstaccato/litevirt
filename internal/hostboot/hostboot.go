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
// Three rules keep that from hiding a host that should be fenced, or
// overwriting a decision made about it:
//
//   - only a SIGTERM of an ACTIVE host leaves the marker (MarkRestarting), and
//     the boot consumes it before its write (BootState): a daemon that
//     crash-loops boots 'active' as before, so it cannot keep re-arming the
//     'upgrading' timeout;
//   - the boot keeps 'upgrading' only while the host is still recorded
//     'upgrading' and the SIGTERM is younger than UpgradingTimeout: a host the
//     cluster may have fenced, put in maintenance or isolated while it was
//     down boots as before;
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
func BootState(ctx context.Context, db *corrosion.Client, host, dataDir string, upgradePending bool, now time.Time) Boot {
	at, marked := takeMarker(dataDir)
	if upgradePending {
		return Boot{State: "upgrading", Reason: "post-upgrade boot; the upgrade watchdog confirms it"}
	}
	if !marked {
		return Boot{State: "active", Reason: "no graceful stop recorded"}
	}
	if age := now.Sub(at); age < 0 || age >= UpgradingTimeout {
		return Boot{State: "active", Reason: fmt.Sprintf("the graceful stop was %s ago; the cluster may have acted on this host since", age.Round(time.Second))}
	}
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return Boot{State: "active", Reason: "this host's record is unreadable"}
	}
	if h.State != "upgrading" {
		return Boot{State: "active", Reason: "recorded " + h.State + " since the graceful stop"}
	}
	return Boot{State: "upgrading", AwaitServing: true, Reason: "graceful restart; active once this daemon serves"}
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

// beforeConfirmWrite, when set, runs between ConfirmServing's read and its
// write. Tests only.
var beforeConfirmWrite func()

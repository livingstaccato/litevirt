package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// THE OWN-ROW HOLD. A daemon makes no write to its own hosts row while that
// row is not the one the cluster admitted for the certificate it holds:
//
//   - arm (a): the row is live and names a serial other than the installed
//     certificate's. At start that is a machine re-added while its data
//     directory still held its old database (its row is the removed
//     machine's); at runtime it is a machine whose admission another one
//     superseded;
//   - arm (b): the row is a tombstone. At start, a machine re-added after its
//     database applied the removal; at runtime, a machine removed while up.
//
// A missing row is not an arm: an empty database has no stale base to
// protect, and the insert it makes is today's registration (and is refused,
// as an earlier incarnation, wherever the cluster holds a re-admitted row).
//
// The hold opens when the own row is live and names the installed serial —
// after anti-entropy from a peer that accepts the certificate, or a
// replicated re-admission. It is bounded by OwnRowHoldTimeout; on timeout the
// writers fall back to what they did before the hold existed, which a
// re-admitted cluster refuses by the incarnation counter. It never blocks the
// daemon: replication, anti-entropy and the gRPC server run throughout.

// ErrOwnRowHeld is returned by a write to this host's own hosts row while the
// own-row hold is engaged.
var ErrOwnRowHeld = errors.New("this host's own row is held until the cluster's admission for its certificate reaches this node")

// OwnRowHoldTimeout bounds a hold. A var so tests can shorten it.
var OwnRowHoldTimeout = 10 * time.Minute

// Own-row hold reasons.
const (
	OwnRowHeldAtStart    = "at_start"
	OwnRowHeldSuperseded = "superseded"
	OwnRowHeldRemoved    = "removed"
)

// OwnRowHoldStatus is the hold's state, for `lv health` (own_row_held).
type OwnRowHoldStatus struct {
	Held     bool
	TimedOut bool
	Arm      string // "a" (other serial) or "b" (tombstone)
	Reason   string // OwnRowHeldAtStart, OwnRowHeldSuperseded, OwnRowHeldRemoved
	Since    time.Time
	// InstalledSerial is the certificate this daemon serves; RecordedSerial
	// what its replica records for its name.
	InstalledSerial, RecordedSerial string
}

type ownRowHold struct {
	mu        sync.Mutex
	enabled   bool
	installed string
	st        OwnRowHoldStatus
	// onChange is called (outside mu) after an apply touched the own row.
	onChange atomic.Pointer[func()]
}

// ConfigureOwnRowHold enables the hold for this client's host, serving the
// certificate installedSerial, and evaluates it against the row as it stands:
// a hold raised now has reason OwnRowHeldAtStart. Called by the daemon before
// its first own-row write. An empty or unreadable serial disables the hold.
func (c *Client) ConfigureOwnRowHold(ctx context.Context, installedSerial string) (OwnRowHoldStatus, error) {
	h := &c.ownHold
	h.mu.Lock()
	h.enabled = installedSerial != "" && !strings.EqualFold(installedSerial, "unknown") && c.hostName != ""
	h.installed = installedSerial
	h.st = OwnRowHoldStatus{}
	h.mu.Unlock()
	return c.EvaluateOwnRowHold(ctx, OwnRowHeldAtStart)
}

// SetOwnRowChangeHook installs fn, called after every committed apply (either
// lane) that changed this host's own hosts row. The daemon re-evaluates the
// hold and runs its own-row reconcile from it.
func (c *Client) SetOwnRowChangeHook(fn func()) { c.ownHold.onChange.Store(&fn) }

// EvaluateOwnRowHold re-reads the own row and raises or opens the hold. reason
// names why a hold raised now is raised: OwnRowHeldAtStart at boot; at runtime
// the arm decides (superseded or removed).
func (c *Client) EvaluateOwnRowHold(ctx context.Context, reason string) (OwnRowHoldStatus, error) {
	h := &c.ownHold
	h.mu.Lock()
	enabled, installed := h.enabled, h.installed
	h.mu.Unlock()
	if !enabled {
		return OwnRowHoldStatus{}, nil
	}
	rows, err := c.Query(ctx, `SELECT cert_serial, deleted_at FROM hosts WHERE name = ?`, c.hostName)
	if err != nil {
		return c.OwnRowHold(), err
	}
	arm, recorded := "", ""
	if len(rows) == 1 {
		recorded = rows[0].String("cert_serial")
		switch {
		case rows[0].String("deleted_at") != "":
			arm = "b"
		case !strings.EqualFold(recorded, installed):
			arm = "a"
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case arm == "":
		h.st = OwnRowHoldStatus{}
	case !h.st.Held || h.st.Arm != arm:
		r := reason
		if r != OwnRowHeldAtStart {
			r = OwnRowHeldSuperseded
			if arm == "b" {
				r = OwnRowHeldRemoved
			}
		}
		h.st = OwnRowHoldStatus{Held: true, Arm: arm, Reason: r, Since: time.Now()}
	}
	if h.st.Held {
		h.st.InstalledSerial, h.st.RecordedSerial = installed, recorded
		if !h.st.TimedOut && time.Since(h.st.Since) >= OwnRowHoldTimeout {
			h.st.TimedOut = true
		}
	}
	return h.st, nil
}

// OwnRowHold returns the hold's current state.
func (c *Client) OwnRowHold() OwnRowHoldStatus {
	c.ownHold.mu.Lock()
	defer c.ownHold.mu.Unlock()
	st := c.ownHold.st
	if st.Held && !st.TimedOut && time.Since(st.Since) >= OwnRowHoldTimeout {
		c.ownHold.st.TimedOut = true
		st.TimedOut = true
	}
	return st
}

// ownRowWriteRefused returns ErrOwnRowHeld for a write to name while the hold
// is engaged and has not timed out. A timed-out hold lets the write through:
// the writers fall back to their behaviour before the hold, and a cluster
// that holds a later incarnation refuses the write by the counter.
func (c *Client) ownRowWriteRefused(name string) error {
	if name == "" || name != c.hostName {
		return nil
	}
	st := c.OwnRowHold()
	if st.Held && !st.TimedOut {
		return fmt.Errorf("%w (%s, arm %s, held %s)", ErrOwnRowHeld, st.Reason, st.Arm,
			time.Since(st.Since).Round(time.Second))
	}
	return nil
}

// OwnRowWritable is ownRowWriteRefused for writers outside this package (the
// daemon's address and endpoint reconcile, operator RPCs on this node).
func (c *Client) OwnRowWritable(name string) error { return c.ownRowWriteRefused(name) }

// noteOwnRowApplied fires the own-row hook after commit when a replicated
// hosts statement for this host changed a row.
func (c *Client) noteOwnRowApplied(tx *sql.Tx, s Statement, sh StmtShape) {
	if c.hostName == "" || c.ownHold.onChange.Load() == nil {
		return
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != 1 {
		return
	}
	if name, _ := pk[0].(string); name == c.hostName {
		c.deferAfterCommit(tx, c.fireOwnRowChange)
	}
}

// noteOwnRowMerged is noteOwnRowApplied for an anti-entropy row.
func (c *Client) noteOwnRowMerged(tx *sql.Tx, table syncTable, row []interface{}) {
	if c.hostName == "" || c.ownHold.onChange.Load() == nil || table.Name != "hosts" {
		return
	}
	if cellStr(row, columnIndexMap(table.Columns), "name") == c.hostName {
		c.deferAfterCommit(tx, c.fireOwnRowChange)
	}
}

func (c *Client) fireOwnRowChange() {
	if fn := c.ownHold.onChange.Load(); fn != nil && *fn != nil {
		go (*fn)()
	}
}

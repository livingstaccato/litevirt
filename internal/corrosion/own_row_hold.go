package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
// A row naming the certificate the installed one renewed is not an arm: a
// renewal (live, or while the host was down) re-records the serial at once, as
// it always has, and peers accept the successor. The installed certificate is
// read at every evaluation, so a live renewal is seen.
//
// The hold opens when the own row is live and names the installed serial —
// after anti-entropy from a peer that accepts the certificate, or a
// replicated re-admission. Every locally originated write to the own hosts
// row is refused while it holds (client.go, the local write paths). It never
// blocks the daemon: replication, anti-entropy and the gRPC server run
// throughout.
//
// Only a hold raised at start over a row at incarnation 0 times out
// (OwnRowHoldTimeout): the writers then fall back to what they did before the
// hold existed, which is the previous release's behaviour. A hold over a
// counted row, and every hold raised at runtime (superseded, removed), never
// times out: there the local row may be another machine's admission, and a
// write stamped with its key would be accepted everywhere and could move the
// name back to a machine the cluster has superseded.

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
	// Incarnation is the own row's incarnation when the hold was raised.
	Incarnation int64
	Arm         string // "a" (other serial) or "b" (tombstone)
	Reason      string // OwnRowHeldAtStart, OwnRowHeldSuperseded, OwnRowHeldRemoved
	Since       time.Time
	// InstalledSerial is the certificate this daemon serves; RecordedSerial
	// what its replica records for its name.
	InstalledSerial, RecordedSerial string
}

// InstalledCert reports the certificate this daemon serves: its serial and,
// for a renewal, the serial it renewed ("" otherwise). Lower-case hex.
type InstalledCert func() (serial, renewedFrom string)

// AdmissionMemory is this host's durable, host-local record of the admission
// it was last admitted under: the (incarnation, created_at) of its own row
// while that row named its certificate. It is what tells this machine's own
// admission from another machine's when its certificate was reissued outside
// `lv host renew-cert` (the auth.trust_rotated_peer_certs recovery). The
// daemon keeps it in its PKI directory (daemon/own_row.go). Load reports
// ok=false when there is none.
type AdmissionMemory interface {
	Load() (incarnation int64, createdAt string, ok bool)
	Store(incarnation int64, createdAt string) error
}

type ownRowHold struct {
	mu        sync.Mutex
	enabled   bool
	installed InstalledCert
	memory    AdmissionMemory
	st        OwnRowHoldStatus
	// onChange is called (outside mu) after an apply touched the own row.
	onChange atomic.Pointer[func()]
}

// ConfigureOwnRowHold enables the hold for this client's host, serving the
// certificate installed reports, and evaluates it against the row as it
// stands: a hold raised now has reason OwnRowHeldAtStart. Called by the daemon
// before its first own-row write. A nil installed disables the hold.
func (c *Client) ConfigureOwnRowHold(ctx context.Context, installed InstalledCert) (OwnRowHoldStatus, error) {
	h := &c.ownHold
	h.mu.Lock()
	h.enabled = installed != nil && c.hostName != ""
	h.installed = installed
	h.st = OwnRowHoldStatus{}
	h.mu.Unlock()
	return c.EvaluateOwnRowHold(ctx, OwnRowHeldAtStart)
}

// SetOwnAdmissionMemory installs the record of this host's own admission
// (AdmissionMemory). Call before ConfigureOwnRowHold. Nil: no memory, and a
// reissued certificate over a counted row is held, as for any other machine.
func (c *Client) SetOwnAdmissionMemory(m AdmissionMemory) {
	c.ownHold.mu.Lock()
	c.ownHold.memory = m
	c.ownHold.mu.Unlock()
}

// ownRowView is the own row as the hold judges it.
type ownRowView struct {
	found             bool
	serial, createdAt string
	deleted           bool
	n                 int64
}

// ownRowArm is the hold's arm over row for a host serving installed (which
// renewed renewedFrom), with mem the remembered own admission: "" when the row
// is this machine's to write, "a" when it names another certificate, "b"
// when it is removed. A missing row is not an arm.
//
// A row naming the installed certificate, or the one it renewed, is this
// machine's. So is a counted row whose key is the admission this machine
// remembers being admitted under: its certificate was reissued outside the
// renewal flow, and the re-record is its own. Another admission always has
// another key, so it is never mistaken for this one.
func ownRowArm(row ownRowView, installed, renewedFrom string, mem AdmissionMemory) string {
	switch {
	case !row.found:
		return ""
	case row.deleted:
		return "b"
	case strings.EqualFold(row.serial, installed):
		return ""
	case renewedFrom != "" && strings.EqualFold(row.serial, renewedFrom):
		return ""
	case row.n >= 1 && rememberedAdmission(mem, row):
		return ""
	default:
		return "a"
	}
}

// rememberedAdmission reports whether row is the admission mem remembers.
func rememberedAdmission(mem AdmissionMemory, row ownRowView) bool {
	if mem == nil {
		return false
	}
	n, at, ok := mem.Load()
	return ok && n == row.n && at == row.createdAt
}

const ownRowSelectSQL = `SELECT cert_serial, deleted_at, incarnation, created_at FROM hosts WHERE name = ?`

func ownRowFrom(rows []Row) ownRowView {
	if len(rows) != 1 {
		return ownRowView{}
	}
	r := rows[0]
	return ownRowView{found: true, serial: r.String("cert_serial"), deleted: r.String("deleted_at") != "",
		n: int64(r.Int("incarnation")), createdAt: r.String("created_at")}
}

// StaticInstalledCert is an InstalledCert that always reports serial.
func StaticInstalledCert(serial, renewedFrom string) InstalledCert {
	return func() (string, string) { return serial, renewedFrom }
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
	enabled, installedFn := h.enabled, h.installed
	h.mu.Unlock()
	if !enabled {
		return OwnRowHoldStatus{}, nil
	}
	installed, renewedFrom := installedFn()
	if installed == "" || strings.EqualFold(installed, "unknown") {
		return c.OwnRowHold(), nil // unreadable: change nothing
	}
	rows, err := c.Query(ctx, ownRowSelectSQL, c.hostName)
	if err != nil {
		return c.OwnRowHold(), err
	}
	row := ownRowFrom(rows)
	h.mu.Lock()
	mem := h.memory
	h.mu.Unlock()
	arm := ownRowArm(row, installed, renewedFrom, mem)
	// Remember the admission this machine holds: a live counted row naming
	// its certificate (or the one it renewed).
	if arm == "" && row.found && !row.deleted && row.n >= 1 && mem != nil && !rememberedAdmission(mem, row) &&
		(strings.EqualFold(row.serial, installed) || (renewedFrom != "" && strings.EqualFold(row.serial, renewedFrom))) {
		if err := mem.Store(row.n, row.createdAt); err != nil {
			slog.Warn("could not record this host's own admission", "incarnation", row.n, "error", err)
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
		h.st = OwnRowHoldStatus{Held: true, Arm: arm, Reason: r, Since: time.Now(), Incarnation: row.n}
	}
	if h.st.Held {
		h.st.InstalledSerial, h.st.RecordedSerial = installed, row.serial
		// A held row whose incarnation rose is another machine's admission:
		// the hold over it is a supersession now, and never times out,
		// whatever it was raised over.
		if row.n > h.st.Incarnation {
			h.st.Incarnation = row.n
			if h.st.Arm == "a" {
				h.st.Reason = OwnRowHeldSuperseded
			}
		}
		h.st.TimedOut = h.st.timedOut()
	}
	return h.st, nil
}

// timedOut reports whether a hold has run past its timeout. Only a hold
// raised at start over a row at incarnation 0 can (see THE OWN-ROW HOLD).
func (st OwnRowHoldStatus) timedOut() bool {
	return st.Held && st.Reason == OwnRowHeldAtStart && st.Incarnation == 0 &&
		time.Since(st.Since) >= OwnRowHoldTimeout
}

// OwnRowHold returns the hold's current state.
func (c *Client) OwnRowHold() OwnRowHoldStatus {
	c.ownHold.mu.Lock()
	defer c.ownHold.mu.Unlock()
	if c.ownHold.st.timedOut() {
		c.ownHold.st.TimedOut = true
	}
	return c.ownHold.st
}

// ownRowWriteRefused returns ErrOwnRowHeld for a write to name while the hold
// is engaged and has not timed out. A timed-out hold (at start, over a row at
// incarnation 0) lets the write through: the writers fall back to their
// behaviour before the hold.
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

// ownRowTables are the tables a host's own-row writers write, and the column
// naming the host: the hosts row and its split copies.
var ownRowTables = map[string]string{
	"hosts":           "name",
	"host_membership": "host_name",
	"host_runtime":    "host_name",
	"host_labels":     "host_name",
}

// ownRowStatementRefused refuses a locally originated statement about this
// host's own row (hosts or a split copy) unless the row, read now inside the
// write's transaction, is this machine's to write: every own-row writer goes
// through it, wherever it is called from (activation, capability labels,
// update labels, UpgradeHost, ...), and whatever the hold's last evaluation
// said. A timed-out hold lets through only a write over a row still at
// incarnation 0. Run by both local write paths (client.go).
func (c *Client) ownRowStatementRefused(ctx context.Context, tx *sql.Tx, s Statement) error {
	if c.hostName == "" || !strings.Contains(s.SQL, "host") {
		return nil
	}
	c.ownHold.mu.Lock()
	enabled, installedFn, mem := c.ownHold.enabled, c.ownHold.installed, c.ownHold.memory
	c.ownHold.mu.Unlock()
	if !enabled {
		return nil
	}
	sh, pkCols, err := parseResolved(s.SQL)
	if err != nil {
		return nil
	}
	col, ok := ownRowTables[sh.Table]
	if !ok {
		return nil
	}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != len(pkCols) {
		return nil
	}
	mine := false
	for i, c2 := range pkCols {
		if c2 == col {
			if name, _ := pk[i].(string); name == c.hostName {
				mine = true
			}
		}
	}
	if !mine {
		return nil
	}
	installed, renewedFrom := installedFn()
	if installed == "" || strings.EqualFold(installed, "unknown") {
		return c.ownRowWriteRefused(c.hostName)
	}
	var row ownRowView
	var serial, created, deleted sql.NullString
	err = tx.QueryRowContext(ctx, ownRowSelectSQL, c.hostName).Scan(&serial, &deleted, &row.n, &created)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil // a missing row is not an arm
	case err != nil:
		return err
	}
	row.found, row.serial, row.createdAt, row.deleted = true, serial.String, created.String, deleted.Valid && deleted.String != ""
	arm := ownRowArm(row, installed, renewedFrom, mem)
	if arm == "" {
		return nil
	}
	st := c.OwnRowHold()
	if st.Held && st.TimedOut && row.n == 0 {
		return nil // the timed-out fallback, over a row still at 0
	}
	return fmt.Errorf("%w (arm %s, row at incarnation %d names %s)", ErrOwnRowHeld, arm, row.n, row.serial)
}

// ErrReRecordAtCountedRow refuses re-recording this host's serial over a row
// at a counted incarnation that names a certificate other than the installed
// one or the one it renewed: that row is another machine's admission, and the
// re-record, stamped with its key, would be accepted everywhere and move the
// name to this machine.
var ErrReRecordAtCountedRow = errors.New("this host's own row is another admission's; its serial is not re-recorded over it")

// ErrCertSwappedAtRuntime refuses a running daemon's re-record of a
// certificate that is not a renewal of the one its counted row records: a
// certificate swapped while the daemon runs is held until it restarts, when
// the boot's registration decides it (reRecordRefused).
var ErrCertSwappedAtRuntime = errors.New("a certificate swapped while the daemon runs, not by a renewal, is re-recorded only once the daemon restarts")

// installedRenews reports whether serial is the installed certificate and a
// renewal of recorded (the hold's certificate source says so).
func (c *Client) installedRenews(serial, recorded string) bool {
	c.ownHold.mu.Lock()
	src := c.ownHold.installed
	c.ownHold.mu.Unlock()
	if src == nil {
		return false
	}
	installed, renewedFrom := src()
	return strings.EqualFold(installed, serial) && renewedFrom != "" && strings.EqualFold(renewedFrom, recorded)
}

// reRecordRefused decides a re-record of serial over the own row naming
// recorded at (n, createdAt). At incarnation 0 it is the previous release's
// behaviour and always allowed. At n ≥ 1 it is allowed for a renewal of the
// recorded certificate (the installed certificate names recorded as the one
// it renewed), and over the admission this machine remembers being admitted
// under (AdmissionMemory): a certificate reissued outside the renewal flow.
// Without the own-row hold's certificate source nothing proves either, and
// the re-record is refused.
func (c *Client) reRecordRefused(name, recorded, serial string, n int64, createdAt string) error {
	if n < 1 || name != c.hostName {
		return nil
	}
	c.ownHold.mu.Lock()
	src, mem := c.ownHold.installed, c.ownHold.memory
	c.ownHold.mu.Unlock()
	if src != nil {
		installed, renewedFrom := src()
		if strings.EqualFold(installed, serial) {
			if renewedFrom != "" && strings.EqualFold(renewedFrom, recorded) {
				return nil
			}
			if rememberedAdmission(mem, ownRowView{found: true, n: n, createdAt: createdAt}) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w (recorded %s, installed %s, incarnation %d)", ErrReRecordAtCountedRow, recorded, serial, n)
}

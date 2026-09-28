package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Host membership on a clock of its own (colonelpanik/litevirt#267).
//
// `hosts` is one row per host with ONE updated_at, and a dozen unrelated
// writers: the daemon reports its own version, schema and resources; operators
// configure fencing, role and region; the failover coordinator and operators
// move the host's state; a healthy peer records its isolation. Replication is
// statement-level with a row-level LWW gate, so two concurrent writes to
// DIFFERENT columns of the same host are not independent. A replica that
// applied the newer one first refuses the older one as stale, and the older
// write is lost there — or, when the two land at the same instant, the resolver
// rightly refuses to coin-flip `state` and the row stays divergent.
//
// This file gives the coordinator-owned columns a second home with a clock of
// their own:
//
//	hosts.state                              -> host_membership.state
//	hosts.isolation_epoch / isolation_reason -> host_membership.isolation_epoch / isolation_reason
//
// isolation_reason travels with the epoch because it is never written without
// it: IsolateHost sets both, ClearHostIsolation clears both. Nothing else about
// a host is written only by these writers, so nothing else moves in this slice;
// the operator-configured and self-reported columns (#267's host_config and
// host_runtime groups) stay on `hosts`. state and the isolation epoch still
// share host_membership's one clock with each other.
//
// THE ROLLING-UPGRADE CONTRACT. Two facts about a previous-release node decide
// the ordering, and both are facts about its binary:
//
//   - it has no ledger entry for any statement on host_membership, so a write
//     to it back-pressures that node's whole replication stream;
//   - it reads state and isolation from `hosts` and nowhere else.
//
// So nothing writes host_membership until host_membership_split_v1 has DURABLY
// latched on this node — a mandatory, ReplicationGated token, so the latch
// cannot form while any host this node replicates to is on the previous build.
// Until then every writer writes the hosts columns exactly as the previous
// release did, and every reader reads them.
//
// Once latched, SplitHostMembership copies every host's current values into
// host_membership, and from the end of this node's first complete pass
// ("live"):
//
//   - every writer of state and isolation writes BOTH homes, in one batch under
//     one updated_at: the hosts columns in their previous-release statement
//     shapes, and host_membership. The hosts copy is what keeps a rollback of
//     one release safe — a node back on the previous build reads hosts.state
//     and nothing else, and it must still see every drain, fence and
//     isolation. Nothing ever clears or freezes the hosts columns in this
//     release; retiring them is a later release's step behind a second token
//     (docs/design/host-membership-retire-old-columns.md).
//   - every reader resolves state and isolation from host_membership, falling
//     back to the hosts columns for a host that has no membership row yet.
//
// The hosts copy still shares the hosts row's clock, so it can still lose a
// concurrent write the way it always could — that copy is exactly as good as
// the previous release's, which is what a rolled-back reader needs. The
// membership copy is the one that no longer loses.
//
// THE READ RULE is not "the newer row wins". A version report makes the hosts
// row newer without saying anything about state, and on a replica that refused
// the hosts half of a concurrent state write (the #267 loss) the hosts row is
// newer AND its state is the stale one. So the membership row wins, except for
// a column whose hosts value has MOVED since this node last looked, on a hosts
// row newer than the membership row — see membershipRow.resolve.
//
// THE LATCH-SKEW WINDOW is what that exception is for. Latches form per node,
// so for a few seconds after one node latches its neighbour may not have yet,
// and that neighbour's writers write hosts only. Each node keeps
// host_membership_absorbed, a NODE-LOCAL record of the hosts values it last
// looked at; a hosts value that differs from the record, on a newer hosts row,
// is such a write. Readers take it at once and the next pass carries it into
// host_membership.
//
// The exception is honoured only for hostMembershipAbsorbWindow after this node
// went live. It has one false positive, and it is the reason for the bound:
// dual-writes move the hosts columns too, so a replica that received state S1
// (both halves), then a version report, then S2 — whose hosts half the newer
// version report refused — holds hosts.state = S1 on a newer hosts row. If no
// pass ran between S1 and S2 its record still predates S1, and S1 reads as a
// late write. Every pass and every local write refreshes the record, so this
// needs two state changes and a concurrent hosts write inside one pass
// interval — possible, and not something a steady-state cluster should be
// exposed to at all. Legacy writers only exist during the roll, so after the
// window the membership row simply wins.
//
// Two further limits, both of the window. A late write is stamped with the
// hosts row's updated_at, not the instant of the write. And a node that takes
// its first record after a late write reached it keeps that write as its
// baseline, relying on a node whose record predates it to carry it across.
//
// TIMESTAMPS. A copied row takes the hosts row's updated_at, never NowTS, for
// the #268 reason: every node copies the same replicated hosts row, so every
// node writes the same membership row and the copies converge instead of
// racing, and a node whose hosts row is behind copies an OLDER timestamp that
// loses to a fresher node's copy.

// hostMembershipLiveFile is the durable half of "this node has completed a
// split pass", holding the instant it did. NODE-LOCAL: it describes which
// columns this node's readers trust.
const hostMembershipLiveFile = "host_membership_live"

// hostMembershipAbsorbWindow is how long after going live a node recognises a
// write to the hosts columns made by a node that has not latched yet. Per-node
// latches form within one capability-driver cycle of each other on a healthy
// fleet; this is generous against that, and short against the steady state.
var hostMembershipAbsorbWindow = 10 * time.Minute

// SetHostMembershipGate injects the predicate that permits WRITING
// host_membership. Wired at daemon start, before the host's first write, to
// the durable host_membership_split_v1 latch marker.
//
// Nil-safe and FAIL CLOSED: an unset gate writes the hosts columns only, which
// is exactly the previous release's behaviour. A wiring omission costs the
// split and never a peer's replication stream. The test constructors leave it
// closed; a test that wants the split opens it itself.
func (c *Client) SetHostMembershipGate(fn func() bool) { c.hostMembershipGate = fn }

// MayWriteHostMembership reports whether this node may write host_membership
// (nil-safe, fail closed).
func (c *Client) MayWriteHostMembership() bool {
	return c.hostMembershipGate != nil && c.hostMembershipGate()
}

// HostMembershipLive reports whether this node has completed a split pass with
// the gate open: its writers write host_membership and its readers read it.
func (c *Client) HostMembershipLive() bool {
	if c.hostMembershipLive.Load() {
		return true
	}
	// The marker only matters for a node that went live in an EARLIER
	// process: in this one, markHostMembershipLive sets the flag. So it is
	// consulted once, not on every read — HostIsolation runs per replication
	// push.
	if c.dataDir == "" || c.hostMembershipLiveChecked.Swap(true) {
		return false
	}
	path := filepath.Join(c.dataDir, hostMembershipLiveFile)
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	since := fi.ModTime()
	if b, err := os.ReadFile(path); err == nil {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b))); err == nil {
			since = t
		}
	}
	c.hostMembershipLiveSince.Store(since.UnixNano())
	c.hostMembershipLive.Store(true)
	return true
}

func (c *Client) markHostMembershipLive() {
	if c.hostMembershipLive.Load() {
		return
	}
	now := time.Now().UTC()
	c.hostMembershipLiveSince.Store(now.UnixNano())
	c.hostMembershipLive.Store(true)
	if c.dataDir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(c.dataDir, hostMembershipLiveFile),
		[]byte(now.Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
		// In-memory the node is live. After a restart it reads the hosts
		// columns until its first pass — the pre-split behaviour, and safe,
		// because every live write also writes them. The next pass retries.
		c.hostMembershipLive.Store(false)
		slog.Warn("host membership split: could not persist the live marker; retrying next pass", "error", err)
	}
}

// membershipView is how this node reads membership right now: live says
// whether host_membership is read at all, absorb whether a late write to the
// hosts columns is still recognised (THE LATCH-SKEW WINDOW).
func (c *Client) membershipView() (live, absorb bool) {
	if !c.HostMembershipLive() {
		return false, false
	}
	since := time.Unix(0, c.hostMembershipLiveSince.Load())
	return true, time.Since(since) < hostMembershipAbsorbWindow
}

// membershipVals are the columns this slice moves.
type membershipVals struct {
	State  string
	Epoch  int64
	Reason string
}

// membershipRow is one host as a reader or the pass sees it: its hosts columns
// and updated_at, its host_membership row, and this node's absorbed record.
type membershipRow struct {
	name       string
	hosts      membershipVals
	hostsTS    string
	memPresent bool
	mem        membershipVals
	memTS      string
	absPresent bool
	abs        membershipVals
}

// resolve is THE read rule, shared by every reader and by the pass.
//
// Before this node is live, or for a host with no membership row, the hosts
// columns — what the previous release reads. Otherwise the membership row.
// While absorb holds, a column whose hosts value has moved since this node last
// looked AND whose hosts row is newer than the membership row is taken from
// hosts: a write made by a node whose latch had not formed yet. state and the
// isolation pair are judged separately, so a late state change does not undo an
// isolation recorded in host_membership, or vice versa.
func (r membershipRow) resolve(live, absorb bool) membershipVals {
	if !live || !r.memPresent {
		return r.hosts
	}
	out := r.mem
	if absorb && r.absPresent && lwwOrder(r.memTS, r.hostsTS) < 0 {
		if r.hosts.State != r.abs.State {
			out.State = r.hosts.State
		}
		if r.hosts.Epoch != r.abs.Epoch || r.hosts.Reason != r.abs.Reason {
			out.Epoch, out.Reason = r.hosts.Epoch, r.hosts.Reason
		}
	}
	return out
}

// membershipCols and membershipJoins are the read side of a host's membership,
// for any query over `hosts h`. Qualified and aliased, so they can sit beside
// other hosts columns.
const (
	membershipCols = `h.state AS h_state, h.isolation_epoch AS h_epoch,
		COALESCE(h.isolation_reason, '') AS h_reason, h.updated_at AS h_ts,
		m.host_name AS m_key, m.state AS m_state, m.isolation_epoch AS m_epoch,
		m.isolation_reason AS m_reason, m.updated_at AS m_ts,
		a.host_name AS a_key, a.state AS a_state, a.isolation_epoch AS a_epoch,
		a.isolation_reason AS a_reason`
	membershipJoins = ` LEFT JOIN host_membership m ON m.host_name = h.name AND m.deleted_at IS NULL
		LEFT JOIN host_membership_absorbed a ON a.host_name = h.name`
	membershipScanSQL = `SELECT h.name AS name, ` + membershipCols + ` FROM hosts h` + membershipJoins
)

func membershipRowFrom(r Row, name string) membershipRow {
	return membershipRow{
		name:       name,
		hosts:      membershipVals{State: r.String("h_state"), Epoch: r.Int64("h_epoch"), Reason: r.String("h_reason")},
		hostsTS:    r.String("h_ts"),
		memPresent: r.String("m_key") != "",
		mem:        membershipVals{State: r.String("m_state"), Epoch: r.Int64("m_epoch"), Reason: r.String("m_reason")},
		memTS:      r.String("m_ts"),
		absPresent: r.String("a_key") != "",
		abs:        membershipVals{State: r.String("a_state"), Epoch: r.Int64("a_epoch"), Reason: r.String("a_reason")},
	}
}

func scanMembership(ctx context.Context, c *Client, where string, args ...interface{}) ([]membershipRow, error) {
	rows, err := c.Query(ctx, membershipScanSQL+where, args...)
	if err != nil {
		return nil, err
	}
	out := make([]membershipRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, membershipRowFrom(r, r.String("name")))
	}
	return out, nil
}

// hostMembershipOf resolves one live host's membership, nil when the host has
// no live hosts row.
func hostMembershipOf(ctx context.Context, c *Client, host string) (*membershipVals, error) {
	rows, err := scanMembership(ctx, c, ` WHERE h.name = ? AND h.deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	v := rows[0].resolve(c.membershipView())
	return &v, nil
}

// resolvedHostStates is every live host's resolved state, by name.
func resolvedHostStates(ctx context.Context, c *Client) (map[string]string, error) {
	rows, err := scanMembership(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	live, absorb := c.membershipView()
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.name] = r.resolve(live, absorb).State
	}
	return out, nil
}

// The membership writers. Both upserts are explicit on the primary key, so the
// origin applies them whether or not it holds the row and a receiver LWW-gates
// them on updated_at (DispExplicitUpsert).
const (
	// hostMembershipUpsertSQL writes every column: the pass's copy, and a
	// carried-across late write.
	hostMembershipUpsertSQL = `INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET state = excluded.state,
		   isolation_epoch = excluded.isolation_epoch, isolation_reason = excluded.isolation_reason,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	// hostMembershipStateSQL changes state and nothing else on a row that
	// exists. The isolation values are only used by a receiver that has no row
	// yet, which takes them from the writer's view.
	hostMembershipStateSQL = `INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET state = excluded.state,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	// The isolation writers keep hosts' guards: record only over epoch 0,
	// clear only the pinned epoch (isolation.go says why).
	hostMembershipIsolateSQL = `UPDATE host_membership SET isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE host_name = ? AND deleted_at IS NULL AND isolation_epoch = 0`
	hostMembershipClearIsolationSQL = `UPDATE host_membership SET isolation_epoch = 0, isolation_reason = '', updated_at = ?
		 WHERE host_name = ? AND deleted_at IS NULL AND isolation_epoch = ?`
)

// membershipEpochIs is the guard of a live isolation write: host has a live
// membership row whose epoch is want. Evaluated inside the write's transaction.
func membershipEpochIs(ctx context.Context, host string, want int64) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var got int64
		err := tx.QueryRowContext(ctx,
			`SELECT isolation_epoch FROM host_membership WHERE host_name = ? AND deleted_at IS NULL`, host).Scan(&got)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return got == want, nil
	}
}

// absorbedUpsertSQL records the hosts values this node last looked at. LOCAL
// only (execLocal): never on the replication stream.
const absorbedUpsertSQL = `INSERT INTO host_membership_absorbed (host_name, state, isolation_epoch, isolation_reason)
	 VALUES (?, ?, ?, ?)
	 ON CONFLICT(host_name) DO UPDATE SET state = excluded.state,
	   isolation_epoch = excluded.isolation_epoch, isolation_reason = excluded.isolation_reason`

// HostMembershipReport is what one SplitHostMembership pass did.
type HostMembershipReport struct {
	// Copied counts hosts given their first membership row.
	Copied int
	// Absorbed counts late hosts-column writes carried across.
	Absorbed int
}

// membershipCopyTS is the updated_at a copied row carries: the hosts row's. See
// TIMESTAMPS above.
func (c *Client) membershipCopyTS(hostsTS string) string {
	if _, ok := tsInstant(hostsTS); ok {
		return hostsTS
	}
	return c.NowTS()
}

// SplitHostMembership copies hosts' state and isolation into host_membership,
// and — inside the absorb window — carries across a later write to those hosts
// columns by a node that had not latched yet. It never writes the hosts
// columns. It does nothing unless the host_membership_split_v1 gate is open,
// and it is idempotent. The daemon runs it at start and periodically, and
// every membership writer runs it first. Its replicated writes go out on the
// WAL lane and are repaired by public anti-entropy.
func (c *Client) SplitHostMembership(ctx context.Context) (HostMembershipReport, error) {
	if !c.MayWriteHostMembership() {
		return HostMembershipReport{}, nil
	}
	c.hostMembershipMu.Lock()
	defer c.hostMembershipMu.Unlock()
	return c.splitHostMembershipLocked(ctx)
}

func (c *Client) splitHostMembershipLocked(ctx context.Context) (HostMembershipReport, error) {
	var rep HostMembershipReport
	rows, err := scanMembership(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return rep, fmt.Errorf("host membership split: scan: %w", err)
	}
	// Before its first pass a node has no record to absorb against; its
	// window opens when the pass marks it live.
	_, absorb := c.membershipView()
	var firstErr error
	note := func(host string, err error) {
		slog.Warn("host membership split: pass incomplete; retrying next cycle", "host", host, "error", err)
		if firstErr == nil {
			firstErr = fmt.Errorf("host membership split: %s: %w", host, err)
		}
	}
	for _, r := range rows {
		switch {
		case !r.memPresent:
			if err := c.writeMembershipRow(ctx, r.name, r.hosts, c.membershipCopyTS(r.hostsTS)); err != nil {
				note(r.name, err)
				continue
			}
			rep.Copied++
		case !r.absPresent:
			// A membership row this node did not write (a peer's copy, or a
			// host created since the split): take its current hosts values as
			// the baseline and trust the row.
		case r.hosts != r.abs:
			// A hosts column moved since this node last looked: a dual-write
			// (whose membership half already says the same), or a late write.
			if merged := r.resolve(true, absorb); merged != r.mem {
				// resolve only departs from r.mem when the hosts row is the
				// newer one, so its updated_at beats the membership row's.
				if err := c.writeMembershipRow(ctx, r.name, merged, r.hostsTS); err != nil {
					note(r.name, err)
					continue
				}
				rep.Absorbed++
			}
		default:
			continue
		}
		if err := c.execLocal(ctx, absorbedUpsertSQL, r.name, r.hosts.State, r.hosts.Epoch, r.hosts.Reason); err != nil {
			note(r.name, err)
		}
	}
	if firstErr == nil {
		c.markHostMembershipLive()
	}
	return rep, firstErr
}

// writeMembershipRow is the pass's one replicated write. It takes updatedAt
// from its caller because the pass stamps the HOSTS row's updated_at, never a
// fresh clock (see TIMESTAMPS above).
func (c *Client) writeMembershipRow(ctx context.Context, host string, v membershipVals, updatedAt string) error {
	return c.Execute(ctx, hostMembershipUpsertSQL, host, v.State, v.Epoch, v.Reason, updatedAt)
}

// withMembershipWrite runs a state or isolation writer. live is true when the
// writer must write host_membership as well as the hosts columns, false when it
// writes the hosts columns only (the gate is closed, or this node has not
// completed a pass yet).
//
// With the gate open it holds hostMembershipMu and runs the split pass first,
// so the writer works from what the pass just carried across — without it a
// writer that bumped the membership row's clock could bury a late hosts write
// the pass had not seen yet.
func (c *Client) withMembershipWrite(ctx context.Context, fn func(live bool) error) error {
	if !c.MayWriteHostMembership() {
		return fn(false)
	}
	c.hostMembershipMu.Lock()
	defer c.hostMembershipMu.Unlock()
	if _, err := c.splitHostMembershipLocked(ctx); err != nil {
		slog.Warn("host membership split: pass before a membership write failed", "error", err)
	}
	return fn(c.HostMembershipLive())
}

// currentIsolation is host's resolved isolation, for a live state writer's
// insert values: a receiver with no membership row for the host yet takes them.
func currentIsolation(ctx context.Context, c *Client, host string) (int64, string, error) {
	cur, err := hostMembershipOf(ctx, c, host)
	if err != nil || cur == nil {
		return 0, "", err
	}
	return cur.Epoch, cur.Reason, nil
}

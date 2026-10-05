package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Holding a host's audit rows until its own chain has caught up.
//
// A host is the only writer of its audit sub-chain, and InsertAuditLog chains
// each row onto the tail it reads from the LOCAL replica. That is sound only
// while the local replica holds everything the host has ever written. A host
// rebuilt on an empty database and re-added under its old name does not: its
// history is on its peers and arrives by anti-entropy some time after the
// daemon starts. On the kvm003-f3 lab (drill 6) the rebuilt daemon audited its
// first actions within seconds, chained them onto the empty tail — seq 1,
// prev_hash "" — and opened a second chain under a host name that already had
// one. Every node then reported a hash mismatch and duplicated sequence numbers,
// permanently, since signed rows are never resealed. A node restored from an
// older snapshot is the same hazard with a shorter gap.
//
// The verifier stays strict. Accepting "a signed chain restart" as legitimate
// would let a host truncate its own history and start again, which is the
// attack the chain exists to show. So the writer waits instead: while a hold is
// configured and the tail is not yet trusted, every row for this host is HELD —
// written to a spool directory, durably, so a restart in that window loses
// nothing — and lands, in the order it was audited, once the tail is the real
// one. Its stamp is the moment it was audited, not the moment it landed.
//
// The tail is trusted once:
//
//   - the replica has caught up: an anti-entropy exchange with a peer has
//     completed (Client.ReplicaCaughtUp), so the local audit_log, the
//     lifecycle records and the chain heads hold everything that peer held; and
//   - the local tail has reached everything the cluster's own records say the
//     chain reached: every verified retirement boundary of the host's keys
//     (the `lv host rm` that preceded a rebuild records one, CA-signed, at the
//     tail it removed the host at) and every verified chain head within its
//     key's standing (auditCatchUpTarget).
//
// The second condition cannot hold forever. A retirement boundary an operator
// raised past the real tail, or a head published by a leaked key, can name a
// sequence no row will ever reach. After auditCatchUpPatience of a caught-up
// replica the shortfall is not replication lag, and the hold opens with an
// error naming it: the rows land, and if they fork, `lv audit verify` says so.
//
// A cluster of one has nobody to catch up with. A node that sees no peer — no
// gossip member and no other live host row — is trusted at once if it founded
// the cluster (no join peers configured) or already holds history of its own. A
// node configured to JOIN an existing cluster that holds none of its own history
// is exactly the rebuilt host, and it waits: at its first start its hosts table
// can name only itself before gossip has formed.
//
// Holding costs a restart up to one anti-entropy interval of audit latency (the
// rows are not lost; they land with their original stamps). That is the price
// of not being able to tell a restart from a rebuild locally, and it is paid
// only until the first exchange completes.

// AuditHoldDirName is the spool directory under the daemon's data dir.
const AuditHoldDirName = "audit-hold"

// maxHeldAuditRows bounds the spool. A host that cannot catch up for long enough
// to audit this many actions has a problem an unbounded disk write would only
// hide; past it a row is logged in full at error level and not written.
var maxHeldAuditRows = 10000

// auditCatchUpPatience is how long a caught-up replica may stay short of what
// the cluster's records say this host's chain reached before the hold opens
// anyway. It matches headSettleWindow, the verifier's own bound on replication
// lag. A var so tests can shorten it.
var auditCatchUpPatience = headSettleWindow

// auditHoldRecheck is how long a computed catch-up target is reused while the
// hold is closed: it reads and verifies every lifecycle record and chain head,
// which is not free on a busy audit path.
const auditHoldRecheck = time.Second

// auditHoldLogEvery bounds the "still holding" warning.
const auditHoldLogEvery = time.Minute

// ErrAuditChainNotCaughtUp is returned by AdoptAuditKey while this host's audit
// rows are held: a contract start taken from a replica that does not yet hold
// the host's history would claim, or excuse, the wrong rows, permanently.
var ErrAuditChainNotCaughtUp = errors.New("this host's audit chain has not caught up from its peers yet")

// AuditHoldConfig configures HoldAuditUntilCaughtUp.
type AuditHoldConfig struct {
	// Host is the host whose rows are held — the daemon's own. Rows for any
	// other host name are never held.
	Host string
	// Joiner is true when this node was set up to join an existing cluster
	// (join_peers configured). A joiner with no history of its own is never
	// trusted as a cluster of one.
	Joiner bool
	// SpoolDir is where held rows are kept. Empty holds them in memory only,
	// which is for tests: a daemon restart then loses them.
	SpoolDir string
}

// HoldAuditUntilCaughtUp makes this client hold cfg.Host's audit rows until its
// chain tail is trustworthy (see the comment at the top of this file). Rows
// already spooled under cfg.SpoolDir by an earlier process are kept, and land
// with the first rows after the hold opens. Unset, nothing is held, which is
// every client but a daemon's.
func (c *Client) HoldAuditUntilCaughtUp(cfg AuditHoldConfig) {
	h := &auditHold{cfg: cfg}
	if cfg.SpoolDir != "" {
		names, _ := filepath.Glob(filepath.Join(cfg.SpoolDir, "*.json"))
		h.count = len(names)
	}
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	c.auditChain.hold = h
	if t := c.auditChain.tails[cfg.Host]; t != nil {
		t.ready = false
	}
}

// AuditChainHeld reports whether hostName's audit rows are still being held,
// re-checking first, so a caller polling it is also what lands the held rows
// when nothing else is being audited. False when no hold is configured.
func (c *Client) AuditChainHeld(ctx context.Context, hostName string) bool {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != hostName {
		return false
	}
	return !c.openAuditChainLocked(ctx, c.auditChain.tail(hostName), h)
}

// auditHold is the state of one host's hold. Guarded by chainState.mu.
type auditHold struct {
	cfg        AuditHoldConfig
	mem        []heldAuditRow // held rows when there is no spool, or the spool failed
	count      int            // rows held, spooled and in memory
	ordinal    int64          // orders rows held in the same nanosecond
	caughtUpAt time.Time      // first time the replica was seen caught up
	target     int64          // the last auditCatchUpTarget, and when it was read
	targetAt   time.Time
	loggedAt   time.Time
}

// heldAuditRow is one held row as spooled.
type heldAuditRow struct {
	Record AuditRecord `json:"record"`
	// At is the moment a generated stamp is taken from (RFC3339Nano) — when
	// the action was audited. Empty for a caller-supplied stamp, which
	// Record.Timestamp carries verbatim.
	At      string `json:"at,omitempty"`
	HeldAt  int64  `json:"held_at"`
	Ordinal int64  `json:"ordinal"`

	path string // the spool file, when it came from one
}

// holdAuditLocked holds r instead of appending it, when the hold applies and
// has not opened. It reports whether r was held. Caller holds chainState.mu.
func (c *Client) holdAuditLocked(ctx context.Context, tail *chainTail, r AuditRecord, generated bool) (bool, error) {
	h := c.auditChain.hold
	if h == nil || r.HostName != h.cfg.Host || tail.ready {
		return false, nil
	}
	if c.openAuditChainLocked(ctx, tail, h) {
		return false, nil
	}
	h.ordinal++
	row := heldAuditRow{Record: r, HeldAt: time.Now().UnixNano(), Ordinal: h.ordinal}
	if generated {
		row.At = c.now().UTC().Format(time.RFC3339Nano)
		row.Record.Timestamp = ""
	}
	c.spoolAuditLocked(h, row)
	return true, nil
}

// spoolAuditLocked keeps row until the hold opens: on disk when there is a
// spool, in memory otherwise or when the disk write fails. An id already held
// is not held twice — the first row with an id is the one InsertAuditLog keeps.
func (c *Client) spoolAuditLocked(h *auditHold, row heldAuditRow) {
	for _, m := range h.mem {
		if m.Record.ID == row.Record.ID {
			return
		}
	}
	var path string
	if h.cfg.SpoolDir != "" {
		path = heldAuditPath(h.cfg.SpoolDir, row.Record.ID)
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
	if h.count >= maxHeldAuditRows {
		slog.Error("audit row NOT written: this host's audit chain has not caught up from its peers and "+
			"the hold is full; the row is recorded here and nowhere else",
			"limit", maxHeldAuditRows, "id", row.Record.ID, "action", row.Record.Action,
			"target", row.Record.Target, "detail", row.Record.Detail, "result", row.Record.Result,
			"username", row.Record.Username, "host", row.Record.HostName, "at", row.At)
		return
	}
	h.count++
	if path != "" {
		err := writeHeldAudit(h.cfg.SpoolDir, path, row)
		if err == nil {
			return
		}
		slog.Error("could not spool a held audit row to disk; it is held in memory and is lost "+
			"if the daemon stops before this host's audit chain catches up",
			"id", row.Record.ID, "action", row.Record.Action, "error", err)
	}
	h.mem = append(h.mem, row)
}

// heldAuditPath names a held row's spool file by a hash of its id: ids are
// caller-supplied and need not be file-name safe.
func heldAuditPath(dir, id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json")
}

func writeHeldAudit(dir, path string, row heldAuditRow) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if err := secretfile.Write(path, data, 0o600); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// openAuditChainLocked opens the hold when the tail can be trusted: it re-reads
// the tail from the caught-up replica — whatever an earlier reader cached — and
// lands every held row on it. Reports whether the hold is open.
func (c *Client) openAuditChainLocked(ctx context.Context, tail *chainTail, h *auditHold) bool {
	if tail.ready {
		return true
	}
	now := time.Now()
	ok, why := c.auditTailCaughtUp(ctx, h)
	if !ok {
		if h.loggedAt.IsZero() || now.Sub(h.loggedAt) >= auditHoldLogEvery {
			h.loggedAt = now
			slog.Warn("holding this host's audit rows until its own audit chain has caught up from its "+
				"peers; appending to a tail that is not the real one would fork the chain for good",
				"host", h.cfg.Host, "held", h.count, "reason", why)
		}
		return false
	}
	// Re-read, never trust what is cached: PublishAuditChainHead, HostTailSeq
	// and the startup reseal all load the tail, and on a rebuilt host they did
	// so from the empty replica.
	var fresh chainTail
	if err := loadHostTail(ctx, c, h.cfg.Host, &fresh); err != nil {
		slog.Warn("could not read this host's audit chain tail; its audit rows stay held",
			"host", h.cfg.Host, "error", err)
		return false
	}
	tail.hash, tail.seq = fresh.hash, fresh.seq
	if raisesStampCeiling(fresh.ts, tail.ts) {
		tail.ts = fresh.ts
	}
	tail.known = true
	n, err := c.landHeldAuditLocked(ctx, tail, h)
	if err != nil {
		slog.Error("could not append this host's held audit rows; they stay held and are retried",
			"host", h.cfg.Host, "landed", n, "error", err)
		return false
	}
	tail.ready = true
	slog.Info("this host's audit chain has caught up from its peers; held audit rows appended after "+
		"its real tail", "host", h.cfg.Host, "after_seq", fresh.seq, "landed", n)
	return true
}

// auditTailCaughtUp reports whether h's host may append to the tail its local
// replica holds, and if not, why.
func (c *Client) auditTailCaughtUp(ctx context.Context, h *auditHold) (bool, string) {
	host := h.cfg.Host
	caught, why := c.ReplicaCaughtUp()
	if !caught {
		alone, err := c.auditClusterOfOne(ctx, host)
		if err != nil {
			return false, why + " (and the hosts table could not be read: " + err.Error() + ")"
		}
		if !alone {
			return false, why
		}
		if !h.cfg.Joiner {
			return true, "" // the founder of a cluster of one: nobody holds rows it lacks
		}
		if local, err := freshHostTailSeq(ctx, c, host); err == nil && local > 0 {
			return true, "" // alone, with its own history on disk
		}
		return false, why + "; this node was set up to join a cluster and holds none of its own " +
			"audit history, so a peer may hold rows of its chain it has not seen"
	}
	if h.caughtUpAt.IsZero() {
		h.caughtUpAt = time.Now()
	}
	local, err := freshHostTailSeq(ctx, c, host)
	if err != nil {
		return false, err.Error()
	}
	// The target reads and verifies every lifecycle record and head, which is
	// not free on an audit path, so a recent one is reused. A local tail that
	// has moved past the reused value is checked against a fresh one: the target
	// only rises, and opening must never rest on a stale low reading.
	if h.targetAt.IsZero() || time.Since(h.targetAt) >= auditHoldRecheck || local >= h.target {
		target, err := auditCatchUpTarget(ctx, c, c.AuditKeyringOf(), host)
		if err != nil {
			return false, "could not read what the cluster records about this host's chain: " + err.Error()
		}
		h.target, h.targetAt = target, time.Now()
	}
	target := h.target
	if local >= target {
		return true, ""
	}
	if waited := time.Since(h.caughtUpAt); waited >= auditCatchUpPatience {
		slog.Error("this host's audit chain is still short of what the cluster's records say it reached, "+
			"long after its replica caught up; appending anyway rather than holding its audit rows "+
			"forever. If the missing rows exist somewhere they will fork the chain and `lv audit verify` "+
			"reports it; a retirement boundary or chain head naming a sequence that was never written "+
			"cannot be met at all",
			"host", host, "local_tail", local, "attested", target, "waited", waited.Round(time.Second))
		return true, ""
	}
	return false, fmt.Sprintf("the replica has caught up, but this node's copy of its own chain ends at "+
		"seq %d and the cluster's records say it reached %d", local, target)
}

// auditClusterOfOne reports whether this node sees no peer at all: no gossip
// member and no other live host row. Both, because either can be empty on a
// node that has peers (grpcapi.Server.clusterOfOne).
func (c *Client) auditClusterOfOne(ctx context.Context, self string) (bool, error) {
	if len(c.Members()) > 0 {
		return false, nil
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h.Name != self {
			return false, nil
		}
	}
	return true, nil
}

// auditCatchUpTarget is the furthest sequence the cluster's own verified records
// say hostName's chain reached: every retirement boundary of its keys, and every
// chain head — a retired key's head only up to its boundary, since past it the
// key has no standing. A local tail below this is behind its own history.
func auditCatchUpTarget(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string) (int64, error) {
	lifecycle, err := auditKeyLifecycle(ctx, c, keyring)
	if err != nil {
		return 0, err
	}
	retired := retirementsFrom(lifecycle)
	var target int64
	for lk, seq := range retired {
		if lk.host == hostName && seq > target {
			target = seq
		}
	}
	if keyring == nil {
		return target, nil // a head nobody can verify asserts nothing
	}
	heads, err := latestAuditHeadsByKey(ctx, c)
	if err != nil {
		return 0, err
	}
	for _, h := range heads[hostName] {
		if err := keyring.VerifyHead(ctx, c, hostName, h.Epoch, h.Seq, h.HeadHash,
			h.KeyID, h.Signature, h.CreatedAt); err != nil {
			continue
		}
		seq := h.Seq
		if boundary, ok := retired[lifecycleKey{host: hostName, keyID: h.KeyID}]; ok && seq > boundary {
			seq = boundary
		}
		if seq > target {
			target = seq
		}
	}
	return target, nil
}

// landHeldAuditLocked appends every held row, oldest first, and forgets each
// once it is in. Caller holds chainState.mu and has loaded the tail.
func (c *Client) landHeldAuditLocked(ctx context.Context, tail *chainTail, h *auditHold) (int, error) {
	rows := append([]heldAuditRow(nil), h.mem...)
	if h.cfg.SpoolDir != "" {
		names, err := filepath.Glob(filepath.Join(h.cfg.SpoolDir, "*.json"))
		if err != nil {
			return 0, err
		}
		for _, path := range names {
			if strings.HasPrefix(filepath.Base(path), ".") {
				continue // a writer's temp file
			}
			row, err := readHeldAudit(path)
			if err != nil || row.Record.HostName != h.cfg.Host {
				reason := "not a held audit row for this host"
				if err != nil {
					reason = err.Error()
				}
				slog.Error("audit hold: spool file not appended; it is kept beside the spool as .rejected",
					"file", path, "reason", reason)
				_ = os.Rename(path, strings.TrimSuffix(path, ".json")+".rejected")
				continue
			}
			row.path = path
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, k int) bool {
		if rows[i].HeldAt != rows[k].HeldAt {
			return rows[i].HeldAt < rows[k].HeldAt
		}
		return rows[i].Ordinal < rows[k].Ordinal
	})
	landed := 0
	for _, row := range rows {
		var at time.Time
		if row.At != "" {
			if t, err := time.Parse(time.RFC3339Nano, row.At); err == nil {
				at = t
			} else {
				at = c.now()
			}
		}
		if err := insertAuditLocked(ctx, c, tail, row.Record, at); err != nil {
			return landed, fmt.Errorf("append held audit row %s: %w", row.Record.ID, err)
		}
		landed++
		if row.path != "" {
			if err := os.Remove(row.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return landed, fmt.Errorf("remove landed audit row %s from the spool: %w", row.Record.ID, err)
			}
		} else {
			for i, m := range h.mem {
				if m.Record.ID == row.Record.ID {
					h.mem = append(h.mem[:i], h.mem[i+1:]...)
					break
				}
			}
		}
	}
	h.count = len(h.mem)
	return landed, nil
}

func readHeldAudit(path string) (heldAuditRow, error) {
	var row heldAuditRow
	fi, err := os.Lstat(path)
	if err != nil {
		return row, err
	}
	if !fi.Mode().IsRegular() {
		return row, fmt.Errorf("not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return row, err
	}
	if err := json.Unmarshal(data, &row); err != nil {
		return row, err
	}
	if row.Record.ID == "" || filepath.Base(heldAuditPath("", row.Record.ID)) != filepath.Base(path) {
		return row, fmt.Errorf("row id does not match its file name")
	}
	return row, nil
}

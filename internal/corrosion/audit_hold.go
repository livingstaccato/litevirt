package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Holding a rebuilt host's audit rows until its own chain has arrived.
//
// A host is the only writer of its audit sub-chain, and InsertAuditLog chains
// each row onto the tail it reads from the LOCAL replica. A host rebuilt on an
// empty database and re-added under its old name has none of its history
// locally: it is on its peers, and arrives by anti-entropy some time after the
// daemon starts. On the kvm003-f3 lab (drill 6) the rebuilt daemons audited their
// first actions within seconds, chained them onto the empty tail — seq 1,
// prev_hash "" — and opened a second chain under a name that already had one.
// Every node then reported a hash mismatch and duplicated seqs for good, since
// signed rows are never resealed.
//
// The verifier stays strict; the writer waits. What it waits FOR has to come
// from someone who has the history. The rebuilt host's own replica cannot say —
// that is the problem — and neither can "one anti-entropy exchange completed":
// drill 6 rebuilds three hosts at once, and an exchange between two of them
// completes while both are empty. So the target is handed over at admission:
// `lv host add` asks the admitting node, which holds the name's history, for the
// last seq and content hash that name wrote (AdmitHostResponse), signs the pair
// with the cluster CA and writes it beside the new machine's certificate
// (AuditRejoinFileName). The daemon holds its rows only when that record names
// history its replica does not have yet, and opens the hold when a row at that
// seq with that hash is present locally — fetched from whichever peer had it.
//
// So a normal restart never holds (its replica already holds its tail), and a
// brand-new name never holds (there is no record, or it names seq 0).
//
// Held rows are written to a spool directory, durably, so a restart in the
// window loses nothing. They are numbered as they are held, and land in that
// order once the hold opens, each stamped with the moment it was audited. No row
// is ever dropped. Past maxHeldAuditRows the node instead stops taking audited
// actions it could refuse: AuditHoldFull is what grpcapi refuses client
// mutations and logins on. Denied logins — the one audited action an
// unauthenticated caller can repeat at will — are coalesced into one held row
// while the hold lasts, so they cannot fill it.

// AuditHoldDirName is the spool directory under the daemon's data dir.
const AuditHoldDirName = "audit-hold"

// AuditRejoinFileName is the CA-signed admission record `lv host add` writes
// into the new machine's pki dir.
const AuditRejoinFileName = "audit-rejoin.json"

// maxHeldAuditRows is how many held rows a node accepts before AuditHoldFull
// turns its refusable audited actions away. Rows written past it are still held
// — a background writer cannot be refused — but nothing an operator or a client
// asks for runs until the hold has landed. A var so tests can lower it.
var maxHeldAuditRows = 10000

// auditLandBatch bounds how many held rows land per acquisition of the chain
// lock, so landing a long hold does not stall every other audit write.
const auditLandBatch = 100

// ErrAuditChainNotCaughtUp is returned by AdoptAuditKey while this host's audit
// rows are held: a contract start taken from a replica that does not yet hold
// the host's history would claim, or excuse, the wrong rows, permanently.
var ErrAuditChainNotCaughtUp = errors.New("this host's audit chain has not caught up from its peers yet")

// auditRejoinDomain separates the rejoin signature from every other CA signature.
const auditRejoinDomain = "litevirt-audit-rejoin-v1"

// AuditRejoin is the admission record: hostName's audit chain had reached Seq,
// whose row hashed to Hash, when the name was admitted again. Signature is the
// cluster CA's, over all three.
type AuditRejoin struct {
	Host      string `json:"host"`
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

func auditRejoinDigest(host string, seq int64, hash string) []byte {
	h := sha256.New()
	writeField(h, auditRejoinDomain)
	writeField(h, host)
	writeField(h, strconv.FormatInt(seq, 10))
	writeField(h, strings.ToLower(hash))
	return h.Sum(nil)
}

// SignAuditRejoin signs an admission record with the cluster CA key in pkiDir.
// Run where the CA key is: `lv host add`.
func SignAuditRejoin(pkiDir, host string, seq int64, hash string) (AuditRejoin, error) {
	key, err := loadClusterCAKey(pkiDir)
	if err != nil {
		return AuditRejoin{}, err
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, auditRejoinDigest(host, seq, hash))
	if err != nil {
		return AuditRejoin{}, fmt.Errorf("sign the audit rejoin record: %w", err)
	}
	return AuditRejoin{Host: host, Seq: seq, Hash: hash, Signature: hex.EncodeToString(sig)}, nil
}

// LoadAuditRejoin reads and verifies pkiDir's admission record for host. ok is
// false when there is none. A record that does not verify against the cluster
// CA, or names another host, is an error.
func LoadAuditRejoin(pkiDir, host string) (AuditRejoin, bool, error) {
	var rj AuditRejoin
	data, err := os.ReadFile(filepath.Join(pkiDir, AuditRejoinFileName))
	if errors.Is(err, os.ErrNotExist) {
		return rj, false, nil
	}
	if err != nil {
		return rj, false, err
	}
	if err := json.Unmarshal(data, &rj); err != nil {
		return rj, false, fmt.Errorf("parse %s: %w", AuditRejoinFileName, err)
	}
	if rj.Host != host {
		return rj, false, fmt.Errorf("%s names host %q, not %q", AuditRejoinFileName, rj.Host, host)
	}
	roots, err := LoadAuditVerifier(pkiDir)
	if err != nil {
		return rj, false, err
	}
	pub, okKey := roots.caCert.PublicKey.(*ecdsa.PublicKey)
	sig, herr := hex.DecodeString(rj.Signature)
	if !okKey || herr != nil || !ecdsa.VerifyASN1(pub, auditRejoinDigest(rj.Host, rj.Seq, rj.Hash), sig) {
		return rj, false, fmt.Errorf("%s is not signed by the cluster CA", AuditRejoinFileName)
	}
	return rj, true, nil
}

// AuditChainTail returns hostName's last seq and that row's content hash as this
// replica holds them, in the verifier's order. (0, "") for a name with no rows.
func AuditChainTail(ctx context.Context, c *Client, hostName string) (int64, string, error) {
	var t chainTail
	if err := loadHostTail(ctx, c, hostName, &t); err != nil {
		return 0, "", err
	}
	if t.seq == 0 {
		return 0, "", nil
	}
	hash := t.hash
	rows, err := c.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ? AND seq = ?
		 ORDER BY timestamp DESC, id DESC LIMIT 1`, hostName, t.seq)
	if err != nil {
		return 0, "", err
	}
	if len(rows) == 1 {
		hash = rows[0].String("content_hash")
	}
	return t.seq, hash, nil
}

// AuditHoldConfig configures HoldAuditUntilCaughtUp.
type AuditHoldConfig struct {
	// Host is the host whose rows are held — the daemon's own. Rows for any
	// other host name are never held.
	Host string
	// Target and TargetHash are the admission record's: the hold opens once a
	// row at seq Target hashing to TargetHash is in the local replica. Target 0
	// holds nothing, and only lands rows an earlier process left in the spool.
	Target     int64
	TargetHash string
	// SpoolDir is where held rows are kept. Empty holds them in memory only,
	// which is for tests: a daemon restart then loses them.
	SpoolDir string
}

// ConfigureAuditHold installs the hold a starting daemon needs: it reads the
// admission record in pkiDir and holds only when that record names history this
// replica does not have yet. The returned config says what was installed. A
// record that does not verify is reported and NOT acted on.
func ConfigureAuditHold(ctx context.Context, c *Client, pkiDir, host, spoolDir string) (AuditHoldConfig, error) {
	cfg := AuditHoldConfig{Host: host, SpoolDir: spoolDir}
	rj, ok, rerr := LoadAuditRejoin(pkiDir, host)
	if ok && rj.Seq > 0 {
		local, err := freshHostTailSeq(ctx, c, host)
		if err != nil {
			return cfg, err
		}
		if local < rj.Seq || !auditRowPresent(ctx, c, host, rj.Seq, rj.Hash) {
			cfg.Target, cfg.TargetHash = rj.Seq, rj.Hash
		}
	}
	c.HoldAuditUntilCaughtUp(cfg)
	return cfg, rerr
}

// auditRowPresent reports whether host has a row at seq with hash ("" matches
// any) in this replica.
func auditRowPresent(ctx context.Context, c *Client, host string, seq int64, hash string) bool {
	rows, err := c.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ? AND seq = ?`, host, seq)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if hash == "" || strings.EqualFold(r.String("content_hash"), hash) {
			return true
		}
	}
	return false
}

// HoldAuditUntilCaughtUp makes this client hold cfg.Host's audit rows until a
// row at cfg.Target hashing to cfg.TargetHash is in its replica. Rows already
// spooled under cfg.SpoolDir by an earlier process are kept, and land first.
// Unset, nothing is held, which is every client but a daemon's.
func (c *Client) HoldAuditUntilCaughtUp(cfg AuditHoldConfig) {
	h := &auditHold{cfg: cfg}
	if cfg.SpoolDir != "" {
		for _, row := range readHeldSpool(cfg.SpoolDir, cfg.Host, false) {
			h.count++
			if row.HeldSeq >= h.nextSeq {
				h.nextSeq = row.HeldSeq + 1
			}
			if row.Coalesced > 0 {
				h.coalescedID = row.Record.ID
			}
		}
	}
	if h.nextSeq == 0 {
		h.nextSeq = 1
	}
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	c.auditChain.hold = h
	if t := c.auditChain.tails[cfg.Host]; t != nil {
		t.ready = false
	}
}

// AuditChainHeld reports whether hostName's audit rows are still held. It opens
// a hold whose target is present and that has nothing left to land, but never
// lands rows itself (LandHeldAudit does). False when no hold is configured.
func (c *Client) AuditChainHeld(ctx context.Context, hostName string) bool {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != hostName {
		return false
	}
	return !c.openAuditChainLocked(ctx, c.auditChain.tail(hostName), h)
}

// AuditHoldFull reports whether hostName's hold has reached maxHeldAuditRows:
// the node must refuse every audited action it can refuse, rather than take it
// with nowhere for its row to go.
func (c *Client) AuditHoldFull(hostName string) bool {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != hostName {
		return false
	}
	if t := c.auditChain.tails[hostName]; t != nil && t.ready {
		return false
	}
	return h.count >= maxHeldAuditRows
}

// AuditHoldStatus describes hostName's hold for logs and health: whether rows
// are held, how many, and what the hold is waiting for.
func (c *Client) AuditHoldStatus(ctx context.Context, hostName string) (held bool, count int, waiting string) {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != hostName {
		return false, 0, ""
	}
	if c.openAuditChainLocked(ctx, c.auditChain.tail(hostName), h) {
		return false, 0, ""
	}
	_, why := c.auditTargetReached(ctx, h)
	if why == "" {
		why = fmt.Sprintf("%d held row(s) are landing", h.count)
	}
	return true, h.count, why
}

// LandHeldAudit appends held rows, at most auditLandBatch per hold of the chain
// lock, once the target is present. It reports whether rows are still held. The
// daemon calls it from its own goroutine, so landing never runs on an RPC.
func (c *Client) LandHeldAudit(ctx context.Context, hostName string) (bool, error) {
	for {
		held, more, err := c.landHeldBatch(ctx, hostName)
		if err != nil || !more {
			return held, err
		}
	}
}

func (c *Client) landHeldBatch(ctx context.Context, hostName string) (held, more bool, err error) {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != hostName {
		return false, false, nil
	}
	tail := c.auditChain.tail(hostName)
	if tail.ready {
		return false, false, nil
	}
	if ok, _ := c.auditTargetReached(ctx, h); !ok {
		return true, false, nil
	}
	if !h.tailLoaded {
		// Re-read, never trust what is cached: PublishAuditChainHead, HostTailSeq
		// and the startup reseal all load the tail, and on a rebuilt host they did
		// so from the empty replica.
		var fresh chainTail
		if err := loadHostTail(ctx, c, hostName, &fresh); err != nil {
			return true, false, err
		}
		tail.hash, tail.seq = fresh.hash, fresh.seq
		if raisesStampCeiling(fresh.ts, tail.ts) {
			tail.ts = fresh.ts
		}
		tail.known = true
		h.tailLoaded = true
	}
	n, err := c.landHeldAuditLocked(ctx, tail, h, auditLandBatch)
	h.landed += n
	if err != nil {
		return true, false, err
	}
	if h.count > 0 {
		return true, true, nil
	}
	tail.ready = true
	slog.Info("this host's audit chain has caught up from its peers; held audit rows appended after "+
		"its real tail", "host", hostName, "landed", h.landed)
	return false, false, nil
}

// auditHold is the state of one host's hold. Guarded by chainState.mu.
type auditHold struct {
	cfg         AuditHoldConfig
	mem         []heldAuditRow // held rows when there is no spool, or the spool failed
	count       int            // rows held, spooled and in memory
	nextSeq     int64          // the next row's HeldSeq; persisted in each row
	coalescedID string         // the held row denied logins are folded into
	tailLoaded  bool
	landed      int
}

// heldAuditRow is one held row as spooled.
type heldAuditRow struct {
	Record AuditRecord `json:"record"`
	// At is the moment a generated stamp is taken from (RFC3339Nano) — when
	// the action was audited. Empty for a caller-supplied stamp, which
	// Record.Timestamp carries verbatim.
	At string `json:"at,omitempty"`
	// HeldSeq is the order rows were held in, which is the order they land in.
	// A counter, not a clock: a clock stepped back during the hold would land
	// rows out of the order they were audited.
	HeldSeq int64 `json:"held_seq"`
	// Coalesced counts the denied logins folded into this row; LastAt and
	// LastDetail describe the latest of them.
	Coalesced  int    `json:"coalesced,omitempty"`
	LastAt     string `json:"last_at,omitempty"`
	LastTarget string `json:"last_target,omitempty"`
	LastDetail string `json:"last_detail,omitempty"`

	path string // the spool file, when it came from one
}

// isDeniedLogin is the audited action an unauthenticated caller can repeat at
// will, and so the one that is coalesced while held.
func isDeniedLogin(r AuditRecord) bool {
	return r.Action == "auth.login" && r.Result == "denied"
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
	at := ""
	if generated {
		at = c.now().UTC().Format(time.RFC3339Nano)
		r.Timestamp = ""
	}
	if isDeniedLogin(r) && h.coalescedID != "" {
		c.coalesceDeniedLoginLocked(h, r, at)
		return true, nil
	}
	row := heldAuditRow{Record: r, At: at, HeldSeq: h.nextSeq}
	if isDeniedLogin(r) {
		row.Coalesced = 1
	}
	if c.spoolAuditLocked(h, row) {
		h.nextSeq++
		if row.Coalesced > 0 {
			h.coalescedID = r.ID
		}
	}
	if h.count == maxHeldAuditRows {
		slog.Error("this host's audit hold is full; it now refuses every audited action it can refuse "+
			"until its audit chain has caught up from its peers",
			"host", h.cfg.Host, "held", h.count)
	}
	return true, nil
}

// coalesceDeniedLoginLocked folds a denied login into the held row already
// carrying them.
func (c *Client) coalesceDeniedLoginLocked(h *auditHold, r AuditRecord, at string) {
	if at == "" {
		at = r.Timestamp
	}
	update := func(row *heldAuditRow) {
		row.Coalesced++
		row.LastAt, row.LastTarget, row.LastDetail = at, r.Target, r.Detail
	}
	for i := range h.mem {
		if h.mem[i].Record.ID == h.coalescedID {
			update(&h.mem[i])
			return
		}
	}
	path := heldAuditPath(h.cfg.SpoolDir, h.coalescedID)
	row, err := readHeldAudit(path)
	if err != nil {
		slog.Error("could not read the coalesced denied-login row back from the audit hold spool; "+
			"holding this attempt as its own row", "error", err)
		h.coalescedID = ""
		nr := heldAuditRow{Record: r, At: at, HeldSeq: h.nextSeq, Coalesced: 1}
		if c.spoolAuditLocked(h, nr) {
			h.nextSeq++
			h.coalescedID = r.ID
		}
		return
	}
	update(&row)
	if err := writeHeldAudit(h.cfg.SpoolDir, path, row); err != nil {
		slog.Error("could not update the coalesced denied-login row in the audit hold spool",
			"error", err, "attempt_target", r.Target, "attempt_detail", r.Detail)
	}
}

// spoolAuditLocked keeps row until the hold opens: on disk when there is a
// spool, in memory otherwise or when the disk write fails. An id already held
// is not held twice — the first row with an id is the one InsertAuditLog keeps.
// Reports whether the row was newly held. Nothing is ever dropped.
func (c *Client) spoolAuditLocked(h *auditHold, row heldAuditRow) bool {
	for _, m := range h.mem {
		if m.Record.ID == row.Record.ID {
			return false
		}
	}
	if h.cfg.SpoolDir != "" {
		path := heldAuditPath(h.cfg.SpoolDir, row.Record.ID)
		if _, err := os.Stat(path); err == nil {
			return false
		}
		err := writeHeldAudit(h.cfg.SpoolDir, path, row)
		if err == nil {
			h.count++
			return true
		}
		slog.Error("could not spool a held audit row to disk; it is held in memory and is lost "+
			"if the daemon stops before this host's audit chain catches up",
			"id", row.Record.ID, "action", row.Record.Action, "error", err)
	}
	h.mem = append(h.mem, row)
	h.count++
	return true
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

// openAuditChainLocked opens a hold that has nothing left to land and whose
// target is present. Reports whether the hold is open.
func (c *Client) openAuditChainLocked(ctx context.Context, tail *chainTail, h *auditHold) bool {
	if tail.ready {
		return true
	}
	if h.count > 0 {
		return false // held rows land first, in order, from LandHeldAudit
	}
	if ok, _ := c.auditTargetReached(ctx, h); !ok {
		return false
	}
	var fresh chainTail
	if err := loadHostTail(ctx, c, h.cfg.Host, &fresh); err != nil {
		return false
	}
	tail.hash, tail.seq = fresh.hash, fresh.seq
	if raisesStampCeiling(fresh.ts, tail.ts) {
		tail.ts = fresh.ts
	}
	tail.known = true
	tail.ready = true
	return true
}

// auditTargetReached reports whether the admission record's row is present in
// this replica, and if not, what is missing.
func (c *Client) auditTargetReached(ctx context.Context, h *auditHold) (bool, string) {
	if h.cfg.Target <= 0 {
		return true, ""
	}
	if auditRowPresent(ctx, c, h.cfg.Host, h.cfg.Target, h.cfg.TargetHash) {
		return true, ""
	}
	local, _ := freshHostTailSeq(ctx, c, h.cfg.Host)
	if local >= h.cfg.Target {
		return false, fmt.Sprintf("this node's copy of its own audit chain reaches seq %d, but its row at seq %d "+
			"does not hash to %s as the admission record says: it holds a different history than the "+
			"cluster had for this name", local, h.cfg.Target, h.cfg.TargetHash)
	}
	return false, fmt.Sprintf("waiting for this host's own audit history from its peers: the admission "+
		"record says its chain reached seq %d, and this node's copy ends at %d", h.cfg.Target, local)
}

// landHeldAuditLocked appends up to limit held rows, in the order they were
// held, and forgets each once it is in. Caller holds chainState.mu and has
// loaded the tail.
func (c *Client) landHeldAuditLocked(ctx context.Context, tail *chainTail, h *auditHold, limit int) (int, error) {
	rows := append([]heldAuditRow(nil), h.mem...)
	if h.cfg.SpoolDir != "" {
		rows = append(rows, readHeldSpool(h.cfg.SpoolDir, h.cfg.Host, true)...)
	}
	sort.SliceStable(rows, func(i, k int) bool { return rows[i].HeldSeq < rows[k].HeldSeq })
	landed := 0
	defer func() { h.count = len(h.mem) + countSpool(h.cfg.SpoolDir) }()
	for _, row := range rows {
		if landed >= limit {
			break
		}
		var at time.Time
		if row.At != "" {
			if t, err := time.Parse(time.RFC3339Nano, row.At); err == nil {
				at = t
			} else {
				at = c.now()
			}
		}
		rec := row.Record
		if row.Coalesced > 1 {
			rec.Detail = strings.TrimSpace(fmt.Sprintf("%s; coalesced while this host's audit chain was held: "+
				"%d denied login attempts, first %s, last %s (target=%q %s)",
				rec.Detail, row.Coalesced, row.At+rec.Timestamp, row.LastAt, row.LastTarget, row.LastDetail))
		}
		if err := insertAuditLocked(ctx, c, tail, rec, at); err != nil {
			return landed, fmt.Errorf("append held audit row %s: %w", row.Record.ID, err)
		}
		landed++
		if row.Record.ID == h.coalescedID {
			h.coalescedID = ""
		}
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
	return landed, nil
}

func countSpool(dir string) int {
	if dir == "" {
		return 0
	}
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	return len(names)
}

// readHeldSpool reads every held row in dir. A file that does not parse, or
// names another host, is set aside as .rejected when reject is set.
func readHeldSpool(dir, host string, reject bool) []heldAuditRow {
	names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	var rows []heldAuditRow
	for _, path := range names {
		if strings.HasPrefix(filepath.Base(path), ".") {
			continue // a writer's temp file
		}
		row, err := readHeldAudit(path)
		if err == nil && row.Record.HostName != host {
			err = fmt.Errorf("not a held audit row for %s", host)
		}
		if err != nil {
			if reject {
				slog.Error("audit hold: spool file not appended; it is kept beside the spool as .rejected",
					"file", path, "reason", err)
				_ = os.Rename(path, strings.TrimSuffix(path, ".json")+".rejected")
			}
			continue
		}
		row.path = path
		rows = append(rows, row)
	}
	return rows
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

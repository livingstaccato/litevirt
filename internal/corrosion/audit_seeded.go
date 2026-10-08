package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Seeded: does this replica hold the cluster's history?
//
// AdmitHost hands a re-added machine the audit chain position of its name, read
// from the admitting node's replica (audit_hold.go), and "no history" from a
// replica that simply has not received the history yet is the fork the hold
// exists to prevent. Neither of the obvious signals says whether a replica has
// it. "One anti-entropy exchange completed" is satisfied by an exchange with a
// peer as empty as this one — in drill 6 three hosts are rebuilt together, and
// a rebuilt host's first exchange is as likely to be with another rebuilt host
// as with a survivor. "Alone in the cluster" is satisfied by a rebuilt host at
// first boot, whose hosts table names only itself.
//
// Seeded is that fact, carried forward. A replica is seeded when:
//
//   - it founded the cluster (the genesis mint in daemon.seedAdminUser): there
//     is no earlier history to lack;
//   - it already held rows of its own host the first time a build with this
//     marker ran on it, and was not holding them: an existing member at a
//     rolling upgrade. The decision is taken once per state.db and recorded,
//     so a rebuilt host that later writes rows of its own is NOT grandfathered
//     on a restart;
//   - otherwise, only once it has completed an anti-entropy exchange with a peer
//     that reported itself seeded and not holding its own audit rows. That
//     exchange merged every table that differed, so this replica now holds
//     everything that seeded peer held. An older peer reports nothing, which
//     reads as not seeded.
//
// The marker is local and never replicated: it is a statement about this
// replica. It is a file under data_dir bound to this state.db's voter
// incarnation (minted once per state.db by InitSchema), so it dies with the
// replica — a lost or replaced state.db gets a new incarnation and the old
// marker no longer counts. An in-place `lv host reseed` keeps the incarnation,
// and with it the marker; that is sound, because a reseed keeps every audit
// table and the hosts table (reseedKeepTables) and only adds the source's rows,
// so the replica still holds everything it held when it was seeded. No table is added, so there is no schema change
// and no statement shape.

// AuditSeededFileName is the marker under data_dir.
const AuditSeededFileName = "audit-seeded.json"

type auditSeededMarker struct {
	Incarnation string `json:"incarnation"`
	Seeded      bool   `json:"seeded"`
	Reason      string `json:"reason"`
	At          string `json:"at"`
	// Asserted: an operator asserted this replica seeded (AuditSeededAssertFileName)
	// at AssertedAt. AssertionAudited is set once the signed audit.seeded_asserted
	// row is in the log (RecordAuditSeededAssertion).
	Asserted         bool   `json:"asserted,omitempty"`
	AssertedAt       string `json:"asserted_at,omitempty"`
	AssertionAudited bool   `json:"assertion_audited,omitempty"`
	// AssertNonce is the secret an operator's assertion must contain
	// (AuditSeededAssertFileName): 256 random bits, minted with the marker and
	// again after each assertion is applied. It exists only in this 0600 file —
	// never in state.db, never replicated, never in an RPC response or a log
	// line — so reading it takes root's (or the daemon's) access to data_dir.
	AssertNonce string `json:"assert_nonce,omitempty"`
}

// newAuditAssertNonce mints an assert nonce.
func newAuditAssertNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint the seeded assertion nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// auditSeededState is a client's view of its marker. A client with no data dir
// (tests) keeps it in memory only.
type auditSeededState struct {
	mu      sync.Mutex
	loaded  bool
	decided bool
	seeded  bool
	// problem says why the marker could not be used, if it could not: the
	// replica is then treated as decided and NOT seeded (fails closed).
	problem string

	asserted, assertionAudited bool
	assertedAt                 string
	// assertNonce is the marker's AssertNonce; "" when there is no usable
	// marker for this state.db, and then no assertion is honoured.
	assertNonce string

	// unpersisted: a decision was taken and could not be written. Until it is
	// (RetryAuditSeededDecision), the replica is not seeded AND this host's own
	// audit rows are held, so nothing on disk can make the next start's upgrade
	// rule grandfather it (audit_hold.go, auditTargetReached).
	unpersisted   bool
	pendingSeeded bool
	pendingReason string
}

func (c *Client) auditSeededPath() string {
	if c.dataDir == "" {
		return ""
	}
	return filepath.Join(c.dataDir, AuditSeededFileName)
}

// loadAuditSeededLocked reads the marker once. Caller holds c.seeded.mu.
//
// Only an absent marker, or one written for a DIFFERENT state.db, leaves the
// replica undecided. A marker that is present and cannot be used — unreadable,
// unparseable, or not checkable against this state.db — counts as decided and
// not seeded. Treating it as undecided would hand the next start to the
// upgrade rule, which grandfathers any replica holding rows of its own: a
// rebuilt host whose hold has since opened would be seeded without ever
// exchanging with a seeded peer.
func (c *Client) loadAuditSeededLocked(ctx context.Context) {
	if c.seeded.loaded {
		return
	}
	c.seeded.loaded = true
	path := c.auditSeededPath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	failClosed := func(why string) {
		c.seeded.decided, c.seeded.seeded, c.seeded.problem = true, false, why
		slog.Error("this replica's seeded marker cannot be used; the replica is treated as NOT seeded "+
			"and does not vouch for audit chain positions at host admission", "file", path, "problem", why)
	}
	if err != nil {
		failClosed("marker unreadable: " + err.Error())
		return
	}
	var m auditSeededMarker
	if err := json.Unmarshal(data, &m); err != nil {
		failClosed("marker does not parse: " + err.Error())
		return
	}
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		failClosed("this state.db's incarnation cannot be read: " + err.Error())
		return
	}
	if m.Incarnation != inc {
		return // another state.db's marker: this replica has decided nothing yet
	}
	c.seeded.decided, c.seeded.seeded = true, m.Seeded
	c.seeded.asserted, c.seeded.assertedAt, c.seeded.assertionAudited = m.Asserted, m.AssertedAt, m.AssertionAudited
	c.seeded.assertNonce = m.AssertNonce
	if m.AssertNonce == "" {
		// A marker from the build before the nonce: add one, keeping the
		// decision exactly as recorded. Failing here costs only the ability to
		// assert until a later write succeeds; the decision itself stands.
		n, err := newAuditAssertNonce()
		if err == nil {
			m.AssertNonce = n
			var data []byte
			if data, err = json.Marshal(m); err == nil {
				err = secretfile.Write(path, data, 0o600)
			}
		}
		if err != nil {
			slog.Warn("could not add an assertion nonce to this replica's seeded marker; an operator's "+
				"seeded assertion is not honoured until it is written", "file", path, "error", err)
			return
		}
		c.seeded.assertNonce = m.AssertNonce
	}
}

// writeAuditSeededLocked persists a decision and adopts it only once it is
// durable. A decision that cannot be written leaves the replica not seeded in
// this process (fails closed) and records the problem.
func (c *Client) writeAuditSeededLocked(ctx context.Context, seeded bool, reason string) error {
	path := c.auditSeededPath()
	if path == "" {
		c.seeded.decided, c.seeded.seeded, c.seeded.problem, c.seeded.unpersisted = true, seeded, "", false
		return nil
	}
	nonce := c.seeded.assertNonce
	err := func() error {
		inc, err := c.VoterIncarnation(ctx)
		if err != nil {
			return err
		}
		if nonce == "" {
			if nonce, err = newAuditAssertNonce(); err != nil {
				return err
			}
		}
		data, err := json.Marshal(auditSeededMarker{Incarnation: inc, Seeded: seeded, Reason: reason,
			At: time.Now().UTC().Format(time.RFC3339), Asserted: c.seeded.asserted,
			AssertedAt: c.seeded.assertedAt, AssertionAudited: c.seeded.assertionAudited,
			AssertNonce: nonce})
		if err != nil {
			return err
		}
		return secretfile.Write(path, data, 0o600)
	}()
	if err != nil {
		c.seeded.decided, c.seeded.seeded = true, false
		c.seeded.unpersisted, c.seeded.pendingSeeded, c.seeded.pendingReason = true, seeded, reason
		c.seeded.problem = "the seeded marker could not be written: " + err.Error()
		return err
	}
	c.seeded.decided, c.seeded.seeded, c.seeded.problem, c.seeded.unpersisted = true, seeded, "", false
	c.seeded.assertNonce = nonce
	return nil
}

// AuditSeededProblem says why this replica's seeded marker could not be used
// or written, or "" when it could. A replica with a problem is not seeded.
func (c *Client) AuditSeededProblem(ctx context.Context) string {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	return c.seeded.problem
}

// AuditSeeded reports whether this replica is seeded (see above).
func (c *Client) AuditSeeded(ctx context.Context) bool {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	return c.seeded.seeded
}

// MarkAuditSeeded records that this replica is seeded, durably. why is logged
// and kept in the marker.
func (c *Client) MarkAuditSeeded(ctx context.Context, why string) error {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	if c.seeded.seeded {
		return nil
	}
	if err := c.writeAuditSeededLocked(ctx, true, why); err != nil {
		return fmt.Errorf("record this replica as seeded: %w", err)
	}
	slog.Info("this replica now holds the cluster's history (seeded); it may vouch for audit chain "+
		"positions at host admission", "reason", why)
	return nil
}

// MarkAuditSeededForTests marks a test client seeded, as a bootstrapped
// cluster's founder would be.
func (c *Client) MarkAuditSeededForTests() {
	_ = c.MarkAuditSeeded(context.Background(), "test")
}

// DecideAuditSeeded takes the once-per-state.db decision at daemon start. It
// returns whether the replica is seeded. A replica that has decided already
// keeps its decision; an undecided one is seeded only if it holds rows of its
// own host and is not holding them — an existing member at a rolling upgrade.
// Called after ConfigureAuditHold and before the daemon writes anything.
func DecideAuditSeeded(ctx context.Context, c *Client, host string) (bool, error) {
	if seeded, done, err := c.consumeAuditSeededAssertion(ctx); done {
		return seeded, err
	}
	held := c.AuditChainHeld(ctx, host)
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	if c.seeded.decided {
		return c.seeded.seeded, nil
	}
	rows, err := c.Query(ctx, `SELECT 1 AS present FROM audit_log WHERE host_name = ? LIMIT 1`, host)
	if err != nil {
		return false, err
	}
	seeded := len(rows) > 0 && !held
	reason := "first start of this build on a replica holding none of its own audit history"
	if seeded {
		reason = "first start of this build on a replica already holding its own audit history (upgrade)"
	} else if held {
		reason = "first start of this build while holding its own audit rows"
	}
	if err := c.writeAuditSeededLocked(ctx, seeded, reason); err != nil {
		// Not adopted: a decision that is not durable could be taken differently
		// on the next start, so this process proceeds as not seeded, and holds
		// its own audit rows until the decision is written (RetryAuditSeededDecision).
		// Rows of its own landing first are what would let the next start's
		// upgrade rule grandfather it.
		c.seeded.mu.Unlock()
		c.reholdAudit(host)
		c.seeded.mu.Lock()
		return false, fmt.Errorf("record this replica's seeded decision: %w", err)
	}
	slog.Info("recorded whether this replica holds the cluster's history", "seeded", seeded, "reason", reason)
	return seeded, nil
}

// AuditSeededAssertFileName is the operator's way out of a cluster with no
// seeded replica at all — a single-node cluster whose founder lost its
// state.db, or a total loss — where `lv host add` is otherwise refused
// forever. Root copies the "assert_nonce" field of the seeded marker
// (AuditSeededFileName) into it and restarts the daemon; the next start records this replica as seeded, on the operator's
// word, writes a signed audit.seeded_asserted row once the keyring is wired
// (RecordAuditSeededAssertion), and removes the file. If this replica does NOT
// hold the cluster's history, an admission it then vouches for can let a
// re-added host fork its audit chain: the assertion is the operator taking
// that on.
//
// What keeps a non-root user from asserting is that nothing short of root can
// read or write data_dir: storage pools cannot be created on or above it, nor
// write into one that reaches it; a VM's ISO and other host paths named in a
// spec cannot point into it; and image import cannot read a host file into a
// guest, by path or through a qcow2/VMDK backing or data-file reference. Those
// confinements are the barrier. Someone who can write data_dir can replace the
// marker, or state.db itself, and no secret kept there stops them.
//
// Within that, the nonce stops what the confinements leave: a writer who can
// drop the assertion file but not read the marker, a value learned from an RPC
// — the voter incarnation is NOT secret: GetRecoveryClaim returns it to an
// operator, the replicated voter_configs rows carry every voter's, and
// GetVoterConfig and InspectRecoveryClaim show it to a viewer — and a stale
// file outliving its state.db. It exists only in the 0600 marker, is never
// replicated, and no RPC, log line or audit row carries it. The marker is bound
// to this state.db's incarnation and the nonce to the marker, so a replaced
// state.db gets a new nonce and a file left behind for the old one is not
// applied; the nonce is replaced once an assertion is applied, too.
const AuditSeededAssertFileName = "audit-seeded-assert"

// consumeAuditSeededAssertion applies an operator's assertion, if a valid one
// is present. done is false when there is none to apply.
func (c *Client) consumeAuditSeededAssertion(ctx context.Context) (seeded, done bool, err error) {
	if c.dataDir == "" {
		return false, false, nil
	}
	assert := filepath.Join(c.dataDir, AuditSeededAssertFileName)
	fi, lerr := os.Lstat(assert)
	if lerr != nil {
		if !errors.Is(lerr, os.ErrNotExist) {
			slog.Warn("could not check for a seeded assertion; none is applied", "file", assert, "error", lerr)
		}
		return false, false, nil
	}
	removeIt := func() {
		if err := os.Remove(assert); err != nil {
			slog.Warn("could not remove the seeded assertion; it is not applied again: this replica "+
				"has recorded it, and replaced the nonce it names", "file", assert, "error", err)
		}
	}
	var content []byte
	if fi.Mode().IsRegular() && fi.Size() <= 256 {
		content, _ = os.ReadFile(assert)
	}
	c.seeded.mu.Lock()
	c.loadAuditSeededLocked(ctx)
	nonce := c.seeded.assertNonce
	got := strings.TrimSpace(string(content))
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		c.seeded.mu.Unlock()
		// Neither value is logged: the nonce is the secret.
		slog.Error("a seeded assertion is present but does not contain this replica's assert nonce; "+
			"it is IGNORED. To assert, copy the \"assert_nonce\" field of the seeded marker into it "+
			"(a marker that is missing or unusable has none)", "file", assert,
			"marker", filepath.Join(c.dataDir, AuditSeededFileName))
		return false, false, nil
	}
	if c.seeded.asserted {
		// Applied already, and the file outlived its removal: not again.
		c.seeded.mu.Unlock()
		removeIt()
		return false, false, nil
	}
	prevAsserted, prevAt, prevAudited := c.seeded.asserted, c.seeded.assertedAt, c.seeded.assertionAudited
	c.seeded.asserted, c.seeded.assertedAt, c.seeded.assertionAudited = true, time.Now().UTC().Format(time.RFC3339Nano), false
	c.seeded.assertNonce = "" // used: the write below mints its successor
	werr := c.writeAuditSeededLocked(ctx, true, "operator asserted ("+AuditSeededAssertFileName+")")
	if werr != nil {
		// Not applied: the file stays, and the next start applies it. Nothing is
		// left pending — a retry would persist "seeded" without the assertion
		// that must be audited with it.
		c.seeded.asserted, c.seeded.assertedAt, c.seeded.assertionAudited = prevAsserted, prevAt, prevAudited
		c.seeded.assertNonce = nonce
		c.seeded.unpersisted = false
	}
	c.seeded.mu.Unlock()
	if werr != nil {
		return false, true, fmt.Errorf("record the operator's seeded assertion: %w", werr)
	}
	slog.Warn("this replica was asserted seeded by an operator: it vouches for audit chain positions at "+
		"host admission on the operator's word that it holds the cluster's history", "file", assert)
	removeIt()
	return true, true, nil
}

// RecordAuditSeededAssertion writes the signed audit.seeded_asserted row for an
// operator's assertion that has not been audited yet — exactly once. Called by
// the daemon after its signing keyring is wired: a row written before it would
// be unsigned after a signed history. The row's id is derived from the
// assertion, so a crash between the row and the marker's flag cannot write it
// twice. A held host spools it like any other row.
func RecordAuditSeededAssertion(ctx context.Context, c *Client, host string) error {
	c.seeded.mu.Lock()
	c.loadAuditSeededLocked(ctx)
	pending, at := c.seeded.asserted && !c.seeded.assertionAudited, c.seeded.assertedAt
	c.seeded.mu.Unlock()
	if !pending {
		return nil
	}
	sum := sha256.Sum256([]byte(host + "\x00" + at))
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID:       "audit-seeded-asserted-" + hex.EncodeToString(sum[:8]),
		Username: "root@" + host,
		HostName: host,
		Action:   "audit.seeded_asserted",
		Target:   host,
		Detail: "asserted at " + at + " by root on this host (" + AuditSeededAssertFileName + "): this " +
			"replica vouches for audit chain positions at host admission on the operator's word that it " +
			"holds the cluster's history; a re-added host admitted through it forks its chain if it does not",
		Result: "success",
	}); err != nil {
		return fmt.Errorf("audit the seeded assertion: %w", err)
	}
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.seeded.assertionAudited = true
	if err := c.writeAuditSeededLocked(ctx, c.seeded.seeded, "operator asserted ("+AuditSeededAssertFileName+")"); err != nil {
		return fmt.Errorf("record that the seeded assertion is audited: %w", err)
	}
	return nil
}

// RetryAuditSeededDecision writes a decision that could not be written when it
// was taken. Until it is written the replica is not seeded and its own audit
// rows are held (auditSeededUnpersisted).
func (c *Client) RetryAuditSeededDecision(ctx context.Context) error {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	if !c.seeded.unpersisted {
		return nil
	}
	return c.writeAuditSeededLocked(ctx, c.seeded.pendingSeeded, c.seeded.pendingReason)
}

// auditSeededPending reports a decision taken and not yet written, and why.
func (c *Client) auditSeededPending() (bool, string) {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	return c.seeded.unpersisted, c.seeded.problem
}

// reholdAudit closes host's hold again, so its own rows are held until the
// hold re-opens (auditTargetReached). DecideAuditSeeded's check of the hold
// opened it before the decision's write failed.
func (c *Client) reholdAudit(host string) {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	h := c.auditChain.hold
	if h == nil || h.cfg.Host != host {
		return
	}
	if t := c.auditChain.tails[host]; t != nil {
		t.ready = false
	}
	h.tailLoaded = false
}

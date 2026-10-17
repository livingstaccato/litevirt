package corrosion

import (
	"context"
	"log/slog"
	"time"
)

// Mint clearance: a node must not record lease term N+1 from a ledger that has
// not seen the cluster's N+1.
//
// The term a new tenure claims is MAX(term)+1 over THIS node's replica
// (nextLeaseTerm). That is only a cluster-unique number if this replica already
// holds every term the cluster has minted, and a node that was away does not: a
// restarted daemon, or a node reconnecting after a partition, comes back with
// the ledger as it was when it left. Its own expired lease row then classifies
// as a lapse-and-retake, it allocates the term a peer took while it was gone,
// and it commits a second claimant for that term. leader_lease_terms keeps both
// rows by design (immutableMergeKeepLocalRow), so that is a PERMANENT
// immutable-ledger conflict, which only `lv cluster acknowledge-lease-term`
// clears. Observed on the lab: a daemon started at 08:34:40 minted its own
// dual_run_detector term 5 at 08:34:45, eight minutes after a peer had.
//
// The clearance is the quorum high-water read the lease-term barrier already
// runs for executors (GetLeaseTermHighWater, fanned out to every healthy peer
// and required from a quorum): before committing N+1, the node confirms that no
// reachable peer has seen N+1 or higher. It is asked about the TERM, not about
// how long ago the process started, which is why it also covers the no-restart
// case — a long partition healing presents exactly the same stale ledger, with
// no restart for a "wait after start" rule to key on.
//
// It is asked only for a mint. A renewal of a tenure this node already holds
// mints nothing and asks nothing, so a holder keeps its lease through any
// partition exactly as before; and a poll that finds a peer's live lease never
// reaches the mint either (see AcquireLeaseWithTerm). Mints are rare — one per
// change of tenure — so the read costs one RPC per healthy peer per takeover.
//
// A TAKEOVER needs a second answer from the same read. The term ledger can be
// current while leader_election is not: a renewal writes only leader_election,
// and leader_election is anti-entropy excluded (merging it would corrupt), so
// a replica that has every term row — by anti-entropy, a reseed, or a WAL
// stream that delivered the mint but not the renewals after it — can still
// carry the holder's expiry from several renewals ago, or no row at all. It
// then reads a live lease as lapsed, and the term check passes, because nobody
// has minted the term it is about to claim. Minting it deposes the live holder:
// the holder receives the higher term, fails closed on its next renewal, and
// until then both nodes act as leader. ReplicaCaughtUp cannot close this — it
// is marked by an anti-entropy exchange, which never carries leader_election.
// So each peer's answer also carries its own leader_election row, and a
// takeover is withheld while any answering peer shows the lease live for
// another holder at the caller's instant. The holder itself, when reachable,
// is one of those peers. A mint over this node's OWN live lease (retiring a
// contested term, or a termless tenure taking its term) is not a takeover and
// is not held to this: a contest loser's row names the loser live on its own
// replica, and waiting it out would stall the convergence the retirement is.
//
// A withheld mint is reported as "not held", the same shape as losing the
// race: the caller retries on its next poll, by which time replication has
// usually delivered the row the node was missing, and it then classifies from
// the real ledger.

// LeaseMintRequest is what a mint clearance is asked about.
type LeaseMintRequest struct {
	Key    string
	Term   int64  // the term this node would record
	Holder string // this node
	// Takeover is true when this node's own replica shows no live tenure of
	// its own: it is taking the lease from a holder whose lease it reads as
	// lapsed, or from nobody.
	Takeover bool
	// Now is the instant the caller classified the lease at, RFC3339 UTC —
	// the clock its own expiry comparison used, so a peer's expiry is judged
	// against the same instant.
	Now string
	// TTL is the lease's: how long a tenure taken now would last.
	TTL time.Duration
}

// LeaseMintClearanceFunc reports whether this node may record req.Term for
// req.Key now. ok=false withholds the mint; reason says why, for the log.
type LeaseMintClearanceFunc func(ctx context.Context, req LeaseMintRequest) (ok bool, reason string)

// SetLeaseMintClearance injects the check run before every new lease term is
// recorded. Wired at daemon start to the gRPC server's quorum high-water read
// (grpcapi.Server.LeaseMintClearance).
//
// Nil means no check, which is what a single-package test Client has: it has
// no peers to ask. The daemon always wires it.
func (c *Client) SetLeaseMintClearance(fn LeaseMintClearanceFunc) { c.leaseMintClearance = fn }

// clearLeaseMint runs the clearance for req and logs a withholding once per
// key per reason.
func (c *Client) clearLeaseMint(ctx context.Context, req LeaseMintRequest) bool {
	if c.leaseMintClearance == nil {
		return true
	}
	key := req.Key
	ok, reason := c.leaseMintClearance(ctx, req)
	c.mintWithheldMu.Lock()
	prev := c.mintWithheld[key]
	if ok {
		delete(c.mintWithheld, key)
	} else {
		if c.mintWithheld == nil {
			c.mintWithheld = make(map[string]string, 1)
		}
		c.mintWithheld[key] = reason
	}
	c.mintWithheldMu.Unlock()
	switch {
	case !ok && prev != reason:
		slog.Warn("leader lease: not claiming a new term yet — this node cannot confirm its view "+
			"of the key is current, and a term claimed from a stale view is either a permanent "+
			"immutable-ledger conflict or a live holder deposed (retries each poll)",
			"lease", key, "term", req.Term, "takeover", req.Takeover, "reason", reason)
	case ok && prev != "":
		slog.Info("leader lease: new-term claim cleared", "lease", key, "term", req.Term)
	}
	return ok
}

// A term decided for another node (lease_term_claim_v1).
//
// The quorum high-water read above is a READ, not a lock: two nodes that take
// a dead holder's lease over in the same instant both read the same high
// water, both clear, and both record the next term. Once a voter generation
// with members is adopted the clearance therefore also DECIDES the term, by a
// single-decree claim among the adopted voter generation
// (grpcapi.Server.LeaseMintClearance), and a term is recorded only by the node
// the decision names. The other learns who holds the term and records nothing.
//
// What the loser learned has to outlive the call. The winner's term row and
// lease row reach the loser by replication, and until they do the loser's
// replica still shows the dead holder's expired lease and the old high water:
// its next poll would allocate the same term again and ask again, and if the
// winner died between the decision and its mint, it would ask forever — the
// term is decided, so every claim for it learns the same holder. So the
// loser keeps the decision and treats it as the winner's lease taken at the
// instant it learned of it: no mint until a TTL has passed from then (a live
// winner's rows arrive well inside it, and the ordinary lease rules take
// over), and after that the next mint allocates ABOVE the decided term,
// exactly as a lapsed lease is taken at the next term.
//
// In memory: after a restart the next claim for the term learns it again.

// leaseTermDecision is one decided term, as this node learned it.
type leaseTermDecision struct {
	term   int64
	holder string
	at     time.Time // the caller's clock when it learned the decision
}

// NoteLeaseTermDecided records that term of the lease key was decided for
// holder, learned at at: the caller's clock (LeaseMintRequest.Now) plus the
// time its clearance took, so the wait counts from learning, not from
// classifying. A decision for an older term than one already noted is
// ignored.
//
// In memory, and keyed by host name: a winner that crashed before recording
// its term and restarted can still record that old term late, after another
// node waited it out and recorded the next one. That is still one holder per
// term, and the lower term is fenced by the barrier and the contest rule.
func (c *Client) NoteLeaseTermDecided(key string, term int64, holder string, at time.Time) {
	if key == "" || term <= 0 || holder == "" {
		return
	}
	c.mintWithheldMu.Lock()
	defer c.mintWithheldMu.Unlock()
	if d, ok := c.leaseDecided[key]; ok && d.term > term {
		return
	}
	if c.leaseDecided == nil {
		c.leaseDecided = make(map[string]leaseTermDecision, 1)
	}
	c.leaseDecided[key] = leaseTermDecision{term: term, holder: holder, at: at}
}

// decidedElsewhere adjusts next, the term this node would record for key, for
// a term decided for another node. wait is true while that node may still be
// recording and acting under its term: until ttl after the decision was
// learned, as of now. Otherwise next is moved above the decided term when it
// would claim it.
func (c *Client) decidedElsewhere(key, holder string, next int64, now time.Time, ttl time.Duration) (int64, bool) {
	c.mintWithheldMu.Lock()
	d, ok := c.leaseDecided[key]
	c.mintWithheldMu.Unlock()
	if !ok || d.holder == holder || d.term < next {
		return next, false
	}
	if now.Before(d.at.Add(ttl)) {
		return next, true
	}
	return d.term + 1, false
}

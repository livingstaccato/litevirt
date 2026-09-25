package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// leaseUpsertSQL takes or renews a leader lease.
//
// The expiry compare uses the bound RFC3339 `now`, NOT datetime('now'):
// expires_at is stored RFC3339 ("…T…Z") and datetime('now') yields
// space-separated text, so a string compare breaks once the date matches
// ('T' > ' ') — a same-day lease NEVER looked expired, so a dead leader's lease
// could not transfer and failover stalled cluster-wide until the UTC date rolled
// over. All three original call sites carried their own copy of that fix and
// their own comment about it, which is what triplicated code looks like just
// before it diverges.
//
// The key is a BOUND parameter. The failover coordinator's copy used a literal
// ('failover'), giving it a different registered statement shape from the other
// two; one bound form means one shape for all three consumers.
//
// updated_at is bound separately from the expiry-compare `now` because it is the
// LWW conflict key and comes from Client.NowTS(); see mintLeaseTermSQL.
const leaseUpsertSQL = `INSERT INTO leader_election (key, holder, expires_at, updated_at)
	 VALUES (?, ?, ?, ?)
	 ON CONFLICT(key) DO UPDATE
	   SET holder = excluded.holder,
	       expires_at = excluded.expires_at,
	       updated_at = excluded.updated_at
	   WHERE leader_election.expires_at < ?
	      OR leader_election.holder = excluded.holder`

// maxLeaseAttempts bounds the classify-then-commit loop. An iteration is spent
// only when the state changed under us — another claimant took the lease or the
// term we allocated — which resolves in one or two rounds.
const maxLeaseAttempts = 3

// AcquireLeaseWithTerm takes or renews the leader lease for key and returns the
// caller's fencing term.
//
// It replaces three copy-pasted implementations (grpcapi/dualrun.go,
// failover/coordinator.go, scheduler/rebalancer.go) that ran the identical
// guarded upsert and read-back. They are merged because a term acquired by one
// path and checked by another must come from the same code.
//
// held=false always comes with term 0. A term is only meaningful to its holder,
// and handing one to a loser invites it to be used.
//
// Contention is NOT an error. Every other ExecuteBatchGuarded caller returns
// applied=false when its guard declines, and the callers here map an error onto
// a paged store-error metric and onto aborting an in-progress fence as "lease
// lost" — so returning one for transient contention paged with a wrong cause and
// abandoned fences of genuinely dead hosts. Exhausting the attempts reports
// "not held", which is the same shape as losing the race and is what the callers
// already handle.
func AcquireLeaseWithTerm(ctx context.Context, c *Client, key, holder string, ttl time.Duration, now time.Time) (bool, int64, error) {
	// The clock is re-sampled on EVERY attempt, not once at entry.
	//
	// A holder that enters before its expiry and then stalls past the TTL -- a
	// GC pause, an IO stall, a slow DB, or simply losing the classification
	// race and looping -- used to resume and compare its own now-expired lease
	// against the PRE-PAUSE instant. curExpires >= nowRFC was then still true,
	// the call classified as a renewal, and it returned the OLD term while
	// writing an expiry that could already be in the past. That is exactly the
	// case the tenure rule below says must mint a new term.
	//
	// entry is a monotonic anchor and the offset is added to the CALLER's
	// clock, so an injected `now` keeps its meaning (the first attempt is
	// indistinguishable from sampling it directly) while real elapsed time
	// still advances the comparison.
	entry := time.Now()

	for attempt := 0; attempt < maxLeaseAttempts; attempt++ {
		cur := now.Add(time.Since(entry))
		nowRFC := cur.UTC().Format(time.RFC3339)
		expires := cur.Add(ttl).UTC().Format(time.RFC3339)
		// Classification is re-derived on every iteration. It cannot be hoisted:
		// a declined guard means the state it described has changed, and the most
		// common change is a sibling caller on THIS node having just acquired the
		// lease — in which case this call is now a renewal, not a retryable
		// acquisition.
		curHolder, curExpires, err := leaseRow(ctx, c, key)
		if err != nil {
			return false, 0, err
		}

		// The ledger is not writable yet: hold the lease the pre-ledger way and
		// report no term. This is the mid-rolling-upgrade state — a peer on the
		// previous release cannot resolve the mint's statement shape, and an
		// unregistered shape back-pressures its entire replication stream — so the
		// mint waits for DurablyLatched(lease_term_ledger_v1). See
		// SetLeaseTermLedgerGate.
		//
		// This runs BEFORE any ledger classification, and that ordering is the
		// whole point. The classification below fails closed on a term belonging
		// to another holder, which is right when we can mint — it stops this node
		// promoting itself above the term race's winner — but a node that mints
		// NOTHING has no escalation to prevent, and refusing there returned
		// held=false while our own leader_election row still named us and still
		// blocked every peer's guarded upsert. The lease stopped being renewed and
		// could not transfer, so failover, rebalancing and dual-run detection all
		// stood down for most of every TTL, indefinitely, on a path whose contract
		// is that availability is unaffected.
		if !c.MayMintLeaseTerm() {
			return holdLeaseWithoutTerm(ctx, c, key, holder, expires, nowRFC, curHolder, curExpires)
		}

		newest, err := newestLeaseTerm(ctx, c, key)
		if err != nil {
			return false, 0, err
		}
		// Who the ledger says holds the newest incarnation. For a contested term
		// that is the one claimant allowed to continue, not whichever claim this
		// replica happened to keep — see leader_lease_contest.go.
		effective, contested := c.effectiveLeaseHolder(key, newest)

		// Both sides are RFC3339 UTC, so a lexical compare is a time compare.
		// Expiry is consulted deliberately: holder identity alone does NOT prove
		// an uninterrupted tenure. A lease that fully lapsed — a GC pause, a
		// SIGSTOP, an IO stall longer than the TTL — and was then re-taken by its
		// own prior holder is a NEW tenure, because the lapse is exactly the
		// window in which other nodes were entitled to act. Treating it as a
		// renewal kept the old term and made work from before the lapse
		// indistinguishable from work after it.
		ourTenure := curHolder == holder && curExpires >= nowRFC

		if ourTenure {
			switch {
			case newest.Term > 0 && newest.Holder == holder && contested && effective != holder:
				// Our term is contested and a lower-sorting claimant exists: STAND
				// DOWN. No renewal, no term. Our leader_election row keeps naming us
				// until it expires, and deferTakeover stops us re-taking it then.
				return false, 0, nil

			case newest.Term > 0 && newest.Holder == holder && contested:
				// Our term is contested and we are the claimant that continues —
				// but not under this term, whose other claims every other replica
				// still records. Retire it: mint above it, atomically with the
				// renewal, so the term we act under is one no replica attributes to
				// anyone else and the contested one falls below every threshold.
				held, term, err := takeLeaseAndMintTerm(ctx, c, key, holder, expires, nowRFC, cur,
					!c.heldTermlessIncarnation(key), newest.Term)
				if err != nil {
					return false, 0, err
				}
				if held {
					return true, term, nil
				}
				if term == leaseContended {
					continue
				}
				return false, 0, nil

			case newest.Term > 0 && newest.Holder == holder && !c.heldTermlessIncarnation(key):
				// Same tenure, term already recorded: renew, mint nothing. A
				// renewal that bumped the term would make the holder invalidate
				// its own in-flight work every renewal interval.
				if renewClassifiedHook != nil {
					renewClassifiedHook()
				}
				// Re-check the tenure against a FRESH clock before committing.
				//
				// Everything above was decided from an instant sampled before
				// this point, and the gap is unbounded: the classification is
				// held under no lock, and the caller can stall in it past its
				// own TTL. Renewing on that stale reading returns the OLD term
				// for a lease that has actually lapsed -- and a lapse is
				// precisely the window in which other nodes were entitled to
				// act, so work from before it must not carry the term used
				// after it.
				//
				// curExpires is the DURABLE expiry, so comparing it against a
				// fresh instant is the real question. Falling through to
				// re-classify (rather than refusing) lets the next iteration
				// take the lapsed lease properly and mint a new term.
				if live := now.Add(time.Since(entry)).UTC().Format(time.RFC3339); curExpires < live {
					continue
				}
				held, err := renewLeaseAtTerm(ctx, c, key, holder, expires, nowRFC, newest.Term)
				if err != nil {
					return false, 0, err
				}
				if !held {
					continue // lost it mid-renewal; re-classify rather than guess
				}
				c.noteHandedTerm(key, newest.Term)
				return true, newest.Term, nil

			case newest.Term > 0 && newest.Holder != holder:
				// A peer's claim is newer than ours while our own
				// leader_election row still names us. FAIL CLOSED: return no
				// term rather than minting a fresh higher one.
				//
				// Minting here is the escalation this design exists to prevent —
				// it would promote whichever node lost the term race ABOVE the
				// winner, inverting fencing. leader_election is anti-entropy
				// excluded while leader_lease_terms is replicated, so this skew
				// is reachable in ordinary operation and must not be read as
				// "no term yet".
				return false, 0, nil
			}
			// newest.Term == 0: no term exists for this key at all. Fall through
			// and acquire one. This is the rolling-upgrade case — a node that
			// restarts still holding a lease minted by a binary with no term
			// ledger — and it is now provably ONLY that case: the custom merge
			// keeps the local row, so a peer can no longer overwrite our term,
			// and reseedKeepTables stops a reseed from deleting it.
		}

		// Not ours. An expired lease whose row names someone other than the
		// ledger's current incarnation is not ours to take yet — its real holder
		// may be renewing over it right now. See deferTakeover.
		if !ourTenure && curExpires < nowRFC && newest.Term > 0 &&
			deferTakeover(curHolder, curExpires, effective, holder, now, ttl) {
			return false, 0, nil
		}

		// Whether the ledger's newest term belongs to the incarnation we are
		// holding right now, which is what separates a renewal from a
		// lapse-and-retake by the same node.
		incarnationHasTerm := newest.Term > 0 && newest.Holder == holder &&
			!c.heldTermlessIncarnation(key)
		held, term, err := takeLeaseAndMintTerm(ctx, c, key, holder, expires, nowRFC, cur, incarnationHasTerm, 0)
		if err != nil {
			return false, 0, err
		}
		if held {
			c.noteHandedTerm(key, term)
			return true, term, nil
		}
		if term == leaseContended {
			continue // the term we allocated was taken; re-classify and retry
		}
		return false, 0, nil
	}
	// Contention never settled. Reported as "not held", never as an error.
	return false, 0, nil
}

// holdLeaseWithoutTerm is the entire lease path while the term ledger is not
// writable — the pre-ledger behaviour, reproduced exactly.
//
// The term is ALWAYS 0 here, including when this key's ledger already holds a
// row naming us. A term is a claim about one unbroken tenure, and only the mint
// re-establishes that correspondence: with the gate open, a lease that lapsed
// and was re-taken by its own prior holder classifies as a new tenure and mints
// a fresh term, so the ledger row and the tenure stay in step. A node that
// cannot mint cannot do that, so a surviving row says only "this node held some
// earlier tenure" — reporting its term would hand out the PRE-LAPSE number for
// work done after the lapse, which is the staleness AcquireLeaseWithTerm's
// expiry check exists to prevent. Withholding it costs nothing that is not
// already withheld: enforcement refuses on term 0 by design, and
// LeaseTermReadiness withholds lease_term_v1 for exactly this reason.
//
// A peer's live lease short-circuits before the upsert. The statement would be
// a zero-row no-op — its ON CONFLICT ... WHERE takes the row only when the
// lease is expired or already ours — but a no-op still writes a mutation_log
// row and wakes the replicator, because both write paths log the statements they
// were GIVEN rather than the ones that changed anything. Every non-holder
// polling three lease keys would then emit sustained replicated no-ops onto the
// stream this gate exists to keep quiet, for as long as the gate stays closed.
func holdLeaseWithoutTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC, curHolder, curExpires string) (bool, int64, error) {
	if curHolder != "" && curHolder != holder && curExpires >= nowRFC {
		return false, 0, nil
	}
	held, err := renewLease(ctx, c, key, holder, expires, nowRFC)
	if err != nil {
		return false, 0, err
	}
	if !held {
		return false, 0, nil
	}
	// This incarnation carries NO term. Recording that is what stops a later
	// gate-open acquisition mistaking the ledger's stale term for this tenure's
	// own -- see noteHandedTerm.
	c.noteHandedTerm(key, 0)
	return true, 0, nil
}

// termlessIncarnations records, per lease key, that THIS PROCESS is currently
// holding the lease with no term at all.
//
// leader_lease_terms records (key, term, holder) but not which INCARNATION of
// that holder minted it, so holder identity alone cannot tell an unbroken
// tenure from a lapse-and-retake by the same node. That gap is reachable
// without any exotic failure: mint term N, lose the activation marker so
// MayMintLeaseTerm goes false, let the lease lapse, re-take it termlessly, and
// then have the marker come back. The ledger still says term N belongs to us,
// the classification reads "same tenure, term already recorded", and work from
// before the lapse carries the same term as work after it.
//
// The flag is deliberately narrow: ONLY an explicitly termless acquisition
// clears the tenure. A sibling caller on this same node that advances the term
// in the ledger is a legitimate move forward and is still adopted, and a fresh
// process that finds its own term in the ledger still self-heals into it --
// that is the documented rolling-upgrade path, not this defect.
//
// In memory, because the thing being tracked is a property of this process's
// hold on the lease, not of the replicated row.
var (
	termlessMu           sync.Mutex
	termlessIncarnations = map[*Client]map[string]bool{}
)

// noteHandedTerm records the term returned to a caller for key. Zero means this
// incarnation holds the lease with no term; anything positive clears that.
func (c *Client) noteHandedTerm(key string, term int64) {
	termlessMu.Lock()
	defer termlessMu.Unlock()
	m := termlessIncarnations[c]
	if m == nil {
		m = map[string]bool{}
		termlessIncarnations[c] = m
	}
	m[key] = term == 0
}

// heldTermlessIncarnation reports whether this process took the current lease
// on key without a term. While that is true, a positive term in the ledger
// belongs to an EARLIER tenure and must not be adopted as this one's.
func (c *Client) heldTermlessIncarnation(key string) bool {
	termlessMu.Lock()
	defer termlessMu.Unlock()
	return termlessIncarnations[c][key]
}

// leaseContended is the sentinel takeLeaseAndMintTerm returns alongside
// held=false when the guard declined for a retryable reason (the allocated term
// slot was taken) rather than a terminal one (someone else holds the lease).
const leaseContended int64 = -1

// renewLease runs the guarded upsert alone — no term — and reports whether this
// node holds the lease afterwards.
//
// Named for its common caller, but the statement takes an EXPIRED lease from
// another holder just as it renews our own (see leaseUpsertSQL's WHERE), which
// is what makes it the whole pre-ledger acquisition path as well: it is what
// AcquireLeaseWithTerm falls back to while the term ledger is not yet writable.
// renewClassifiedHook is a test-only seam fired after AcquireLeaseWithTerm has
// classified the lease and read its newest term, and BEFORE the renewal
// commits. That gap is the race: the classification is not held under any lock,
// so a sibling caller on this same host can let the lease lapse, re-take it and
// mint a higher term while this caller is stalled in it.
//
// Same shape and same reason as ackPersistedHook in resolver_tracker.go: the
// window cannot be reached deterministically from outside.
var renewClassifiedHook func()

// renewLeaseAtTerm renews a lease the caller classified as its own live tenure
// at expectTerm, and declines if either half of that classification no longer
// holds.
//
// The unguarded renewLease below cannot do this. It checks only that the row
// still names the holder, which a sibling caller on the SAME host satisfies
// after it has let the lease lapse and re-taken it — so the stalled caller's
// renewal succeeded and it returned the term it read before the lapse, a term
// the ledger had already superseded. Its caller then stamped work with a
// superseded term and every executor refused it as stale, which reads as a
// failed rebalance on a node that holds the lease perfectly well.
func renewLeaseAtTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC string, expectTerm int64) (bool, error) {
	applied, err := c.ExecuteBatchGuarded(ctx,
		func(tx *sql.Tx) (bool, error) {
			return leaseRenewableTx(ctx, tx, key, holder, nowRFC, expectTerm)
		},
		[]Statement{
			{SQL: leaseUpsertSQL, Params: []interface{}{key, holder, expires, c.NowTS(), nowRFC}},
		})
	if err != nil {
		return false, fmt.Errorf("renew lease %q at term %d: %w", key, expectTerm, err)
	}
	// Declined is not an error: the caller re-classifies, which is how it comes
	// back with the term the ledger actually holds.
	return applied, nil
}

// leaseRenewableTx re-checks BOTH halves of the caller's classification inside
// the renewal's own transaction: that this is still an unbroken tenure of ours,
// and that the term it classified at is still the newest one.
//
// Expiry is consulted as well as holder identity, for the same reason
// AcquireLeaseWithTerm consults it: a lease that fully lapsed and was re-taken
// by its own prior holder is a NEW tenure, and the lapse is exactly the window
// other nodes were entitled to act in. Holder identity alone cannot see it.
func leaseRenewableTx(ctx context.Context, tx *sql.Tx, key, holder, nowRFC string, expectTerm int64) (bool, error) {
	var curHolder, expiresAt string
	err := tx.QueryRowContext(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key).Scan(&curHolder, &expiresAt)
	switch {
	case err == sql.ErrNoRows:
		// No row to renew. Whatever happened, this is not the tenure we classified.
		return false, nil
	case err != nil:
		return false, err
	}
	if curHolder != holder || expiresAt < nowRFC {
		return false, nil
	}
	var newest int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(term), 0) FROM leader_lease_terms WHERE key = ? AND deleted_at IS NULL`,
		key).Scan(&newest); err != nil {
		return false, err
	}
	return newest == expectTerm, nil
}

func renewLease(ctx context.Context, c *Client, key, holder, expires, nowRFC string) (bool, error) {
	if err := c.Execute(ctx, leaseUpsertSQL,
		key, holder, expires, c.NowTS(), nowRFC); err != nil {
		return false, fmt.Errorf("renew lease for %q: %w", key, err)
	}
	cur, _, err := leaseRow(ctx, c, key)
	if err != nil {
		return false, err
	}
	return cur == holder, nil
}

// takeLeaseAndMintTerm takes a lease and records a new incarnation ATOMICALLY.
//
// The two writes share one transaction via ExecuteBatchGuarded, whose guard runs
// inside that transaction against a consistent snapshot. Without atomicity a
// crash between them leaves the durable state as holder-recorded-with-no-term,
// which the next call would classify as the rolling-upgrade self-heal.
//
// The guard checks all three preconditions, which is why this cannot be done in
// SQL: a replicated INSERT must be `INSERT ... VALUES` (an
// `INSERT ... SELECT ... WHERE` is refused with `expected "VALUES", got
// "SELECT"`), so the term checks have nowhere to live in the statement. And
// dropping them is worse than having no atomicity: losing the race while still
// minting leaves an orphan term row that raises MAX(term) above the real
// holder's own term, actively fencing the legitimate leader.
//
// incarnationHasTerm says the ledger's newest term belongs to the incarnation
// the caller holds now; retire is the contested term the caller is retiring
// (0 for an ordinary acquisition), which lets the caller's own live tenure mint
// above its own term where clause 2 of leaseAcquirableTx would otherwise refuse
// it as a renewal.
func takeLeaseAndMintTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC string, now time.Time, incarnationHasTerm bool, retire int64) (bool, int64, error) {
	acquiredAt := now.UTC().Format(time.RFC3339)

	next, err := nextLeaseTerm(ctx, c, key)
	if err != nil {
		return false, 0, err
	}

	applied, err := c.ExecuteBatchGuarded(ctx,
		func(tx *sql.Tx) (bool, error) {
			return leaseAcquirableTx(ctx, tx, key, holder, nowRFC, next, incarnationHasTerm, retire)
		},
		[]Statement{
			{SQL: leaseUpsertSQL, Params: []interface{}{key, holder, expires, c.NowTS(), nowRFC}},
			// Built inline rather than via mintLeaseTermStmt so this function is
			// the statement's resolvable emitter: stmtshapecheck's reachability
			// guard refuses a registered shape whose builder it cannot tie to a
			// live caller, and routing the only production mint through a helper
			// hid it. mintLeaseTermStmt stays for the WAL-apply test, which needs
			// the same shape as a Statement value.
			{SQL: mintLeaseTermSQL, Params: []interface{}{key, next, holder, acquiredAt, acquiredAt, c.NowTS()}},
		})
	if err != nil {
		return false, 0, fmt.Errorf("acquire lease %q with term: %w", key, err)
	}
	if applied {
		// The guard held the client lock across the whole transaction and
		// confirmed both the lease and the term slot, so neither write was
		// dropped.
		return true, next, nil
	}

	// Declined. Distinguish "someone else holds the lease" — terminal — from
	// "the state moved under us" — retryable with a fresh classification.
	cur, _, err := leaseRow(ctx, c, key)
	if err != nil {
		return false, 0, err
	}
	if cur != "" && cur != holder {
		return false, 0, nil
	}
	return false, leaseContended, nil
}

// leaseRow reads key's current holder and expiry. holder is "" when the row is
// absent.
func leaseRow(ctx context.Context, c *Client, key string) (holder, expiresAt string, err error) {
	rows, err := c.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key)
	if err != nil {
		return "", "", fmt.Errorf("read lease row for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	return rows[0].String("holder"), rows[0].String("expires_at"), nil
}

// leaseAcquirableTx is the ACQUISITION precondition, evaluated as a whole inside
// the caller's transaction. All of it has to be one guard: each clause below
// closes a hole that checking the others alone left open.
//
//  1. The lease must be takeable — absent, expired, or already ours. This
//     mirrors leaseUpsertSQL's WHERE exactly, so the guard and the statement
//     cannot disagree about who may write.
//
//  2. If it is already ours and still live, a term must NOT already exist for
//     this key. Without this clause a same-holder caller that should have
//     RENEWED instead minted: production runs three distinct *Rebalancer values
//     against one key (the proposing loop, the executor loop, and the
//     RunRebalance RPC), so several callers with the same holder race the first
//     acquisition and every takeover. One committed term 1; another, classified
//     from a read taken before that commit, found slot 2 free and minted it.
//     Two rows for one unbroken tenure, and the caller left holding the lower
//     term sits below the rejection threshold — fenced by its own ledger.
//     Re-classifying on retry is not enough on its own, because the losing
//     caller's guard has to REJECT before the retry can reclassify.
//
//  3. term must be above every retained term. nextLeaseTerm runs outside the
//     transaction, so a peer's replicated term N+5 can arrive in the window
//     between the allocation read and this transaction, leaving slot N+1 free
//     while the cluster's rejection threshold has moved to N+5. Checking only
//     that the SLOT was unclaimed let the legitimate new holder record a term
//     below that threshold — the same inversion as an orphan term, arriving on
//     the success path. Comparing against MAX rather than existence also covers
//     the slot check, since tombstoned rows keep their number reserved.
//
// incarnationHasTerm narrows clause 2 to the term of the incarnation being
// held: a same-holder term left by a tenure that lapsed and was re-taken
// termlessly is an earlier tenure's, not a renewal of this one.
//
// retire > 0 relaxes clause 2 for exactly one case: retiring a contested term
// (see leader_lease_contest.go). The newest live term must still be that term
// and still recorded as ours on this replica, so a retirement classified from a
// read that has since been superseded — by a peer's higher term, or by a
// sibling caller that already retired it — declines like any other stale
// classification.
func leaseAcquirableTx(ctx context.Context, tx *sql.Tx, key, holder, nowRFC string, term int64, incarnationHasTerm bool, retire int64) (bool, error) {
	var curHolder, expiresAt string
	err := tx.QueryRowContext(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key).Scan(&curHolder, &expiresAt)
	switch {
	case err == sql.ErrNoRows:
		// Absent: acquirable.
	case err != nil:
		return false, err
	default:
		expired := expiresAt < nowRFC
		if !expired && curHolder != holder {
			return false, nil // someone else holds it
		}
		if !expired && curHolder == holder {
			// Our own live tenure. Only an acquisition if it has no term yet
			// (the rolling-upgrade self-heal).
			var n int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM leader_lease_terms WHERE key = ? AND deleted_at IS NULL`,
				key).Scan(&n); err != nil {
				return false, err
			}
			// A term exists for this key -- but it is only a RENEWAL if it
			// belongs to the incarnation we are currently holding. A node that
			// minted a term, lost its mint gate, let the lease lapse and
			// re-took it termlessly still has that old term in the ledger under
			// its own name; treating it as ours would carry a dead tenure's
			// term into a new one.
			if n > 0 && retire <= 0 && incarnationHasTerm {
				return false, nil // this incarnation's own term: a renewal
			}
			if n > 0 && retire > 0 {
				var newestTerm int64
				var newestHolder string
				if err := tx.QueryRowContext(ctx,
					`SELECT term, holder FROM leader_lease_terms
					  WHERE key = ? AND deleted_at IS NULL
					  ORDER BY term DESC LIMIT 1`, key).Scan(&newestTerm, &newestHolder); err != nil {
					return false, err
				}
				if newestTerm != retire || newestHolder != holder {
					return false, nil
				}
			}
		}
	}

	var maxTerm int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(term), 0) FROM leader_lease_terms WHERE key = ?`, key).Scan(&maxTerm); err != nil {
		return false, err
	}
	return maxTerm < term, nil
}

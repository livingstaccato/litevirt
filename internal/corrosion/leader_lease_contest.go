package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Contested lease terms, and the rule that makes a contested LEASE converge
// while the contested LEDGER ROW does not.
//
// Two survivors that claim one expired lease within a replication latency each
// commit the same (key, term) naming themselves. That is not exotic: it is what
// every leader death looks like when the survivors poll on the same interval.
// Nothing about it then heals on its own, for three independent reasons:
//
//   - leader_election: each replica's row names its own claimant, and a peer's
//     upsert is a no-op against a live row with a different holder
//     (leaseUpsertSQL's WHERE). The table is anti-entropy excluded.
//   - leader_lease_terms: each replica keeps its own claim, deliberately
//     (immutableMergeKeepLocalRow — two claims for one tenure are evidence and
//     are never coin-flipped).
//   - AcquireLeaseWithTerm then classifies every tick on every claimant as a
//     renewal of its own live tenure at its own newest term, and renews
//     forever.
//
// The ledger's contract is left exactly as it is. The convergence happens one
// layer up, in who is allowed to keep ACTING:
//
//  1. Every replica learns the full set of claimants for a contested term: the
//     WAL path notes a peer's mint that INSERT OR IGNORE dropped against a
//     different local holder, and the anti-entropy path notes the same
//     disagreement when it keeps the local row. Both claims are real — a peer
//     did commit that row — so noting them asserts nothing about which was
//     legitimate.
//  2. The claimants are ordered by holder name, and the lowest-sorting one is
//     the only one that may continue. Every claimant computes the same answer
//     from the same set, and the global minimum can never be told to stand down
//     by it, so the rule can neither elect two nor elect none.
//  3. A claimant that is NOT the minimum stands down: it stops renewing and
//     reports the lease not held, from the moment it learns of a lower claim.
//  4. The minimum does NOT keep acting under the contested term. It retires it,
//     minting a fresh term above it atomically with its renewal. The contested
//     term is then below every replica's rejection threshold, so neither of its
//     two ledger rows can ever again authorise anything — which is how "two
//     ledger values for one term" stops mattering without either being deleted.
//  5. A stood-down claimant's own leader_election row still names it until it
//     expires, and a naive takeover at that point would mint above the winner
//     and restart the fight. So an expired lease whose recorded holder is not
//     the ledger's current incarnation is not taken over until it has been
//     expired for a further TTL: a live incarnation renews well inside that and
//     its upsert then lands over the expired row, while a dead one is taken
//     over exactly one TTL later than usual. See deferTakeover.
//
// The register is in memory. After a restart it refills from the next
// anti-entropy exchange, because the two rows still disagree and the merge
// re-compares them every sweep — the same property that makes an unresolved tie
// re-appear after a restart (see acknowledgedTies). It is deliberately NOT the
// unresolved-tie register: an operator acknowledging a tie clears evidence
// tracking, and must never be what lets a losing claimant resume acting.

type leaseTermID struct {
	key  string
	term int64
}

type leaseContestRegister struct {
	mu sync.Mutex
	m  map[leaseTermID]map[string]struct{}
}

// noteLeaseTermClaims records holders as claimants of (key, term). Empty holders
// are ignored. It logs once per claimant newly added to an already-contested
// term, so a sweep that re-observes the same contest is silent.
func (c *Client) noteLeaseTermClaims(key string, term int64, holders ...string) {
	if key == "" || term <= 0 {
		return
	}
	r := &c.leaseContests
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = make(map[leaseTermID]map[string]struct{})
	}
	id := leaseTermID{key, term}
	set := r.m[id]
	if set == nil {
		set = make(map[string]struct{}, 2)
		r.m[id] = set
	}
	added := false
	for _, h := range holders {
		if h == "" {
			continue
		}
		if _, ok := set[h]; !ok {
			set[h] = struct{}{}
			added = true
		}
	}
	if added && len(set) > 1 {
		claimants := sortedClaimants(set)
		slog.Warn("leader lease: contested term — every claimant except the lowest-sorting "+
			"one stands down, and that one retires the term by minting above it",
			"key", key, "term", term, "claimants", claimants, "continues", claimants[0])
	}
}

// leaseTermClaimants returns every holder known to have claimed (key, term),
// sorted, or nil when the term is not contested (fewer than two claimants).
func (c *Client) leaseTermClaimants(key string, term int64) []string {
	r := &c.leaseContests
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.m[leaseTermID{key, term}]
	if len(set) < 2 {
		return nil
	}
	return sortedClaimants(set)
}

func sortedClaimants(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// effectiveLeaseHolder is who the ledger says holds the incarnation `newest`:
// its recorded holder, unless the term is contested, in which case the one
// claimant the convergence rule lets continue.
func (c *Client) effectiveLeaseHolder(key string, newest leaseTerm) (holder string, contested bool) {
	if newest.Term <= 0 {
		return newest.Holder, false
	}
	if cl := c.leaseTermClaimants(key, newest.Term); len(cl) > 0 {
		return cl[0], true
	}
	return newest.Holder, false
}

// deferTakeover reports whether this node must NOT yet take over an expired
// lease.
//
// It defers when the expired row names someone other than the ledger's current
// incarnation (and that incarnation is not us): this node has never seen that
// incarnation's lease lapse, only the lease of whoever its row happens to name.
// The case that matters is a claimant that stood down from a contested term —
// its own row names it and expires, while the winner's renewals were no-ops
// against it — but it is equally true of a bystander whose row missed a
// takeover. A live incarnation's next renewal lands over the expired row well
// inside one TTL; if none has by then, the incarnation is presumed dead exactly
// as an ordinary expiry would presume it, one TTL late.
//
// An unparseable expiry does not defer: this is a liveness heuristic, and the
// fencing it protects is the term ledger's, not this.
func deferTakeover(curHolder, curExpires, effective, holder string, now time.Time, ttl time.Duration) bool {
	if curHolder == "" || effective == "" || effective == curHolder || effective == holder {
		return false
	}
	exp, err := time.Parse(time.RFC3339, curExpires)
	if err != nil {
		return false
	}
	return !now.After(exp.Add(ttl))
}

// noteLeaseTermMergeConflict is the anti-entropy half of the claimant register:
// called by immutableMergeKeepLocalRow when it keeps a LIVE local
// leader_lease_terms row over a LIVE incoming row with different facts.
func (c *Client) noteLeaseTermMergeConflict(cols []string, localRow, incoming []interface{}) {
	ki, ti, hi := indexOf(cols, "key"), indexOf(cols, "term"), indexOf(cols, "holder")
	if ki < 0 || ti < 0 || hi < 0 || ki >= len(localRow) || ti >= len(localRow) || hi >= len(localRow) ||
		ki >= len(incoming) || ti >= len(incoming) || hi >= len(incoming) {
		return
	}
	term, err := strconv.ParseInt(coercePKString(localRow[ti]), 10, 64)
	if err != nil {
		return
	}
	c.noteLeaseTermClaims(coerceString(localRow[ki]), term,
		coerceString(localRow[hi]), coerceString(incoming[hi]))
}

// noteLeaseTermWALClaim is the WAL half: a peer's mint that INSERT OR IGNORE
// dropped because this replica already holds a live row for the same
// (key, term) naming a different holder. Without it a contest is only noticed on
// the next anti-entropy sweep, a minute later, and every claimant renews until
// then.
func (c *Client) noteLeaseTermWALClaim(ctx context.Context, tx *sql.Tx, cols []string, vals []interface{}) {
	ki, ti, hi := indexOf(cols, "key"), indexOf(cols, "term"), indexOf(cols, "holder")
	if ki < 0 || ti < 0 || hi < 0 || ki >= len(vals) || ti >= len(vals) || hi >= len(vals) {
		return
	}
	key := coerceString(vals[ki])
	incoming := coerceString(vals[hi])
	term, err := strconv.ParseInt(coercePKString(vals[ti]), 10, 64)
	if err != nil || key == "" || incoming == "" {
		return
	}
	var local string
	if err := tx.QueryRowContext(ctx,
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = ? AND deleted_at IS NULL`,
		key, term).Scan(&local); err != nil {
		return // absent (a constraint dropped it — noteIgnoredInsert's case) or unreadable
	}
	if local != incoming {
		c.noteLeaseTermClaims(key, term, local, incoming)
	}
}

// IsLeaseHolder reports whether host is the current holder of the lease `key`
// as this replica's term ledger sees it: its leader_election row is live and
// names host, AND the ledger's newest incarnation (contest-aware, via
// effectiveLeaseHolder) is host's.
//
// The row alone is not enough. A claimant that stood down from a contested term
// keeps a live row naming itself for up to one TTL — the winner's renewals are
// no-ops against it — while the ledger already carries the winner's fresh term,
// or at least records the contest. Reading only the row, two hosts both reported
// themselves leader for that window.
//
// A key with no term rows (a lease never minted through the ledger) falls back
// to the row. A ledger read error returns it: this is a reporting question, and
// the caller decides what an unanswerable one means.
func IsLeaseHolder(ctx context.Context, c *Client, key, host string, now time.Time) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT holder FROM leader_election WHERE key = ? AND expires_at >= ?`,
		key, now.UTC().Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("read lease %q: %w", key, err)
	}
	if len(rows) == 0 || rows[0].String("holder") != host {
		return false, nil
	}
	newest, err := newestLeaseTerm(ctx, c, key)
	if err != nil {
		return false, err
	}
	if newest.Term <= 0 {
		return true, nil
	}
	effective, _ := c.effectiveLeaseHolder(key, newest)
	return effective == host, nil
}

package corrosion

import (
	"context"
	"sync"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Settled ties in anti-entropy (colonelpanik/litevirt#262).
//
// An unresolved tie is kept local on BOTH sides on purpose (resolver_tracker.go),
// so the table holding it never digests equal to the peer holding the other
// version. Every scheduled pass therefore found the table mismatched, pulled it,
// merged nothing, and did it again: a 15-minute soak on the 5-node lab logged
// ~60 pulls per node of leader_lease_terms, all for one contested lease term
// that only an operator can answer (`lv cluster acknowledge-lease-term`), and an
// acknowledgement leaves both rows exactly as they are, so it never stopped.
//
// A pull already carries everything needed to prove the difference is only
// that. After the merge, the pulled rows are compared with the local table
// under one read lock; if the two hold the same primary keys and every row that
// differs is a tracked tie whose version set (tieVersions) holds BOTH this
// node's version and the peer's, the table is SETTLED against this peer at the (local, remote) digest pair
// the pass saw. The same scan yields the local digest, so the proof and the
// digest describe one state.
//
// A scheduled pass skips a table only when all of these still hold:
//   - the peer's digest is the one recorded, and so is ours: ANY write on
//     either side — a new row, a repair, a tombstone — moves a digest, and
//     the table is pulled on that very pass;
//   - every tie the proof relied on is still tracked with both versions, so a
//     register cleared by some other path puts the table back to pulling;
//   - the replica is caught up, as for observation tables.
//
// What is NOT settled, deliberately: a row the merge refused for any reason
// other than a tracked tie (a future-skewed timestamp, a gate that is closed
// today and open tomorrow, a quarantined origin). Those are differences a
// later pull can resolve without either digest moving, so a table holding one
// fails the proof and is pulled every pass, exactly as before.
//
// The operator's full pass (`lv cluster converge`, RunOnce) ignores the record
// and pulls every mismatched table. Nothing here touches the register itself:
// the tie stays tracked, so the ha.lww.unresolved condition, `lv doctor
// divergence` and litevirt_lww_tie_unresolved_current keep reporting it.
//
// The record is in memory and per node, so a restart starts with none: the
// first pass pulls, re-observes the tie (re-populating the register, which is
// also in memory) and settles it again.

// settledTies is this node's record, keyed by peer and table.
type settledTies struct {
	mu      sync.Mutex
	entries map[string]settledTie
}

// settledTie is one proven (local, remote) digest pair and the ties the proof
// relied on.
type settledTie struct {
	local  TableDigest
	remote TableDigest
	ties   map[string][2]string // unresolvedKey -> (local, peer) version fingerprints
}

func settledKey(peer, table string) string { return peer + "\x00" + table }

func remoteDigest(r *pb.TableDigest) TableDigest {
	return TableDigest{Name: r.GetName(), Count: int(r.GetCount()), Hash: r.GetHash(), HashV2: r.GetHashV2()}
}

func sameDigest(a, b TableDigest) bool {
	return a.Count == b.Count && a.Hash == b.Hash && a.HashV2 == b.HashV2
}

// deferSettledTies splits the mismatched tables a scheduled pass would pull
// into those it must pull and those already settled against this peer at
// exactly these digests.
func (c *Client) deferSettledTies(peer string, tables []string, local map[string]TableDigest, remote map[string]*pb.TableDigest) (pull, settled []string) {
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		return tables, nil
	}
	c.settled.mu.Lock()
	defer c.settled.mu.Unlock()
	for _, t := range tables {
		e, ok := c.settled.entries[settledKey(peer, t)]
		l, lok := local[t]
		r, rok := remote[t]
		if ok && lok && rok && sameDigest(e.local, l) && sameDigest(e.remote, remoteDigest(r)) && c.tiesStillTracked(e.ties) {
			settled = append(settled, t)
			continue
		}
		pull = append(pull, t)
	}
	return pull, settled
}

// tiesStillTracked reports whether every row is still a tracked tie holding
// both versions the proof saw.
func (c *Client) tiesStillTracked(ties map[string][2]string) bool {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	for key, v := range ties {
		if !c.tieVersionsKnownLocked(key, v[0], v[1]) {
			return false
		}
	}
	return len(ties) > 0
}

// recordSettledTies runs after a successful merge of dump, pulled from peer
// for tables. A table whose remaining difference is proven to be tracked ties
// only is recorded as settled at (its local digest now, the peer's digest the
// pass saw); every other pulled table has any record dropped.
//
// The peer's digest is the one read BEFORE the dump. If the peer wrote in
// between, the dump is newer than the digest recorded, and the next pass sees
// a different peer digest and pulls again: the race costs a pull, never a
// skipped difference.
func (c *Client) recordSettledTies(ctx context.Context, peer string, tables []string, dump []byte, remote map[string]*pb.TableDigest) {
	tracked := c.UnresolvedTieTables()
	var payload *syncPayload
	for _, t := range tables {
		key := settledKey(peer, t)
		r, rok := remote[t]
		if tracked[t] == 0 || !rok {
			c.dropSettled(key)
			continue
		}
		if payload == nil {
			p, err := decompressPayload(dump)
			if err != nil {
				c.dropSettled(key)
				continue
			}
			payload = p
		}
		var st *syncTable
		for i := range payload.Tables {
			if payload.Tables[i].Name == t {
				st = &payload.Tables[i]
				break
			}
		}
		if st == nil {
			c.dropSettled(key)
			continue
		}
		local, ties, ok := c.residualIsTrackedTies(ctx, *st)
		if !ok {
			c.dropSettled(key)
			continue
		}
		c.settled.mu.Lock()
		if c.settled.entries == nil {
			c.settled.entries = make(map[string]settledTie)
		}
		c.settled.entries[key] = settledTie{local: local, remote: remoteDigest(r), ties: ties}
		c.settled.mu.Unlock()
	}
}

func (c *Client) dropSettled(key string) {
	c.settled.mu.Lock()
	delete(c.settled.entries, key)
	c.settled.mu.Unlock()
}

// residualIsTrackedTies reports whether the local table differs from the
// peer's rows st only by ties this node tracks, with both versions in front of
// it already in the row's version set — whichever peer each was first seen
// from, so an N-way contest (every node its own claim) settles against every
// peer, not only the last one met. It returns the local digest of the state it
// examined (computed from the same scan, the same way StateDigest does) and
// the ties it relied on. Any doubt — a column list that differs, a row on one
// side only, a differing row whose versions the register has not both seen —
// answers false, which means "keep pulling".
func (c *Client) residualIsTrackedTies(ctx context.Context, st syncTable) (TableDigest, map[string][2]string, bool) {
	pkCols := tablePrimaryKeys[st.Name]
	if len(pkCols) == 0 {
		return TableDigest{}, nil, false
	}

	c.mu.RLock()
	rows, err := c.db.QueryContext(ctx, "SELECT * FROM "+st.Name)
	if err != nil {
		c.mu.RUnlock()
		return TableDigest{}, nil, false
	}
	cols, err := rows.Columns()
	if err != nil || !sameColumns(cols, st.Columns) {
		rows.Close()
		c.mu.RUnlock()
		return TableDigest{}, nil, false
	}
	pkIdx := columnIndexes(cols, pkCols)
	if len(pkIdx) != len(pkCols) {
		rows.Close()
		c.mu.RUnlock()
		return TableDigest{}, nil, false
	}
	wantV2 := c.digestV2On()
	v2ok := wantV2
	var v1Keys, v2Keys []string
	byPK := make(map[string][]interface{})
	scanOK := true
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			// digestTableRows skips such a row; the proof cannot vouch for it.
			scanOK = false
			continue
		}
		// Digest exactly as digestTableRows does, from the raw cells.
		v1Keys = append(v1Keys, encodeRowCells(vals))
		if v2ok {
			ek, eerr := encodeRowCellsV2(cols, vals)
			if eerr != nil {
				v2ok, v2Keys = false, nil
			} else {
				v2Keys = append(v2Keys, ek)
			}
		}
		// Compare as the merge does: []byte → string, then a JSON round trip
		// so value kinds match the post-transit peer row (fetchLocalRowCells).
		norm := make([]interface{}, len(vals))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				norm[i] = string(b)
			} else {
				norm[i] = v
			}
		}
		norm = jsonRoundTripCells(norm)
		byPK[pkKeyAt(norm, pkIdx)] = norm
	}
	rowsErr := rows.Err()
	rows.Close()
	c.mu.RUnlock()
	if !scanOK || rowsErr != nil || len(byPK) != len(st.Rows) {
		return TableDigest{}, nil, false
	}

	ties := make(map[string][2]string)
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	for _, row := range st.Rows {
		if len(row) != len(cols) {
			return TableDigest{}, nil, false
		}
		pk := pkKeyAt(row, pkIdx)
		local, ok := byPK[pk]
		if !ok {
			return TableDigest{}, nil, false
		}
		if encodeRowCells(local) == encodeRowCells(row) {
			continue
		}
		key := unresolvedKey(st.Name, pk)
		v := [2]string{versionFingerprint(local), versionFingerprint(row)}
		if !c.tieVersionsKnownLocked(key, v[0], v[1]) {
			return TableDigest{}, nil, false
		}
		ties[key] = v
	}
	if len(ties) == 0 {
		// Nothing differs row by row: whatever the digests disagree on, it is
		// not a tie, and this record is only for ties.
		return TableDigest{}, nil, false
	}
	d := TableDigest{Name: st.Name, Count: len(v1Keys), Hash: hashRowKeys(v1Keys)}
	if v2ok {
		d.HashV2 = hashRowKeys(v2Keys)
	}
	return d, ties, true
}

func sameColumns(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

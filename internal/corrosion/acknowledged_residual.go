package corrosion

import (
	"context"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Acknowledged ties in the convergence report.
//
// An acknowledged tie leaves both rows exactly as they are, so the table that
// holds it never digests equal across hosts, and `lv cluster converge` used to
// call it a SAFETY-FAULT forever: every host's tie count was non-zero and the
// hashes differed, which is all that report could see. An operator who had
// investigated and acknowledged the term had no way to get a converged cluster
// back short of the evidence going away, which it never does by design.
//
// Counting such a table converged needs more than "every tie on it is
// acknowledged": the hashes would differ just the same if an unrelated row had
// drifted beside the tie, and a report that folded that into "converged" would
// hide real drift behind a reviewed fault. So each host also reports a
// RESIDUAL digest: the table hashed with every acknowledged-tie row replaced by
// a marker that names only its primary key. Two hosts' residuals agree exactly
// when they hold the same set of acknowledged contested rows and are identical
// everywhere else. The report counts the table converged only when every host
// reporting it supplies a residual and all of them agree.
//
// A residual is withheld — never approximated — whenever this host cannot
// vouch for it: the table has an UNACKNOWLEDGED tie here (the report must
// raise that), an acknowledged tie names a row this host no longer holds, or a
// row does not encode. The report then falls back to the old verdict.

// TieTableCounts counts, per table, every tracked tie (UnresolvedTieTables)
// and the subset an operator has acknowledged on this node, from ONE snapshot
// of the register, so the subset can never exceed its superset.
func (c *Client) TieTableCounts() (tracked, acknowledged map[string]int) {
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	tracked, acknowledged = make(map[string]int), make(map[string]int)
	for k, t := range c.unresolvedTies {
		i := strings.IndexByte(k, 0)
		if i <= 0 {
			continue
		}
		tracked[k[:i]]++
		if t.acknowledged {
			acknowledged[k[:i]]++
		}
	}
	return tracked, acknowledged
}

// AcknowledgedResiduals returns, for each of tables in which this node tracks
// at least one acknowledged tie and no unacknowledged one, the residual digest
// described above. Tables it cannot vouch for are absent.
//
// It scans only those tables, which on a healthy cluster is none, so the cost
// is nothing until an operator has acknowledged something.
func (c *Client) AcknowledgedResiduals(ctx context.Context, tables []string) map[string]string {
	acked := map[string]map[string]bool{}
	live := map[string]bool{}
	c.tieMu.Lock()
	for k, t := range c.unresolvedTies {
		i := strings.IndexByte(k, 0)
		if i <= 0 {
			continue
		}
		table, pk := k[:i], k[i+1:]
		if !t.acknowledged {
			live[table] = true
			continue
		}
		if acked[table] == nil {
			acked[table] = map[string]bool{}
		}
		acked[table][pk] = true
	}
	c.tieMu.Unlock()

	out := map[string]string{}
	for _, t := range tables {
		if len(acked[t]) == 0 || live[t] {
			continue
		}
		if r, ok := c.acknowledgedResidual(ctx, t, acked[t]); ok {
			out[t] = r
		}
	}
	return out
}

// acknowledgedResidual hashes table with each row whose primary key is in
// ackedPKs replaced by a marker naming only that key. The key spelling is the
// merge's (a JSON round trip, then pkKeyAt), which is what the register is
// keyed by, as in residualIsTrackedTies. Rows are encoded with the
// order-invariant v2 encoding, so column order does not matter; a row that
// does not encode withholds the residual.
func (c *Client) acknowledgedResidual(ctx context.Context, table string, ackedPKs map[string]bool) (string, bool) {
	pkCols := tablePrimaryKeys[table]
	if len(pkCols) == 0 || !(replicatedTableSet[table] || sensitiveTableSet[table]) {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	rows, err := c.db.QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "", false
	}
	pkIdx := columnIndexes(cols, pkCols)
	if len(pkIdx) != len(pkCols) {
		return "", false
	}
	var keys []string
	found := 0
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", false
		}
		norm := make([]interface{}, len(vals))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				norm[i] = string(b)
			} else {
				norm[i] = v
			}
		}
		pk := pkKeyAt(jsonRoundTripCells(norm), pkIdx)
		if ackedPKs[pk] {
			found++
			keys = append(keys, "acknowledged\x00"+pk)
			continue
		}
		enc, err := encodeRowCellsV2(cols, vals)
		if err != nil {
			return "", false
		}
		keys = append(keys, "row\x00"+enc)
	}
	if rows.Err() != nil || found != len(ackedPKs) {
		return "", false
	}
	return "v2:" + hashRowKeys(keys), true
}

// TieAckVerdict is what every host's verification digest says about one
// table's tracked ties. It is the one place that decides whether a table is
// held apart only by acknowledged ties: `lv cluster converge` lists such a
// table ACKNOWLEDGED, and `lv doctor divergence` classes its rows
// acknowledged_tie, so the two commands cannot disagree.
type TieAckVerdict struct {
	// Ties is every tracked tie in the table, summed across reporting hosts.
	Ties int32
	// Acknowledged is the acknowledged subset, clipped per host to that
	// host's tracked count.
	Acknowledged int32
	// Vouching lists the hosts that can vouch for the table: they track at
	// least one tie in it, every one acknowledged, and supplied a residual.
	// A host that tracks nothing here cannot say its difference is the
	// acknowledged rows; a rebuilt host with an empty register is one.
	Vouching []string
	// NotVouching lists the other hosts that reported the table.
	NotVouching []string
	residuals   map[string]bool
}

// Live is the number of tracked ties no operator has acknowledged.
func (v *TieAckVerdict) Live() int32 { return v.Ties - v.Acknowledged }

// VouchedBy reports whether host vouched for the table.
func (v *TieAckVerdict) VouchedBy(host string) bool {
	for _, h := range v.Vouching {
		if h == host {
			return true
		}
	}
	return false
}

// AcknowledgedOnly reports whether the table is held apart only by ties every
// reporting host has acknowledged, and every host's residual (the table with
// those rows masked) agrees, so nothing else differs.
func (v *TieAckVerdict) AcknowledgedOnly() bool {
	return v.Live() == 0 && v.Acknowledged > 0 && len(v.NotVouching) == 0 && len(v.residuals) == 1
}

// TieAckVerdicts reads every host's verification digest, per table. Hosts are
// listed in the order the digests name them.
func TieAckVerdicts(hosts []*pb.StateDigestResponse) map[string]*TieAckVerdict {
	out := map[string]*TieAckVerdict{}
	for _, h := range hosts {
		for _, t := range h.GetTables() {
			v := out[t.GetName()]
			if v == nil {
				v = &TieAckVerdict{residuals: map[string]bool{}}
				out[t.GetName()] = v
			}
			tracked := t.GetUnresolvedTies()
			a := t.GetAcknowledgedTies()
			if a > tracked {
				a = tracked
			}
			v.Ties += tracked
			v.Acknowledged += a
			// Every host must vouch: hold ties here, all of them
			// acknowledged, and a residual.
			if tracked == 0 || a != tracked || t.GetAcknowledgedResidual() == "" {
				v.NotVouching = append(v.NotVouching, h.GetHostName())
			} else {
				v.Vouching = append(v.Vouching, h.GetHostName())
				v.residuals[t.GetAcknowledgedResidual()] = true
			}
		}
	}
	return out
}

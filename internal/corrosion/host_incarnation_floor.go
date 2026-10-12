package corrosion

import (
	"database/sql"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// The hosts floor under anti-entropy: a row of a host's previous incarnation
// never replaces the re-admitted one, however new its updated_at.
//
// A host removed while it was down and re-added while its data directory still
// held the OLD database boots with its own row live there, and every write it
// makes is newer than the re-admission (host_readmit.go, THE INCARNATION).
// Its replicated writes are single-column updates, and every node applies them
// over the re-admission's reset row. But anti-entropy is a pull of whole rows:
// a node that pulled that host's row before its writes arrived took the whole
// stale row, which is strictly newer, so no tie rule ever saw it. The removed
// machine's labels, region, role, fence target, watchdog and grpc_port came
// back on that node, and where every survivor pulled first the cluster settled
// on the stale row with nothing to report.
//
// So a node holding a re-admitted row keeps it against an incoming live row
// whose created_at is earlier than the re-admission's stamp (olderIncarnation).
// The judgement is by the stamp, never by comparing the two rows' updated_at.
// Nothing is lost by refusing: the stale side's later writes still
// reach this node by WAL and apply over the row it keeps, after which the two
// rows tie and the tie chain hands the stale side this row, whole.
//
// What it does not refuse:
//   - a row with no fixed-width created_at locally: a host inserted by an
//     older build and never re-admitted, or a node that has not applied the
//     re-admission (that node takes the stale
//     row as before, then the re-admitted one by the tie once the writes
//     catch up);
//   - an incoming row of the same or a later incarnation, a tombstone, or a
//     dump that does not carry created_at;
//   - the WAL lane. A WAL write to hosts from the stale side is a column
//     update and carries no created_at; the one hosts write that does is
//     InsertHost, which is how a machine re-added on an EMPTY database
//     registers, and that must apply over the stamped row. Its created_at is
//     written after the admission, so anti-entropy carries it too; that
//     machine's insert can lose here only to a clock skew larger than the time
//     between its admission and its daemon's first start.
func hostsOlderIncarnationRefused(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error) {
	idx := columnIndexMap(table.Columns)
	if _, ok := idx["created_at"]; !ok {
		return false, "", nil
	}
	if _, ok := idx["deleted_at"]; !ok {
		return false, "", nil
	}
	if cellStr(row, idx, "deleted_at") != "" {
		return false, "", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, "", err
	}
	if cellStr(localRow, idx, "deleted_at") != "" {
		return false, "", nil
	}
	if olderIncarnation(cellStr(localRow, idx, "created_at"), cellStr(row, idx, "created_at")) {
		return true, "older_incarnation", nil
	}
	return false, "", nil
}

// olderIncarnation reports whether incoming is an earlier incarnation than the
// local row: local's created_at is in the fixed-width form a re-admission
// stamps (and this build's InsertHost writes), and incoming's is earlier than
// it by more than hlc.MaxSkewMS.
//
// The grace is the skew the HLC already tolerates. A re-admission's stamp is
// the admitter's HLC physical time, which can lead any host's wall clock by
// up to MaxSkewMS once the admitter has adopted a peer that runs ahead; a
// machine re-added on an EMPTY database inserts its row after its admission,
// but by its own wall clock, so its created_at can fall up to that far behind
// the stamp while being the newer incarnation. Its insert carries the only
// copy of its grpc_port besides a re-admission's, so it must not be refused.
// A genuinely stale row carries its original insert's created_at, which
// predates the re-admission by the host's whole first membership, its downtime
// and its removal. The one case the grace gives up is a host added and then
// re-admitted within MaxSkewMS: there the floor and the tie rule pass, and the
// row falls back to plain LWW, as before this rule. An unparseable incoming
// value is no evidence.
func olderIncarnation(localCreated, incomingCreated string) bool {
	if !isReadmitStamp(localCreated) {
		return false
	}
	l, _ := time.Parse(time.RFC3339, localCreated)
	in, err := time.Parse(time.RFC3339, incomingCreated)
	return err == nil && in.Before(l.Add(-time.Duration(hlc.MaxSkewMS)*time.Millisecond))
}

// isReadmitStamp reports whether s is in the re-admission stamp's form.
func isReadmitStamp(s string) bool {
	t, err := time.Parse(nowTSLayout, s)
	return err == nil && t.UTC().Format(nowTSLayout) == s
}

const hostsIncarnationAdvice = "A peer offered this host's row from before its re-admission (an older " +
	"created_at): the host was re-added while its data directory still held its old database. The " +
	"re-admitted row is kept; the host's own later writes still arrive by replication"

// refusalLogInterval is how often the floor's warning names one row. The
// refusal repeats every anti-entropy cycle on every node holding the
// re-admitted row, for as long as the re-added host's writes have not arrived
// or an older-build peer holds its stale row; the counter
// (merge_apply_rejected, reason older_incarnation) counts every one.
const refusalLogInterval = 10 * time.Minute

// refusalLogLimiter lets a row's warning through once per refusalLogInterval.
type refusalLogLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *refusalLogLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if t, ok := l.last[key]; ok && now.Sub(t) < refusalLogInterval {
		return false
	}
	if len(l.last) >= 4096 { // bounded: forget everything rather than grow
		l.last = map[string]time.Time{}
	}
	l.last[key] = now
	return true
}

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A statement a node logs for replication is applied by its peers only if its
// shape is in the compatibility ledger (corrosion.LedgerLookup). An unregistered
// one is refused by every receiver, and the refusal BACK-PRESSURES: the whole
// batch rolls back, the sender's watermark stays where it was, and every write
// that node makes afterwards waits behind the refused one, forever.
//
// Product code cannot do this — stmtshapecheck fails CI on any builder whose
// shape is not registered. A fleet scenario can: it seeds state with raw
// n.DB.Execute calls, which stmtshapecheck does not scan (it loads no test
// files). Under IndependentReplicas such a seed silently stops replication from
// that node for the rest of the test, and a scenario asserting that something
// did NOT reach a peer then passes whatever the product does. It happened:
// setHostCapacity's raw `UPDATE hosts` and a raw image-catalog INSERT stalled
// the iSCSI fleet tests' replication (iscsi-lun-report.md, round 3).
//
// So the harness refuses it. When a cluster stops, every node's mutation_log is
// read back and each statement is checked against the receiver's first two
// refusals: it must parse (corrosion.FingerprintSQL) and its shape must be in
// the ledger (corrosion.LedgerLookup). One that fails either fails the test,
// naming the statement; so does a log the check cannot read, because a
// statement it cannot see is one it cannot clear. Seed a replicated row through
// a corrosion builder, or, where every node should hold it without replication,
// write it on each with localExec (local_exec.go).
//
// The check is narrower than the receiver, and deliberately so. The receiver
// (Replicator.applyStatementLWW) also normalises a few prior-release shapes
// through a legacy transformer before parsing, refuses a registered shape whose
// parameter count does not match it, and refuses a capability-gated shape
// emitted before its capability latched. This check reports none of those: a
// wrong-arity write or a premature gated shape still stalls a stream unseen,
// and a scenario that emits a prior-release statement the transformer accepts
// would be reported although a receiver applies it. Product builders cannot
// produce the first two (stmtshapecheck); a scenario emitting the third says
// so with AllowUnregisteredReplicatedWrites.
//
// A shared-database cluster (SharedCRDT) replicates nothing and is not checked.
// A scenario that writes an unregistered shape ON PURPOSE — to test the
// back-pressure itself — says so with AllowUnregisteredReplicatedWrites.

// AllowUnregisteredReplicatedWrites turns off the stop-time shape check for
// this cluster, for a scenario whose subject is a statement no receiver
// applies. The reason is logged so the exemption is visible in the test output.
func (c *Cluster) AllowUnregisteredReplicatedWrites(reason string) {
	c.t.Helper()
	if strings.TrimSpace(reason) == "" {
		c.t.Fatal("fleet: AllowUnregisteredReplicatedWrites needs a reason")
	}
	c.unregisteredAllowed = reason
	c.t.Logf("fleet: replicated-shape check off for this cluster: %s", reason)
}

// checkReplicatedShapes is the stop-time check described above. It runs once,
// from Stop, before any database closes, and reports through shapeErrorf
// (t.Errorf unless a test of the check itself captures it).
func (c *Cluster) checkReplicatedShapes() {
	if c.shapesChecked {
		return
	}
	c.shapesChecked = true
	if report := c.replicatedShapeReport(); report != "" {
		errorf := c.shapeErrorf
		if errorf == nil {
			errorf = c.t.Errorf
		}
		errorf("%s", report)
	}
}

// replicatedShapeReport is what checkReplicatedShapes fails the test with, or
// "" when there is nothing to report.
func (c *Cluster) replicatedShapeReport() string {
	if c.opts.SharedCRDT || c.unregisteredAllowed != "" {
		return ""
	}
	bad, unreadable := unregisteredReplicatedStatements(c.Nodes)
	if len(bad) == 0 && len(unreadable) == 0 {
		return ""
	}
	mode := "scenario-steered replication"
	if c.opts.IndependentReplicas {
		mode = "IndependentReplicas"
	}
	var b strings.Builder
	if len(bad) > 0 {
		fmt.Fprintf(&b, "fleet (%s): the scenario logged %d replicated statement shape(s) no receiver applies. "+
			"Each one back-pressures replication from the node that wrote it for the rest of the test, "+
			"so an assertion that something did not reach a peer can pass vacuously. Write the row "+
			"through a corrosion builder, or locally on each node that should hold it (localExec):\n%s",
			mode, len(bad), strings.Join(bad, "\n"))
	}
	if len(unreadable) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "fleet (%s): the replicated-shape check could not read every node's mutation_log, "+
			"so it cannot clear what it did not see:\n%s", mode, strings.Join(unreadable, "\n"))
	}
	return b.String()
}

// unregisteredReplicatedStatements reads every node's mutation_log and returns,
// once per distinct SQL, each statement a receiver would refuse as an
// unparseable or unregistered shape, with the nodes that logged it; and, in
// unreadable, every log or entry it could not read.
func unregisteredReplicatedStatements(nodes []*Node) (bad, unreadable []string) {
	ctx := context.Background()
	where := map[string]map[string]bool{} // sql → node names
	why := map[string]string{}
	for _, n := range nodes {
		if n.DB == nil {
			continue
		}
		rows, err := n.DB.DB().QueryContext(ctx, `SELECT seq, stmts FROM mutation_log`)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("  - %s: read mutation_log: %v", n.Name, err))
			continue
		}
		for rows.Next() {
			var seq int64
			var raw string
			if err := rows.Scan(&seq, &raw); err != nil {
				unreadable = append(unreadable, fmt.Sprintf("  - %s: scan mutation_log: %v", n.Name, err))
				continue
			}
			var stmts []corrosion.Statement
			if err := json.Unmarshal([]byte(raw), &stmts); err != nil {
				// An undecodable entry back-pressures a receiver too.
				unreadable = append(unreadable, fmt.Sprintf("  - %s: mutation_log seq %d does not decode: %v", n.Name, seq, err))
				continue
			}
			for _, s := range stmts {
				reason := ""
				if fp, err := corrosion.FingerprintSQL(s.SQL); err != nil {
					reason = fmt.Sprintf("unparseable: %v", err)
				} else if _, ok := corrosion.LedgerLookup(fp); !ok {
					reason = "unregistered shape " + fp
				}
				if reason == "" {
					continue
				}
				if where[s.SQL] == nil {
					where[s.SQL] = map[string]bool{}
				}
				where[s.SQL][n.Name] = true
				why[s.SQL] = reason
			}
		}
		if err := rows.Err(); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("  - %s: read mutation_log: %v", n.Name, err))
		}
		rows.Close()
	}
	for sql, ns := range where {
		var names []string
		for n := range ns {
			names = append(names, n)
		}
		sort.Strings(names)
		bad = append(bad, fmt.Sprintf("  - %s (%s; logged on %s)",
			strings.Join(strings.Fields(sql), " "), why[sql], strings.Join(names, ", ")))
	}
	sort.Strings(bad)
	return bad, unreadable
}

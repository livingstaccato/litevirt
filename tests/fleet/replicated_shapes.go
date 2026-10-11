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
// read back and each statement is fingerprinted exactly as a receiver would;
// one no receiver can apply fails the test, naming the statement. Seed a
// replicated row through a corrosion builder, or, where every node should hold
// it without replication, write it on each with localExec (local_exec.go).
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
// from Stop, before any database closes.
func (c *Cluster) checkReplicatedShapes() {
	if c.shapesChecked || c.opts.SharedCRDT || c.unregisteredAllowed != "" {
		c.shapesChecked = true
		return
	}
	c.shapesChecked = true
	bad := unregisteredReplicatedStatements(c.Nodes)
	if len(bad) == 0 {
		return
	}
	mode := "scenario-steered replication"
	if c.opts.IndependentReplicas {
		mode = "IndependentReplicas"
	}
	c.t.Errorf("fleet (%s): the scenario logged %d replicated statement shape(s) no receiver applies. "+
		"Each one back-pressures replication from the node that wrote it for the rest of the test, "+
		"so an assertion that something did not reach a peer can pass vacuously. Write the row "+
		"through a corrosion builder, or locally on each node that should hold it (localExec):\n%s",
		mode, len(bad), strings.Join(bad, "\n"))
}

// unregisteredReplicatedStatements reads every node's mutation_log and returns,
// once per distinct SQL, each statement a receiver would refuse as an
// unparseable or unregistered shape, with the nodes that logged it.
func unregisteredReplicatedStatements(nodes []*Node) []string {
	ctx := context.Background()
	where := map[string]map[string]bool{} // sql → node names
	why := map[string]string{}
	for _, n := range nodes {
		if n.DB == nil {
			continue
		}
		rows, err := n.DB.DB().QueryContext(ctx, `SELECT stmts FROM mutation_log`)
		if err != nil {
			continue // closed or never opened: nothing this check can read
		}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				continue
			}
			var stmts []corrosion.Statement
			if json.Unmarshal([]byte(raw), &stmts) != nil {
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
		rows.Close()
	}
	var out []string
	for sql, ns := range where {
		var names []string
		for n := range ns {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, fmt.Sprintf("  - %s (%s; logged on %s)",
			strings.Join(strings.Fields(sql), " "), why[sql], strings.Join(names, ", ")))
	}
	sort.Strings(out)
	return out
}

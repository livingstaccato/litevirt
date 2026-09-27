package corrosion

import (
	"context"
	"strings"
	"testing"
)

// TestFencedClaimConflictQueryUsesAnIndex pins the cost of the fenced-claim
// conflict guard.
//
// That guard counts rows matching (lease_term, lease_key, executor_host), and
// it deliberately INCLUDES tombstones — a conflicting claim is evidence, not a
// consumable. So its cost grows with every proof ever written rather than with
// the live set, and it runs inside the claim's write transaction while the
// global client mutex is held. Unindexed, a year into a busy cluster it walks
// hundreds of thousands of rows, once per claim, with dozens of claims in
// flight after a host loss — and health publishes, lease renewals and
// replication applies all queue behind it on that node.
//
// EXPLAIN QUERY PLAN is the assertion because the property is "this does not
// scan", which no functional test can observe: the guard returns the same
// answer either way, just slower.
func TestFencedClaimConflictQueryUsesAnIndex(t *testing.T) {
	c := newTestDB(t)

	rows, err := c.Query(context.Background(),
		`EXPLAIN QUERY PLAN
		 SELECT COUNT(*) FROM runtime_action_proofs
		  WHERE lease_term = ? AND lease_key = ? AND executor_host = ?
		    AND coordinator <> ? AND id <> ?`,
		1, "failover", "h1", "coord", "p1")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no query plan returned; this test cannot see what it claims to check")
	}

	var plan strings.Builder
	for _, r := range rows {
		plan.WriteString(r.String("detail"))
		plan.WriteString("\n")
	}
	got := plan.String()

	if !strings.Contains(got, "idx_proofs_term_claimant") {
		t.Errorf("the fenced-claim conflict guard does not use idx_proofs_term_claimant.\n"+
			"plan:\n%s"+
			"Without it this is a full scan of every proof ever written, inside the claim's "+
			"write transaction, under the client mutex. If the index was made partial-on-live "+
			"it no longer serves this query, because the guard counts tombstones on purpose.", got)
	}
	if strings.Contains(got, "SCAN runtime_action_proofs") &&
		!strings.Contains(got, "USING INDEX") && !strings.Contains(got, "USING COVERING INDEX") {
		t.Errorf("the guard falls back to a table scan.\nplan:\n%s", got)
	}
}

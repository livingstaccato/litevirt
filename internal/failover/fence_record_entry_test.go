package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestFailover_FenceRowAndStateShareOneEntry pins that a verified fence's
// fencing_log row and the 'fenced' state it establishes replicate as ONE
// mutation_log entry. An entry is applied in one transaction, so no peer can
// hold the row without the state. As two entries, a successor that held the
// row with the host still 'active' skipped the host as recently fenced, and a
// leader that died between the two pushes left it there.
//
// Mutation: write the two with InsertFenceLog and markHostState again.
func TestFailover_FenceRowAndStateShareOneEntry(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, name := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")

	c := NewCoordinator("first", db)
	c.Now = func() time.Time { return now }
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Detail: "verified off", Success: true}
	})
	c.RunOnce(ctx)

	rows, err := db.Query(ctx, `SELECT seq, stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var withRow []string
	stateAlone := 0
	for _, r := range rows {
		s := r.String("stmts")
		hasRow := strings.Contains(s, "INTO fencing_log")
		hasState := strings.Contains(s, "UPDATE hosts SET state")
		switch {
		case hasRow:
			withRow = append(withRow, s)
		case hasState && strings.Contains(s, `"fenced"`):
			stateAlone++
		}
	}
	if len(withRow) != 1 {
		t.Fatalf("%d mutation_log entries carry the fence row, want 1", len(withRow))
	}
	if !strings.Contains(withRow[0], "UPDATE hosts SET state") {
		t.Errorf("the fence row's entry does not carry the host's 'fenced' state: %s", withRow[0])
	}
	if stateAlone != 0 {
		t.Errorf("%d separate entries write the 'fenced' state; a peer can apply the row without it", stateAlone)
	}
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "fenced" {
		t.Errorf("bad is %+v after a verified fence, want 'fenced'", h)
	}
}

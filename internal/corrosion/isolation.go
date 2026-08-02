package corrosion

import (
	"context"
	"errors"
	"fmt"
)

// Isolation epoch (§A). A node whose local state was produced OUTSIDE the
// cluster's current compatibility regime — rolled back below a latched
// capability token, or isolated by an operator — must not be able to inject
// that state back. The epoch is CLUSTER state about a host: replicated, so
// every peer independently refuses the quarantined node's replication, and
// peer-written, because a node that cannot be trusted to replicate cannot be
// trusted to record its own quarantine.

// Isolation reasons. Kept as a closed set so the admission refusal and the
// operator surfaces can be reasoned about (and so a typo can't invent a state).
const (
	IsolationRolledBackLatch = "rolled_back_latch" // below a token this node had latched
	IsolationManual          = "manual"            // operator-driven (lv host isolate)
	IsolationSchemaForward   = "schema_forward"    // local schema ahead of the cluster
)

var isolationReasons = map[string]bool{
	IsolationRolledBackLatch: true,
	IsolationManual:          true,
	IsolationSchemaForward:   true,
}

// ErrSelfIsolation rejects a node recording its OWN isolation. The whole point
// of putting the epoch in cluster state is that the observation comes from a
// healthy peer; a self-write would let a node that is lying about its state
// also control the record of that state.
var ErrSelfIsolation = errors.New("a node may not record its own isolation — a healthy peer must observe it")

// ErrIsolationNotMonotone rejects an epoch that would not increase. The column
// is monotone by contract: re-isolating an already-isolated host is a no-op
// rather than a fresh epoch, and nothing may lower it except a verified reseed.
var ErrIsolationNotMonotone = errors.New("isolation epoch must increase")

// IsolateHost records host as isolated at the next cluster-wide epoch. observer
// is the host making the observation and MUST NOT be the subject.
//
// The epoch is cluster-wide-max + 1 rather than per-host + 1 so the value
// orders isolations across the cluster: an operator reading two isolated hosts
// can tell which was quarantined later without a separate timestamp column
// (which a rolled-back node's clock could poison).
func IsolateHost(ctx context.Context, c *Client, observer, host, reason string) error {
	if observer == "" || host == "" {
		return invalidf("isolation requires an observer and a subject host")
	}
	if observer == host {
		return fmt.Errorf("%w (observer=%s)", ErrSelfIsolation, observer)
	}
	if !isolationReasons[reason] {
		return invalidf("isolation reason %q: want rolled_back_latch|manual|schema_forward", reason)
	}
	next, err := nextIsolationEpoch(ctx, c)
	if err != nil {
		return err
	}
	now := c.NowTS()
	// Guarded on NOT-ALREADY-ISOLATED. The detector runs every sweep, so an
	// already-isolated host must keep its ORIGINAL epoch: re-stamping a fresh
	// one on each pass would make the number meaningless (it is supposed to
	// order isolations), rewrite the row forever, and — worse — move the epoch
	// out from under a reseed that pinned it, so a verified reseed could never
	// clear anything. Two peers racing to isolate the same node converge for
	// the same reason: the first write wins, the second is a no-op.
	n, err := c.ExecuteRows(ctx,
		`UPDATE hosts SET isolation_epoch = ?, isolation_reason = ?, updated_at = ?
		 WHERE name = ? AND deleted_at IS NULL AND isolation_epoch = 0`,
		next, reason, now, host)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrIsolationNotMonotone
	}
	return nil
}

// nextIsolationEpoch reads the cluster-wide maximum and returns max+1.
func nextIsolationEpoch(ctx context.Context, c *Client) (int64, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(MAX(isolation_epoch), 0) AS m FROM hosts`)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 1, nil
	}
	return rows[0].Int64("m") + 1, nil
}

// ClearHostIsolation is the ONLY writer that lowers the epoch, and exists for
// exactly one caller: a reseed that has VERIFIED convergence. expectedEpoch
// pins the isolation the reseed actually reconciled, so an isolation recorded
// while the reseed was running is not silently cleared by it — the node stays
// quarantined and the operator reseeds again against the newer fact.
func ClearHostIsolation(ctx context.Context, c *Client, host string, expectedEpoch int64) error {
	if host == "" || expectedEpoch <= 0 {
		return invalidf("clearing isolation requires a host and the epoch being cleared")
	}
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE hosts SET isolation_epoch = 0, isolation_reason = '', updated_at = ?
		 WHERE name = ? AND deleted_at IS NULL AND isolation_epoch = ?`,
		now, host, expectedEpoch)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// HostIsolation reports a host's recorded isolation. A host row that is absent
// reports NOT isolated: absence is an unknown host (a fresh peer, a removed
// one), which the mTLS/admission layers judge on their own terms — inventing
// an isolation here would refuse legitimate first contact.
func HostIsolation(ctx context.Context, c *Client, host string) (epoch int64, reason string, err error) {
	rows, err := c.Query(ctx,
		`SELECT isolation_epoch AS e, COALESCE(isolation_reason, '') AS r
		 FROM hosts WHERE name = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return 0, "", err
	}
	if len(rows) == 0 {
		return 0, "", nil
	}
	return rows[0].Int64("e"), rows[0].String("r"), nil
}

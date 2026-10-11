package fleet

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// localExec writes sql to db's own database and nowhere else: nothing is
// logged for replication, so no peer ever sees it and nothing queues behind
// it. It is the write for what a scenario means to exist on ONE node — a
// tampered or missing row, a failure-injection trigger, a node-local seed
// every node is given separately — and the replacement for a raw replicated
// Execute whose shape no receiver applies (replicated_shapes.go). A row that
// must reach peers is written through the corrosion builder production uses.
//
// It is not Execute minus the log. It runs straight on the client's database
// handle, so, unlike Execute, it:
//   - takes no client lock (Client.Mu): it is not serialised with the
//     client's own writers or the replicator's apply, so a write that meets one
//     mid-transaction is left to SQLite's own locking, and can fail with a
//     lock error where Execute would have waited its turn;
//   - ignores a WAL quarantine, which refuses Execute outright;
//   - runs the SQL exactly as written: an UPDATE is not swapped for the
//     LWW-guarded form Execute applies to a live row (appliedForm), so it lands
//     unconditionally — usually what a tamper means, and never what a scenario
//     modelling a real write should use;
//   - is still seen by the client's pre-update hook, so digests and the digest
//     cache account for it as for any local write.
func localExec(ctx context.Context, db *corrosion.Client, sql string, args ...any) error {
	_, err := db.DB().ExecContext(ctx, sql, args...)
	return err
}

// localExecRows is localExec reporting how many rows the statement changed.
func localExecRows(ctx context.Context, db *corrosion.Client, sql string, args ...any) (int64, error) {
	res, err := db.DB().ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

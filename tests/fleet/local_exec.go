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

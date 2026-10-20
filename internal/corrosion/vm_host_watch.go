package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
)

// vmHostWatchParses counts the statements the watch has parsed, for a test
// that the idle watch parses none.
var vmHostWatchParses atomic.Int64

// vmHostWatch is a local observer of the VM rows replication applies here:
// after each applied entry that wrote the vms table, it is told the owner and
// owner epoch of each VM it watches, as that entry left them. A state sync
// that merged vms rows wholesale is reported as unknown, since the rows it
// skipped past are not seen. It writes nothing and changes no replicated
// shape; a migration target uses it to end its records of an incoming move
// once that move's VM row changes (grpcapi migrationStubLedger).
type vmHostWatch struct {
	watched func() []string
	seen    func(vm, host string, epoch int64, known bool)
}

// SetVMHostWatch installs the observer: watched names the VMs of interest
// (called under the apply's lock: it must not touch the database), seen is
// called after the apply commits. Nil removes it.
func (c *Client) SetVMHostWatch(watched func() []string, seen func(vm, host string, epoch int64, known bool)) {
	if watched == nil || seen == nil {
		c.vmHostWatch.Store(nil)
		return
	}
	c.vmHostWatch.Store(&vmHostWatch{watched: watched, seen: seen})
}

// noteVMHostsInTx reports, after tx commits, the owner and epoch each watched
// VM has in tx once stmts applied, when any of stmts wrote vms.
func (c *Client) noteVMHostsInTx(ctx context.Context, tx *sql.Tx, stmts []Statement) {
	w := c.vmHostWatch.Load()
	if w == nil {
		return
	}
	// Nothing watched is the common case: no statement is parsed for it.
	watched := w.watched()
	if len(watched) == 0 {
		return
	}
	touches := false
	for _, s := range stmts {
		vmHostWatchParses.Add(1)
		if structuralTableLabel(s.SQL) == "vms" {
			touches = true
			break
		}
	}
	if !touches {
		return
	}
	for _, vm := range watched {
		var host string
		var epoch int64
		err := tx.QueryRowContext(ctx, `SELECT host_name, vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, vm).Scan(&host, &epoch)
		known := err == nil
		if errors.Is(err, sql.ErrNoRows) {
			known, host = true, "" // the VM is gone: no move of it is open
		}
		vm, host, epoch, known := vm, host, epoch, known
		c.deferAfterCommit(tx, func() { w.seen(vm, host, epoch, known) })
	}
}

// noteVMRowsSynced reports every watched VM as unknown after tx commits: a
// state sync merged vms rows, and what they were between is not seen.
func (c *Client) noteVMRowsSynced(tx *sql.Tx) {
	w := c.vmHostWatch.Load()
	if w == nil {
		return
	}
	for _, vm := range w.watched() {
		vm := vm
		c.deferAfterCommit(tx, func() { w.seen(vm, "", 0, false) })
	}
}

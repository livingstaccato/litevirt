package corrosion

// Two edits of one VM's desired spec made from the same spec_generation.
//
// Every out-of-band edit (MutateDesiredSpec) and every operation's claim
// (BeginVMOperation) is a compare-and-swap: WHERE spec_generation = E, SET
// spec_generation = E+1. Two hosts that each make one from E — one on each
// side of a partition, or an operation on the owner racing a metadata edit
// elsewhere — produce two versions of the spec at E+1. Before spec_conflict_v1
// each replica kept whichever reached it first: the other's CAS missed and
// applied as a silent zero-row no-op. Anti-entropy then took the newer row by
// timestamp, which dropped one edit without a trace and could overwrite an
// operation's barrier with an out-of-band edit while the operation ran.
//
// Once spec_conflict_v1 has latched, an out-of-band edit carries the owner
// epoch it was made at (vmSpecMutateAtEpochSQL). Gated by the latch because a
// previous-release peer has no ledger entry for that shape.

// The out-of-band spec edit. vmSpecMutateSQL is the previous release's shape,
// emitted until spec_conflict_v1 latches; vmSpecMutateAtEpochSQL carries the
// owner epoch the edit was made at, so a receiver can tell an edit made under
// a superseded owner from a concurrent one.
const (
	vmSpecMutateSQL = `UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, updated_at = ?
			 WHERE name = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
	vmSpecMutateAtEpochSQL = `UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, updated_at = ?
			 WHERE name = ? AND vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
)

// SetSpecConflictGate injects the predicate that says spec_conflict_v1 has
// durably latched, wired at daemon start. Nil-safe: an unset gate reads
// false, so spec edits keep the previous release's shape and resolution.
func (c *Client) SetSpecConflictGate(fn func() bool) {
	if fn == nil {
		c.specConflictGate.Store(nil)
		return
	}
	c.specConflictGate.Store(&fn)
}

// SpecConflictOn reports whether spec_conflict_v1 has durably latched here.
func (c *Client) SpecConflictOn() bool {
	fn := c.specConflictGate.Load()
	return fn != nil && (*fn)()
}

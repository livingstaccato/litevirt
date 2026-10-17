package corrosion

import (
	"context"
	"database/sql"
	"errors"
)

// specMutateMaxRetries bounds MutateDesiredSpec's optimistic read-modify-CAS loop
// against a concurrent spec_generation bump. Real operations are serialized by the
// active_operation_id barrier, so this only covers two out-of-band metadata writers
// (labels, health-spec repair) racing on one VM — rare, and each retry re-reads.
const specMutateMaxRetries = 6

// ErrSpecMutateContention is returned when MutateDesiredSpec exhausts its retry
// budget — a persistent generation race on one VM, which should never happen in
// practice and signals a bug or pathological contention rather than a lost update.
var ErrSpecMutateContention = errors.New("corrosion: MutateDesiredSpec exceeded retry budget under spec-generation contention")

// MutateDesiredSpec reads name's desired spec JSON, applies fn, and persists the
// result under the active_operation_id mutation barrier, bumping spec_generation
// EXACTLY ONCE. It is the sanctioned way to change a VM's desired spec OUTSIDE an
// F1 operation (labels, health-spec repair, a direct stopped-VM redefine); an
// operation sets its desired spec atomically via BeginVMOperation instead. Along
// with UpdateObservedActuals it replaces the old blind UpdateVMSpec so no writer
// can bypass the barrier or the generation discipline.
//
//   - applied=false, nil error → an operation currently holds the barrier (or the
//     VM is gone); the caller MUST defer without writing.
//   - A no-op patch (fn returns the spec byte-identical) reports applied=true with
//     the CURRENT generation and does NOT bump spec_generation.
//   - It NEVER writes cpu_actual/mem_actual (those are observed-live values written
//     only by UpdateObservedActuals).
//
// newGen is the VM's spec_generation after the call (the bumped value, or the
// unchanged value for a no-op / deferral) — thread it into a later
// UpdateObservedActuals so the observation records against the spec it applied to.
//
// The new spec keeps the firewall identity the current spec holds, whatever fn
// returns (keepFirewallID): a spec writer can neither set nor drop it.
func MutateDesiredSpec(ctx context.Context, c *Client, name string, fn func(oldSpec string) (string, error)) (applied bool, newGen int64, err error) {
	return mutateDesiredSpec(ctx, c, name, fn, func(old string) (string, error) {
		return firewallIDOf(TagMemberVM, old), nil
	})
}

// mutateDesiredSpec is MutateDesiredSpec storing the firewall identity keepFor
// returns for the spec it read. Only MutateDesiredSpec (the current identity)
// and MintFirewallID call it.
func mutateDesiredSpec(ctx context.Context, c *Client, name string, fn func(oldSpec string) (string, error),
	keepFor func(oldSpec string) (string, error), tagOwners ...FirewallTagWorkload) (applied bool, newGen int64, err error) {
	var incarnation, owner string
	var epoch int64
	for attempt := 0; attempt < specMutateMaxRetries; attempt++ {
		rows, qerr := c.Query(ctx,
			`SELECT spec, spec_generation, active_operation_id, created_at, host_name, vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
		if qerr != nil {
			return false, 0, qerr
		}
		if len(rows) == 0 {
			return false, 0, nil // no such VM — caller treats as not-applied
		}
		if attempt == 0 {
			incarnation, owner, epoch = rows[0].String("created_at"), rows[0].String("host_name"), rows[0].Int64("vm_owner_epoch")
		} else if rows[0].String("created_at") != incarnation || rows[0].String("host_name") != owner || rows[0].Int64("vm_owner_epoch") != epoch {
			return false, rows[0].Int64("spec_generation"), nil
		}
		oldSpec := rows[0].String("spec")
		specGen := rows[0].Int64("spec_generation")
		if rows[0].String("active_operation_id") != "" {
			return false, specGen, nil // barrier held by an in-flight operation → defer
		}
		newSpec, ferr := fn(oldSpec)
		if ferr != nil {
			return false, specGen, ferr
		}
		keep, kerr := keepFor(oldSpec)
		if kerr != nil {
			return false, specGen, kerr
		}
		if newSpec, ferr = keepFirewallID(TagMemberVM, newSpec, keep); ferr != nil {
			return false, specGen, ferr
		}
		// Bind the sampled row inside the write transaction. Generation alone
		// repeats after delete/recreate; a no-op must not report a stale read as
		// successful either. Retrying stays within this invocation's incarnation
		// and owner, while ordinary concurrent metadata writes may be recomputed.
		guard := func(tx *sql.Tx) (bool, error) {
			if err := checkFirewallTagWorkloads(ctx, &LocalTx{tx: tx}, tagOwners); err != nil {
				return false, err
			}
			var currentSpec, active, created, host string
			var generation, ownerEpoch int64
			err := tx.QueryRowContext(ctx,
				`SELECT spec, spec_generation, active_operation_id, created_at, host_name, vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, name).
				Scan(&currentSpec, &generation, &active, &created, &host, &ownerEpoch)
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			return created == incarnation && host == owner && ownerEpoch == epoch &&
				generation == specGen && active == "" && currentSpec == oldSpec, nil
		}
		// Preserve the incoming epoch-carrying shape and content-only no-op
		// once latched. Even a no-op must pass the incarnation/barrier guard.
		specConflict := c.SpecConflictOn()
		changed := newSpec != oldSpec
		if specConflict {
			changed = specContentHash(newSpec) != specContentHash(oldSpec)
		}
		var stmts []Statement
		if changed {
			now := c.NowTS()
			if specConflict {
				stmts = []Statement{{SQL: vmSpecMutateAtEpochSQL,
					Params: []interface{}{stampSpec(newSpec, oldSpec, now), now, name, epoch, specGen}}}
			} else {
				stmts = []Statement{{SQL: vmSpecMutateSQL,
					Params: []interface{}{newSpec, now, name, specGen}}}
			}
		}
		applied, uerr := c.ExecuteBatchGuarded(ctx, guard, stmts)
		if uerr != nil {
			return false, specGen, uerr
		}
		if applied {
			if !changed {
				return true, specGen, nil
			}
			return true, specGen + 1, nil
		}
	}
	return false, 0, ErrSpecMutateContention
}

// UpdateObservedActuals writes ONLY cpu_actual/mem_actual, under a CAS on the owner
// epoch and (optionally) the spec generation, so a stale observation can't record
// actuals against a spec that has since changed or a VM that has since transferred
// owners. It NEVER bumps spec_generation — otherwise reading actuals back would
// fail an operation's completion CAS against the desired generation.
//
// Pass expectedOwnerEpoch < 0 to skip the owner check and/or expectedSpecGen < 0 to
// skip the generation check (a direct sequential write outside an F1 operation,
// e.g. a stopped-VM redefine that just persisted its spec). Returns applied (a row
// was updated), error.
func UpdateObservedActuals(ctx context.Context, c *Client, name string, cpu, mem int, expectedOwnerEpoch, expectedSpecGen int64) (bool, error) {
	// One of four CONSTANT statements rather than SQL built by concatenation, each passed
	// LITERALLY at its call site so the ledger/CI guard can resolve it and the apply path can
	// structurally validate it. All four are full-PK LWW updates on vms (WHERE name = ?).
	const (
		base     = `UPDATE vms SET cpu_actual = ?, mem_actual = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`
		epoch    = base + ` AND vm_owner_epoch = ?`
		gen      = base + ` AND spec_generation = ?`
		epochGen = base + ` AND vm_owner_epoch = ? AND spec_generation = ?`
	)
	ts := c.NowTS()
	switch {
	case expectedOwnerEpoch >= 0 && expectedSpecGen >= 0:
		n, err := c.ExecuteRowsStrict(ctx, epochGen, cpu, mem, ts, name, expectedOwnerEpoch, expectedSpecGen)
		return n > 0, err
	case expectedOwnerEpoch >= 0:
		n, err := c.ExecuteRowsStrict(ctx, epoch, cpu, mem, ts, name, expectedOwnerEpoch)
		return n > 0, err
	case expectedSpecGen >= 0:
		n, err := c.ExecuteRowsStrict(ctx, gen, cpu, mem, ts, name, expectedSpecGen)
		return n > 0, err
	default:
		n, err := c.ExecuteRowsStrict(ctx, base, cpu, mem, ts, name)
		return n > 0, err
	}
}

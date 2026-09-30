package corrosion

import "sync"

// DispLiveRowUpdate: full-PK LWW updates that must never modify a tombstone.
//
// The VM state writers (UpdateVMState, UpdateVMStateStrict,
// UpdateVMStateAtEpoch, UpdateVMHost, and the parent statement of
// CommitMigrationOwnership) are keyed on the name, plus the owner epoch for the
// epoch form. A tombstone has that name too. On the kvm003-f3 lab, 2026-09-30,
// a stale delete tombstoned claimvm while it kept running on node-4. node-4's
// health checker had listed the VM before the tombstone arrived and wrote
// "running" after it, and the name-keyed UPDATE landed on the tombstone and
// replicated. Every replica ended up with a row that was both `running` and
// deleted.
//
// WHY THE WIRE SHAPE DOES NOT CHANGE. Appending `AND deleted_at IS NULL` to the
// builders would mint new fingerprints. A receiver on the previous release does
// not know them, and an unknown shape back-pressures: the apply fails closed and
// the sender's whole stream stops at it. These are among the most frequent
// statements a cluster sends, so every upgraded node's stream to every older
// peer would stall for the length of a rolling upgrade. Gating the new shape on
// a capability token would avoid that, at the cost of a token whose only job is
// to say "this binary knows one more fingerprint".
//
// So the statements keep their shape, and the guard travels with the
// FINGERPRINT instead of the SQL text. Their ledger entry carries
// DispLiveRowUpdate. Every node that recognises the fingerprint as that
// disposition applies the statement through its guarded form (liveRowGuarded):
// the origin in its own write path, and each receiver on the WAL lane,
// including the replay of a parked update. DispAuditReseal set the precedent of
// a receiver applying a statement through a stricter form than the one it
// carries.
//
// What this buys during a roll:
//   - an upgraded origin never writes a tombstone, so it never publishes the
//     `running`-and-deleted row;
//   - an upgraded receiver refuses a state write that reaches its tombstone,
//     whichever release sent it. That is the case of a sender whose row was
//     still live when it wrote;
//   - a receiver on the previous release applies these statements exactly as
//     before, because they are the shapes it already knows.
//
// Only an update whose WHERE rejected a row that IS present is a refusal. An
// update that met no row at all is still parked for the row's arrival
// (parked_updates.go), and it is replayed through the same guarded form.
//
// Anti-entropy moves rows, not statements, so it is unaffected. It carries the
// newer of two copies, and after this change no upgraded node makes a
// tombstone newer by writing state onto it.

// liveRowUpdateSQLs are the statements registered as DispLiveRowUpdate. Each
// must be a full-PK UPDATE that binds updated_at, on a table with a deleted_at
// column, and must not itself carry the deleted_at predicate: appending one to
// the WHERE must be all that separates the guarded form from the wire form.
var liveRowUpdateSQLs = []string{
	vmStateUpdateSQL,
	vmStateAtEpochSQL,
	vmHostStateSQL,
}

const liveRowPredicate = " AND deleted_at IS NULL"

// liveRowGuardedByFP maps each registered fingerprint to its guarded form.
var liveRowGuardedByFP = buildLiveRowGuarded()

func buildLiveRowGuarded() map[string]string {
	m := make(map[string]string, len(liveRowUpdateSQLs))
	for _, s := range liveRowUpdateSQLs {
		fp, err := FingerprintSQL(s)
		if err != nil {
			panic("live-row update SQL does not parse: " + s + ": " + err.Error())
		}
		guarded := s + liveRowPredicate
		// The guarded form binds exactly the wire form's parameters, in the same
		// order. The receiver executes it with the INCOMING params, so anything
		// else would bind a sender's values to the wrong columns.
		wire, _, err := parseResolved(s)
		if err != nil {
			panic("live-row update SQL does not resolve: " + s + ": " + err.Error())
		}
		g, _, err := parseResolved(guarded)
		if err != nil {
			panic("live-row guarded SQL does not resolve: " + guarded + ": " + err.Error())
		}
		if wire.Kind != KindUpdate || !wire.HasFullPKIdentity || wire.UpdatedAtParamIdx < 0 {
			panic("live-row update must be a full-PK UPDATE binding updated_at: " + s)
		}
		if wire.ValidateParamArity(wire.ParamCount) != nil || g.ValidateParamArity(wire.ParamCount) != nil {
			panic("live-row guarded form must bind the wire form's parameters: " + s)
		}
		m[fp] = guarded
	}
	return m
}

// liveRowGuardCache memoises liveRowGuarded by SQL text. Replicated statements
// are finite static SQL (stmtshapecheck refuses anything else), so the cache
// is bounded by the number of builders.
var liveRowGuardCache sync.Map // string → string ("" = not a live-row update)

// liveRowGuarded returns s with its SQL replaced by the guarded form when s is
// a registered live-row update, and s unchanged otherwise. Parameters are
// never touched.
func liveRowGuarded(s Statement) Statement {
	if v, ok := liveRowGuardCache.Load(s.SQL); ok {
		if g := v.(string); g != "" {
			s.SQL = g
		}
		return s
	}
	g := ""
	if fp, err := FingerprintSQL(s.SQL); err == nil {
		g = liveRowGuardedByFP[fp]
	}
	liveRowGuardCache.Store(s.SQL, g)
	if g != "" {
		s.SQL = g
	}
	return s
}

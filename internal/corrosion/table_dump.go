package corrosion

import (
	"errors"
	"fmt"
)

// Table-scoped repair dumps (colonelpanik/litevirt#262).
//
// Anti-entropy used to answer ANY mismatched public table by pulling the peer's
// full public dump — every row of every table — so one drifted row in a small
// table cost a transfer and a merge proportional to the whole cluster's state.
// A table-scoped dump carries only the tables whose digests disagreed, plus the
// tables their merge cannot run without.

// ErrTableDumpEmpty is a table-scoped dump request that resolves to no table.
// It is refused rather than read as "everything": the full dump has its own RPC,
// and an empty list meaning all of it would turn a caller's bug into a full
// transfer that looks like a scoped one.
var ErrTableDumpEmpty = errors.New("table dump: no replicated table requested")

// ErrTableDumpSensitive is a table-scoped dump request naming a table of the
// sensitive lane. Those tables are repaired only through the peer-only
// sensitive dump, whose sender-CN check this public lane does not make.
var ErrTableDumpSensitive = errors.New("table dump: sensitive-lane table requested")

// mergeAuthorityParents names the tables whose rows a table's anti-entropy
// merge reads out of the SAME payload (antiEntropyAuthorityDecision via the
// manifest authorityOrderedMergeTables builds from it). A child row whose
// parent is missing from the payload is kept local, so a dump of the child
// alone would carry the repair and apply none of it.
func mergeAuthorityParents(table string) []string {
	switch {
	case vmAuthorityChildTables[table]:
		return []string{"vms"}
	case table == "container_interfaces":
		return []string{"containers"}
	case table == "operation_steps":
		// operationStepAuthorityKeepsLocal reads the source operation, then the
		// workload it names (sourceOperationWorkloadAuthority).
		return []string{"operations", "vms", "containers"}
	}
	return nil
}

// ResolveTableDump turns a requested table list into the tables a scoped dump
// carries, in tableNames order: the requested public tables plus their merge
// authority parents. A name the public lane does not replicate is dropped (a
// peer on another schema may name one); a sensitive-lane name is refused.
func ResolveTableDump(tables []string) ([]string, error) {
	want := make(map[string]bool, len(tables))
	for _, t := range tables {
		if sensitiveTableSet[t] {
			return nil, fmt.Errorf("%w: %s", ErrTableDumpSensitive, t)
		}
		if !replicatedTableSet[t] {
			continue
		}
		want[t] = true
		for _, p := range mergeAuthorityParents(t) {
			want[p] = true
		}
	}
	out := make([]string, 0, len(want))
	for _, t := range tableNames {
		if want[t] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, ErrTableDumpEmpty
	}
	return out, nil
}

// DumpTablesBytes is DumpStateBytes restricted to ResolveTableDump(tables): the
// same gzipped payload, secret columns included, merged by the same
// MergeStateBytesLWW. Peer-only for the same reason as the full dump.
func (c *Client) DumpTablesBytes(tables []string) ([]byte, error) {
	resolved, err := ResolveTableDump(tables)
	if err != nil {
		return nil, err
	}
	return c.dumpStateForTables(resolved), nil
}

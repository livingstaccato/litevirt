package corrosion

import (
	"fmt"
	"sort"
)

// Bucket-scoped repair dumps (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md).
//
// A table-scoped dump narrowed further to the buckets whose digests disagreed.
// The one rule a narrowing must keep is the authority manifest's: a child row
// is merged against its parent row IN THE SAME PAYLOAD. bucketKeyColumns keys
// a VM child by vm_name and its parent vms row by name (a container interface
// and its container likewise), so the parent narrowed to the SAME buckets
// holds every parent row the pulled children can name. A parent pulled for a
// table that is not bucketed (operation_steps) is pulled whole.

// dumpScope is, per table, the buckets a dump carries; a nil set is the whole
// table.
type dumpScope map[string]map[int]bool

// coBucketedWithParent reports whether table's rows share bucket keys with its
// merge-authority parents, so the parents may be narrowed to its buckets.
func coBucketedWithParent(table string) bool {
	return vmAuthorityChildTables[table] || table == "container_interfaces"
}

// widen adds buckets to table's scope; nil buckets make it whole, and whole
// stays whole.
func (s dumpScope) widen(table string, buckets map[int]bool) {
	cur, present := s[table]
	switch {
	case !present:
		if buckets == nil {
			s[table] = nil
			return
		}
		cp := make(map[int]bool, len(buckets))
		for b := range buckets {
			cp[b] = true
		}
		s[table] = cp
	case cur == nil:
		// already whole
	case buckets == nil:
		s[table] = nil
	default:
		for b := range buckets {
			cur[b] = true
		}
	}
}

// bucketSet validates one table's requested buckets: nil (whole) when the
// table is not bucketed, the list is empty, or any index is out of range.
func bucketSet(table string, idx []int) map[int]bool {
	if len(idx) == 0 || bucketKeyColumns(table) == nil {
		return nil
	}
	set := make(map[int]bool, len(idx))
	for _, b := range idx {
		if b < 0 || b >= BucketCount {
			return nil
		}
		set[b] = true
	}
	return set
}

// resolveTableDumpScope is ResolveTableDump with bucket narrowing: the
// requested public tables and their merge-authority parents, each with the
// buckets it carries.
func resolveTableDumpScope(tables []string, buckets map[string][]int) ([]string, dumpScope, error) {
	scope := dumpScope{}
	for _, t := range tables {
		if sensitiveTableSet[t] {
			return nil, nil, fmt.Errorf("%w: %s", ErrTableDumpSensitive, t)
		}
		if !replicatedTableSet[t] {
			continue
		}
		set := bucketSet(t, buckets[t])
		scope.widen(t, set)
		for _, p := range mergeAuthorityParents(t) {
			if set != nil && coBucketedWithParent(t) {
				scope.widen(p, set)
			} else {
				scope.widen(p, nil)
			}
		}
	}
	out := make([]string, 0, len(scope))
	for _, t := range tableNames {
		if _, ok := scope[t]; ok {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, nil, ErrTableDumpEmpty
	}
	return out, scope, nil
}

// resolveSensitiveDumpScope narrows the sensitive lane to the named sensitive
// tables (any other name is dropped) and their buckets. No sensitive table has
// a merge-authority parent.
func resolveSensitiveDumpScope(tables []string, buckets map[string][]int) ([]string, dumpScope) {
	scope := dumpScope{}
	for _, t := range tables {
		if sensitiveTableSet[t] {
			scope.widen(t, bucketSet(t, buckets[t]))
		}
	}
	out := make([]string, 0, len(scope))
	for _, t := range sensitiveTableNames {
		if _, ok := scope[t]; ok {
			out = append(out, t)
		}
	}
	return out, scope
}

// narrowToBuckets keeps the rows of st whose bucket is in set. A row whose
// bucket cannot be computed is kept: sending a row the peer did not need costs
// a merge of an identical row, and dropping one could hide a repair.
func narrowToBuckets(st syncTable, set map[int]bool) syncTable {
	if set == nil {
		return st
	}
	keyIdx := columnIndexes(st.Columns, bucketKeyColumns(st.Name))
	if len(keyIdx) == 0 {
		return st
	}
	kept := st.Rows[:0]
	for _, row := range st.Rows {
		b, ok := rowBucket(row, keyIdx)
		if !ok || set[b] {
			kept = append(kept, row)
		}
	}
	st.Rows = kept
	return st
}

// DumpTablesScopedBytes is DumpTablesBytes narrowed to buckets
// (table -> bucket indexes of BucketScheme). A table with no entry is whole.
// Peer-only, like the full dump.
func (c *Client) DumpTablesScopedBytes(tables []string, buckets map[string][]int) ([]byte, error) {
	resolved, scope, err := resolveTableDumpScope(tables, buckets)
	if err != nil {
		return nil, err
	}
	return c.dumpStateForScope(resolved, scope), nil
}

// DumpSensitiveTablesScopedBytes is the sensitive-lane dump narrowed to the
// named sensitive tables and their buckets. Callers must have checked the
// peer, as for DumpSensitiveStateBytes.
func (c *Client) DumpSensitiveTablesScopedBytes(tables []string, buckets map[string][]int) []byte {
	resolved, scope := resolveSensitiveDumpScope(tables, buckets)
	if len(resolved) == 0 {
		return c.dumpStateForScope(nil, nil)
	}
	return c.dumpStateForScope(resolved, scope)
}

// sortedBuckets is a scope's buckets in ascending order, for logs and tests.
func sortedBuckets(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for b := range set {
		out = append(out, b)
	}
	sort.Ints(out)
	return out
}

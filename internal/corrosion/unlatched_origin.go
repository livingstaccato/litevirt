package corrosion

import "strings"

// The origin test shared by every dual-write migration's absorb
// (absorbUnlatchedSecretWrite for credentials_split_v1,
// absorbUnlatchedMembershipWrite for host_membership_split_v1).
//
// A writer that has switched to a new table always puts the new-table
// statement in the SAME entry — the statements one write commits together, the
// unit the WAL carries — as its old-column statement; neither migration has a
// switched path that writes the old column without it. So an old-column write
// in an entry that does not write the new table was made by a writer that had
// not switched.
//
// That is the only reliable record of the origin. mutation_log.origin names the
// host an entry came from, but nothing records whether that host had latched
// (Ping reports advertised tokens, not latched ones), and an anti-entropy row
// merge carries no origin at all.

// entryWritesTable reports whether one entry writes table. The table is taken
// from the structural parse, never from a substring, so a comment or a string
// literal naming the table cannot fake it.
func entryWritesTable(stmts []Statement, table string) bool {
	for _, s := range stmts {
		if !strings.Contains(s.SQL, table) {
			continue
		}
		if sh, _, err := parseResolved(s.SQL); err == nil && sh.Table == table {
			return true
		}
	}
	return false
}

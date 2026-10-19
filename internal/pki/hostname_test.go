package pki

import (
	"strings"
	"testing"
)

// A host's pair lives in the operator's PKI directory as <name>.crt and
// <name>.key, beside the cluster's own files. A name equal to one of their
// stems replaced that file ("ca" overwrote the cluster CA and ca.key), and a
// name with a separator or ".." wrote outside the directory.
//
// Mutations: drop the reserved loop — "ca" and the others pass; drop the
// EqualFold (use ==) — "CA" passes; drop the suffix check — "node-1-migration"
// passes; drop the leading-character check — "-rf" and ".hidden" pass.
func TestValidateHostName_RefusesReservedAndEscapingNames(t *testing.T) {
	for _, name := range []string{
		"ca", "CA", "Ca", "client", "host", "HOST", "gossip", "migration-ca", "ui", "audit-signing", "lv-cli",
		"node-1-migration", "node-1-MIGRATION",
		"", ".", "..", "../esc", "/../esc", "a/b", `a\b`, "-rf", ".hidden", "a b", "a\x00b",
		strings.Repeat("a", 201),
	} {
		if err := ValidateHostName(name); err == nil {
			t.Errorf("ValidateHostName(%q) = nil, want a refusal", name)
		}
	}
}

// Names existing clusters use keep validating: the rule refuses only what
// collides or escapes, and keeps safename's charset (upper case, '_', '.').
func TestValidateHostName_AcceptsExistingNames(t *testing.T) {
	for _, name := range []string{
		"host-a", "node-1", "node-9", "kvm003-f3", "Node_1", "n1.example.com", "cache", "cab", "hostess",
		"client-1", "migration", "ca1", "lv-cli2", "a-migration-1", strings.Repeat("a", 200),
	} {
		if err := ValidateHostName(name); err != nil {
			t.Errorf("ValidateHostName(%q) = %v, want nil", name, err)
		}
	}
}

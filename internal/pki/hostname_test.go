package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
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

// Ordinary names pass the new-name rule: it refuses what collides or escapes,
// and otherwise asks only safename's charset (upper case, '_', '.' allowed).
// Older builds had no rule; their names are TestValidateHostPathName's.
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

// Containment is the only rule for a name an older build admitted (it had
// none): every legacy name passes, every traversal fails.
//
// Mutations: drop the separator case — "a/b" passes; drop the leading '-'
// case — "-rf" passes; drop the length bound — 231 bytes passes.
func TestValidateHostPathName(t *testing.T) {
	for _, name := range []string{"Host", "ui", "ca", "web-migration", "node+1", "Node 1", ".hidden", "ünï",
		strings.Repeat("a", MaxHostPathNameLen)} {
		if err := ValidateHostPathName(name); err != nil {
			t.Errorf("ValidateHostPathName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", "../esc", `a\b`, "a\x00b", "-rf",
		strings.Repeat("a", MaxHostPathNameLen+1)} {
		if err := ValidateHostPathName(name); err == nil {
			t.Errorf("ValidateHostPathName(%q) = nil, want a refusal", name)
		}
	}
}

// Where <name>.crt|.key is written beside the directory's own files, an
// existing name must not be one of their stems or lv-cli; other legacy names
// pass.
//
// Mutation: drop the reserved loop from ValidateExistingHostName — "ca" passes.
func TestValidateExistingHostName(t *testing.T) {
	for _, name := range []string{"ca", "CA", "client", "host", "Host", "ui", "lv-cli", "../esc"} {
		if err := ValidateExistingHostName(name); err == nil {
			t.Errorf("ValidateExistingHostName(%q) = nil, want a refusal", name)
		}
	}
	for _, name := range []string{"node+1", "web-migration", "Node 1", ".hidden"} {
		if err := ValidateExistingHostName(name); err != nil {
			t.Errorf("ValidateExistingHostName(%q) = %v, want nil", name, err)
		}
	}
}

// OperatorPKIFileAt names the directory's own files, and nothing else.
//
// Mutation: drop the exact-name case — "ca.key" is not reported.
func TestOperatorPKIFileAt(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"ca.key", "client.crt", "gossip.key", "migration-ca.key"} {
		if f, ok := OperatorPKIFileAt(filepath.Join(dir, n)); !ok || f != n {
			t.Errorf("OperatorPKIFileAt(%s) = %q, %v", n, f, ok)
		}
	}
	for _, n := range []string{"node-1.key", "ui.key", "web-migration.crt"} {
		if f, ok := OperatorPKIFileAt(filepath.Join(dir, n)); ok {
			t.Errorf("OperatorPKIFileAt(%s) = %q, want none", n, f)
		}
	}
}

// IsClientOnlyCert is the host-versus-client discriminator peer trust and the
// claim verifiers share: ClientAuth without ServerAuth.
//
// Mutation: return false when ClientAuth is seen — the client certificate is
// not recognised.
func TestIsClientOnlyCert(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateCA(ca, caKey); err != nil {
		t.Fatal(err)
	}
	if err := GenerateClientCert(ca, caKey, filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key"), "lv-cli"); err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostCert(ca, caKey, filepath.Join(dir, "h.crt"), filepath.Join(dir, "h.key"), "lv-cli", nil); err != nil {
		t.Fatal(err)
	}
	load := func(n string) *x509.Certificate {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		c, err := ParseCertPEM(b)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if !IsClientOnlyCert(load("c.crt")) {
		t.Error("the client certificate is not client-only")
	}
	if IsClientOnlyCert(load("h.crt")) {
		t.Error("a host certificate is client-only")
	}
	if IsClientOnlyCert(nil) || IsClientOnlyCert(&x509.Certificate{}) {
		t.Error("a nil or EKU-less certificate is client-only")
	}
}

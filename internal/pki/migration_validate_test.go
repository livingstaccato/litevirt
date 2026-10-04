package pki

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testMigrationCA mints a migration CA in a fresh directory.
func testMigrationCA(t *testing.T) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	cert, key = filepath.Join(dir, MigrationCACertName), filepath.Join(dir, MigrationCAKeyName)
	if err := GenerateMigrationCA(cert, key); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// testHostCert issues node-1's certificate from the CA and returns its bytes.
func testHostCert(t *testing.T, caCert, caKey string) (cert, key []byte) {
	t.Helper()
	dir := t.TempDir()
	c, k := filepath.Join(dir, "h.crt"), filepath.Join(dir, "h.key")
	if err := GenerateHostCert(caCert, caKey, c, k, "node-1", net.ParseIP("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	return mustRead(t, c), mustRead(t, k)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateMigrationCredentials_AcceptsAMatchingSet(t *testing.T) {
	caC, caK := testMigrationCA(t)
	cert, key := testHostCert(t, caC, caK)
	if _, _, err := ValidateMigrationCredentials(mustRead(t, caC), cert, key, time.Now()); err != nil {
		t.Fatalf("a matching set was refused: %v", err)
	}
}

// A push copies host.crt and host.key one at a time. A migration that starts
// between them sees the new certificate with the old key.
//
// Mutation: drop the tls.X509KeyPair check — this passes validation.
func TestValidateMigrationCredentials_RefusesAKeyFromAnotherCertificate(t *testing.T) {
	caC, caK := testMigrationCA(t)
	cert, _ := testHostCert(t, caC, caK)
	_, otherKey := testHostCert(t, caC, caK)
	_, _, err := ValidateMigrationCredentials(mustRead(t, caC), cert, otherKey, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v; want a key/certificate mismatch", err)
	}
}

// Mutation: verify against a pool built from the leaf itself — this passes.
func TestValidateMigrationCredentials_RefusesACertificateFromACAOutsideTheBundle(t *testing.T) {
	caC, _ := testMigrationCA(t)
	otherC, otherK := testMigrationCA(t)
	cert, key := testHostCert(t, otherC, otherK)
	_, _, err := ValidateMigrationCredentials(mustRead(t, caC), cert, key, time.Now())
	if err == nil || !strings.Contains(err.Error(), "not issued by a CA in") {
		t.Fatalf("err = %v; want refusal of a certificate from an untrusted CA", err)
	}
}

// The overlap phase: ca.crt holds old then new; certificates from either verify.
//
// Mutation: make parseCABundle return only the first PEM block — the
// new-CA certificate is refused.
func TestValidateMigrationCredentials_AcceptsEitherCAOfATwoCABundle(t *testing.T) {
	oldC, oldK := testMigrationCA(t)
	newC, newK := testMigrationCA(t)
	bundle := append(mustRead(t, oldC), mustRead(t, newC)...)
	for name, ca := range map[string][2]string{"old": {oldC, oldK}, "new": {newC, newK}} {
		cert, key := testHostCert(t, ca[0], ca[1])
		if _, cas, err := ValidateMigrationCredentials(bundle, cert, key, time.Now()); err != nil {
			t.Errorf("%s-CA certificate refused against the bundle: %v", name, err)
		} else if len(cas) != 2 {
			t.Errorf("bundle parsed to %d CAs; want 2", len(cas))
		}
	}
}

// Mutation: skip validation in InstallQemuMigrationTLS — the torn key lands
// in QEMU's directory.
func TestInstallQemuMigrationTLS_RefusesATornSetAndKeepsTheInstalledOne(t *testing.T) {
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil || !ok {
		t.Fatalf("first install: ok=%v err=%v", ok, err)
	}
	before := mustRead(t, filepath.Join(qemu, "server-key.pem"))

	caC, caK := testMigrationCA(t)
	_, strayKey := testHostCert(t, caC, caK)
	if err := os.WriteFile(filepath.Join(MigrationDir(pkiDir), MigrationHostKeyName), strayKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err == nil || ok {
		t.Fatalf("torn set installed: ok=%v err=%v", ok, err)
	}
	if after := mustRead(t, filepath.Join(qemu, "server-key.pem")); string(after) != string(before) {
		t.Fatal("a refused install still replaced QEMU's key")
	}
}

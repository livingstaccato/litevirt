package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectMigrationTLS_UnprovisionedHostIsNotAnError(t *testing.T) {
	info, err := InspectMigrationTLS(t.TempDir(), time.Now())
	if err != nil || info.Provisioned {
		t.Fatalf("info=%+v err=%v; want unprovisioned, no error", info, err)
	}
}

// Two of the three files is an incomplete set, not an unprovisioned host: the
// doctor and the rotation's preflight must say which file is missing.
//
// Mutation: restore the early return on the first missing file — the host
// reads as unprovisioned.
func TestInspectMigrationTLS_PartialSetIsIncompleteNotUnprovisioned(t *testing.T) {
	pkiDir := t.TempDir()
	provisionMigration(t, pkiDir)
	if err := os.Remove(filepath.Join(MigrationDir(pkiDir), MigrationHostKeyName)); err != nil {
		t.Fatal(err)
	}
	info, err := InspectMigrationTLS(pkiDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Provisioned || !strings.Contains(info.ValidationError, MigrationHostKeyName) {
		t.Fatalf("info = %+v; want provisioned with a validation error naming %s", info, MigrationHostKeyName)
	}
	if len(info.TrustedCAs) != 1 || info.CertIssuerFingerprint == "" {
		t.Errorf("info = %+v; want the files that are there still reported", info)
	}
}

// Mutation: set CertIssuerFingerprint from TrustedCAs[0] unconditionally —
// the new-CA certificate reports the old CA.
func TestInspectMigrationTLS_NamesTheIssuerAmongTwoTrustedCAs(t *testing.T) {
	pkiDir := t.TempDir()
	dir := MigrationDir(pkiDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldC, _ := testMigrationCA(t)
	newC, newK := testMigrationCA(t)
	cert, key := testHostCert(t, newC, newK)
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(MigrationCAName, append(mustRead(t, oldC), mustRead(t, newC)...))
	write(MigrationHostCertName, cert)
	write(MigrationHostKeyName, key)

	info, err := InspectMigrationTLS(pkiDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	newFP, _ := CAFileFingerprint(newC)
	oldFP, _ := CAFileFingerprint(oldC)
	if !info.Provisioned || info.ValidationError != "" {
		t.Fatalf("info=%+v; want a valid provisioned set", info)
	}
	if len(info.TrustedCAs) != 2 || info.TrustedCAs[0].Fingerprint != oldFP || info.TrustedCAs[1].Fingerprint != newFP {
		t.Fatalf("trusted = %+v; want [old, new]", info.TrustedCAs)
	}
	if info.CertIssuerFingerprint != newFP {
		t.Fatalf("issuer = %s; want the new CA %s", info.CertIssuerFingerprint, newFP)
	}
	if info.CertNotAfter.IsZero() {
		t.Fatal("certificate expiry not reported")
	}
}

// An invalid set still reports what it holds, so the operator can see why.
//
// Mutation: return early on a validation error — TrustedCAs is empty.
func TestInspectMigrationTLS_ReportsAnInvalidSetsContents(t *testing.T) {
	pkiDir := t.TempDir()
	provisionMigration(t, pkiDir)
	caC, caK := testMigrationCA(t)
	_, stray := testHostCert(t, caC, caK)
	if err := os.WriteFile(filepath.Join(MigrationDir(pkiDir), MigrationHostKeyName), stray, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InspectMigrationTLS(pkiDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info.ValidationError == "" || len(info.TrustedCAs) != 1 || info.CertNotAfter.IsZero() {
		t.Fatalf("info = %+v; want a validation error AND the CA and expiry", info)
	}
}

// Mutation: compare with > instead of < against now+MigrationExpiryWarning —
// the 89-day case is missed.
func TestMigrationTLSInfo_Expiring(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	info := MigrationTLSInfo{
		Provisioned:  true,
		CertNotAfter: now.Add(89 * day),
		TrustedCAs:   []MigrationCAInfo{{Fingerprint: "aa", NotAfter: now.Add(91 * day)}, {Fingerprint: "bb", NotAfter: now.Add(-day)}},
	}
	got := info.Expiring(now)
	if len(got) != 2 {
		t.Fatalf("got %+v; want the certificate (89d) and CA bb (expired), not CA aa (91d)", got)
	}
	if got[0].What != "host certificate" || got[0].Expired {
		t.Errorf("got[0] = %+v; want the host certificate, not yet expired", got[0])
	}
	if got[1].What != "CA bb" || !got[1].Expired {
		t.Errorf("got[1] = %+v; want CA bb, expired", got[1])
	}
}

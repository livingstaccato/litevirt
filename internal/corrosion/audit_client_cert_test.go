package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// auditSignerFrom loads a signing keyring for host from an explicit pair.
func auditSignerFrom(t *testing.T, caDir, crt, key, host string) *AuditKeyring {
	t.Helper()
	k, err := LoadAuditKeyringFromPaths(caDir, crt, key, host)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The audit signature checks bound a key to a host by the certificate's Common
// Name alone. On a cluster where an older build admitted a host named
// "lv-cli", the distributable client key (held by every operator) could be
// published as that host's audit key, sign its rows and heads, and stand as
// its key in a lifecycle record.
//
// A host's own audit identities still verify: its host certificate (the
// signer before rotation), a dedicated audit signing certificate, and a
// second one after a rotation, while the earlier ones stay resolvable.
//
// Mutations: drop the client-only check in certFor — the client key's row
// verifies and KeyBelongsToHost says yes; in trustSubmittedCert — the
// submitted client certificate is admitted.
func TestAuditVerifiers_RefuseAClientCertificateNamedAsAHost(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	ca := newClaimTestCA(t)
	dir := t.TempDir()
	path := func(n string) string { return filepath.Join(dir, n) }
	if err := pki.GenerateClientCert(ca.cert, ca.key, path("cli.crt"), path("cli.key"), "lv-cli"); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(ca.cert, ca.key, path("host.crt"), path("host.key"), "node-1", nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"audit1", "audit2"} {
		if err := pki.GenerateAuditSigningCert(ca.cert, ca.key, path(n+".crt"), path(n+".key"), "node-1"); err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := LoadAuditVerifier(ca.dir)
	if err != nil {
		t.Fatal(err)
	}

	client := auditSignerFrom(t, ca.dir, path("cli.crt"), path("cli.key"), "lv-cli")
	if err := client.PublishSigningKey(ctx, c); err != nil {
		t.Fatal(err)
	}
	sig, err := client.SignRow("h", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyRow(ctx, c, "lv-cli", client.keyID, "h", 1, sig); err == nil ||
		!strings.Contains(err.Error(), "client certificate") {
		t.Errorf("a row signed with the client key as lv-cli = %v, want refused", err)
	}
	if verifier.KeyBelongsToHost(ctx, c, client.keyID, "lv-cli") {
		t.Error("KeyBelongsToHost: the client key belongs to host lv-cli")
	}
	cert, err := parseCertPEM([]byte(client.certPEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.trustSubmittedCert(cert, client.keyID); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Errorf("trustSubmittedCert(client certificate) = %v, want refused", err)
	}

	// node-1's host key (the pre-rotation signer), then two dedicated audit
	// keys in turn: every one keeps verifying its rows, and belongs to node-1.
	for i, pair := range [][2]string{{"host.crt", "host.key"}, {"audit1.crt", "audit1.key"}, {"audit2.crt", "audit2.key"}} {
		k := auditSignerFrom(t, ca.dir, path(pair[0]), path(pair[1]), "node-1")
		if err := k.PublishSigningKey(ctx, c); err != nil {
			t.Fatal(err)
		}
		sig, err := k.SignRow("h", int64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := LoadAuditVerifier(ca.dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.VerifyRow(ctx, c, "node-1", k.keyID, "h", int64(i+1), sig); err != nil {
			t.Errorf("%s: node-1's row = %v", pair[0], err)
		}
		if !fresh.KeyBelongsToHost(ctx, c, k.keyID, "node-1") {
			t.Errorf("%s: KeyBelongsToHost(node-1) = false", pair[0])
		}
		kc, err := parseCertPEM([]byte(k.certPEM))
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.trustSubmittedCert(kc, k.keyID); err != nil {
			t.Errorf("%s: trustSubmittedCert = %v", pair[0], err)
		}
	}
}

// `lv host retire-audit-key` hands RecordSignedRetirement a certificate and its
// signatures; one naming host "lv-cli" that is the client certificate is
// refused at the CN binding, before anything is verified or stored.
//
// Mutation: drop the client-only check in RecordSignedRetirement — the refusal
// comes later, from trustSubmittedCert, not the binding.
func TestRecordSignedRetirement_RefusesAClientCertificate(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	ca := newClaimTestCA(t)
	dir := t.TempDir()
	if err := pki.GenerateClientCert(ca.cert, ca.key, filepath.Join(dir, "cli.crt"), filepath.Join(dir, "cli.key"), "lv-cli"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cli.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(b)
	err = RecordSignedRetirement(ctx, c, ca.dir, "lv-cli", "k1", 1, certPEM, "00", "00", "00")
	if err == nil || !strings.Contains(err.Error(), `retirement certificate for "lv-cli" is a client certificate`) {
		t.Fatalf("RecordSignedRetirement with the client certificate = %v, want refused at the binding", err)
	}
}

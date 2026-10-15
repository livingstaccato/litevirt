package fleet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func shortAutomationCertificates(t *testing.T, c *Cluster, deadline time.Time) {
	t.Helper()
	caPEM, err := os.ReadFile(c.caCert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM, err := os.ReadFile(c.caKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(caKeyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		// The harness already loaded the original signer during startup. Mint a
		// CA-authenticated successor so production hot reload observes this pair.
		if _, _, err := pki.RenewLocal(c.caCert, c.caKey, n.PKIDir, n.Name); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(n.PKIDir, "host.crt"), filepath.Join(n.PKIDir, "host.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.NotAfter = deadline
		cert.ExtraExtensions = cert.Extensions
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &pair.PrivateKey.(*ecdsa.PrivateKey).PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(n.PKIDir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Globally relaxing Historical would admit untrusted expired material; replay
// instead trusts locally persisted anchors, and new replicas need a fresh head.
func TestAutomationReplayExpiredHistoryAndRenewedHead(t *testing.T) {
	expiry := time.Now().Add(12 * time.Second).Truncate(time.Second)
	f := newAutomationFixtureWith(t, 3, true, func(c *Cluster) { shortAutomationCertificates(t, c, expiry) })
	original, ok, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 1)
	if err != nil || !ok {
		t.Fatal(err)
	}
	for _, a := range original.Certificate.Accepts {
		block, _ := pem.Decode([]byte(a.CertPEM))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.NotAfter.Equal(expiry) {
			t.Fatalf("fixture did not use expiring accept: %v", err)
		}
	}
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "before-renewal")); err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
	// Renewal is CA-authenticated continuity, not a peer-provided replacement root.
	for _, n := range f.cluster.Nodes {
		serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := corrosion.RecordOwnCertSerial(f.Context(), n.DB, n.Name, serial); err != nil {
			t.Fatal(err)
		}
	}
	f.cluster.WaitConverged(t, convergeTimeout)
	for _, n := range f.cluster.Nodes {
		installRenewal(t, f.cluster, n)
	}
	time.Sleep(time.Until(expiry.Add(100 * time.Millisecond)))
	verifier, err := corrosion.LoadClaimVerifier(f.cluster.Nodes[0].PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(f.Context(), f.cluster.Nodes[0].DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Historical().Verify(original.Certificate, corrosion.CertExpectation{Key: original.Certificate.Key, ValueDigest: original.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: 2}); err == nil {
		t.Fatal("global historical verifier accepted expired leaf")
	}
	n := f.cluster.Nodes[2]
	for _, table := range []string{"local_automation_requests", "local_automation_prefix"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("locally anchored expired replay failed: %v", err)
	}
	if _, err := f.cluster.PeerClient(n, f.cluster.Nodes[0]).GetAutomationDecision(f.Context(), &pb.GetAutomationDecisionRequest{}); err != nil {
		t.Fatalf("renewed prefix transport failed: %v", err)
	}
	// Remove all history and anchors from one voter. It must obtain a fresh
	// current quorum head and verify the backwards bytes before applying them.
	for _, table := range []string{"local_automation_requests", "local_automation_prefix", "local_automation_history", "local_automation_anchors"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("fresh head did not authenticate expired predecessors: %v", err)
	}
	f.Converge(t)
	if _, err := f.Engine(2).Submit(f.Context(), f.Barrier(2, "after-expiry")); err != nil {
		t.Fatalf("renewed quorum did not progress: %v", err)
	}
	f.Converge(t)
}

// A peer cannot substitute a CA while preserving names, incarnations, digest,
// ballot, generation and even a complete quorum-shaped certificate.
func TestAutomationReplayRejectsUnauthenticatedRootReplacement(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	r, ok, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 1)
	if err != nil || !ok {
		t.Fatal(err)
	}
	fake := t.TempDir()
	caCert := filepath.Join(fake, "ca.crt")
	caKey := filepath.Join(fake, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	for i, a := range r.Certificate.Accepts {
		dir := filepath.Join(fake, a.Voter)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), a.Voter, nil); err != nil {
			t.Fatal(err)
		}
		signer, err := corrosion.LoadClaimSigner(dir, a.Voter)
		if err != nil {
			t.Fatal(err)
		}
		r.Certificate.Accepts[i], err = signer.Sign(a.Key, a.ConfigGeneration, a.Ballot, a.ValueDigest, a.VoterIncarnation)
		if err != nil {
			t.Fatal(err)
		}
	}
	before := f.Head(t, 1)
	if err := f.Engine(1).Install(f.Context(), r); err == nil {
		t.Fatal("unauthenticated root replacement admitted")
	}
	if f.Head(t, 1) != before {
		t.Fatal("fake root changed applied prefix")
	}
	rows, err := f.cluster.Nodes[1].DB.Query(f.Context(), `SELECT count(*) AS n FROM local_automation_recovery`)
	if err != nil || rows[0].Int64("n") != 0 {
		t.Fatalf("fake root acquired staging authority: %v", err)
	}
}

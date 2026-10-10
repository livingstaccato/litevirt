package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// renewalChain mints a host certificate for name and n successive renewals of
// it (each over a key generated in its pki dir), returning them oldest first.
func renewalChain(t *testing.T, name string, n int) []*x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(dir, "host.crt")
	if err := pki.GenerateHostCert(caCert, caKey, crt, filepath.Join(dir, "host.key"), name, net.ParseIP("10.0.0.9")); err != nil {
		t.Fatal(err)
	}
	first, err := pki.ParseCertPEM(mustRead(t, crt))
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{first}
	for i := 0; i < n; i++ {
		if _, _, err := pki.RenewLocal(caCert, caKey, dir, name); err != nil {
			t.Fatal(err)
		}
		c, err := pki.ParseCertPEM(mustRead(t, crt))
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	return chain
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func leafCtx(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 1234},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}},
	})
}

// A renewed host stays a peer through the swap: its certificate names the
// recorded one as its predecessor, signed by the CA, so peers accept it before
// the re-recorded serial reaches them.
//
// Mutation: drop the RenewedFromSerial clause in isTrustedHostCN — the renewed
// certificate is refused until replication catches up.
func TestPeerTrust_ARenewedCertificateIsAcceptedBeforeItsSerialReplicates(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	chain := renewalChain(t, "node-r", 2)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-r", Address: "10.0.0.9", State: "active", CertSerial: chain[0].SerialNumber.Text(16),
	}); err != nil {
		t.Fatal(err)
	}
	if !s.isTrustedHostCN(leafCtx(chain[0]), "node-r") {
		t.Fatal("the recorded certificate was refused")
	}
	if !s.isTrustedHostCN(leafCtx(chain[1]), "node-r") {
		t.Fatal("the CA-issued successor of the recorded certificate was refused: a renewal partitions the host " +
			"until its serial replicates")
	}
	// Only ONE hop: a successor of the successor names a serial nobody recorded.
	if s.isTrustedHostCN(leafCtx(chain[2]), "node-r") {
		t.Fatal("a renewal of a renewal was accepted against a record two certificates old")
	}
}

// The extension never reopens a re-admitted name to an older certificate: the
// pin still refuses everything that does not name what admission recorded.
//
// Mutation: compare the predecessor against the presented serial (or skip the
// comparison) — the predecessor certificate is accepted once the record moved on.
func TestPeerTrust_ARenewalDoesNotReopenTheOldCertificate(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	chain := renewalChain(t, "node-r", 1)
	// The renewed node re-recorded its serial: the predecessor is now stale.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-r", Address: "10.0.0.9", State: "active", CertSerial: chain[1].SerialNumber.Text(16),
	}); err != nil {
		t.Fatal(err)
	}
	if s.isTrustedHostCN(leafCtx(chain[0]), "node-r") {
		t.Fatal("the certificate a renewal replaced is still accepted after the record moved on")
	}
	if !s.isTrustedHostCN(leafCtx(chain[1]), "node-r") {
		t.Fatal("the recorded renewed certificate was refused")
	}
}

// A successor that is not a HOST certificate gains nothing from the extension.
//
// Mutation: drop callerCertHasServerAuth from the renewal clause.
func TestPeerTrust_ARenewalClauseStillRequiresAHostCertificate(t *testing.T) {
	ctx := context.Background()
	s := trustFixture(t)
	chain := renewalChain(t, "node-r", 1)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "node-r", Address: "10.0.0.9", State: "active", CertSerial: chain[0].SerialNumber.Text(16),
	}); err != nil {
		t.Fatal(err)
	}
	clientOnly := *chain[1]
	clientOnly.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if s.isTrustedHostCN(leafCtx(&clientOnly), "node-r") {
		t.Fatal("a client-only certificate carrying a renewal extension was accepted as a peer")
	}
}

// A renewed node signs its votes with the certificate it now presents. The
// renewal revokes the old one, and every verifier checks the CRL, so a signer
// left on the old certificate would lose the node its vote.
//
// Mutation: make followRenewedIdentityLocked return immediately — the signer
// keeps the boot-time serial.
func TestClaimSigner_FollowsARenewedHostCertificate(t *testing.T) {
	s := voterTestServer(t)
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	before := signer.Serial()
	if _, _, err := pki.RenewLocal(filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "ca.key"), s.pkiDir, s.hostName); err != nil {
		t.Fatal(err)
	}
	certPEM := mustRead(t, filepath.Join(s.pkiDir, "host.crt"))
	renewed, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err = s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Serial() == before || signer.Serial() != renewed.SerialNumber.Text(16) {
		t.Fatalf("claim signer still signs with %s after a renewal to %s", signer.Serial(), renewed.SerialNumber.Text(16))
	}
	acc, err := signer.Sign(corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig}, 1,
		corrosion.Ballot{Round: 1, Coordinator: s.hostName}, "d", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pki.ParseCertPEM([]byte(acc.CertPEM)); err != nil || got.SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Fatalf("the accept carries the wrong certificate: %v", err)
	}
}

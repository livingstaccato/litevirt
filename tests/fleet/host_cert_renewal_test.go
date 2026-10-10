package fleet

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// installRenewal renews n's host certificate in place through the host-side
// install `lv host renew-cert` drives (key generated in n's pki dir, one atomic
// switch), and returns the new serial plus a pki dir holding the PREVIOUS pair.
func installRenewal(t *testing.T, c *Cluster, n *Node) (string, string) {
	t.Helper()
	oldDir := t.TempDir()
	for _, f := range []string{"ca.crt", "host.crt", "host.key"} {
		b, err := os.ReadFile(filepath.Join(n.PKIDir, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(oldDir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, next, err := pki.RenewLocal(c.caCert, c.caKey, n.PKIDir, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	return next, oldDir
}

// servedSerial dials target as source and returns the serial target presents.
func servedSerial(t *testing.T, source, target *Node) string {
	t.Helper()
	cfg, err := pki.PeerTLSConfig(source.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", target.Address, target.Port), cfg)
	if err != nil {
		t.Fatalf("dial %s: %v", target.Name, err)
	}
	defer conn.Close()
	return strings.ToLower(conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16))
}

// pushAs sends an empty replication push to target, authenticated with the
// pair in pkiDir under sender's name, and returns the RPC error.
func pushAs(t *testing.T, pkiDir, sender string, target *Node) error {
	t.Helper()
	cfg, err := pki.PeerTLSConfig(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient(fmt.Sprintf("%s:%d", target.Address, target.Port),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	_, err = pb.NewLiteVirtClient(cc).PushMutations(context.Background(), &pb.ReplicateRequest{
		Sender: sender, SenderVersion: "fleet-test", SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
	})
	return err
}

// TestFleet_HostCertRenewalKeepsThePeerTrusted renews a running node's cluster
// certificate and checks the property the renewal exists for: no moment at
// which its peers refuse it.
//
//  1. The renewed node serves the new certificate without a restart, and a
//     replication push it makes with it is accepted by a peer whose record
//     still names the old serial — the successor is accepted on the CA's word.
//  2. Once the node re-records its serial and that replicates, the peer pins
//     the new certificate: the OLD one, still CA-valid, is refused as a peer
//     (and, since the peer has seen the successor, refused outright).
//  3. Revoking the old serial makes the old certificate fail the handshake
//     outright, while the renewed one keeps working — renewal does not route
//     around revocation.
//
// Mutations: drop the RenewedFromSerial clause in grpcapi isTrustedHostCN —
// step 1's push is refused (PermissionDenied); set Certificates statically in
// pki.ServerTLSConfig — step 1 sees the old serial served.
func TestFleet_HostCertRenewalKeepsThePeerTrusted(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b := c.Nodes[0], c.Nodes[1]
	oldSerial := strings.ToLower(servedSerial(t, b, a))

	newSerial, oldDir := installRenewal(t, c, a)

	// 1. served at once, and accepted by a peer still pinning the old serial.
	if got := servedSerial(t, b, a); got != newSerial {
		t.Fatalf("%s still serves %s after renewal to %s (was %s): the listener did not reload",
			a.Name, got, newSerial, oldSerial)
	}
	if _, rec, _, _ := hostRowOf(t, b, a.Name); !strings.EqualFold(rec, oldSerial) {
		t.Fatalf("fixture: %s already records %s for %s", b.Name, rec, a.Name)
	}
	if err := pushAs(t, a.PKIDir, a.Name, b); status.Code(err) == codes.PermissionDenied {
		t.Fatalf("%s refused the renewed %s while its record still named the predecessor: %v", b.Name, a.Name, err)
	}

	// 2. a re-records its serial (the daemon's cert watch), and it replicates.
	if wrote, err := corrosion.RecordOwnCertSerial(ctx, a.DB, a.Name, newSerial); err != nil || !wrote {
		t.Fatalf("re-record on %s: wrote=%v err=%v", a.Name, wrote, err)
	}
	pumpMutations(t, c, a, b)
	if _, rec, _, _ := hostRowOf(t, b, a.Name); !strings.EqualFold(rec, newSerial) {
		t.Fatalf("%s records %s for %s after the re-record replicated, want %s", b.Name, rec, a.Name, newSerial)
	}
	// Refused either way: as no longer the host (PermissionDenied), or — once
	// b holds the successor, which it has from a's push above — outright, as a
	// certificate the CA replaced (connIdentityGate).
	if err := pushAs(t, oldDir, a.Name, b); err == nil ||
		(status.Code(err) != codes.PermissionDenied && !strings.Contains(err.Error(), "replaced")) {
		t.Fatalf("%s accepted %s's REPLACED certificate as a peer after the record moved on: %v", b.Name, a.Name, err)
	}
	if err := pushAs(t, a.PKIDir, a.Name, b); status.Code(err) == codes.PermissionDenied {
		t.Fatalf("%s refused the renewed and recorded %s: %v", b.Name, a.Name, err)
	}

	// 3. revocation of the old serial stops it at the handshake.
	if err := pki.GenerateCRL(c.caCert, c.caKey, filepath.Join(b.PKIDir, "crl.pem"), []string{oldSerial}); err != nil {
		t.Fatal(err)
	}
	if err := pushAs(t, oldDir, a.Name, b); err == nil || status.Code(err) == codes.PermissionDenied {
		t.Fatalf("a revoked certificate got past the handshake: %v", err)
	}
	if err := pushAs(t, a.PKIDir, a.Name, b); err != nil && status.Code(err) == codes.Unavailable {
		t.Fatalf("revoking the replaced certificate cut off the renewed one: %v", err)
	}
}

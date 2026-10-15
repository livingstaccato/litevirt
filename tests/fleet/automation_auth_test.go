package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Both ordinary CA-issued client mTLS and a valid admin API token can access
// public reads, but neither may fetch or install private certified envelopes.
func TestAutomationDecisionPrefixPeerOnly(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	c := f.cluster
	n := c.Nodes[0]
	token := userOn(t, c, n, "automation-admin", "admin")
	dir := t.TempDir()
	cert := filepath.Join(dir, "client.crt")
	key := filepath.Join(dir, "client.key")
	if err := pki.GenerateClientCert(c.caCert, c.caKey, cert, key, "automation-client"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(c.caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid CA fixture")
	}
	for _, bearer := range []bool{false, true} {
		opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}))}
		if bearer {
			opts = append(opts, grpc.WithPerRPCCredentials(staticBearer{token}))
		}
		conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", n.Address, n.Port), opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		client := pb.NewLiteVirtClient(conn)
		if _, err := client.ListHosts(f.Context(), &pb.ListHostsRequest{}); err != nil {
			t.Fatalf("valid public client bearer=%v failed authentication: %v", bearer, err)
		}
		if _, err := client.GetAutomationDecision(f.Context(), &pb.GetAutomationDecisionRequest{Sequence: 1}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("non-host prefix fetch bearer=%v = %v", bearer, err)
		}
		if _, err := client.InstallAutomationDecision(f.Context(), &pb.InstallAutomationDecisionRequest{RecordJson: []byte("untrusted")}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("non-host prefix install bearer=%v = %v", bearer, err)
		}
	}
}

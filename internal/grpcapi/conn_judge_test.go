package grpcapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// An established connection is re-judged: after the client's host
// certificate is renewed and the new serial recorded, the connection made with
// the old certificate is closed and the client's next call arrives with the
// new one; after that certificate is revoked, the live connection is cut and no
// new handshake succeeds. Before the sweep, the old connection keeps working —
// which is exactly the gap the tracker closes.
//
// Mutations: make staleHostIdentity return false — the renewed client keeps
// calling with the old certificate; drop the peer-revoked check in ConnJudge —
// the revoked client keeps its connection.
func TestConnJudge_ClosesConnectionsMadeWithAReplacedOrRevokedCertificate(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	root := t.TempDir()
	srvDir, cliDir := filepath.Join(root, "srv"), filepath.Join(root, "cli")
	for _, d := range []string{srvDir, cliDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	caCert, caKey := filepath.Join(srvDir, "ca.crt"), filepath.Join(srvDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		b, _ := os.ReadFile(filepath.Join(srvDir, f))
		if err := os.WriteFile(filepath.Join(cliDir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(srvDir, "host.crt"), filepath.Join(srvDir, "host.key"),
		s.hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(cliDir, "host.crt"), filepath.Join(cliDir, "host.key"),
		"node-c", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.pkiDir = srvDir
	first, _ := pki.CertSerial(filepath.Join(cliDir, "host.crt"))
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "node-c", Address: "127.0.0.1",
		State: "active", CertSerial: first}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	record := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if p, ok := peer.FromContext(ctx); ok {
			if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
				mu.Lock()
				seen = append(seen, strings.ToLower(ti.State.PeerCertificates[0].SerialNumber.Text(16)))
				mu.Unlock()
			}
		}
		return h(ctx, req)
	}
	srvTLS, err := pki.ServerTLSConfig(srvDir)
	if err != nil {
		t.Fatal(err)
	}
	tracker := pki.NewConnTracker(srvDir)
	gs := grpc.NewServer(grpc.Creds(tracker.ServerCreds(credentials.NewTLS(srvTLS))), grpc.UnaryInterceptor(record))
	healthpb.RegisterHealthServer(gs, health.NewServer())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	cliTLS, err := pki.PeerTLSConfig(cliDir)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cliTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	hc := healthpb.NewHealthClient(cc)
	call := func() (string, error) {
		_, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		mu.Lock()
		defer mu.Unlock()
		if err != nil || len(seen) == 0 {
			return "", err
		}
		return seen[len(seen)-1], nil
	}
	if got, err := call(); err != nil || !strings.EqualFold(got, first) {
		t.Fatalf("first call: %s %v", got, err)
	}

	// The client renews and the cluster records the new serial.
	_, renewed, err := pki.RenewLocal(filepath.Join(cliDir, "ca.crt"), filepath.Join(cliDir, "ca.key"), cliDir, "node-c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrosion.RecordOwnCertSerial(ctx, s.db, "node-c", renewed); err != nil {
		t.Fatal(err)
	}
	if got, _ := call(); !strings.EqualFold(got, first) {
		t.Fatalf("fixture: the established connection already re-handshook (%s)", got)
	}
	judge := s.ConnJudge(ctx)
	if n := tracker.Sweep(judge); n != 1 {
		t.Fatalf("swept %d connections, want the one made with the replaced certificate", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := call()
		if err == nil && got == renewed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client did not reconnect with its renewed certificate (last %s, %v)", got, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The renewed certificate is revoked: the live connection is cut and no
	// handshake succeeds again.
	if err := pki.GenerateCRL(caCert, caKey, filepath.Join(srvDir, "crl.pem"), []string{renewed}); err != nil {
		t.Fatal(err)
	}
	if n := tracker.Sweep(judge); n != 1 {
		t.Fatalf("swept %d connections after a revocation, want 1", n)
	}
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if _, err := call(); err == nil {
			t.Fatal("a revoked certificate kept working after the sweep")
		}
	}
}

package grpcapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// identityServer runs s's real auth interceptors behind a connection tracker,
// as the daemon does, serving the gRPC health service; the client is host
// node-c under the same CA.
type identityServer struct {
	tracker        *pki.ConnTracker
	health         *health.Server
	srvDir, cliDir string
	caCert, caKey  string
	addr           string
}

func newIdentityServer(t *testing.T, s *Server) *identityServer {
	t.Helper()
	root := t.TempDir()
	is := &identityServer{srvDir: filepath.Join(root, "srv"), cliDir: filepath.Join(root, "cli")}
	for _, d := range []string{is.srvDir, is.cliDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	is.caCert, is.caKey = filepath.Join(is.srvDir, "ca.crt"), filepath.Join(is.srvDir, "ca.key")
	if err := pki.GenerateCA(is.caCert, is.caKey); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		b, _ := os.ReadFile(filepath.Join(is.srvDir, f))
		if err := os.WriteFile(filepath.Join(is.cliDir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pki.GenerateHostCert(is.caCert, is.caKey, filepath.Join(is.srvDir, "host.crt"), filepath.Join(is.srvDir, "host.key"),
		s.hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(is.caCert, is.caKey, filepath.Join(is.cliDir, "host.crt"), filepath.Join(is.cliDir, "host.key"),
		"node-c", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.pkiDir = is.srvDir
	first, _ := pki.CertSerial(filepath.Join(is.cliDir, "host.crt"))
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "node-c", Address: "127.0.0.1",
		State: "active", CertSerial: first}); err != nil {
		t.Fatal(err)
	}
	srvTLS, err := pki.ServerTLSConfig(is.srvDir)
	if err != nil {
		t.Fatal(err)
	}
	is.tracker = pki.NewConnTracker(is.srvDir)
	gs := grpc.NewServer(grpc.Creds(is.tracker.ServerCreds(credentials.NewTLS(srvTLS))),
		grpc.StatsHandler(is.tracker.StatsHandler()),
		grpc.UnaryInterceptor(s.UnaryAuthInterceptor), grpc.StreamInterceptor(s.StreamAuthInterceptor))
	is.health = health.NewServer()
	healthpb.RegisterHealthServer(gs, is.health)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	is.addr = lis.Addr().String()
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return is
}

func (is *identityServer) client(t *testing.T) healthpb.HealthClient {
	t.Helper()
	cliTLS, err := pki.PeerTLSConfig(is.cliDir)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient(is.addr, grpc.WithTransportCredentials(credentials.NewTLS(cliTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return healthpb.NewHealthClient(cc)
}

// R2: once a node knows a connection's certificate was REPLACED, no new RPC
// starts on it — even while the client holds a stream open, which used to keep
// the connection usable for up to the full grace. The stream already in
// flight finishes; when it ends the connection closes, and the client's next
// call reconnects with its renewed certificate. A REVOKED certificate gets no
// grace at all: the new RPC is refused and the connection, stream included, is
// cut at once.
//
// Mutations: drop connIdentityGate from UnaryAuthInterceptor — the new unary
// RPC on the replaced certificate's connection succeeds; make the revoked
// case drain instead of closing (immediate=false) — the stream on a revoked
// certificate survives.
func TestConnIdentityGate_NoNewRPCOnAReplacedOrRevokedIdentity(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	is := newIdentityServer(t, s)
	hc := is.client(t)

	sctx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	stream, err := hc.Watch(sctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("open the stream: %v", err)
	}
	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("a call on a current certificate failed: %v", err)
	}

	// node-c renews, and the server learns it from the renewed host's own
	// handshake on a NEW connection.
	if _, _, err := pki.RenewLocal(filepath.Join(is.cliDir, "ca.crt"), filepath.Join(is.cliDir, "ca.key"), is.cliDir, "node-c"); err != nil {
		t.Fatal(err)
	}
	if _, err := is.client(t).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("the renewed certificate's call failed: %v", err)
	}

	// The old connection still carries the stream; a new RPC on it is refused.
	_, err = hc.Check(ctx, &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("a new RPC on a replaced certificate's connection: %v, want Unavailable naming the replacement", err)
	}
	// The stream in flight is left to finish.
	is.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("the stream in flight was cut: %v", err)
	}
	cancelStream()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client did not reconnect with its renewed certificate after the stream ended: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Revoked: a stream is open on the renewed certificate's connection; the
	// certificate is revoked; the next RPC is refused and the stream is cut.
	stream2, err := hc.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream2.Recv(); err != nil {
		t.Fatal(err)
	}
	renewed, _ := pki.CertSerial(filepath.Join(is.cliDir, "host.crt"))
	if err := pki.GenerateCRL(is.caCert, is.caKey, filepath.Join(is.srvDir, "crl.pem"), []string{renewed}); err != nil {
		t.Fatal(err)
	}
	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a new RPC on a revoked certificate's connection: %v, want Unauthenticated", err)
	}
	done := make(chan error, 1)
	go func() { _, err := stream2.Recv(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the stream on a revoked certificate delivered after the revocation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream on a revoked certificate's connection was not cut")
	}
}

// The sweep's judge (pki.ConnTracker) agrees with the per-RPC gate: a
// connection made with a certificate the CA replaced drains — whatever the
// host's row says — and one made with a revoked certificate is closed at once,
// streams in flight included.
//
// Mutations: drop the SupersededError check from ConnJudge — a replaced
// certificate whose row was written back is judged acceptable; drop Immediate
// from the revoked verdict — a revoked certificate's streams get the grace.
func TestConnJudge_SupersededDrainsRevokedClosesAtOnce(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	is := newIdentityServer(t, s)
	old, err := pki.ServedHostCertificate(is.cliDir)
	if err != nil {
		t.Fatal(err)
	}
	if v := s.ConnJudge(ctx)(pki.TrackedConn{Peer: old}); v.Close {
		t.Fatalf("fixture: a current certificate was judged: %+v", v)
	}
	if _, _, err := pki.RenewLocal(filepath.Join(is.cliDir, "ca.crt"), filepath.Join(is.cliDir, "ca.key"), is.cliDir, "node-c"); err != nil {
		t.Fatal(err)
	}
	succ, _ := pki.ServedHostCertificate(is.cliDir)
	pki.NoteSuccessor(is.srvDir, succ)
	// The row still names the replaced serial (newIdentityServer recorded it).
	v := s.ConnJudge(ctx)(pki.TrackedConn{Peer: old})
	if !v.Close || v.Immediate || !strings.Contains(v.Reason, "replaced") {
		t.Fatalf("a replaced certificate's connection: %+v, want it drained", v)
	}
	if err := pki.GenerateCRL(is.caCert, is.caKey, filepath.Join(is.srvDir, "crl.pem"),
		[]string{strings.ToLower(succ.SerialNumber.Text(16))}); err != nil {
		t.Fatal(err)
	}
	if v := s.ConnJudge(ctx)(pki.TrackedConn{Peer: succ}); !v.Close || !v.Immediate {
		t.Fatalf("a revoked certificate's connection: %+v, want it closed at once", v)
	}
}

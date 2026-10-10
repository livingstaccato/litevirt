package pki

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

// The UI/REST loopback client is recycled when this host's certificate is
// renewed (re-review 3's ruling): the next RPC goes over a new connection
// presenting the renewed certificate, and a stream opened before the renewal
// — a console, an event stream — is not cut by the switch.
//
// Mutation: never re-dial in RecyclingConn.current — the RPC after the
// renewal still presents the replaced certificate.
func TestRecyclingConn_MovesToTheRenewedIdentity(t *testing.T) {
	ctx := context.Background()
	dir := setupPKI(t)
	srvTLS, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	record := func(ctx context.Context) {
		if p, ok := peer.FromContext(ctx); ok {
			if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
				mu.Lock()
				seen = append(seen, strings.ToLower(ti.State.PeerCertificates[0].SerialNumber.Text(16)))
				mu.Unlock()
			}
		}
	}
	hs := health.NewServer()
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			record(ctx)
			return h(ctx, req)
		}))
	healthpb.RegisterHealthServer(gs, hs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	r, err := NewRecyclingConn(dir, func() (*grpc.ClientConn, error) {
		cli, err := ClientTLSConfig(dir)
		if err != nil {
			return nil, err
		}
		cli = cli.Clone()
		cli.ServerName = "test-host"
		return grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cli)))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	hc := healthpb.NewHealthClient(r)
	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	stream, err := hc.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}

	prev, next, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 2 || got[0] != prev || got[1] != next {
		t.Fatalf("the loopback client presented %v; want %s, then the renewed %s", got, prev, next)
	}
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("the stream opened before the renewal was cut by the switch: %v", err)
	}
}

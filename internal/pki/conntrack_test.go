package pki

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func trackedServer(t *testing.T, grace time.Duration) (*ConnTracker, healthpb.HealthClient, *grpc.ClientConn) {
	t.Helper()
	dir := setupPKI(t)
	srvTLS, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	tr := NewConnTracker(dir)
	tr.StreamGrace = grace
	gs := grpc.NewServer(grpc.Creds(tr.ServerCreds(credentials.NewTLS(srvTLS))), grpc.StatsHandler(tr.StatsHandler()))
	healthpb.RegisterHealthServer(gs, health.NewServer())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	cli, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli = cli.Clone()
	cli.ServerName = "test-host"
	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cli)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return tr, healthpb.NewHealthClient(cc), cc
}

func dropAll(TrackedConn) Verdict { return Verdict{Close: true, Reason: "test"} }

// A connection the judge rejects is not cut while it carries an RPC — a
// migration or backup stream that began before a renewal finishes — and is
// closed as soon as the RPC ends, or when the grace runs out.
//
// Mutation: ignore in-flight RPCs in Sweep — the open stream is cut at once.
func TestConnTracker_WaitsForInFlightRPCsWithABound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr, hc, _ := trackedServer(t, time.Hour)
	stream, err := hc.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if n := tr.Sweep(dropAll); n != 0 {
		t.Fatalf("closed %d connection(s) with a stream in flight", n)
	}
	cancel()
	// The stream's end closes the draining connection itself, without
	// waiting for the next sweep.
	deadline := time.Now().Add(5 * time.Second)
	for tr.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connection was not closed once its stream ended")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A short grace: the stream is cut when it runs out.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	tr2, hc2, _ := trackedServer(t, 50*time.Millisecond)
	s2, err := hc2.Watch(ctx2, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Recv(); err != nil {
		t.Fatal(err)
	}
	if n := tr2.Sweep(dropAll); n != 0 {
		t.Fatal("cut before the grace started")
	}
	time.Sleep(100 * time.Millisecond)
	if n := tr2.Sweep(dropAll); n != 1 {
		t.Fatalf("closed %d after the grace ran out, want 1", n)
	}
}

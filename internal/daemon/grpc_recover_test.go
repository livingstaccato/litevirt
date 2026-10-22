package daemon

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/metrics"
)

func unregisteredRPCMetrics() *metrics.RPCMetrics {
	return &metrics.RPCMetrics{
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "d_test", Help: "t"}, []string{"method", "code"}),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "r_test", Help: "t"}, []string{"method", "code"}),
	}
}

// chainUnary runs ics the way grpc.ChainUnaryInterceptor does, outermost first.
func chainUnary(ics []grpc.UnaryServerInterceptor, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) grpc.UnaryHandler {
	for i := len(ics) - 1; i >= 0; i-- {
		ic, next := ics[i], h
		h = func(ctx context.Context, req any) (any, error) { return ic(ctx, req, info, next) }
	}
	return h
}

func chainStream(ics []grpc.StreamServerInterceptor, info *grpc.StreamServerInfo, h grpc.StreamHandler) grpc.StreamHandler {
	for i := len(ics) - 1; i >= 0; i-- {
		ic, next := ics[i], h
		h = func(srv any, ss grpc.ServerStream) error { return ic(srv, ss, info, next) }
	}
	return h
}

type ctxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s ctxStream) Context() context.Context { return s.ctx }

// A panic in an RPC handler must come back as Internal through the daemon's
// own interceptor chain, not end the process: a daemon that dies is fenced by
// its peers about 13 s later, with every VM on the host. Removing the recovery
// interceptor from the chain makes this test binary panic.
func TestServerInterceptors_HandlerPanicAnswersInternal(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	dir := t.TempDir()
	svc := grpcapi.NewServer("host-a", dir, dir, db, nil, nil)
	m := unregisteredRPCMetrics()
	const ping = "/litevirt.v1.LiteVirt/Ping" // no auth needed, so the handler runs

	uinfo := &grpc.UnaryServerInfo{FullMethod: ping}
	unary := chainUnary(serverUnaryInterceptors(m, svc), uinfo, func(context.Context, any) (any, error) {
		panic("handler bug")
	})
	if _, err := unary(context.Background(), nil); status.Code(err) != codes.Internal {
		t.Fatalf("unary panic: err = %v, want Internal", err)
	}
	// The process and the chain still serve.
	ok := chainUnary(serverUnaryInterceptors(m, svc), uinfo, func(context.Context, any) (any, error) { return "pong", nil })
	if resp, err := ok(context.Background(), nil); err != nil || resp != "pong" {
		t.Fatalf("after a recovered panic: resp=%v err=%v", resp, err)
	}

	sinfo := &grpc.StreamServerInfo{FullMethod: ping}
	stream := chainStream(serverStreamInterceptors(m, svc), sinfo, func(any, grpc.ServerStream) error {
		panic("stream handler bug")
	})
	if err := stream(nil, ctxStream{ctx: context.Background()}); status.Code(err) != codes.Internal {
		t.Fatalf("stream panic: err = %v, want Internal", err)
	}
}

// The recovery interceptor must come first in the chain, so a panic in any
// interceptor after it is answered too. A nil grpcapi.Server panics inside the
// auth interceptor, after the metrics one; with recovery anywhere but first
// that panic ends this test binary.
func TestServerInterceptors_RecoveryIsFirst(t *testing.T) {
	m := unregisteredRPCMetrics()
	var svc *grpcapi.Server
	uinfo := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/ListVMs"}
	unary := chainUnary(serverUnaryInterceptors(m, svc), uinfo, func(context.Context, any) (any, error) { return nil, nil })
	if _, err := unary(context.Background(), nil); status.Code(err) != codes.Internal {
		t.Fatalf("a panic in the auth interceptor: err = %v, want Internal", err)
	}
	sinfo := &grpc.StreamServerInfo{FullMethod: "/litevirt.v1.LiteVirt/ListVMs"}
	stream := chainStream(serverStreamInterceptors(m, svc), sinfo, func(any, grpc.ServerStream) error { return nil })
	if err := stream(nil, ctxStream{ctx: context.Background()}); status.Code(err) != codes.Internal {
		t.Fatalf("a panic in the stream auth interceptor: err = %v, want Internal", err)
	}
}

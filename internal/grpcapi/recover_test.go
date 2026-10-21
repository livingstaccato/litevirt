package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The recovery decision rests on this: a lock taken with a deferred unlock is
// free again by the time the panic is answered, so the next call on the same
// path is served. The panic is counted by method.
func TestRecoverUnaryInterceptor_ReleasesDeferredLockAndCounts(t *testing.T) {
	var mu sync.Mutex
	info := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/StartVM"}
	before := testutil.ToFloat64(handlerPanics.WithLabelValues("StartVM"))

	_, err := RecoverUnaryInterceptor(context.Background(), nil, info, func(context.Context, any) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]int
		m["boom"]++ // a real runtime panic, not a test-only one
		return nil, nil
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v, want Internal", err)
	}
	if !mu.TryLock() {
		t.Fatal("the handler's deferred unlock did not run before the panic was answered")
	}
	mu.Unlock()
	if got := testutil.ToFloat64(handlerPanics.WithLabelValues("StartVM")) - before; got != 1 {
		t.Fatalf("litevirt_grpc_handler_panics_total{method=StartVM} rose by %v, want 1", got)
	}

	resp, err := RecoverUnaryInterceptor(context.Background(), nil, info, func(context.Context, any) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return "ok", nil
	})
	if err != nil || resp != "ok" {
		t.Fatalf("next call on the same path: resp=%v err=%v", resp, err)
	}
}

// The client gets no panic value: it can carry data from another tenant.
func TestRecoverUnaryInterceptor_DoesNotLeakPanicValue(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/GetVM"}
	_, err := RecoverUnaryInterceptor(context.Background(), nil, info, func(context.Context, any) (any, error) {
		panic("secret-token-abc")
	})
	if s := status.Convert(err).Message(); s == "" || strings.Contains(s, "secret-token-abc") {
		t.Fatalf("message %q must be non-empty and must not carry the panic value", s)
	}
}

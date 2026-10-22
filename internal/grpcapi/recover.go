package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// handlerPanics counts RPC handler panics the recovery interceptors turned into
// an Internal error. Any increase is a bug to report: the call failed, and a
// lock the handler took without a deferred unlock may still be held.
var handlerPanics = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "litevirt_grpc_handler_panics_total",
	Help: "gRPC handler panics recovered and answered with Internal, by method.",
}, []string{"method"})

// RecoverUnaryInterceptor and RecoverStreamInterceptor stop a panic in an RPC
// handler from ending the daemon. grpc-go does not recover handler panics, so
// before these one bad request killed the whole process, peers fenced the
// host about 13 s later, and every VM on it died with nothing wrong with any
// of them.
//
// The panic is answered with codes.Internal, its stack is logged, and
// litevirt_grpc_handler_panics_total counts it. The daemon keeps serving.
//
// Recovering, not exiting, is a decision about what a panic can leave behind:
//
//   - A lock taken with a deferred unlock (the form used throughout) is
//     released while the panic unwinds, before it reaches here.
//   - A lock taken without one stays held. Later calls that need it block: a
//     wedged path, visible in the counter and the log, never a second copy of
//     anything. Exiting would trade it for a fence that kills every workload.
//   - A journaled operation abandoned part way is in the state a crash at the
//     same instant leaves, which the journal exists to make safe; the
//     operation stays open rather than being treated as done.
//
// Neither recovers a panic in a goroutine the handler started (for example
// answerLibvirtCall's deliberate re-panic in migrate.go): that still ends the
// process, as any goroutine's panic does.
//
// Chain them first, so a panic in any later interceptor is caught too.
func RecoverUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if p := recover(); p != nil {
			resp, err = nil, recoveredPanic(info.FullMethod, p)
		}
	}()
	return handler(ctx, req)
}

// RecoverStreamInterceptor is RecoverUnaryInterceptor for streaming RPCs.
func RecoverStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = recoveredPanic(info.FullMethod, p)
		}
	}()
	return handler(srv, ss)
}

func recoveredPanic(fullMethod string, p any) error {
	method := fullMethod
	if i := strings.LastIndexByte(method, '/'); i >= 0 {
		method = method[i+1:]
	}
	handlerPanics.WithLabelValues(method).Inc()
	slog.Error("gRPC handler panicked; answered Internal and kept serving. This is a bug: report it with the stack",
		"method", fullMethod, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
	return status.Errorf(codes.Internal, "internal error in %s: the handler panicked (logged on the serving host)", method)
}

package grpcapi

import (
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// containerOp journals one container day-2 operation (snapshot, revert,
// snapshot delete, backup, restore, migrate) on the host that runs it: an INFO
// line when it starts and when it completes, and a failure line carrying the
// cause. Create, clone and delete already log; these did not, so a backup or a
// migration left nothing in the journal of either host.
//
// It is started only after the request is authorized and has reached the
// host that executes it, so a forwarded call is logged once, where it runs,
// and a refused caller cannot fill the journal.
type containerOp struct {
	op    string
	start time.Time
	attrs []any
}

func (s *Server) startContainerOp(op, name string, kv ...any) *containerOp {
	o := &containerOp{op: op, start: time.Now(), attrs: append([]any{"name", name, "host", s.hostName}, kv...)}
	slog.Info("container "+op+" started", o.attrs...)
	return o
}

// with adds attributes learned after the start (a defaulted backup timestamp).
func (o *containerOp) with(kv ...any) { o.attrs = append(o.attrs, kv...) }

// done logs the outcome. A refusal the caller can act on (a bad argument, a
// name already in use, a precondition) is a WARN; anything else — the
// runtime, the store, a peer — is an ERROR.
func (o *containerOp) done(err error) {
	attrs := append(append([]any{}, o.attrs...), "duration", time.Since(o.start).Round(time.Millisecond).String())
	if err == nil {
		slog.Info("container "+o.op+" completed", attrs...)
		return
	}
	code := status.Code(err)
	attrs = append(attrs, "code", code.String(), "error", err.Error())
	switch code {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.FailedPrecondition,
		codes.PermissionDenied, codes.Unauthenticated, codes.ResourceExhausted, codes.Canceled,
		codes.OutOfRange:
		slog.Warn("container "+o.op+" failed", attrs...)
	default:
		slog.Error("container "+o.op+" failed", attrs...)
	}
}

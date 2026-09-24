package ui

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"
)

// detachedOpCeiling bounds an operation the UI started and stopped watching,
// matching the REST API's (internal/restapi/detached_op.go).
const detachedOpCeiling = 6 * time.Hour

// detachedOpContext keeps ctx's values — the operator's session bearer, so the
// daemon authorises the operation as them — but not its cancellation. A
// server-streaming RPC runs off its stream's context, and net/http cancels the
// request context as soon as the handler returns (#192).
func detachedOpContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedOpCeiling)
}

// drainInBackground reads a stream the handler has stopped watching to its
// end, so the operation runs to completion and the server is never blocked on
// Send once the flow-control window fills. cancel is released when it ends.
func drainInBackground(op string, cancel context.CancelFunc, recv func() error) {
	go func() {
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				slog.Error("ui: detached operation panicked", "op", op, "panic", p)
			}
		}()
		for {
			if err := recv(); err != nil {
				if !errors.Is(err, io.EOF) {
					slog.Warn("ui: detached operation ended with an error", "op", op, "error", err)
				}
				return
			}
		}
	}()
}

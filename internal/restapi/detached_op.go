package restapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// detachedOpCeiling bounds an operation the REST gateway has acknowledged and
// stopped watching. Long enough for a real drain or storage migration of a
// large host; short enough that a wedged one cannot hold a goroutine and a gRPC
// stream open indefinitely.
const detachedOpCeiling = 6 * time.Hour

// detachedOpContext derives a context that keeps ctx's VALUES but not its
// cancellation, bounded by detachedOpCeiling.
//
// The values matter as much as the detachment: the gRPC call is authenticated
// by metadata carried on the request context, so a context built from
// Background() would turn every acknowledged operation into an unauthenticated
// one.
func detachedOpContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedOpCeiling)
}

// ackAndDetach is the non-SSE half of a server-streaming RPC: the caller has
// been told the operation started, so it now has to actually run.
//
// The handler used to open the stream on r.Context(), never call Recv, write
// its ack and return — at which point net/http cancelled r.Context(), the
// stream's parent, and the operation died part-way through. Draining the stream
// in the background does two things: it lets the RPC run to completion, and it
// keeps reading so the server is never blocked on Send once the flow-control
// window fills.
//
// cancel is the detached context's, released once the stream ends.
func ackAndDetach(op string, cancel context.CancelFunc, recv func() (proto.Message, error)) {
	go func() {
		defer cancel()
		// This runs after the handler has returned, so a panic here has no
		// http.Server recover above it and would take the daemon down with it.
		defer func() {
			if p := recover(); p != nil {
				slog.Error("restapi: detached operation panicked", "op", op, "panic", p)
			}
		}()
		for {
			_, err := recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					slog.Debug("restapi: detached operation completed", "op", op)
				} else {
					slog.Warn("restapi: detached operation ended with an error", "op", op, "error", err)
				}
				return
			}
		}
	}()
}

// ackTimeout bounds how long the gateway will wait for a streaming operation's
// FIRST message before acknowledging it anyway.
//
// It must stay well under the server's WriteTimeout (120s), or the client sees
// a dead connection instead of an answer and retries — and every retry adds
// another blocked goroutine, another gRPC stream and another queued lock
// waiter, none of which the disconnected client can cancel.
const ackTimeout = 30 * time.Second

// ackTimeoutForTest is the budget firstOrDetach actually uses. A var so a test
// can shrink it; nothing in production reassigns it.
var ackTimeoutForTest = ackTimeout

// firstOrDetach waits up to ackTimeout for the first message of a
// server-streaming RPC.
//
// The operation itself runs on a detached, six-hour context, which is right:
// once acknowledged it must outlive the request. But the ACKNOWLEDGEMENT was
// waiting on that same context, so a first message that cannot be produced —
// MigrateVM cannot send MIGRATE_VALIDATING until it holds the per-VM lock, and
// a nightly backup can hold that for minutes — blocked the handler far past
// the point the client gave up.
//
// On timeout the stream is handed on exactly as a normal ack would hand it on,
// and the caller reports 202 Accepted. The in-flight Recv is NOT abandoned: its
// result is delivered to the detached reader first, so no message is dropped.
func firstOrDetach(recv func() (proto.Message, error)) (first proto.Message, err error, timedOut bool, rest func() (proto.Message, error)) {
	type result struct {
		m   proto.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, e := recv()
		ch <- result{m, e}
	}()

	select {
	case r := <-ch:
		return r.m, r.err, false, recv
	case <-time.After(ackTimeoutForTest):
		// The goroutine above still owns the first Recv. The detached reader
		// takes its result before reading anything further, or the first
		// message would be lost.
		var once sync.Once
		var pending result
		var got bool
		return nil, nil, true, func() (proto.Message, error) {
			once.Do(func() {
				pending = <-ch
				got = true
			})
			if got {
				got = false
				return pending.m, pending.err
			}
			return recv()
		}
	}
}

package daemon

import (
	"log/slog"
	"time"
)

// gracefulStopWait is how long a shutdown lets in-flight RPCs finish before
// the gRPC server is stopped outright.
const gracefulStopWait = 5 * time.Second

// grpcStopper is the gRPC server, as stopServing stops it.
type grpcStopper interface {
	GracefulStop()
	Stop()
}

// consoleAuditFlusher is the console audit, as stopServing ends it
// (grpcapi.Server: docs/audit-log.md "Console sessions").
type consoleAuditFlusher interface {
	MarkConsoleShutdown()
	FlushConsoleAudit()
}

// stopServing ends serving at a shutdown, in an order the console audit
// depends on:
//
//  1. MarkConsoleShutdown: a console session that ends from here on ended
//     because of the stop;
//  2. GracefulStop, or Stop after grace (console streams never end on their
//     own, so with one open this always takes the full grace);
//  3. afterStop (what must still run with the database open);
//  4. FlushConsoleAudit: every open session's close row, and every row a
//     handler ended by the stop is still writing, before the caller closes
//     the database. It is bounded (grpcapi.consoleFlushTimeout).
func stopServing(srv grpcStopper, consoles consoleAuditFlusher, grace time.Duration, afterStop func()) {
	consoles.MarkConsoleShutdown()
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Warn("graceful shutdown timed out, forcing stop")
		srv.Stop()
	}
	afterStop()
	consoles.FlushConsoleAudit()
}

package daemon

import "time"

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
//  2. stopGRPC: GracefulStop, then Stop once graceful has passed (console
//     streams never end on their own, so with one open this always takes the
//     full graceful bound). It returns within graceful+forced whatever the
//     handlers do: a Stop that is itself stuck behind a handler in the kernel
//     (lab 2 N-5) is given up on and left running, with that handler;
//  3. close(stopped): Run's awaitServe stops waiting on Serve, which returns
//     only once a stop has finished — so it is closed on every one of
//     stopGRPC's exits (graceful done, forced done, given up), before
//     anything below can wait;
//  4. afterStop (what must still run with the database open);
//  5. FlushConsoleAudit: every open session's close row, and every row a
//     handler ended by the stop is still writing, before the caller closes
//     the database. It is bounded (grpcapi.consoleFlushTimeout), and safe when
//     step 2 gave up: a console handler still running is either still live
//     (the flush closes it, and its later end finds it closed) or holds a
//     claim the flush waits for, and a row it decides after the flush is
//     refused.
//
// There is no Stop call here outside stopGRPC: an inline Stop after the
// graceful bound can block on the server's mutex behind GracefulStop's wait
// for a stuck handler, which is the hang stopGRPC bounds.
func stopServing(srv grpcStopper, consoles consoleAuditFlusher, graceful, forced time.Duration,
	stopped chan<- struct{}, afterStop func()) {
	consoles.MarkConsoleShutdown()
	stopGRPC(srv, graceful, forced)
	close(stopped)
	afterStop()
	consoles.FlushConsoleAudit()
}

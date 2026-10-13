package daemon

import (
	"log/slog"
	"time"

	"google.golang.org/grpc"
)

// grpcStopper is the part of *grpc.Server a shutdown stops.
type grpcStopper interface {
	GracefulStop()
	Stop()
}

const (
	// grpcGracefulStop is how long a shutdown lets the RPCs in flight finish.
	grpcGracefulStop = 5 * time.Second
	// grpcForcedStop bounds the forced stop that follows.
	grpcForcedStop = 5 * time.Second
	// serveReturnBound is how long Run waits for Serve to return once the
	// stop above has finished or been given up on.
	serveReturnBound = time.Second
)

// stopGRPC stops srv gracefully, and forcibly once graceful has passed. It
// returns within graceful+forced whatever the handlers in flight do.
//
// A handler can be stuck where nothing interrupts it: a stat on a hard NFS
// mount whose server does not answer stays in the kernel until the server
// answers (lab 2 N-5). grpc-go's GracefulStop waits for every handler, and,
// once the connections are gone, does so holding the server's mutex; Stop
// needs that mutex to finish. So a Stop after a GracefulStop that is waiting
// on such a handler can wait as long as the handler does — and, behind it,
// so does Serve, which returns only once a stop has finished. Neither is
// waited on past its bound here: a stop still running then is left behind,
// with the handler it waits on, and the process exits without them.
func stopGRPC(srv grpcStopper, graceful, forced time.Duration) {
	gracefulDone := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(gracefulDone)
	}()
	select {
	case <-gracefulDone:
		return
	case <-time.After(graceful):
	}
	slog.Warn("graceful shutdown timed out, forcing stop")
	forcedDone := make(chan struct{})
	go func() {
		srv.Stop()
		close(forcedDone)
	}()
	select {
	case <-forcedDone:
	case <-gracefulDone:
	case <-time.After(forced):
		slog.Warn("gRPC server did not stop: a request is still running (storage that does not answer?); shutting down without it")
	}
}

// awaitServe is Serve's error (from serveErr). Once stopped is closed — the
// shutdown's stopGRPC has returned — it waits at most bound more: a Serve
// that has not returned by then waits on a stop stopGRPC gave up on, and is
// taken as stopped.
func awaitServe(serveErr <-chan error, stopped <-chan struct{}, bound time.Duration) error {
	select {
	case err := <-serveErr:
		return err
	case <-stopped:
	}
	select {
	case err := <-serveErr:
		return err
	case <-time.After(bound):
		slog.Warn("gRPC Serve did not return after the server was stopped; exiting without it")
		return grpc.ErrServerStopped
	}
}

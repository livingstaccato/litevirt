package daemon

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// stuckRPCServer serves a gRPC server every call of which blocks until the
// test ends, as a handler stuck in a stat on a hard NFS mount whose server
// does not answer does (lab 2 N-5: two starts of a VM on the dead pool). It
// returns the server, Serve's error channel, and a wait that returns once
// calls handlers are running, each on a connection of its own (each `lv
// start` is a process of its own).
func stuckRPCServer(t *testing.T, calls int) (*grpc.Server, <-chan error) {
	t.Helper()
	release := make(chan struct{})
	entered := make(chan struct{}, calls)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
		entered <- struct{}{}
		<-release // nothing in Go can interrupt a syscall stuck in the kernel
		return nil
	}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		close(release)
		wg.Wait()
	})
	for i := 0; i < calls; i++ {
		conn, err := grpc.NewClient("passthrough:///"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.Invoke(ctx, "/litevirt.v1.LiteVirt/StartVM", &emptypb.Empty{}, &emptypb.Empty{})
		}()
	}
	for i := 0; i < calls; i++ {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d calls reached their handler", i, calls)
		}
	}
	return srv, serveErr
}

// Lab 2 N-5: a graceful restart while two starts of a VM on a dead NFS pool
// were pending did not exit (2 of 2); with one pending it did. The cause is
// in how a stuck handler meets grpc-go's two stops. GracefulStop, once the
// connections are gone, waits for the handlers while holding the server's
// mutex; Stop, called after the graceful bound, needs that mutex to finish.
// Whichever of the two takes the mutex first when the forced close removes
// the last connection decides it: if GracefulStop does, Stop never returns,
// Serve never returns, and the daemon stays `deactivating` until the I/O
// returns — systemd's SIGKILL at TimeoutStopSec, and the peers' 2-minute
// `upgrading` grace, are all that is left.
//
// The daemon's shutdown therefore never waits on either stop past its own
// bound, nor on Serve once the stop is over. The race needs several tries to
// show, so the shutdown is run many times; each must finish within its
// bound.
//
// Mutations: "Stop called inline after the graceful bound" — the shutdown
// hangs: red. "Run waits on Serve unbounded" — red.
func TestShutdown_HandlersStuckOnStorageDoNotHoldTheDaemon(t *testing.T) {
	const graceful, forced, serveBound = 100 * time.Millisecond, 300 * time.Millisecond, 200 * time.Millisecond
	for _, calls := range []int{1, 2} {
		for i := 0; i < 15; i++ {
			srv, serveErr := stuckRPCServer(t, calls)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				stopped := make(chan struct{})
				go func() {
					stopGRPC(srv, graceful, forced)
					close(stopped)
				}()
				_ = awaitServe(serveErr, stopped, serveBound)
			}()
			select {
			case <-finished:
			case <-time.After(graceful + forced + serveBound + 3*time.Second):
				t.Errorf("%d stuck call(s), try %d: the shutdown did not finish within its bound", calls, i+1)
			}
		}
	}
}

// A shutdown with no RPC in flight stops gracefully, and Serve's own answer
// is what Run returns.
func TestShutdown_AnIdleServerStopsGracefully(t *testing.T) {
	srv, serveErr := stuckRPCServer(t, 0)
	stopped := make(chan struct{})
	t0 := time.Now()
	go func() {
		stopGRPC(srv, 5*time.Second, 5*time.Second)
		close(stopped)
	}()
	// Run takes ErrServerStopped (a stop before Serve began) as no error.
	if err := awaitServe(serveErr, stopped, time.Second); err != nil && err != grpc.ErrServerStopped {
		t.Fatalf("Serve after a graceful stop: %v", err)
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Fatalf("an idle server's stop took %v", took)
	}
}

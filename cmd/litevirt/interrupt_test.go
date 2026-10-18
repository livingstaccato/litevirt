package main

import (
	"bytes"
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// heldClient holds each delete or rebuild until its context ends, as a real
// RPC does when its caller cancels, and answers OK if it never does.
type heldClient struct {
	pb.LiteVirtClient
	started chan<- struct{}
}

func (c heldClient) hold(ctx context.Context) error {
	c.started <- struct{}{}
	select {
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-time.After(5 * time.Second):
		return nil
	}
}

func (c heldClient) DeleteVM(ctx context.Context, _ *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.hold(ctx)
}

func (c heldClient) DeleteContainer(ctx context.Context, _ *pb.DeleteContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.hold(ctx)
}

func (c heldClient) RebuildVM(ctx context.Context, req *pb.RebuildVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: req.Name}, c.hold(ctx)
}

// An interrupt while a delete or rebuild is in flight cancels the command's
// context: the RPC returns Canceled, the command says the operation may still
// complete and names the command that shows it, and the process exits with
// 128 + the signal. A second signal exits at once.
//
// Mutations: execute the root without the context (Execute()) — the RPC is
// never cancelled and the command reports success; drop the signal's exit
// code — exit 1; let a second signal do nothing — red.
func TestInterrupt_AnInFlightCommandReportsWhatMayStillCompleteAndExits(t *testing.T) {
	for _, c := range []struct {
		name  string
		args  []string
		sig   syscall.Signal
		want  string
		check string
	}{
		{"lv rm, SIGINT", []string{"rm", "vm1"}, syscall.SIGINT, "the delete may still complete", "`lv ls`"},
		{"lv rm, SIGTERM", []string{"rm", "vm1"}, syscall.SIGTERM, "the delete may still complete", "`lv ls`"},
		{"lv ct rm", []string{"ct", "rm", "ct1"}, syscall.SIGINT, "the delete may still complete", "`lv ct ls`"},
		{"lv rebuild", []string{"rebuild", "vm1"}, syscall.SIGINT, "the rebuild may still complete", "`lv ls`"},
	} {
		t.Run(c.name, func(t *testing.T) {
			started := make(chan struct{}, 1)
			orig := cli.Connect
			cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
				return heldClient{started: started}, func() {}, nil
			}
			t.Cleanup(func() { cli.Connect = orig })

			exited := make(chan int, 1)
			in := newInterrupts(context.Background(), func(code int) { exited <- code })
			go func() {
				<-started
				in.deliver(c.sig)
			}()
			var stderr bytes.Buffer
			code := runRoot(in.ctx, newRootCmd(), c.args, in.caught, &stderr)

			if want := 128 + int(c.sig); code != want {
				t.Errorf("exit code = %d, want %d; stderr:\n%s", code, want, stderr.String())
			}
			if out := stderr.String(); !strings.Contains(out, c.want) || !strings.Contains(out, c.check) ||
				!strings.Contains(out, "interrupted before the answer arrived") {
				t.Errorf("stderr = %q, want the interruption reported with %q and %s", out, c.want, c.check)
			}

			in.deliver(c.sig)
			select {
			case got := <-exited:
				if got != 128+int(c.sig) {
					t.Errorf("a second signal exited with %d, want %d", got, 128+int(c.sig))
				}
			case <-time.After(time.Second):
				t.Error("a second signal did not exit")
			}
		})
	}
}

// A real SIGINT reaches the command's context once the watch is installed.
func TestInterrupt_WatchCancelsTheContextOnSIGINT(t *testing.T) {
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("SIGINT is ignored in this process (started in the background); the watch leaves it so")
	}
	in := newInterrupts(context.Background(), func(int) { t.Error("a first signal exited") })
	stop := in.watch()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGINT did not cancel the command's context")
	}
	if in.caught() != syscall.SIGINT {
		t.Errorf("caught = %v, want SIGINT", in.caught())
	}
}

// The daemon shuts down on SIGINT/SIGTERM itself; every other command gets
// the interrupt handler.
func TestInterrupt_OnlyTheDaemonHandlesItsOwnSignals(t *testing.T) {
	root := newRootCmd()
	if !handlesOwnSignals(root, []string{"daemon"}) {
		t.Error("the daemon would get the CLI's interrupt handler")
	}
	for _, args := range [][]string{{"rm", "vm1"}, {"compose", "up", "-f", "x.yaml"}, {"rebuild", "vm1"}, {}} {
		if handlesOwnSignals(root, args) {
			t.Errorf("%v would run without the interrupt handler", args)
		}
	}
}

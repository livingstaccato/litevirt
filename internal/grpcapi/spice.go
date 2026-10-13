package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// spiceReporter is the backend's answer to whether SPICE can connect on this
// host at all (libvirt.Client.SpiceUnusable: a FIPS-mode kernel cannot).
type spiceReporter interface {
	SpiceUnusable() string
}

// spiceUnusable is why a SPICE client cannot connect to a console on this
// host, "" when nothing says so.
func (s *Server) spiceUnusable() string {
	if r, ok := s.virt.(spiceReporter); ok {
		return r.SpiceUnusable()
	}
	return ""
}

// GetSpiceInfo returns the SPICE port for a running VM that has SPICE
// graphics enabled, the host it runs on, and the console's password.
//
// The SPICE listener is bound to that host's 127.0.0.1 (xmlgen), so
// host:port is reachable only on the host itself or through a tunnel to it.
// A client anywhere else goes through ProxySpice (`lv spice --launch` /
// `--listen`), which carries each SPICE channel to the listener.
//
// ProxySpice relays SPICE unchanged (a SPICE password travels encrypted to a
// key the listener makes for each link, so a relay cannot present it the
// way ProxyVNC presents a VNC one), so the response carries the console's
// password (docs/ui.md "Console passwords") for the client to present — to
// a caller that passed vm.console, and never logged.
func (s *Server) GetSpiceInfo(ctx context.Context, req *pb.GetSpiceInfoRequest) (*pb.GetSpiceInfoResponse, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	// SPICE is interactive console/graphics access to the guest; require
	// vm.console on the VM's tenancy project, checked on the entry host where
	// the caller identity is present (before any forward to the owning host).
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return nil, err
	}
	if vm.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is not running (state: %s)", req.VmName, vm.State)
	}

	// If the VM lives on another host, forward to that host's daemon. We
	// already authenticated; the inter-daemon mTLS handles the hop.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.GetSpiceInfo(ctx, req)
	}

	port, err := s.virt.GetVMSpicePort(req.VmName)
	if err != nil || port < 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"SPICE not available for %q: %v", req.VmName, err)
	}

	// The console's password, if it has one (docs/ui.md "Console
	// passwords"). ProxySpice relays SPICE unchanged, so the client presents
	// it itself; this caller passed the vm.console check above on its entry host. Read
	// from the RUNNING domain, and never logged.
	// A password that cannot be read degrades rather than refuses: the info
	// goes back without it, and the client prompts.
	password, err := s.virt.ConsolePassword(req.VmName, "spice")
	if err != nil {
		slog.Warn("spice console password unreadable; returning the connection info without it", "vm", req.VmName, "error", err)
		password = ""
	}

	host, err := corrosion.GetHost(ctx, s.db, vm.HostName)
	if err != nil || host == nil {
		return nil, status.Errorf(codes.Internal, "lookup host %q: %v", vm.HostName, err)
	}

	// JoinHostPort (not corrosion.PeerTarget, whose port-0 default is a gRPC
	// concern) so the URI handed to a client stays parseable for an IPv6 host.
	// Host/Port are still returned unbracketed for callers that build their own.
	uri := fmt.Sprintf("spice://%s", net.JoinHostPort(host.Address, strconv.Itoa(port)))
	return &pb.GetSpiceInfoResponse{
		Host:     host.Address,
		Port:     int32(port),
		Uri:      uri,
		Password: password,
		Warning:  s.spiceUnusable(),
	}, nil
}

// ProxySpice carries one SPICE channel connection between the caller and the
// VM's SPICE listener on its host's 127.0.0.1. A SPICE client opens several
// channels (main, display, inputs, cursor, ...), each its own stream. The VM
// name is in the "x-vm-name" metadata. A VM on another host is forwarded to
// that host's daemon, as ProxyVNC is.
//
// The bytes go through unchanged: the client presents the console's password
// itself (GetSpiceInfo), so the listener's loopback bind AND the password
// both still stand. Each stream is authorized as its caller (vm.console on
// the VM) on the entry host, and is closed when the caller's credential is
// cut (registerStreamCloser), like a VNC console.
func (s *Server) ProxySpice(stream grpc.BidiStreamingServer[pb.SpiceData, pb.SpiceData]) error {
	if err := s.requirePermPrecheck(stream.Context(), "operator"); err != nil {
		return err
	}
	md, _ := metadataFromStream(stream)
	vmName := ""
	if vals := md.Get("x-vm-name"); len(vals) > 0 {
		vmName = vals[0]
	}
	if vmName == "" {
		return status.Error(codes.InvalidArgument, "x-vm-name metadata required")
	}
	ctx := stream.Context()

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	// Interactive access to the guest: vm.console on THIS VM, checked on the
	// entry host where the caller's identity is present.
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return err
	}
	// As ProxyVNC: a backup keeps the VM running, so its console stays open.
	if vm.State != "running" && vm.State != "backing-up" {
		return status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", vmName, vm.State)
	}

	if vm.HostName != s.hostName {
		return s.forwardSpice(stream, vmName, vm.HostName)
	}

	port, err := s.virt.GetVMSpicePort(vmName)
	if err != nil || port < 0 {
		return status.Errorf(codes.FailedPrecondition, "SPICE is not enabled for VM %q: %v", vmName, err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return status.Errorf(codes.Internal, "connect to SPICE port %d: %v", port, err)
	}
	defer conn.Close()
	// Released at the cut even if this handler is blocked elsewhere (m-2).
	registerStreamCloser(ctx, func() { _ = conn.Close() })

	who := consoleCallerAttrs(ctx)
	slog.Info("SPICE proxy session started", append([]any{"vm", vmName, "port", port}, who...)...)
	defer slog.Info("SPICE proxy session ended", append([]any{"vm", vmName}, who...)...)

	errCh := make(chan error, 2)
	// SPICE TCP → gRPC stream. The only goroutine that Sends; the handler
	// waits for it (bounded) before returning, so nothing writes to the
	// stream after the RPC is over.
	sendDone := make(chan struct{})
	defer func() {
		_ = conn.Close() // ends its Read
		waitRelaySender(sendDone)
	}()
	go func() {
		defer close(sendDone)
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&pb.SpiceData{Data: append([]byte(nil), buf[:n]...)}); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				errCh <- err
				return
			}
		}
	}()
	// gRPC stream → SPICE TCP.
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				errCh <- err
				return
			}
			if _, werr := conn.Write(msg.Data); werr != nil {
				errCh <- werr
				return
			}
		}
	}()

	select {
	case err = <-errCh:
	case <-ctx.Done():
		_ = conn.Close()
		return streamEndError(ctx)
	}
	if err != nil {
		return status.Errorf(codes.Internal, "SPICE proxy error: %v", err)
	}
	return nil
}

// forwardSpice relays a ProxySpice stream to the daemon that owns the VM.
func (s *Server) forwardSpice(incoming grpc.BidiStreamingServer[pb.SpiceData, pb.SpiceData], vmName, hostName string) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
	}
	defer conn.Close()
	defer logForwardedConsole(ctx, "SPICE", vmName, hostName)()
	// The remote leg lives inside this stream's context, so a cut (or this
	// handler's return) ends it, and the owner then closes its SPICE socket.
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	remote, err := client.ProxySpice(metadata.NewOutgoingContext(rctx, metadata.Pairs("x-vm-name", vmName)))
	if err != nil {
		return remoteStreamErr(hostName, err)
	}
	errCh := make(chan error, 2)
	// remote → incoming is the only goroutine that Sends to the caller; it is
	// waited for (bounded) once the remote leg is cancelled.
	sendDone := make(chan struct{})
	defer func() {
		cancel()
		waitRelaySender(sendDone)
	}()
	go func() {
		for {
			msg, err := incoming.Recv()
			if err != nil {
				if err == io.EOF {
					_ = remote.CloseSend()
					err = nil
				}
				errCh <- err
				return
			}
			if err := remote.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		defer close(sendDone)
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				errCh <- err
				return
			}
			if err := incoming.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()
	select {
	case err = <-errCh:
	case <-ctx.Done():
		return streamEndError(ctx)
	}
	return remoteStreamErr(hostName, err)
}

// relaySenderWait bounds how long a relay handler waits for its sending
// goroutine after ending its source: a caller that stopped reading can hold
// a Send in flow control, and the RPC must still end (the interceptor's
// streamCutGrace covers what is left).
const relaySenderWait = time.Second

func waitRelaySender(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(relaySenderWait):
	}
}

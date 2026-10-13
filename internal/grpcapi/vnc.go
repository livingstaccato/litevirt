package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/rfb"
)

// ProxyVNC provides a bidirectional byte stream to the VNC port of a running VM.
// The VM name is passed via incoming metadata key "x-vm-name".
// If the VM is on a remote host, this handler forwards to the remote daemon.
func (s *Server) ProxyVNC(stream grpc.BidiStreamingServer[pb.VNCData, pb.VNCData]) error {
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
	// Path-scoped check on the VM's tenancy project — a console is interactive
	// root access to the guest, so a broad operator role isn't enough; the
	// caller must hold vm.console on THIS VM. Enforced on the entry host where
	// the caller's identity is present (a forwarded peer call carries the
	// daemon's identity, not the user's).
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return err
	}
	// "backing-up" is an online state — the VM keeps running during a backup —
	// so VNC must stay reachable (and a stuck backing-up flag must not lock the
	// operator out).
	if vm.State != "running" && vm.State != "backing-up" {
		return status.Errorf(codes.FailedPrecondition, "VM %q is not running", vmName)
	}

	// Remote VM: forward to the host that owns it.
	if vm.HostName != s.hostName {
		return s.forwardVNC(stream, vmName, vm.HostName)
	}

	// Local VM: connect to the VNC port. A missing VNC graphics device means
	// the VM was created headless (DisableVnc) — report it as a clear
	// configuration condition rather than a vague "not available".
	port, err := s.virt.GetVMVNCPort(vmName)
	if err != nil || port < 0 {
		slog.Warn("vnc port unavailable", "vm", vmName, "error", err)
		return status.Errorf(codes.FailedPrecondition, "VNC is not enabled for VM %q", vmName)
	}

	// The console's password, if it has one (docs/ui.md "Console
	// passwords"). Read from the RUNNING domain, so it is the one the guest
	// started with, wherever it was defined or migrated from. Never logged.
	password, err := s.virt.ConsolePassword(vmName, "vnc")
	if err != nil {
		slog.Warn("vnc console password unreadable", "vm", vmName, "error", err)
		return status.Errorf(codes.Internal, "read the VNC console's password for VM %q: %v", vmName, err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return status.Errorf(codes.Internal, "connect to VNC port %d: %v", port, err)
	}
	defer conn.Close()
	// Released at the cut even if this handler is blocked elsewhere (m-2).
	registerStreamCloser(stream.Context(), func() { _ = conn.Close() })

	viewer := newVNCViewerStream(ctx, stream)
	if password != "" {
		// This host offers the viewer security type None and, once the viewer
		// has picked it, authenticates to the listener itself: the viewer,
		// and every daemon relaying to it, never sees the password, and an
		// older relay needs no change. The viewer side goes first and is
		// bounded, so a viewer that stalls never holds an authenticated
		// listener connection; a refused password reaches a 3.8 viewer as a
		// failed security result. It runs on this goroutine: nothing that
		// writes to the stream outlives the handler.
		var backendErr error
		viewer.setDeadline(time.Now().Add(vncHandshakeTimeout))
		err := rfb.ServeNoAuth(viewer, func() error {
			_ = conn.SetDeadline(time.Now().Add(vncAuthTimeout))
			backendErr = rfb.Authenticate(conn, password)
			_ = conn.SetDeadline(time.Time{})
			return backendErr
		})
		viewer.setDeadline(time.Time{})
		switch {
		case backendErr != nil:
			slog.Warn("vnc console authentication failed", "vm", vmName, "error", backendErr)
			return status.Errorf(codes.Internal, "authenticate to the VNC console of VM %q: %v", vmName, backendErr)
		case errors.Is(err, errVNCHandshakeTimeout):
			_ = conn.Close()
			return status.Errorf(codes.DeadlineExceeded, "the viewer did not complete the VNC handshake within %s", vncHandshakeTimeout)
		case err != nil && ctx.Err() != nil:
			_ = conn.Close()
			return streamEndError(ctx)
		case err != nil:
			return status.Errorf(codes.Aborted, "VNC handshake with the viewer: %v", err)
		}
	}

	slog.Info("VNC proxy session started", "vm", vmName, "port", port, "authenticated", password != "")

	errCh := make(chan error, 2)

	// VNC TCP → gRPC stream
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&pb.VNCData{Data: buf[:n]}); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
		}
	}()

	// gRPC stream → VNC TCP. Through the viewer reader, which hands over
	// first whatever the handshake read past its end.
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := viewer.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
		}
	}()

	// As ConsoleVM: a cut credential ends the stream's context, and the VNC
	// socket is closed here so neither direction outlives it.
	select {
	case err = <-errCh:
	case <-ctx.Done():
		_ = conn.Close()
		slog.Info("VNC proxy session ended: its stream was cut", "vm", vmName)
		return streamEndError(ctx)
	}
	slog.Info("VNC proxy session ended", "vm", vmName)
	if err != nil {
		return status.Errorf(codes.Internal, "VNC proxy error: %v", err)
	}
	return nil
}

// vncAuthTimeout bounds the handshake with a local VNC listener.
const vncAuthTimeout = 10 * time.Second

// vncHandshakeTimeout bounds the whole RFB security handshake with the
// viewer, the listener's included. A variable for the tests.
var vncHandshakeTimeout = 15 * time.Second

// logVNCPasswordStrip says, on the source, that a live migration moves the
// guest without its VNC console password because the target cannot do one
// (EnsureDisksResponse.vnc_password_unavailable; docs/ui.md "Console
// passwords"). The guest arrives with an open VNC console; SPICE keeps its
// password.
func logVNCPasswordStrip(vmName, target string, strip bool) {
	if !strip {
		return
	}
	slog.Warn("live migration moves the guest without its VNC console password: the target cannot do VNC passwords",
		"vm", vmName, "target", target, "strip_vnc_password", true)
}

// vmHasVNCPassword reports whether the running domain's VNC console has a
// password (read from the live secure definition; the value is not kept).
func (s *Server) vmHasVNCPassword(vmName string) bool {
	pw, err := s.virt.ConsolePassword(vmName, "vnc")
	return err == nil && pw != ""
}

// vncViewerStream is the viewer side of a ProxyVNC stream as a byte stream,
// for the RFB handshake this host runs with the viewer (rfb.ServeNoAuth) and
// the relay after it.
//
// One goroutine (pump) is the stream's only reader; Read takes from it, so a
// read can give up at a deadline without leaving a Recv behind that a later
// read would race. The pump ends when the stream does (its context is
// cancelled when the handler returns).
type vncViewerStream struct {
	stream   grpc.BidiStreamingServer[pb.VNCData, pb.VNCData]
	ctx      context.Context
	recv     chan vncRecv
	buf      []byte
	mu       sync.Mutex
	deadline time.Time
}

type vncRecv struct {
	data []byte
	err  error
}

// errVNCHandshakeTimeout is a viewer read that passed its deadline.
var errVNCHandshakeTimeout = errors.New("the viewer did not answer in time")

func newVNCViewerStream(ctx context.Context, stream grpc.BidiStreamingServer[pb.VNCData, pb.VNCData]) *vncViewerStream {
	v := &vncViewerStream{stream: stream, ctx: ctx, recv: make(chan vncRecv)}
	go v.pump()
	return v
}

func (v *vncViewerStream) pump() {
	for {
		msg, err := v.stream.Recv()
		r := vncRecv{err: err}
		if err == nil {
			r.data = msg.Data
		}
		select {
		case v.recv <- r:
		case <-v.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (v *vncViewerStream) setDeadline(t time.Time) {
	v.mu.Lock()
	v.deadline = t
	v.mu.Unlock()
}

func (v *vncViewerStream) Read(p []byte) (int, error) {
	for len(v.buf) == 0 {
		v.mu.Lock()
		deadline := v.deadline
		v.mu.Unlock()
		var expired <-chan time.Time
		if !deadline.IsZero() {
			t := time.NewTimer(time.Until(deadline))
			defer t.Stop()
			expired = t.C
		}
		select {
		case r := <-v.recv:
			if r.err != nil {
				return 0, r.err
			}
			v.buf = r.data
		case <-expired:
			return 0, errVNCHandshakeTimeout
		case <-v.ctx.Done():
			return 0, v.ctx.Err()
		}
	}
	n := copy(p, v.buf)
	v.buf = v.buf[n:]
	return n, nil
}

func (v *vncViewerStream) Write(p []byte) (int, error) {
	if err := v.stream.Send(&pb.VNCData{Data: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// forwardVNC relays a ProxyVNC stream to a remote daemon.
func (s *Server) forwardVNC(incoming grpc.BidiStreamingServer[pb.VNCData, pb.VNCData], vmName, hostName string) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
	}
	defer conn.Close()

	// Forward x-vm-name metadata to the remote daemon.
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vmName))
	remote, err := client.ProxyVNC(outCtx)
	if err != nil {
		return remoteStreamErr(hostName, err)
	}

	errCh := make(chan error, 2)

	// incoming → remote
	go func() {
		for {
			msg, err := incoming.Recv()
			if err != nil {
				if err == io.EOF {
					remote.CloseSend()
					errCh <- nil
				} else {
					errCh <- err
				}
				return
			}
			if err := remote.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// remote → incoming
	go func() {
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
			if err := incoming.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	return remoteStreamErr(hostName, err)
}

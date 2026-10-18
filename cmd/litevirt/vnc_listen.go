package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// printVNCInfo prints a VM's VNC address and, when its console has a
// password, how to reach it without one (docs/ui.md "Console passwords").
func printVNCInfo(w io.Writer, vmName string, vm *pb.VM) {
	fmt.Fprintf(w, "VNC: %s (bound to that host's 127.0.0.1)\n", vm.VncAddress)
	if vm.VncUnknown != "" {
		fmt.Fprintf(w, "Password: %s. `lv vnc %s --listen 127.0.0.1:5900` reaches the console either way.\n", vm.VncUnknown, vmName)
		return
	}
	if vm.VncPasswordRequired {
		fmt.Fprintf(w, "Password: required, and presented only by litevirt. Open the console in the web UI, or run\n"+
			"  lv vnc %s --listen 127.0.0.1:5900\n"+
			"and point a VNC viewer at 127.0.0.1:5900 (no password).\n", vmName)
	}
}

// listenConsoleLoopback opens addr for `lv vnc --listen` and `lv spice
// --launch/--listen`, which must be a loopback address: anyone who could
// reach the port would open the console with the caller's credentials.
func listenConsoleLoopback(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("--listen %q: %w", addr, err)
	}
	ok := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		ok = true
	}
	if !ok {
		return nil, fmt.Errorf("--listen %q: not a loopback address; the port carries the console with your credentials, so it must be 127.0.0.1 (or ::1, localhost)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("--listen %q: %w", addr, err)
	}
	return ln, nil
}

// serveVNCListener carries each connection on ln to the VM's console through
// ProxyVNC — the web UI's path, so the daemon on the VM's host presents the
// console password and the viewer needs none — until ctx ends.
func serveVNCListener(ctx context.Context, c pb.LiteVirtClient, vmName string, ln net.Listener) error {
	return serveConsoleListener(ctx, ln, func(ctx context.Context, conn net.Conn) error {
		return relayVNC(ctx, c, vmName, conn)
	}, func(err error) {
		slog.Warn("vnc console connection ended", "vm", vmName, "error", err)
	})
}

// relayVNC carries one viewer connection over a ProxyVNC stream.
func relayVNC(ctx context.Context, c pb.LiteVirtClient, vmName string, conn net.Conn) error {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := c.ProxyVNC(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vmName)))
	if err != nil {
		return err
	}
	return relayConsole(conn, st,
		func(b []byte) *pb.VNCData { return &pb.VNCData{Data: b} },
		(*pb.VNCData).GetData)
}

// serveConsoleListener accepts connections on ln and carries each with
// relay, until ctx ends; a relay's error goes to onErr.
func serveConsoleListener(ctx context.Context, ln net.Listener, relay func(context.Context, net.Conn) error, onErr func(error)) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := relay(ctx, conn); err != nil {
				onErr(err)
			}
		}()
	}
}

// relayConsole carries one local connection over a console stream of byte
// chunks (ProxyVNC, ProxySpice), both ways, until either side ends.
func relayConsole[T any](conn net.Conn, st grpc.BidiStreamingClient[T, T], wrap func([]byte) *T, data func(*T) []byte) error {
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := st.Send(wrap(append([]byte(nil), buf[:n]...))); serr != nil {
					errCh <- serr
					return
				}
			}
			if rerr != nil {
				_ = st.CloseSend()
				if errors.Is(rerr, io.EOF) {
					rerr = nil
				}
				errCh <- rerr
				return
			}
		}
	}()
	go func() {
		for {
			m, rerr := st.Recv()
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					rerr = nil
				}
				errCh <- rerr
				return
			}
			if _, werr := conn.Write(data(m)); werr != nil {
				errCh <- werr
				return
			}
		}
	}()
	return <-errCh
}

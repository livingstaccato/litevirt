package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newSpiceCmd prints SPICE connection info for a running VM, or carries its
// SPICE console to this machine.
//
// The VM's SPICE listener is bound to its host's 127.0.0.1, so a client
// cannot reach it at the host's address. --launch and --listen open a
// loopback port here whose connections litevirt carries to that listener
// (ProxySpice), the way `lv vnc --listen` carries VNC.
func newSpiceCmd() *cobra.Command {
	var launch, showPassword bool
	var listen string
	cmd := &cobra.Command{
		Use:         "spice <vm>",
		Annotations: map[string]string{ownSignalsAnnotation: "true"},
		Short:       "Print SPICE connection info for a running VM, or open its console here",
		Long: `Without --launch or --listen, prints where the VM's SPICE console is. The
listener is bound to the VM host's 127.0.0.1, so a client cannot connect to
it at the host's address.

--launch opens the console in remote-viewer (from the virt-viewer package)
on this machine: litevirt carries it from a local loopback port to the VM's
host (each connection authorized as you, with vm.console on the VM, and
ended when your session is), and hands remote-viewer the console's password
in a private connection file. The command runs until remote-viewer exits.

--listen opens that local port at an address you choose (a loopback one)
for a SPICE client you start yourself; it runs until Ctrl+C. The client
must present the console's password (docs/ui.md "Console passwords"):
--show-password prints it.

For example:

    lv spice desk --launch

    lv spice desk --listen 127.0.0.1:5930 --show-password
    remote-viewer spice://127.0.0.1:5930

On the VM's host itself, or through an SSH tunnel to it, a client can also
connect directly:

    ssh -o ExitOnForwardFailure=yes -L <port>:127.0.0.1:<port> <ssh-user>@<host>
    remote-viewer spice://127.0.0.1:<port>

VMs gain SPICE by setting graphics.spice: true in compose.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return withClient(ctx, func(ctx context.Context, c pb.LiteVirtClient) error {
				return runSpice(ctx, c, os.Stdout, args[0],
					spiceOpts{launch: launch, listen: listen, showPassword: showPassword}, remoteViewer)
			})
		},
	}
	cmd.Flags().BoolVar(&launch, "launch", false, "Open the console in remote-viewer (requires virt-viewer), carried through the daemon")
	cmd.Flags().StringVar(&listen, "listen", "", "Carry the console to this local loopback address (e.g. 127.0.0.1:5930) through the daemon, for a SPICE client you start")
	cmd.Flags().BoolVar(&showPassword, "show-password", false, "Print the console's password (for a SPICE client you start yourself)")
	return cmd
}

// printSpiceInfo prints where the console is and how to reach it, and the
// console's password only when asked: it is a credential, and terminals are
// logged and shared.
func printSpiceInfo(w io.Writer, vm string, resp *pb.GetSpiceInfoResponse, showPassword bool) {
	fmt.Fprintf(w, "VM:   %s\n", vm)
	fmt.Fprintf(w, "Host: %s\n", resp.Host)
	fmt.Fprintf(w, "Port: %d (bound to that host's 127.0.0.1)\n", resp.Port)
	// Not resp.Uri: that names the host's address, where SPICE never listens.
	fmt.Fprintf(w, "URI:  spice://127.0.0.1:%d (on that host, or through an SSH tunnel to it)\n", resp.Port)
	if resp.Warning != "" {
		fmt.Fprintf(w, "Warning: a SPICE client may not be able to connect: %s\n", resp.Warning)
	}
	switch {
	case resp.Password == "":
	case showPassword:
		fmt.Fprintf(w, "Password: %s\n", resp.Password)
	default:
		fmt.Fprintln(w, "Password: required (print it with --show-password, or use --launch)")
	}
	fmt.Fprintf(w, "Open it here with\n  lv spice %s --launch\nor carry it to a local port for a client you start:\n  lv spice %s --listen 127.0.0.1:5930\n", vm, vm)
}

// spiceOpts are lv spice's flags.
type spiceOpts struct {
	launch, showPassword bool
	listen               string
}

// viewerProc is a started SPICE viewer.
type viewerProc interface {
	Wait() error
	Kill() error
}

// spiceViewerLauncher finds and starts the SPICE viewer for --launch; the
// tests stand in a fake one.
type spiceViewerLauncher struct {
	find  func() (string, error)
	start func(path, vvPath string) (viewerProc, error)
}

// remoteViewer is virt-viewer's remote-viewer, given the connection file
// alone as its argv.
var remoteViewer = spiceViewerLauncher{
	find: func() (string, error) { return exec.LookPath("remote-viewer") },
	start: func(path, vvPath string) (viewerProc, error) {
		cmd := exec.Command(path, spiceLaunchArgs(vvPath)...)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return execViewer{cmd}, nil
	},
}

type execViewer struct{ cmd *exec.Cmd }

func (v execViewer) Wait() error { return v.cmd.Wait() }
func (v execViewer) Kill() error { return v.cmd.Process.Kill() }

// runSpice is lv spice: print the info, and with --launch or --listen carry
// the console from a local loopback port through ProxySpice.
func runSpice(ctx context.Context, c pb.LiteVirtClient, out io.Writer, vmName string, o spiceOpts, viewer spiceViewerLauncher) error {
	resp, err := c.GetSpiceInfo(ctx, &pb.GetSpiceInfoRequest{VmName: vmName})
	if err != nil {
		return fmt.Errorf("spice info: %w", err)
	}
	printSpiceInfo(out, vmName, resp, o.showPassword)
	if !o.launch && o.listen == "" {
		return nil
	}
	var rvPath string
	if o.launch {
		// Before opening anything, so a missing viewer costs nothing.
		if rvPath, err = viewer.find(); err != nil {
			return fmt.Errorf("remote-viewer not found in PATH; install virt-viewer, or use --listen with a SPICE client of your own")
		}
	}
	addr := o.listen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := listenConsoleLoopback(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if resp.Password == "" {
		fmt.Fprintf(out, "\nWarning: this console has no password, so anyone on this machine who connects to %s gets it with your credentials.\n", ln.Addr())
	}
	if !o.launch {
		fmt.Fprintf(out, "\nSPICE console of %s on spice://%s, carried through litevirt. Ctrl+C to stop.\n", vmName, ln.Addr())
		return serveSpiceListener(ctx, c, vmName, ln)
	}
	vv, err := writeSpiceRelayVV(os.TempDir(), vmName, resp, ln)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nLaunching %s on spice://%s, carried through litevirt; this runs until it exits.\n", rvPath, ln.Addr())
	rv, err := viewer.start(rvPath, vv)
	if err != nil {
		// remote-viewer never read it, so it never deleted it.
		_ = os.Remove(vv)
		return err
	}
	// Carry the console while remote-viewer runs: a SPICE client opens
	// channels throughout its session, not only at start.
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	waited := make(chan struct{})
	go func() {
		_ = rv.Wait()
		close(waited)
		cancel()
	}()
	serveErr := serveSpiceListener(serveCtx, c, vmName, ln)
	select {
	case <-waited:
	default:
		// Interrupted, or the local port failed: a viewer left running
		// would only retry a port nobody serves.
		_ = rv.Kill()
		<-waited
	}
	return serveErr
}

// writeSpiceRelayVV writes the connection file for --launch: remote-viewer
// connects to the local port ln, which litevirt carries to the VM's SPICE
// listener, never to the host's address (where SPICE does not listen).
func writeSpiceRelayVV(dir, vm string, resp *pb.GetSpiceInfoResponse, ln net.Listener) (string, error) {
	a, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("the local SPICE port is not TCP: %v", ln.Addr())
	}
	return writeSpiceVV(dir, vm, a.IP.String(), a.Port, resp.Password)
}

// serveSpiceListener carries each connection on ln — one per SPICE channel —
// to the VM's SPICE listener through ProxySpice, until ctx ends.
func serveSpiceListener(ctx context.Context, c pb.LiteVirtClient, vmName string, ln net.Listener) error {
	return serveConsoleListener(ctx, ln, func(ctx context.Context, conn net.Conn) error {
		return relaySpice(ctx, c, vmName, conn)
	}, func(err error) {
		if status.Code(err) == codes.Unimplemented {
			err = fmt.Errorf("a daemon on the way to the VM's host predates SPICE through litevirt (ProxySpice); upgrade it, or use an SSH tunnel to the host: %w", err)
		}
		slog.Warn("spice console connection ended", "vm", vmName, "error", err)
	})
}

// relaySpice carries one SPICE channel connection over a ProxySpice stream.
func relaySpice(ctx context.Context, c pb.LiteVirtClient, vmName string, conn net.Conn) error {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := c.ProxySpice(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vmName)))
	if err != nil {
		return err
	}
	return relayConsole(conn, st,
		func(b []byte) *pb.SpiceData { return &pb.SpiceData{Data: b} },
		(*pb.SpiceData).GetData)
}

// writeSpiceVV writes a virt-viewer connection file for the console into
// dir, readable by this user only, and returns its path. It carries the
// password so it never goes on remote-viewer's command line, where any local
// user could read it; delete-this-file has remote-viewer remove the file once
// it has read it.
func writeSpiceVV(dir, vm, host string, port int, password string) (string, error) {
	f, err := os.CreateTemp(dir, "lv-spice-*.vv")
	if err != nil {
		return "", fmt.Errorf("write the SPICE connection file: %w", err)
	}
	// CreateTemp opens 0600 already; say so, in case a umask or platform
	// differs.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write the SPICE connection file: %w", err)
	}
	body := fmt.Sprintf("[virt-viewer]\ntype=spice\nhost=%s\nport=%d\ntitle=%s\ndelete-this-file=1\nfullscreen=0\n",
		host, port, vm)
	if password != "" {
		body += "password=" + password + "\n"
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write the SPICE connection file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write the SPICE connection file: %w", err)
	}
	return filepath.Clean(f.Name()), nil
}

// spiceLaunchArgs is remote-viewer's argv: the connection file alone.
func spiceLaunchArgs(vvPath string) []string {
	return []string{vvPath}
}

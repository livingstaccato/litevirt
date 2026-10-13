package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
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
		Use:   "spice <vm>",
		Short: "Print SPICE connection info for a running VM, or open its console here",
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

    ssh -L <port>:127.0.0.1:<port> <ssh-user>@<host>
    remote-viewer spice://127.0.0.1:<port>

VMs gain SPICE by setting graphics.spice: true in compose.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return withClient(ctx, func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetSpiceInfo(ctx, &pb.GetSpiceInfoRequest{VmName: vmName})
				if err != nil {
					return fmt.Errorf("spice info: %w", err)
				}
				printSpiceInfo(os.Stdout, vmName, resp, showPassword)
				if !launch && listen == "" {
					return nil
				}
				var rvPath string
				if launch {
					// Before opening anything, so a missing viewer costs nothing.
					if rvPath, err = exec.LookPath("remote-viewer"); err != nil {
						return fmt.Errorf("remote-viewer not found in PATH; install virt-viewer, or use --listen with a SPICE client of your own")
					}
				}
				addr := listen
				if addr == "" {
					addr = "127.0.0.1:0"
				}
				ln, err := listenVNCLoopback(addr)
				if err != nil {
					return err
				}
				defer ln.Close()
				if !launch {
					fmt.Printf("\nSPICE console of %s on spice://%s, carried through litevirt. Ctrl+C to stop.\n", vmName, ln.Addr())
					return serveSpiceListener(ctx, c, vmName, ln)
				}
				vv, err := writeSpiceRelayVV(os.TempDir(), vmName, resp, ln)
				if err != nil {
					return err
				}
				fmt.Printf("\nLaunching %s on spice://%s, carried through litevirt; this runs until it exits.\n", rvPath, ln.Addr())
				rv := exec.Command(rvPath, spiceLaunchArgs(vv)...)
				if err := rv.Start(); err != nil {
					// remote-viewer never read it, so it never deleted it.
					_ = os.Remove(vv)
					return err
				}
				// Carry the console while remote-viewer runs: a SPICE client
				// opens channels throughout its session, not only at start.
				serveCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				waited := make(chan error, 1)
				go func() {
					waited <- rv.Wait()
					cancel()
				}()
				if err := serveSpiceListener(serveCtx, c, vmName, ln); err != nil {
					return err
				}
				if ctx.Err() != nil {
					_ = rv.Process.Kill()
				}
				<-waited
				return nil
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
			if err := relaySpice(ctx, c, vmName, conn); err != nil {
				if status.Code(err) == codes.Unimplemented {
					err = fmt.Errorf("a daemon on the way to the VM's host predates SPICE through litevirt (ProxySpice); upgrade it, or use an SSH tunnel to the host: %w", err)
				}
				slog.Warn("spice console connection ended", "vm", vmName, "error", err)
			}
		}()
	}
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
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := st.Send(&pb.SpiceData{Data: append([]byte(nil), buf[:n]...)}); serr != nil {
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
			if _, werr := conn.Write(m.Data); werr != nil {
				errCh <- werr
				return
			}
		}
	}()
	return <-errCh
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

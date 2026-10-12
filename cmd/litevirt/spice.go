package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newSpiceCmd prints SPICE connection info for a running VM.
//
// litevirt does not bundle a browser-based SPICE client (yet). Operators
// connect with `remote-viewer`, `virt-manager`, or any SPICE client.
//
// Default: print connection details. With --launch, attempt to spawn
// `remote-viewer` if it's installed.
func newSpiceCmd() *cobra.Command {
	var launch, showPassword bool
	cmd := &cobra.Command{
		Use:   "spice <vm>",
		Short: "Print SPICE connection info for a running VM",
		Long: `Returns the SPICE host and port for a running VM that has SPICE
graphics enabled. Connect with:

    remote-viewer "spice://<host>:<port>"

VMs gain SPICE by setting graphics.spice: true in compose.

The console requires a per-VM password once console passwords are in force
(docs/ui.md "Console passwords"). --launch hands it to remote-viewer in a
private connection file; --show-password prints it for a client you start
yourself.

Note: SPICE traffic is NOT proxied through the litevirt daemon today; the
client must be able to reach the host directly. Use SSH tunneling if your
host's SPICE port isn't externally reachable:

    ssh -L 5901:127.0.0.1:<port> <ssh-user>@<host>
    remote-viewer spice://127.0.0.1:5901
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(context.Background(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetSpiceInfo(ctx,
					&pb.GetSpiceInfoRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("spice info: %w", err)
				}
				printSpiceInfo(os.Stdout, args[0], resp, showPassword)
				if launch {
					path, err := exec.LookPath("remote-viewer")
					if err != nil {
						return fmt.Errorf("remote-viewer not found in PATH; install virt-viewer or omit --launch")
					}
					vv, err := writeSpiceVV(os.TempDir(), args[0], resp)
					if err != nil {
						return err
					}
					fmt.Printf("\nLaunching %s %s\n", path, resp.Uri)
					return exec.Command(path, spiceLaunchArgs(vv)...).Start()
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&launch, "launch", false, "Spawn remote-viewer (requires virt-viewer package)")
	cmd.Flags().BoolVar(&showPassword, "show-password", false, "Print the console's password (for a SPICE client you start yourself)")
	return cmd
}

// printSpiceInfo prints the connection details, and the console's password
// only when asked: it is a credential, and terminals are logged and shared.
func printSpiceInfo(w io.Writer, vm string, resp *pb.GetSpiceInfoResponse, showPassword bool) {
	fmt.Fprintf(w, "VM:   %s\n", vm)
	fmt.Fprintf(w, "Host: %s\n", resp.Host)
	fmt.Fprintf(w, "Port: %d\n", resp.Port)
	fmt.Fprintf(w, "URI:  %s\n", resp.Uri)
	switch {
	case resp.Password == "":
	case showPassword:
		fmt.Fprintf(w, "Password: %s\n", resp.Password)
	default:
		fmt.Fprintln(w, "Password: required (print it with --show-password, or use --launch)")
	}
}

// writeSpiceVV writes a virt-viewer connection file for the console into
// dir, readable by this user only, and returns its path. It carries the
// password so it never goes on remote-viewer's command line, where any local
// user could read it; delete-this-file has remote-viewer remove the file once
// it has read it.
func writeSpiceVV(dir, vm string, resp *pb.GetSpiceInfoResponse) (string, error) {
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
		resp.Host, resp.Port, vm)
	if resp.Password != "" {
		body += "password=" + resp.Password + "\n"
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

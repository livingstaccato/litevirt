package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// trustValues is a pool row as shown to, and confirmed by, the operator.
type trustValues struct {
	Name, Host, Driver, Source, Target, MountOptions string
}

// poolTrustExpect is what a non-interactive `lv pool trust` confirms: the
// values the operator checked, given on the command line.
type poolTrustExpect struct {
	driver, source, target, mountOptions string
	mountOptionsSet                      bool
}

func newPoolTrustCmd() *cobra.Command {
	var host string
	var exp poolTrustExpect
	cmd := &cobra.Command{
		Use:   "trust <name>",
		Short: "Confirm that a pool row naming a host is that host's pool",
		Long: `A host acts on a storage pool row naming it only when it created the
pool itself, its config.yaml defines it, or the pool's directory is in its own
pool areas (<data_dir>/disks, pools/, mounts/). Any other row is held untrusted
and named by the pool_row_untrusted condition: nothing is written, mounted or
listed there.

trust asks the pool's host for its row and prints it: driver, source, target
and (nfs) normalized mount options, and why the host does not trust it. What
you confirm is what is sent, never a fresh read of the row: the host records
those values in its local trust ledger only when its row is exactly them, and
refuses otherwise. Check the target first: once trusted, the daemon writes
there as root.

On a terminal it asks y/N. Otherwise it needs the values you checked:
--expect-driver and --expect-target, --expect-source when the row has a
source, and --expect-mount-options when it has mount options. Any difference
from the row is refused.

It needs storage.hostpath at the cluster root, as naming the path in a create
does, and is audited as storage.pool.trust, refusals included.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exp.mountOptionsSet = cmd.Flags().Changed("expect-mount-options")
			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return runPoolTrust(ctx, c, args[0], host, exp, interactive, os.Stdin, os.Stdout)
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the pool's host (default: caller's local host)")
	cmd.Flags().StringVar(&exp.driver, "expect-driver", "", "without a terminal: the driver you checked")
	cmd.Flags().StringVar(&exp.target, "expect-target", "", "without a terminal: the target directory you checked")
	cmd.Flags().StringVar(&exp.source, "expect-source", "", "without a terminal: the source you checked (required when the row has one)")
	cmd.Flags().StringVar(&exp.mountOptions, "expect-mount-options", "", "without a terminal: the nfs mount options you checked (required when the row has some)")
	return cmd
}

// runPoolTrust is `lv pool trust`: preview the host's row, have the operator
// confirm it (a y/N on a terminal, the --expect-* values otherwise), and send
// exactly the confirmed values.
//
// The row is what a forger may have written, so nothing from it, nor from the
// host's answers, reaches the terminal unescaped (termSafe): a control or
// format character could redraw or hide what the operator is confirming. A
// row holding one is not confirmed interactively at all — what the operator
// sees would not be exactly the row — only with --expect-*, which compares
// exact strings.
func runPoolTrust(ctx context.Context, c pb.LiteVirtClient, name, host string, exp poolTrustExpect, interactive bool, in io.Reader, out io.Writer) error {
	prev, err := c.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: name, Host: host, Preview: true})
	if err != nil {
		return fmt.Errorf("read the pool's row on its host: %s", termSafe(err.Error()))
	}
	p := prev.GetPool()
	shown := trustValues{
		Name: p.GetName(), Host: p.GetHost(),
		Driver: p.GetDriver(), Source: p.GetSource(), Target: p.GetTarget(), MountOptions: prev.GetMountOptions(),
	}
	fmt.Fprintf(out, "pool %s on %s:\n  driver:        %s\n  source:        %s\n  target:        %s\n  mount options: %s\n",
		termSafe(shown.Name), termSafe(shown.Host), termSafe(shown.Driver), termSafe(orNone(shown.Source)),
		termSafe(orNone(shown.Target)), termSafe(orNone(shown.MountOptions)))
	if prev.GetAlreadyTrusted() {
		fmt.Fprintf(out, "already trusted by %s (%s); nothing to confirm\n", termSafe(shown.Host), termSafe(prev.GetTrustedAs()))
		return nil
	}
	fmt.Fprintf(out, "not trusted by %s: %s\n", termSafe(shown.Host), termSafe(prev.GetWhy()))

	var confirmed trustValues
	switch {
	case exp.driver != "" || exp.target != "" || exp.source != "" || exp.mountOptionsSet:
		confirmed, err = expectedBinding(shown, exp)
		if err != nil {
			return err
		}
	case interactive:
		if f := shown.unprintable(); f != "" {
			return fmt.Errorf("the row's %s holds a control or format character (shown escaped above), so what a terminal shows is not exactly the row; "+
				"it is not confirmed interactively — check it and pass the exact values with --expect-driver, --expect-target, --expect-source and --expect-mount-options", f)
		}
		fmt.Fprintf(out, "Once trusted, the daemon on %s writes in %s as root. Trust this row? [y/N] ", termSafe(shown.Host), termSafe(orNone(shown.Target)))
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("not confirmed; nothing was recorded")
		}
		confirmed = shown
	default:
		return errors.New("not a terminal: pass the values you checked — --expect-driver and --expect-target, plus --expect-source and --expect-mount-options when the row has them")
	}
	resp, err := c.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{
		Name: confirmed.Name, Host: confirmed.Host,
		Driver: confirmed.Driver, Source: confirmed.Source, Target: confirmed.Target, MountOptions: confirmed.MountOptions,
	})
	if err != nil {
		return fmt.Errorf("trust pool: %s", termSafe(err.Error()))
	}
	fmt.Fprintf(out, "pool %s on %s is now trusted (%s)\n", termSafe(confirmed.Name), termSafe(confirmed.Host), termSafe(resp.GetTrustedAs()))
	return nil
}

// unprintable names the first field of v holding a control or format
// character, "" when none does.
func (v trustValues) unprintable() string {
	unsafe := func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }
	for _, f := range []struct{ name, val string }{
		{"name", v.Name}, {"host", v.Host}, {"driver", v.Driver}, {"source", v.Source},
		{"target", v.Target}, {"mount options", v.MountOptions},
	} {
		if strings.ContainsFunc(f.val, unsafe) {
			return f.name
		}
	}
	return ""
}

// expectedBinding is the confirmation from --expect-*: every value the row
// has must be given, and equal to it. The values sent are the given ones.
func expectedBinding(shown trustValues, exp poolTrustExpect) (trustValues, error) {
	var missing []string
	if exp.driver == "" {
		missing = append(missing, "--expect-driver")
	}
	if exp.target == "" && shown.Target != "" {
		missing = append(missing, "--expect-target")
	}
	if exp.source == "" && shown.Source != "" {
		missing = append(missing, "--expect-source")
	}
	if !exp.mountOptionsSet && shown.MountOptions != "" {
		missing = append(missing, "--expect-mount-options")
	}
	if len(missing) > 0 {
		return trustValues{}, fmt.Errorf("the row has values you did not confirm: pass %s", strings.Join(missing, ", "))
	}
	got := trustValues{Name: shown.Name, Host: shown.Host, Driver: exp.driver, Source: exp.source, Target: cleanOrEmpty(exp.target),
		MountOptions: pooltrust.NormalizeMountOptions(exp.mountOptions)}
	var diff []string
	if !strings.EqualFold(got.Driver, shown.Driver) {
		diff = append(diff, fmt.Sprintf("driver %q, not %q", shown.Driver, got.Driver))
	}
	if got.Source != shown.Source {
		diff = append(diff, fmt.Sprintf("source %q, not %q", shown.Source, got.Source))
	}
	if cleanOrEmpty(got.Target) != cleanOrEmpty(shown.Target) {
		diff = append(diff, fmt.Sprintf("target %q, not %q", shown.Target, got.Target))
	}
	if got.MountOptions != shown.MountOptions {
		diff = append(diff, fmt.Sprintf("mount options %q, not %q", shown.MountOptions, got.MountOptions))
	}
	if len(diff) > 0 {
		return trustValues{}, fmt.Errorf("the row on %s is not what you checked: %s; nothing was recorded", shown.Host, strings.Join(diff, "; "))
	}
	return got, nil
}

func cleanOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

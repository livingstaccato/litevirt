package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Firewall logging (docs/firewall.md, "Logging"): `--log` on the rule-add
// commands, and `lv firewall log-policy`.

// logFlagUsage is the --log flag's help on every rule-add command.
const logFlagUsage = "log each packet the rule matches (docs/firewall.md, Logging)"

// refuseClientLogAction refuses an --action holding "+": logging is asked
// with --log, never in the action.
func refuseClientLogAction(action string) error {
	if strings.Contains(action, "+") {
		return fmt.Errorf("--action %q: an action is accept, drop or reject; use --log to log the rule", action)
	}
	return nil
}

// requireLogSupport asks the connected daemon for its log policy
// before a logged rule is sent: a daemon that predates logging answers
// Unimplemented and would drop the log field, storing the rule unlogged. A
// daemon that answers refuses the write itself until the cluster upgrade has
// finished.
func requireLogSupport(ctx context.Context, c pb.LiteVirtClient, log bool) error {
	if !log {
		return nil
	}
	_, err := c.GetFirewallLogPolicy(ctx, &pb.GetFirewallLogPolicyRequest{})
	switch status.Code(err) {
	case codes.OK, codes.PermissionDenied, codes.Unauthenticated:
		return nil
	case codes.Unimplemented:
		return fmt.Errorf("--log: the daemon you are connected to is older than this lv: upgrade it, or use a host that runs litevirt %s", version)
	}
	return fmt.Errorf("--log: could not confirm the daemon supports firewall logging: %w; retry", err)
}

// ruleAction is a rule's action as the rule listings show it: the plain verdict, and "log"
// for a logged rule.
func ruleAction(action string, log bool) string {
	if log {
		return action + " log"
	}
	return action
}

func newFirewallLogPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log-policy",
		Short: "Show or set the firewall log policy (log the default verdict; the per-NIC log budget)",
	}
	show := &cobra.Command{
		Use:   "status",
		Short: "Show the log policy of the cluster and of every host",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetFirewallLogPolicy(ctx, &pb.GetFirewallLogPolicyRequest{})
				if err != nil {
					return logRPCError(err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "SCOPE\tDEFAULT\tRATE\tBURST\tFROM\tSET BY")
				for i, p := range resp.GetPolicies() {
					def := "off"
					if p.GetDefaultPolicy() {
						def = "on"
					}
					from := "own"
					switch {
					case p.GetInherited():
						from = "inherited"
					case i == 0:
						from = "cluster"
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", p.GetScope(), def, p.GetRate(), p.GetBurst(), from, p.GetSetBy())
				}
				return w.Flush()
			})
		},
	}
	set := func(mode, short string) *cobra.Command {
		var scope string
		var rate, burst uint32
		c := &cobra.Command{
			Use:   mode,
			Short: short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				if mode == "inherit" && scope == "" {
					return fmt.Errorf("inherit needs --scope <host>: the cluster policy is on or off")
				}
				return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
					p, err := c.SetFirewallLogPolicy(ctx, &pb.SetFirewallLogPolicyRequest{Scope: scope, Mode: mode, Rate: rate, Burst: burst})
					if err != nil {
						return logRPCError(err)
					}
					sc := scope
					if sc == "" {
						sc = "cluster"
					}
					if mode == "inherit" {
						fmt.Printf("log policy for %s: inherits the cluster's\n", sc)
						return nil
					}
					fmt.Printf("log policy for %s: default verdict %s, budget %d/s burst %d per NIC side\n", sc, mode, p.GetRate(), p.GetBurst())
					return nil
				})
			},
		}
		c.Flags().StringVar(&scope, "scope", "", "host to scope the policy to (default: cluster-wide)")
		if mode != "inherit" {
			c.Flags().Uint32Var(&rate, "rate", 0, "log records per second per NIC side, 1-10000 (default 5)")
			c.Flags().Uint32Var(&burst, "burst", 0, "log burst per NIC side, packets, 1-10000 (default 10)")
		}
		return c
	}
	cmd.AddCommand(show,
		set("on", "Log each guest NIC's default verdict, and set the per-NIC log budget"),
		set("off", "Stop logging the default verdict (logged rules still log), and set the per-NIC log budget"),
		set("inherit", "Clear a host's own log policy, so the cluster's applies"))
	return cmd
}

// logRPCError explains an Unimplemented reply: the daemon predates logging.
func logRPCError(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("the daemon you are connected to is older than this lv: upgrade it, or use a host that runs litevirt %s", version)
	}
	return err
}

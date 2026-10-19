package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// synfloodUpgradeText is the refusal against a daemon that predates SYN-flood
// protection.
const synfloodUpgradeText = "the daemon does not support SYN-flood protection (it predates it); upgrade litevirtd on the host you are connected to and retry"

// synfloodRPCError explains an Unimplemented reply: the daemon predates
// SYN-flood protection.
func synfloodRPCError(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("%s: %w", synfloodUpgradeText, err)
	}
	return err
}

// newFirewallSynfloodCmd manages SYN-flood protection on guest NICs
// (docs/firewall.md, "SYN-flood protection").
func newFirewallSynfloodCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "synflood",
		Short: "Limit new TCP connections toward guest NICs per source (SYN-flood protection)",
	}
	var scope string
	var rate, burst uint32
	set := func(mode string) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			if mode == "inherit" && scope == "" {
				return fmt.Errorf("inherit clears a host's own policy: --scope <host> is required")
			}
			req := &pb.SetFirewallSynfloodRequest{Scope: scope, Mode: mode}
			if mode == "on" {
				// 0 on the wire means the default; on the command line
				// it is out of range, not a quiet 200 or 1000.
				for _, f := range []struct {
					name string
					v    uint32
				}{{"rate", rate}, {"burst", burst}} {
					if f.v < 1 || f.v > 100000 {
						return fmt.Errorf("--%s %d: want 1-100000", f.name, f.v)
					}
				}
				req.Rate, req.Burst = rate, burst
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				p, err := c.SetFirewallSynflood(ctx, req)
				if err != nil {
					return synfloodRPCError(err)
				}
				fmt.Printf("SYN-flood protection for %s: %s\n", synfloodScopeText(scope), synfloodPolicyText(p))
				return nil
			})
		}
	}
	on := &cobra.Command{
		Use:   "on",
		Short: "Turn SYN-flood protection on, for the cluster or one host (--scope)",
		Long: `Limits new TCP connections (SYNs) toward each guest NIC to --rate per second
from each source address, after a burst of --burst. A SYN past the limit is
dropped (counted, not dropped, while per-NIC enforcement observes). A host's own
policy (--scope <host>) wins over the cluster's. Needs the operator role; audited;
refused until the cluster upgrade has finished.`,
		Args: cobra.NoArgs,
		RunE: set("on"),
	}
	on.Flags().Uint32Var(&rate, "rate", 200, "new SYNs per second per guest NIC and source address (1-100000)")
	on.Flags().Uint32Var(&burst, "burst", 1000, "SYNs let through above the rate before it applies (1-100000)")
	off := &cobra.Command{
		Use:   "off",
		Short: "Turn SYN-flood protection off, for the cluster or one host (--scope)",
		Args:  cobra.NoArgs,
		RunE:  set("off"),
	}
	inherit := &cobra.Command{
		Use:   "inherit",
		Short: "Clear a host's own SYN-flood policy, so the cluster's applies (--scope <host>)",
		Args:  cobra.NoArgs,
		RunE:  set("inherit"),
	}
	for _, c := range []*cobra.Command{on, off, inherit} {
		c.Flags().StringVar(&scope, "scope", "", "host to scope the policy to (default: cluster-wide)")
	}
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show the cluster's SYN-flood policy and each host's",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// The daemon asks every host under its own deadline; this
				// bounds the whole call should it not.
				ctx, cancel := context.WithTimeout(ctx, synfloodStatusTimeout)
				defer cancel()
				r, err := c.GetFirewallSynflood(ctx, &pb.GetFirewallSynfloodRequest{})
				if err != nil {
					return synfloodRPCError(err)
				}
				return printSynflood(os.Stdout, r)
			})
		},
	}
	cmd.AddCommand(statusCmd, on, off, inherit)
	return cmd
}

// synfloodStatusTimeout bounds `lv firewall synflood status`.
const synfloodStatusTimeout = 30 * time.Second

func synfloodScopeText(scope string) string {
	if scope == "" {
		return "the cluster"
	}
	return "host " + scope
}

func synfloodPolicyText(p *pb.FirewallSynfloodPolicy) string {
	if p.GetMode() != "on" {
		return p.GetMode()
	}
	return fmt.Sprintf("on, %d/second burst %d", p.GetRate(), p.GetBurst())
}

// synfloodDropsText is a host's drops per family: "-" where they could not
// be read (its error says why) or where that family is not limited at all
// (in force ipv4-only or ipv6-only), never a 0.
func synfloodDropsText(p *pb.FirewallSynfloodPolicy) (v4, v6 string) {
	if p.GetError() != "" {
		return "-", "-"
	}
	v4, v6 = fmt.Sprint(p.GetDropsV4()), fmt.Sprint(p.GetDropsV6())
	switch p.GetInForce() {
	case "ipv4-only":
		v6 = "-"
	case "ipv6-only":
		v4 = "-"
	}
	return v4, v6
}

// synfloodInForceText is what a host has in force, as the host reported it:
// "-" when it could not be asked (its error says why), "predates" when its
// daemon is older than the report.
func synfloodInForceText(p *pb.FirewallSynfloodPolicy) string {
	switch {
	case p.GetInForce() != "":
		return p.GetInForce()
	case p.GetError() != "":
		return "-"
	}
	return "predates"
}

// printSynflood prints the cluster's policy (the reply's first entry) and
// each host's: its policy, what the host itself has in force (on,
// ipv4-only, ipv6-only, observe, guards-only, no-guest-nics, unavailable or
// off; synfloodInForceText) and its SYN-flood drops per family since its last
// reload (synfloodDropsText).
func printSynflood(out io.Writer, r *pb.GetFirewallSynfloodResponse) error {
	ps := r.GetPolicies()
	if len(ps) == 0 {
		return fmt.Errorf("the daemon returned no SYN-flood policy")
	}
	cl := ps[0]
	fmt.Fprintf(out, "cluster: %s", synfloodPolicyText(cl))
	if cl.GetSetBy() != "" {
		fmt.Fprintf(out, " (set by %s at %s)", cl.GetSetBy(), cl.GetUpdatedAt())
	}
	fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tPOLICY\tIN FORCE\tRATE\tBURST\tFROM\tDROPS V4\tDROPS V6\tSET BY\tERROR")
	for _, p := range ps[1:] {
		from := "host"
		if p.GetInherited() {
			from = "cluster"
		}
		rate, burst := "-", "-"
		if p.GetMode() == "on" {
			rate, burst = fmt.Sprint(p.GetRate()), fmt.Sprint(p.GetBurst())
		}
		setBy := strings.TrimSpace(p.GetSetBy() + " " + p.GetUpdatedAt())
		if setBy == "" {
			setBy = "-"
		}
		host := strings.TrimPrefix(p.GetScope(), "host/")
		inForce := synfloodInForceText(p)
		// A count that could not be read is "-", with why, never a 0.
		d4, d6 := synfloodDropsText(p)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", host, p.GetMode(), inForce, rate, burst, from, d4, d6, setBy, p.GetError())
	}
	return w.Flush()
}

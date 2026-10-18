package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// Firewall logging (docs/firewall.md, "Logging"): `--log` on the rule-add
// commands, and `lv firewall log-policy`.

// logFlagUsage is the --log flag's help on every rule-add command.
const logFlagUsage = "log each packet the rule matches (read with 'lv firewall log')"

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
					if p.GetRate() == 0 && p.GetBurst() == 0 {
						// The daemon could not read the row (no readable
						// row has rate or burst 0): the host's own, or the
						// cluster's it inherits.
						def = "unreadable (read as off at 5/10)"
						if p.GetInherited() {
							def = "unreadable (inherited; read as off at 5/10)"
						}
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
		c.Flags().StringVar(&scope, "scope", "", "host to scope the policy to; leave it out for the cluster-wide policy")
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

// logFollowInterval is how often --follow asks for new records.
var logFollowInterval = 2 * time.Second

func newFirewallLogCmd() *cobra.Command {
	var host, workload, since string
	var limit uint32
	var follow bool
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show the firewall log: packets matched by logged rules and logged default verdicts (needs firewall.log.view)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ListFirewallLogRequest{Host: host, Workload: workload, Limit: limit}
			if since != "" {
				d, err := time.ParseDuration(since)
				if err != nil || d <= 0 {
					return fmt.Errorf("--since %q: want a duration such as 15m or 2h", since)
				}
				req.Since = time.Now().Add(-d).UTC().Format(time.RFC3339)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "TIME\tHOST\tWORKLOAD\tDEVICE\tSIDE\tRULE\tVERDICT\tPROTO\tSRC\tDST\tLEN")
				cursor := map[string]uint64{}
				reported := map[string]string{}
				for {
					resp, err := c.ListFirewallLog(ctx, &pb.ListFirewallLogRequest{Host: req.Host, Workload: req.Workload,
						Since: req.Since, Limit: req.Limit, AfterSeq: maps.Clone(req.AfterSeq)})
					if err != nil {
						if follow && ctx.Err() != nil {
							return w.Flush()
						}
						return logRPCError(err)
					}
					for _, e := range resp.GetEntries() {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", termSafe(e.GetTime()), termSafe(e.GetHost()),
							termSafe(dash(e.GetWorkload())), termSafe(e.GetDevice()), termSafe(e.GetSide()), termSafe(e.GetRuleId()),
							termSafe(e.GetVerdict()), termSafe(dash(e.GetProto())),
							termSafe(hostPort(e.GetSrc(), e.GetSport())), termSafe(hostPort(e.GetDst(), e.GetDport())), e.GetLength())
						if e.GetSeq() > cursor[e.GetHost()] {
							cursor[e.GetHost()] = e.GetSeq()
						}
					}
					if err := w.Flush(); err != nil {
						return err
					}
					for _, h := range slices.Sorted(maps.Keys(resp.GetErrors())) {
						if msg := resp.GetErrors()[h]; reported[h] != msg {
							fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s\n", termSafe(h), termSafe(msg))
							reported[h] = msg
						}
					}
					if !follow {
						return nil
					}
					req.AfterSeq = cursor
					req.Limit = 10000
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(logFollowInterval):
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "one host's log (default: every active host)")
	cmd.Flags().StringVar(&workload, "workload", "", "one workload's records")
	cmd.Flags().StringVar(&since, "since", "", "only records newer than this, e.g. 15m")
	cmd.Flags().Uint32Var(&limit, "limit", 200, "the newest N records (at most 10000)")
	cmd.Flags().BoolVar(&follow, "follow", false, "keep printing new records")
	return cmd
}

// termSafe escapes control characters and format characters (bidi
// overrides and isolates, zero-width marks): a peer's answer is printed as
// is otherwise, and could drive the terminal or reorder what it shows.
func termSafe(s string) string {
	unsafe := func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }
	if !strings.ContainsFunc(s, unsafe) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafe(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

// hostPort is an address with its port, when it has one.
func hostPort(addr string, port uint32) string {
	if addr == "" {
		return "-"
	}
	if port == 0 {
		return addr
	}
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:" + strconv.Itoa(int(port))
	}
	return addr + ":" + strconv.Itoa(int(port))
}

// composeLogs reports whether a compose file holds a rule with `log: true`.
func composeLogs(f *compose.File) bool {
	for _, sg := range f.SecurityGroups {
		for _, r := range sg.Rules {
			if r.Log {
				return true
			}
		}
	}
	if fd := f.FirewallDefaults; fd != nil {
		for _, r := range fd.ClusterRules {
			if r.Log {
				return true
			}
		}
	}
	return false
}

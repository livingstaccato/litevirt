package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// newFirewallTagGroupCmd manages tag groups: named selectors over firewall
// tags, referenced from a rule as --cidr tag:<group> and binding security
// groups to their members' NICs (docs/firewall.md, "Tag groups").
func newFirewallTagGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag-group",
		Short: "Manage tag groups: selectors over firewall tags (needs sg.write to change)",
	}

	var match, networks, sgs []string
	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Create or replace a tag group",
		Long: `Creates a tag group, or replaces its definition. --match k=v matches a
workload whose firewall tags hold k with the value v, --match k one that holds
k at all; several are ANDed. --sg binds the security groups to every NIC of
every member, on the --network networks only when given. The name is
[a-z][a-z0-9_]{0,30} and must not end in _v6; its nft set is lv_tg_<name>.
Needs sg.write at the cluster root, and is refused until the cluster upgrade
has finished.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(match) == 0 {
				return fmt.Errorf("--match is required")
			}
			sel := map[string]string{}
			for _, m := range match {
				k, v, hasValue := strings.Cut(m, "=")
				if k == "" || (hasValue && v == "") {
					// An empty value would mean "has the key", wider than
					// the k=v the operator wrote (an unset $VAR).
					return fmt.Errorf("--match %q: want key=value, or key alone for \"has the key\"", m)
				}
				if _, dup := sel[k]; dup {
					return fmt.Errorf("--match %q: key %q is matched twice; a tag holds one value", m, k)
				}
				sel[k] = v
			}
			g := &pb.FirewallTagGroup{Name: args[0], Match: sel, Networks: networks, SecurityGroups: sgs}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				out, err := c.SetFirewallTagGroup(ctx, &pb.SetFirewallTagGroupRequest{Group: g})
				if err != nil {
					return tagGroupRPCError(err)
				}
				fmt.Printf("Set tag group %s: %s\n", out.GetName(), tagGroupSummary(out))
				return nil
			})
		},
	}
	set.Flags().StringArrayVar(&match, "match", nil, "k=v or k: a firewall tag a member holds (repeatable; ANDed)")
	set.Flags().StringArrayVar(&networks, "network", nil, "limit the security-group binding to this network (repeatable; default: every network)")
	set.Flags().StringArrayVar(&sgs, "sg", nil, "bind this security group to every member's NICs (repeatable)")

	var members bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List tag groups, with --members each member and its addresses",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListFirewallTagGroups(ctx, &pb.ListFirewallTagGroupsRequest{Members: members})
				if err != nil {
					return tagGroupRPCError(err)
				}
				return printTagGroups(os.Stdout, resp.GetGroups(), members)
			})
		},
	}
	ls.Flags().BoolVar(&members, "members", false, "list each group's members and their allocated addresses")

	var force bool
	rm := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a tag group",
		Long: `Removes a tag group. It is refused while a rule references tag:<name>, or
while the group binds security groups to its members' NICs; --force overrides
both for accept rules and the binding. A drop or reject rule referencing the
group always refuses it: delete that rule first.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteFirewallTagGroup(ctx, &pb.DeleteFirewallTagGroupRequest{Name: args[0], Force: force}); err != nil {
					return tagGroupRPCError(err)
				}
				fmt.Printf("Removed tag group %s\n", args[0])
				return nil
			})
		},
	}
	rm.Flags().BoolVar(&force, "force", false, "remove even while accept rules reference the group or its binding is in use")

	cmd.AddCommand(set, ls, rm)
	return cmd
}

// tagGroupUpgradeText is the refusal against a daemon that predates tag
// groups.
const tagGroupUpgradeText = "the daemon does not support tag groups (it predates them); upgrade litevirtd on the host you are connected to and retry"

// tagGroupRPCError explains an Unimplemented reply: the daemon predates tag
// groups.
func tagGroupRPCError(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("%s: %w", tagGroupUpgradeText, err)
	}
	return err
}

// isTagCIDR reports whether a cidr is a tag-group reference in any case or
// padding.
func isTagCIDR(cidr string) bool {
	v := strings.TrimSpace(cidr)
	return len(v) >= 4 && strings.EqualFold(v[:4], "tag:")
}

// requireTagGroupSupport asks the daemon, before a write holding a tag:
// cidr, whether it knows tag groups at all: an older one would store the
// cidr unvalidated (spec §4.8, I-1). The write goes ahead only on an answer
// that proves the daemon has the method: success, or a refusal of the
// caller (PermissionDenied, Unauthenticated), which only a daemon that has
// it returns. Unimplemented refuses with the upgrade text; any other error
// proves nothing about the daemon, so it refuses too, fail closed.
func requireTagGroupSupport(ctx context.Context, c pb.LiteVirtClient, cidrs ...string) error {
	if !slices.ContainsFunc(cidrs, isTagCIDR) {
		return nil
	}
	_, err := c.ListFirewallTagGroups(ctx, &pb.ListFirewallTagGroupsRequest{})
	switch status.Code(err) {
	case codes.OK, codes.PermissionDenied, codes.Unauthenticated:
		return nil
	case codes.Unimplemented:
		return fmt.Errorf("a tag:<group> cidr: %s", tagGroupUpgradeText)
	}
	return fmt.Errorf("a tag:<group> cidr: could not confirm the daemon supports tag groups: %w; retry", err)
}

// composeRuleCIDRs is every rule cidr a compose file holds.
func composeRuleCIDRs(f *compose.File) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(f.SecurityGroups)) {
		for _, r := range f.SecurityGroups[name].Rules {
			out = append(out, r.CIDR)
		}
	}
	if fd := f.FirewallDefaults; fd != nil {
		for _, r := range fd.ClusterRules {
			out = append(out, r.CIDR)
		}
	}
	return out
}

func tagGroupSummary(g *pb.FirewallTagGroup) string {
	if len(g.GetMatch()) == 0 {
		return "unreadable on this host's replica"
	}
	var match []string
	for _, k := range slices.Sorted(maps.Keys(g.GetMatch())) {
		if v := g.GetMatch()[k]; v != "" {
			match = append(match, k+"="+v)
		} else {
			match = append(match, k)
		}
	}
	out := "match " + strings.Join(match, " ")
	if len(g.GetSecurityGroups()) > 0 {
		out += "; binds " + strings.Join(g.GetSecurityGroups(), ",")
		if len(g.GetNetworks()) > 0 {
			out += " on " + strings.Join(g.GetNetworks(), ",")
		} else {
			out += " on every network"
		}
	}
	return out
}

func printTagGroups(w io.Writer, groups []*pb.FirewallTagGroup, members bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDEFINITION\tSET_BY\tUPDATED")
	for _, g := range groups {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.GetName(), tagGroupSummary(g), g.GetSetBy(), g.GetUpdatedAt())
	}
	if err := tw.Flush(); err != nil || !members {
		return err
	}
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tKIND\tWORKLOAD\tHOST\tADDRESSES")
	for _, g := range groups {
		for _, m := range g.GetMembers() {
			host := m.GetHost()
			if host == "" {
				host = "-"
			}
			addrs := strings.Join(m.GetAddresses(), ",")
			if addrs == "" {
				addrs = m.GetAddressNote()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.GetName(), m.GetKind(), m.GetWorkload(), host, addrs)
		}
	}
	return tw.Flush()
}

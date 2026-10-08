package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
)

// newSGCmd groups security-group subcommands. Every write goes through the
// daemon (CreateSecurityGroup, DeleteSecurityGroup, AddSecurityGroupRule,
// RemoveSecurityGroupRule, BindSecurityGroups), which authorizes it and records
// it in the signed audit log (colonelpanik/litevirt#182). The listings read
// through ListSecurityGroups, falling back to the local Corrosion database only
// when the daemon cannot answer (listSecurityGroups). The reconciler on each host watches the
// same tables and re-applies its firewall plan when rules change — see
// internal/firewall/reconciler.go.
func newSGCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sg",
		Aliases: []string{"security-group"},
		Short:   "Manage security groups (distributed firewall)",
	}
	cmd.AddCommand(
		newSGCreateCmd(),
		newSGListCmd(),
		newSGDeleteCmd(),
		newSGRuleAddCmd(),
		newSGRuleListCmd(),
		newSGRuleRemoveCmd(),
		newSGBindCmd(),
	)
	return cmd
}

// newSGBindCmd attaches one or more security groups to a VM's NIC at
// runtime. The next firewall reconciler tick on the owning host
// rerenders nftables — or run `lv firewall reload` to force.
func newSGBindCmd() *cobra.Command {
	var network string
	var sgNames []string
	cmd := &cobra.Command{
		Use:   "bind <vm>",
		Short: "Bind security groups to a VM's NIC",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
					VmName: args[0], NetworkName: network, SecurityGroups: sgNames,
				}); err != nil {
					return err
				}
				fmt.Printf("Bound %v on %s/%s\n", sgNames, args[0], network)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "Compose network name (required; matches vm_interfaces.network_name)")
	cmd.Flags().StringSliceVar(&sgNames, "sg", nil, "Security group name (repeatable; empty list clears bindings)")
	cmd.MarkFlagRequired("network") //nolint:errcheck
	return cmd
}

// openClusterDB opens the local Corrosion database. Only the listings use it,
// and only when the daemon cannot answer (listSecurityGroups). Writes must go
// through the daemon (see sgRPCError). A var so a test can substitute it.
var openClusterDB = func() (*corrosion.Client, error) {
	cfg, err := daemon.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config (must run on a litevirt node): %w", err)
	}
	return corrosion.NewLocalClient(cfg.DataDir, cfg.HostName)
}

func newSGCreateCmd() *cobra.Command {
	var stack string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				sg, err := c.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: args[0], StackName: stack})
				if err != nil {
					return sgRPCError("create", err)
				}
				fmt.Printf("Created security group %q (id=%s)\n", args[0], sg.Id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Limit the SG to one stack (default: cluster-wide)")
	return cmd
}

// sgRPCError explains an Unimplemented reply. A daemon older than the
// security-group RPCs answers every one of them that way, and the CLI must not
// fall back to writing the database itself: that path skipped authorization
// and left no audit row.
func sgRPCError(sub string, err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("lv sg %s: the daemon does not support security-group changes over its API "+
			"(it predates them); upgrade litevirtd on the host you are connected to and retry: %w", sub, err)
	}
	return err
}

func newSGListCmd() *cobra.Command {
	var stack string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List security groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := listSecurityGroups(cmd, &pb.ListSecurityGroupsRequest{StackName: stack})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSTACK\tCREATED")
			for _, sg := range resp.GetGroups() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sg.GetId(), sg.GetName(), sg.GetStackName(), sg.GetCreatedAt())
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Filter to one stack")
	return cmd
}

// listSecurityGroups reads security groups through ListSecurityGroups, so the
// daemon decides what the caller's credential may see — the same RPC the web
// UI reads through. It reads the local database instead only when the daemon
// cannot answer at all: it is down (Unavailable) or predates the RPC
// (Unimplemented). That keeps a listing that worked on a node working through a
// rolling upgrade or a daemon outage, and it opens nothing new: the local
// database is readable only by whoever could already read the file. A refusal is
// the daemon's answer and is returned as it is, never routed around.
func listSecurityGroups(cmd *cobra.Command, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	var resp *pb.ListSecurityGroupsResponse
	err := withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
		var err error
		resp, err = c.ListSecurityGroups(ctx, req)
		return err
	})
	switch status.Code(err) {
	case codes.OK:
		return resp, nil
	case codes.Unavailable, codes.Unimplemented:
		fmt.Fprintf(cmd.ErrOrStderr(), "litevirtd could not answer (%s); reading this node's local database instead.\n",
			status.Convert(err).Message())
		return listSecurityGroupsLocal(cmd.Context(), req)
	default:
		return nil, err
	}
}

// listSecurityGroupsLocal is listSecurityGroups' daemon-unreachable path.
func listSecurityGroupsLocal(ctx context.Context, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	db, err := openClusterDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	groups, err := corrosion.ListSecurityGroups(ctx, db, req.GetStackName())
	if err != nil {
		return nil, err
	}
	resp := &pb.ListSecurityGroupsResponse{}
	for _, g := range groups {
		resp.Groups = append(resp.Groups, &pb.SecurityGroup{Id: g.ID, Name: g.Name, StackName: g.StackName, CreatedAt: g.CreatedAt})
		if !req.GetIncludeRules() {
			continue
		}
		rules, err := corrosion.ListSGRules(ctx, db, g.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			resp.Rules = append(resp.Rules, &pb.SecurityGroupRule{
				Id: r.ID, SgId: r.SGID, Direction: r.Direction, Proto: r.Proto,
				Port: r.PortRange, Cidr: r.CIDR, Action: r.Action, Priority: int32(r.Priority),
			})
		}
	}
	return resp, nil
}

func newSGDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a security group (and its rules)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{Id: args[0]}); err != nil {
					return sgRPCError("rm", err)
				}
				fmt.Printf("Deleted security group %s\n", args[0])
				return nil
			})
		},
	}
}

func newSGRuleAddCmd() *cobra.Command {
	var direction, proto, port, cidr, action string
	var priority int
	cmd := &cobra.Command{
		Use:   "rule-add <sg-id>",
		Short: "Add a rule to a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				rule, err := c.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
					SgId: args[0], Direction: direction, Proto: proto, Port: port,
					Cidr: cidr, Action: action, Priority: int32(priority),
				}})
				if err != nil {
					return sgRPCError("rule-add", err)
				}
				fmt.Printf("Added rule %s\n", rule.Id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&direction, "direction", "ingress", "ingress | egress")
	cmd.Flags().StringVar(&proto, "proto", "all", "tcp | udp | icmp | all")
	cmd.Flags().StringVar(&port, "port", "", "port or range (e.g. 80 or 8000-9000)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "source/dest CIDR or @ipset-name (default: any)")
	cmd.Flags().StringVar(&action, "action", "accept", "accept | drop | reject")
	cmd.Flags().IntVar(&priority, "priority", 100, "lower runs first")
	return cmd
}

func newSGRuleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rule-ls <sg-id>",
		Short: "List rules in a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := listSecurityGroups(cmd, &pb.ListSecurityGroupsRequest{IncludeRules: true})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO")
			for _, r := range resp.GetRules() {
				if r.GetSgId() != args[0] {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.GetId(), r.GetDirection(), r.GetProto(), r.GetPort(), r.GetCidr(), r.GetAction(),
					strconv.Itoa(int(r.GetPriority())))
			}
			return w.Flush()
		},
	}
}

func newSGRuleRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rule-rm <rule-id>",
		Short: "Remove a single rule from a security group (id from `sg rule-ls`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RemoveSecurityGroupRule(ctx, &pb.RemoveSecurityGroupRuleRequest{Id: args[0]}); err != nil {
					return sgRPCError("rule-rm", err)
				}
				fmt.Printf("Removed rule %s\n", args[0])
				return nil
			})
		},
	}
}

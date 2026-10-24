package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/firewall"
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
	var stack, project string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if project != "" {
					if err := requireSGProjects(ctx, c, "create"); err != nil {
						return err
					}
				}
				sg, err := c.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: args[0], StackName: stack, Project: project})
				if err != nil {
					return sgRPCError("create", err)
				}
				if sg.GetProject() != project {
					return fmt.Errorf("lv sg create: asked for a group of project %q, and the daemon created %q (id %s) in project %q; "+
						"remove it with `lv sg rm %s` and upgrade litevirtd on the host you are connected to", project, args[0], sg.GetId(), sg.GetProject(), sg.GetId())
				}
				fmt.Printf("Created security group %q (id=%s)\n", args[0], sg.Id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Limit the SG to one stack (default: cluster-wide)")
	cmd.Flags().StringVar(&project, "project", "", "Project that owns the SG; only its workloads may bind it (default: global)")
	return cmd
}

// errSGProjectsUnsupported is the refusal of --project against a daemon that
// does not implement project security groups.
type errSGProjectsUnsupported struct{ sub, why string }

func (e errSGProjectsUnsupported) Error() string {
	return fmt.Sprintf("lv sg %s --project: the daemon predates project security groups (%s); upgrade litevirtd on the host you are connected to", e.sub, e.why)
}

// sgProjectsProbe is a malformed project name. A daemon that implements
// project security groups validates ListSecurityGroups' project before any
// authorization and answers it InvalidArgument; one that does not knows no
// such field and answers as for any listing (every group, or its refusal of
// the caller). A declared release feature proves nothing: a build can declare
// sg_projects before it implements it.
const sgProjectsProbe = ".."

// requireSGProjects refuses --project against a daemon that does not
// implement project security groups, before anything is created or listed.
// Such a daemon drops the field it does not read: a create would make a
// GLOBAL group every project may bind, and a listing would not be filtered.
// The probe needs no more than any listing does, so a token scoped to a
// project can make it. A daemon that cannot be reached is returned as it is.
func requireSGProjects(ctx context.Context, c pb.LiteVirtClient, sub string) error {
	_, err := c.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{Project: sgProjectsProbe})
	switch {
	case status.Code(err) == codes.InvalidArgument && strings.Contains(status.Convert(err).Message(), "invalid project"):
		return nil
	case err == nil:
		return errSGProjectsUnsupported{sub, "it ignored the project of a listing"}
	case status.Code(err) == codes.PermissionDenied:
		// A previous build checks sg.read at the root before anything else;
		// this one reads the project first.
		return errSGProjectsUnsupported{sub, "it refused the listing before reading its project: " + status.Convert(err).Message()}
	case status.Code(err) == codes.Unimplemented:
		return errSGProjectsUnsupported{sub, "it has no security-group listing"}
	}
	// Anything else is the daemon failing for reasons of its own: say so,
	// and still do nothing.
	return fmt.Errorf("lv sg %s --project: could not ask the daemon whether it supports project security groups: %w", sub, err)
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
	var stack, project string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List security groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := listSecurityGroups(cmd, &pb.ListSecurityGroupsRequest{StackName: stack, Project: project, IncludeRules: true})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tPROJECT\tSTACK\tCREATED")
			for _, sg := range resp.GetGroups() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", sg.GetId(), sg.GetName(), sg.GetProject(), sg.GetStackName(), sg.GetCreatedAt())
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&stack, "stack", "", "Filter to one stack")
	cmd.Flags().StringVar(&project, "project", "", "List one project's SGs and the global ones")
	return cmd
}

// listSecurityGroups reads security groups through ListSecurityGroups, so the
// daemon decides what the caller's credential may see — the same RPC the web
// UI reads through. It reads the local database instead only when no daemon
// answered: the CLI had nothing to connect with (no LV_HOST, no readable PKI
// bundle), the daemon is down (Unavailable), it predates the RPC
// (Unimplemented), or it did not accept the credential (Unauthenticated). That keeps a listing that worked on a node working — before
// the RPC it always read the local database — and it opens nothing new: the
// local database is readable only by whoever could already read the file. A
// refusal of an authenticated caller (PermissionDenied) is the daemon's answer
// and is returned as it is, never routed around.
func listSecurityGroups(cmd *cobra.Command, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	var resp *pb.ListSecurityGroupsResponse
	asked := false
	var unsupported error
	err := withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
		if req.GetProject() != "" {
			// A daemon that cannot be asked is handled below like any other.
			if perr := requireSGProjects(ctx, c, "ls"); perr != nil {
				var old errSGProjectsUnsupported
				if errors.As(perr, &old) {
					unsupported = perr
					return perr
				}
			}
		}
		asked = true
		var err error
		resp, err = c.ListSecurityGroups(ctx, req)
		return err
	})
	if unsupported != nil {
		return nil, unsupported
	}
	var why string
	switch {
	case err == nil:
		return resp, nil
	case !asked:
		// withClient failed before any RPC: no daemon saw the request.
		why = "the CLI could not connect: " + err.Error()
	case status.Code(err) == codes.Unavailable || status.Code(err) == codes.Unimplemented:
		why = "litevirtd could not answer: " + status.Convert(err).Message()
	case status.Code(err) == codes.Unauthenticated:
		// The daemon did not accept the credential (a revoked session, an
		// expired token), so it never judged what the caller may see.
		why = "litevirtd did not accept the CLI's credential: " + status.Convert(err).Message()
	default:
		return nil, err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s; reading this node's local database instead.\n", why)
	local, lerr := listSecurityGroupsLocal(cmd.Context(), req)
	if lerr != nil {
		return nil, fmt.Errorf("%s; and the local database could not be read either: %w", why, lerr)
	}
	return local, nil
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
	toPb := func(r corrosion.SGRule) *pb.SecurityGroupRule {
		action, logged := corrosion.SplitLoggedAction(r.Action)
		return &pb.SecurityGroupRule{
			Id: r.ID, SgId: r.SGID, Direction: r.Direction, Proto: r.Proto,
			Port: r.PortRange, Cidr: r.CIDR, Action: action, Priority: int32(r.Priority), Log: logged,
		}
	}
	for _, g := range groups {
		if p := req.GetProject(); p != "" && g.Project != "" && g.Project != p {
			continue
		}
		resp.Groups = append(resp.Groups, &pb.SecurityGroup{Id: g.ID, Name: g.Name, StackName: g.StackName, CreatedAt: g.CreatedAt, Project: g.Project})
		if !req.GetIncludeRules() {
			continue
		}
		rules, err := corrosion.ListSGRules(ctx, db, g.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			resp.Rules = append(resp.Rules, toPb(r))
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
	var direction, proto, port, cidr, action, macro string
	var priority int
	var logged bool
	cmd := &cobra.Command{
		Use:   "rule-add <sg-id-or-name>",
		Short: "Add a rule to a security group (by id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseClientLogAction(action); err != nil {
				return err
			}
			if macro != "" {
				return runMacroAdd(cmd, macro, direction, cidr, action, func(ctx context.Context, c pb.LiteVirtClient, _ string, row firewall.ExpandedRule) (string, error) {
					rule, err := c.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
						SgId: args[0], Direction: row.Direction, Proto: row.Proto, Port: row.Port,
						Cidr: row.CIDR, Action: row.Action, Priority: int32(priority), Log: logged,
					}})
					if err != nil {
						return "", sgRPCError("rule-add", err)
					}
					return rule.Id, nil
				}, func(ctx context.Context, c pb.LiteVirtClient, id string) error {
					_, err := c.RemoveSecurityGroupRule(ctx, &pb.RemoveSecurityGroupRuleRequest{Id: id})
					return err
				}, func(id string) string { return fmt.Sprintf("Added rule %s\n", id) })
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if err := requireTagGroupSupport(ctx, c, cidr); err != nil {
					return err
				}
				if err := requireLogSupport(ctx, c, logged); err != nil {
					return err
				}
				rule, err := c.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
					SgId: args[0], Direction: direction, Proto: proto, Port: port,
					Cidr: cidr, Action: action, Priority: int32(priority), Log: logged,
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
	cmd.Flags().StringVar(&macro, "macro", "", "add the rules of a named macro instead of --proto/--port (see 'lv firewall macros')")
	cmd.Flags().BoolVar(&logged, "log", false, logFlagUsage)
	return cmd
}

func newSGRuleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rule-ls <sg-id-or-name>",
		Short: "List rules in a security group (by id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := listSecurityGroups(cmd, &pb.ListSecurityGroupsRequest{IncludeRules: true})
			if err != nil {
				return err
			}
			// The argument is a group id or a group name. A name several groups
			// hold lists the rules of each, labelled by group id.
			var matched []string
			for _, g := range resp.GetGroups() {
				if g.GetId() == args[0] {
					matched = []string{g.GetId()}
					break
				}
				if g.GetName() == args[0] {
					matched = append(matched, g.GetId())
				}
			}
			if len(matched) == 0 {
				matched = []string{args[0]}
			}
			label := len(matched) > 1
			if label {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %d security groups are named %q; listing each, labelled by group id.\n", len(matched), args[0])
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if label {
				fmt.Fprintln(w, "SG\tID\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO")
			} else {
				fmt.Fprintln(w, "ID\tDIR\tPROTO\tPORT\tCIDR\tACTION\tPRIO")
			}
			for _, gid := range matched {
				for _, r := range resp.GetRules() {
					if r.GetSgId() != gid {
						continue
					}
					if label {
						fmt.Fprintf(w, "%s\t", gid)
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						r.GetId(), r.GetDirection(), r.GetProto(), r.GetPort(), r.GetCidr(), ruleAction(r.GetAction(), r.GetLog()),
						strconv.Itoa(int(r.GetPriority())))
				}
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

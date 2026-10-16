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
	"github.com/litevirt/litevirt/internal/apimeta"
)

// newFirewallTagCmd manages firewall tags: a per-workload key/value set kept
// apart from labels, which tag groups select on (docs/firewall.md, "Firewall
// tags").
func newFirewallTagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Manage workloads' firewall tags (kept apart from labels; needs sg.write to change)",
	}
	var container bool
	var host string
	target := func() (kind string, err error) {
		if container {
			return "container", nil
		}
		if host != "" {
			return "", fmt.Errorf("--host names a container's host: pass --container too")
		}
		return "vm", nil
	}

	set := &cobra.Command{
		Use:   "set <workload> <key>=<value>...",
		Short: "Set firewall tags on a VM, or a container with --container",
		Long: `Sets firewall tags on one workload, keeping the tags it has. A key and a
value are each [a-z0-9][a-z0-9_.-]{0,62}. Needs sg.write at the cluster root,
and is refused until the cluster upgrade has finished.

The first tag set gives the workload its firewall identity, which follows it
through a migrate, a rebuild and a rolling update; a clone, an import or a
restore under a new name is a new workload with none. A container created by
an earlier build (with no create spec) cannot be tagged until it is created
again.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, err := target()
			if err != nil {
				return err
			}
			tags := map[string]string{}
			for _, kv := range args[1:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || k == "" || v == "" {
					return fmt.Errorf("%q: want key=value", kv)
				}
				tags[k] = v
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				out, err := c.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: kind, Workload: args[0], Host: host, Set: tags})
				if err != nil {
					return firewallTagRPCError(err)
				}
				printFirewallTagsResult(os.Stdout, out)
				return nil
			})
		},
	}

	rm := &cobra.Command{
		Use:   "rm <workload> <key>...",
		Short: "Remove firewall tags from a VM, or a container with --container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, err := target()
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				out, err := c.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: kind, Workload: args[0], Host: host, Remove: args[1:]})
				if err != nil {
					return firewallTagRPCError(err)
				}
				printFirewallTagsResult(os.Stdout, out)
				return nil
			})
		},
	}

	ls := &cobra.Command{
		Use:   "ls [<workload>]",
		Short: "List firewall tags: every tagged workload, or one workload's",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ListFirewallTagsRequest{Host: host}
			if container {
				req.Kind = "container"
			} else if host != "" {
				return fmt.Errorf("--host names a container's host: pass --container too")
			}
			if len(args) == 1 {
				req.Workload = args[0]
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListFirewallTags(ctx, req)
				if err != nil {
					return firewallTagRPCError(err)
				}
				return printFirewallTagsList(os.Stdout, resp.GetTags())
			})
		},
	}
	for _, c := range []*cobra.Command{set, rm, ls} {
		c.Flags().BoolVar(&container, "container", false, "The workload is a container")
		c.Flags().StringVar(&host, "host", "", "The container's host (with --container; default: resolve by name)")
	}
	cmd.AddCommand(set, rm, ls)
	return cmd
}

// firewallTagRPCError explains an Unimplemented reply: the daemon predates
// firewall tags.
func firewallTagRPCError(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("the daemon does not support firewall tags; upgrade the daemon: %w", err)
	}
	return err
}

func tagPairs(tags map[string]string) string {
	if len(tags) == 0 {
		return "none"
	}
	var pairs []string
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		pairs = append(pairs, k+"="+tags[k])
	}
	return strings.Join(pairs, " ")
}

func fwTagWho(t *pb.FirewallTags) string {
	if t.GetKind() == "container" {
		return "container " + t.GetHost() + "/" + t.GetWorkload()
	}
	return "VM " + t.GetWorkload()
}

func printFirewallTagsResult(w io.Writer, t *pb.FirewallTags) {
	fmt.Fprintf(w, "Firewall tags of %s (fw_id %s): %s\n", fwTagWho(t), t.GetFwId(), tagPairs(t.GetTags()))
	if t.GetReplacedFwId() != "" {
		fmt.Fprintf(w, "note: %s held firewall identity %s, which another workload holds too (a copy); it now has its own "+
			"identity, and the tags of %s were cleared from both: %s. Set them again with lv firewall tag set where they belong.\n",
			fwTagWho(t), t.GetReplacedFwId(), t.GetReplacedFwId(), tagPairs(t.GetDroppedTags()))
	} else if len(t.GetDroppedTags()) > 0 {
		fmt.Fprintf(w, "note: %s shared its firewall identity with another workload (a copy); the identity's tags were cleared: %s. "+
			"Set them again with lv firewall tag set where they belong.\n", fwTagWho(t), tagPairs(t.GetDroppedTags()))
	}
}

func printFirewallTagsList(w io.Writer, tags []*pb.FirewallTags) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tWORKLOAD\tHOST\tFW_ID\tTAGS")
	for _, t := range tags {
		id := t.GetFwId()
		if id == "" {
			id = "-"
		}
		tagText := tagPairs(t.GetTags())
		if t.GetOrphan() {
			tagText += " (an earlier incarnation's row, not applied)"
		}
		host := t.GetHost()
		if host == "" {
			host = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.GetKind(), t.GetWorkload(), host, id, tagText)
	}
	return tw.Flush()
}

// firewallTagsLine is the "Firewall tags:" line of an inspect, "" when the
// daemon cannot say (it predates firewall tags, or the caller may not read
// them).
func firewallTagsLine(ctx context.Context, c pb.LiteVirtClient, kind, name, host string) string {
	resp, err := c.ListFirewallTags(ctx, &pb.ListFirewallTagsRequest{Kind: kind, Workload: name, Host: host})
	if err != nil {
		return ""
	}
	return apimeta.FirewallTagsLine(resp.GetTags())
}

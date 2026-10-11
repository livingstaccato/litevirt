package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newHostLUNHoldsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lun-holds [host]",
		Short: "List the holds a host keeps on iSCSI LUNs a rebuild or recreate moved",
		Long: `A rebuild or recreate of a VM with a disk on an iSCSI LUN moves the LUN's claim
before the VM is torn down, and the host running it keeps a durable hold on
the LUN until the re-created VM's rows reach it, or the host the VM was
re-created on shows nothing holding the LUN, or that host is removed. While
the hold stands, no other VM can take the LUN.

This lists those holds, on one host or on every host: the VM, its LUNs, the
host it was re-created on, and since when. A record the host cannot read is
listed with its error: while one stands, that host answers no LUN question.
Remove a hold that must go with "lv host lun-hold discard".`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, err := lunHoldHosts(ctx, c, args)
				if err != nil {
					return err
				}
				out := cmd.OutOrStdout()
				var resps []*pb.ISCSILUNHoldsResponse
				for _, h := range hosts {
					resp, err := c.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Host: h})
					if err != nil {
						if len(args) == 1 {
							return fmt.Errorf("iSCSI LUN holds on %s: %w", h, err)
						}
						fmt.Fprintf(cmd.ErrOrStderr(), "%s: cannot list its iSCSI LUN holds: %v\n", h, err)
						continue
					}
					resps = append(resps, resp)
				}
				printLUNHolds(out, resps, time.Now())
				return nil
			})
		},
	}
}

func newHostLUNHoldCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lun-hold",
		Short: "Act on a host's iSCSI LUN holds",
	}
	cmd.AddCommand(newHostLUNHoldDiscardCmd())
	return cmd
}

func newHostLUNHoldDiscardCmd() *cobra.Command {
	var host string
	var yes bool
	cmd := &cobra.Command{
		Use:   "discard <lun>",
		Short: "Move a host's hold on an iSCSI LUN aside, so the LUN can be taken again",
		Long: `Moves aside every hold record that names <lun> — a LUN key as "lv host lun-holds"
shows it (iscsi:<target>/lun<n>), a hold's token, or a record's file name — to
<data_dir>/iscsi-lun-holds/discarded/ on that host, where it is kept, and
reloads the host's holds at once, with no restart. Admin only, and audited.

A hold is what keeps a second VM off a LUN while a re-created VM's rows are on
their way. Discard one only once it is safe:

  - the VM it names shows running in "lv ls" on the host the hold names as
    its run host, with its rows on the hold's host too; or
  - that VM no longer exists, and no domain of it runs on any host.

A record the host cannot read names no VM: find it from the LUN's claim
before discarding it (docs/storage.md).

Without --host, every host is asked and the one holding <lun> is used.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("discarding a hold can let another VM take a LUN a guest still writes: check " +
					"what the hold names first (lv host lun-holds), then pass --yes")
			}
			match := args[0]
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				target := host
				if target == "" {
					hosts, err := lunHoldHosts(ctx, c, nil)
					if err != nil {
						return err
					}
					var holding []string
					for _, h := range hosts {
						resp, err := c.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Host: h})
						if err != nil {
							return fmt.Errorf("cannot ask %s for its iSCSI LUN holds (%w): name the host with --host", h, err)
						}
						for _, hd := range resp.Holds {
							if lunHoldNamed(match, hd) {
								holding = append(holding, h)
								break
							}
						}
					}
					switch len(holding) {
					case 0:
						return fmt.Errorf("no host holds %q", match)
					case 1:
						target = holding[0]
					default:
						return fmt.Errorf("%q is held on %s: name one with --host", match, strings.Join(holding, ", "))
					}
				}
				resp, err := c.ISCSILUNHolds(ctx, &pb.ISCSILUNHoldsRequest{Host: target, Discard: match})
				if err != nil {
					return fmt.Errorf("discard on %s: %w", target, err)
				}
				out := cmd.OutOrStdout()
				for _, f := range resp.Discarded {
					fmt.Fprintf(out, "Moved %s aside on %s (iscsi-lun-holds/%s/).\n", f, resp.Host, "discarded")
				}
				printLUNHolds(out, []*pb.ISCSILUNHoldsResponse{resp}, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "The host whose hold to discard (default: the one host holding it)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the discard")
	return cmd
}

// lunHoldHosts is the host named, or every host.
func lunHoldHosts(ctx context.Context, c pb.LiteVirtClient, args []string) ([]string, error) {
	if len(args) == 1 {
		return args, nil
	}
	resp, err := c.ListHosts(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	var out []string
	for _, h := range resp.Hosts {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out, nil
}

// lunHoldNamed reports whether match names hd as the server matches it: its
// file, its token, or one of its LUNs.
func lunHoldNamed(match string, hd *pb.ISCSILUNHold) bool {
	if match == hd.File || match == strings.TrimSuffix(hd.File, ".json") || (hd.Token != "" && match == hd.Token) {
		return true
	}
	_, ok := hd.Luns[match]
	return ok
}

func printLUNHolds(out io.Writer, resps []*pb.ISCSILUNHoldsResponse, now time.Time) {
	any := false
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, r := range resps {
		if r.LoadError != "" {
			fmt.Fprintf(out, "%s answers no LUN question: %s\n", r.Host, r.LoadError)
		}
		for _, hd := range r.Holds {
			if !any {
				fmt.Fprintln(w, "HOST\tLUN\tVM\tDISK\tRUN HOST\tSINCE\tSTATE")
				any = true
			}
			if hd.Error != "" {
				fmt.Fprintf(w, "%s\t-\t-\t-\t-\t-\tUNREADABLE %s: %s\n", r.Host, hd.File, hd.Error)
				continue
			}
			since := hd.Since
			if at, err := time.Parse(time.RFC3339Nano, hd.Since); err == nil {
				since = fmt.Sprintf("%s (%s ago)", at.UTC().Format(time.RFC3339), now.Sub(at).Round(time.Second))
			}
			state := "waiting for evidence"
			if hd.Active {
				state = "re-creating"
			}
			keys := make([]string, 0, len(hd.Luns))
			for k := range hd.Luns {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s (%s)\n", r.Host, k, hd.VmName, hd.Luns[k], hd.RunHost, since, state, hd.Token)
			}
		}
	}
	w.Flush()
	if !any {
		fmt.Fprintln(out, "No iSCSI LUN holds.")
	}
}

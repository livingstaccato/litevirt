package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// haSetDeadline is the per-call deadline of `lv cluster ha arm|disarm`. The
// handler waits up to 60 s for the change to be confirmed and then a further
// 20 s, so the call needs at least 90 s whatever deadline the caller had.
const haSetDeadline = 120 * time.Second

// haSetContext is ctx with a deadline of haSetDeadline, even when ctx's own is
// shorter; cancelling ctx still cancels it.
func haSetContext(ctx context.Context) (context.Context, context.CancelFunc) {
	out, cancel := context.WithTimeout(context.WithoutCancel(ctx), haSetDeadline)
	stop := context.AfterFunc(ctx, func() {
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			cancel()
		}
	})
	return out, func() { stop(); cancel() }
}

// lv cluster ha [arm|disarm] — show or change the cluster HA policy
// (docs/migration-failover.md, "Disarming HA for planned maintenance").
func newClusterHACmd() *cobra.Command {
	var reason string
	var fenceDown bool
	cmd := &cobra.Command{
		Use:   "ha [arm|disarm]",
		Short: "Show, disarm or arm automatic fencing and recovery cluster-wide",
		Long: `With no argument, show the cluster HA policy: armed or disarmed, who set it,
when and why, each voter's latest answer, whether the first use has been paid,
and, while disarmed, the hosts an arm would fence.

  disarm  no host is fenced and no workload recovered automatically until arm.
          Health probes, re-admission of hosts that answer, partition pause and
          every operator action are kept.
  arm     automatic fencing and recovery resume. Refused while any host that is
          not in maintenance is reported down, unless --fence-down-hosts: those
          hosts are fenced on the next cycle.

A change needs the admin role and the connected host's voter majority, and
returns once a majority of the voters (under region scope, of every region)
holds it. It can take up to 80 s.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state := ""
			if len(args) == 1 {
				switch args[0] {
				case "arm":
					state = "armed"
				case "disarm":
					state = "disarmed"
				default:
					return fmt.Errorf("unknown argument %q: lv cluster ha [arm|disarm]", args[0])
				}
			} else if reason != "" || fenceDown {
				return errors.New("--reason and --fence-down-hosts go with arm or disarm")
			}
			if fenceDown && state != "armed" {
				return errors.New("--fence-down-hosts goes with arm")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var st *pb.HAPolicyStatus
				var err error
				if state != "" {
					sctx, cancel := haSetContext(ctx)
					defer cancel()
					st, err = c.SetHAPolicy(sctx, &pb.SetHAPolicyRequest{State: state, Reason: reason, FenceDownHosts: fenceDown})
					if err != nil {
						return fmt.Errorf("set cluster HA: %w", err)
					}
				} else if st, err = c.GetHAPolicy(ctx, &emptypb.Empty{}); err != nil {
					return fmt.Errorf("get cluster HA: %w", err)
				}
				printHAPolicy(os.Stdout, st)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why HA is being changed (shown by lv cluster ha and in the audit log)")
	cmd.Flags().BoolVar(&fenceDown, "fence-down-hosts", false, "arm even though hosts are reported down; they are fenced on the next cycle")
	return cmd
}

func printHAPolicy(out io.Writer, st *pb.HAPolicyStatus) {
	fmt.Fprintf(out, "HA:        %s\n", st.GetState())
	if st.GetSetBy() != "" {
		fmt.Fprintf(out, "Set by:    %s at %s\n", st.GetSetBy(), st.GetAt())
	}
	if st.GetReason() != "" {
		fmt.Fprintf(out, "Reason:    %s\n", st.GetReason())
	}
	if !st.GetFirstUsePaid() {
		fmt.Fprintln(out, "First use: pending: the first disarm needs every host (maintenance hosts included) reachable")
	}
	fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "VOTER\tSTATUS\tANSWER\tPOLICY AT\n")
	for _, v := range st.GetVoters() {
		ans := "armed"
		switch {
		case !v.GetHaKnown():
			ans = "-"
		case v.GetHaDisarmed():
			ans = "disarmed"
		}
		at := v.GetHaPolicyAt()
		if at == "" {
			at = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.GetHost(), v.GetStatus(), ans, at)
	}
	w.Flush()
	if len(st.GetRegions()) > 0 {
		var short []string
		for _, r := range st.GetRegions() {
			if !r.GetConfirmed() {
				short = append(short, r.GetRegion())
			}
		}
		if len(short) == 0 {
			fmt.Fprintln(out, "\nEvery region holding a voter has a confirming majority.")
		} else {
			fmt.Fprintf(out, "\nRegions without a confirming majority: %s. The policy does not hold there yet.\n", strings.Join(short, ", "))
		}
	}
	if len(st.GetWouldBeFenced()) > 0 {
		fmt.Fprintf(out, "\nArming would fence: %s (lv cluster ha arm --fence-down-hosts)\n", strings.Join(st.GetWouldBeFenced(), ", "))
	}
}

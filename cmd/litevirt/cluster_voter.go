package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lv cluster voter — the explicit voter set (colonelpanik/litevirt#251 step 2,
// docs/design/recovery-claims.md §4). Every change is a decided generation:
// one member per generation, decided by a majority of the current one (or,
// for init, unanimously by the proposed members), so every node moves at the
// same generation.
func newClusterVoterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "voter",
		Short: "Show and change the cluster's explicit voter set",
		Long: `The voter set is the population every quorum counts: the fence quorum, the
recovery quorum and the health gate's quorum proof. Once voter_config_v1 has latched
and the cluster is clean, automatic genesis writes generation 1 from the hosts' current
state; from then on it changes only through these commands, never because a host went
offline, into maintenance or was fenced.`,
	}
	cmd.AddCommand(
		newClusterVoterLsCmd(),
		newClusterVoterInitCmd(),
		newClusterVoterAddCmd(),
		newClusterVoterRmCmd(),
		newClusterVoterResetCmd(),
	)
	return cmd
}

func newClusterVoterLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "Show the adopted voter generation and each member's state",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetVoterConfig(ctx, &pb.GetVoterConfigRequest{})
				if err != nil {
					return fmt.Errorf("voter set: %w", err)
				}
				printVoterConfig(resp)
				return nil
			})
		},
	}
}

func printVoterConfig(resp *pb.GetVoterConfigResponse) {
	fmt.Printf("Reported by %s.\n", resp.GetReportingHost())
	if !resp.GetExplicit() {
		switch {
		case resp.GetAdoptedGeneration() > 0:
			fmt.Printf("Generation %d (%s): no members — the voter set is derived from host state.\n",
				resp.GetAdoptedGeneration(), resp.GetChange())
		case !resp.GetGateOpen():
			fmt.Println("No voter generation yet: voter_config_v1 has not latched on this host.")
		default:
			fmt.Println("No voter generation yet: the voter set is derived from host state until genesis.")
		}
		if d := resp.GetGenesisPending(); d != "" {
			fmt.Printf("Genesis pending: %s\n", d)
		}
		fmt.Printf("Derived voters: %s\n", strings.Join(resp.GetDerivedVoters(), ", "))
		return
	}
	fmt.Printf("Generation %d (%s), decided %s by %s.\n", resp.GetAdoptedGeneration(), resp.GetChange(),
		resp.GetCreatedAt(), resp.GetCreatedBy())
	if resp.GetLatestGeneration() > resp.GetAdoptedGeneration() {
		fmt.Printf("Generation %d is recorded here but not adopted yet.\n", resp.GetLatestGeneration())
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "MEMBER\tHOST STATE\tREACHABLE\tVOTING\tDETAIL\n")
	for _, m := range resp.GetMembers() {
		voting := "yes"
		if m.GetAbstaining() {
			voting = "ABSTAINING"
		} else if !m.GetReachable() {
			voting = "unknown"
		}
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n", m.GetName(), m.GetHostState(), m.GetReachable(), voting, m.GetDetail())
	}
	w.Flush()
}

func confirmVoterChange(yes bool, prompt string) (bool, error) {
	if yes {
		return true, nil
	}
	if !stdinIsTerminal() {
		return false, errNoTTYConfirm
	}
	fmt.Print(prompt + " [y/N] ")
	var ans string
	fmt.Scanln(&ans)
	if ans != "y" && ans != "Y" {
		fmt.Println("Aborted.")
		return false, nil
	}
	return true, nil
}

func printVoterChange(resp *pb.ChangeVoterConfigResponse) {
	var names []string
	for _, m := range resp.GetMembers() {
		names = append(names, m.GetName())
	}
	members := strings.Join(names, ", ")
	if members == "" {
		members = "(none — derived from host state)"
	}
	fmt.Printf("Generation %d (%s): %s\n", resp.GetGeneration(), resp.GetChange(), members)
	if d := resp.GetDetail(); d != "" {
		fmt.Println("  " + d)
	}
}

func newClusterVoterInitCmd() *cobra.Command {
	var members []string
	var yes bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Start a voter generation by hand on a cluster that cannot become clean",
		Long: `Automatic genesis writes generation 1 on its own once every host is voting-eligible
and reachable. init is the fallback for a cluster that cannot become clean — for example
one with a permanently dead host that has not been removed — and the only way to start a
new member generation after 'lv cluster voter reset'. It is refused while automatic
genesis could still succeed.

Every listed member must be reachable and sign: a first generation is decided
unanimously, because no earlier generation has a majority that could decide it.

  --members a,b,c   the members (default: the hosts that vote today)
  --yes             skip the confirmation prompt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				preview, err := c.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "init", Members: members, DryRun: true})
				if err != nil {
					return fmt.Errorf("voter init: %w", err)
				}
				fmt.Println("Proposed voter generation:")
				printVoterChange(preview)
				if ok, err := confirmVoterChange(yes, "Propose it?"); !ok || err != nil {
					return err
				}
				resp, err := c.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "init", Members: members})
				if err != nil {
					return fmt.Errorf("voter init: %w", err)
				}
				printVoterChange(resp)
				return nil
			})
		},
	}
	cmd.Flags().StringSliceVar(&members, "members", nil, "comma-separated member hosts (default: the hosts that vote today)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func newClusterVoterAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <host>",
		Short: "Add one host to the voter set (one member per generation)",
		Long: `Decides the next generation with host added, by a majority of the current one. The
host must be reachable: it supplies its voter incarnation, and imports claim state from a
sealed majority of the current generation before it counts toward any majority.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return voterChange(cmd.Context(), "add", args[0])
		},
	}
}

func newClusterVoterRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <host>",
		Short: "Remove one host from the voter set (one member per generation)",
		Long: `Decides the next generation with host removed, by a majority of the current one.
Removing an unreachable member is allowed — that is the case after a fence. A fenced
host stays a member, and keeps counting in every quorum's denominator, until this is run.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return voterChange(cmd.Context(), "rm", args[0])
		},
	}
}

func newClusterVoterResetCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Return the cluster to the voter set derived from host state",
		Long: `Decides a generation with no members, by a majority of the current one, so every
node returns to the derived voter set at the same generation. It is sticky: automatic
genesis never runs again, and only 'lv cluster voter init' starts a new member generation.
It is the exit from explicit voting when the voter configuration itself is suspect, not a
rollback tool.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := confirmVoterChange(yes, "Return every node to the derived voter set?"); !ok || err != nil {
				return err
			}
			return voterChange(cmd.Context(), "reset", "")
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func voterChange(ctx context.Context, op, host string) error {
	return withClient(ctx, func(ctx context.Context, c pb.LiteVirtClient) error {
		resp, err := c.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: op, Host: host})
		if err != nil {
			return fmt.Errorf("voter %s: %w", op, err)
		}
		printVoterChange(resp)
		return nil
	})
}

package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// accessVLANMovesDocs is where the finding points.
const accessVLANMovesDocs = "docs/networking.md#access-vlan-nics-need-a-vlan-filtering-bridge"

// unfilteredMoveNetworks is the networks, sorted, that allow moving their
// access-VLAN VMs onto bridges that do not filter VLANs. Pure, so the
// selection is testable without a cluster.
func unfilteredMoveNetworks(nets []*pb.NetworkInfo) []string {
	var out []string
	for _, n := range nets {
		if n.GetAllowUnfilteredAccessVlanMoves() {
			out = append(out, n.GetName())
		}
	}
	sort.Strings(out)
	return out
}

func newDoctorAccessVLANMovesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "access-vlan-moves",
		Short: "Report networks that let access-VLAN VMs move onto bridges that do not filter VLANs",
		Long: `List the networks with --allow-unfiltered-access-vlan-moves on (lv network set).

On such a network, lv migrate and lv host drain may move a VM with an
access-VLAN NIC (trunk: with one VLAN) onto a host whose bridge does not filter
VLANs, where the NIC joins that bridge's untagged segment, shared with every
plain NIC and the host. Off by default; lv health names each such network too
(access_vlan_unfiltered_moves_allowed).

Read-only. Turn it off with lv network set <name> --allow-unfiltered-access-vlan-moves=false.
See ` + accessVLANMovesDocs + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNetworks(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("list networks: %w", err)
				}
				found := unfilteredMoveNetworks(resp.GetNetworks())
				if len(found) == 0 {
					fmt.Println("no network lets access-VLAN VMs move onto bridges that do not filter VLANs")
					return nil
				}
				for _, n := range found {
					fmt.Printf("%s: access-VLAN VMs may be moved onto bridges that do not filter VLANs (their untagged segment)\n", n)
				}
				fmt.Printf("\n%d network(s) allow it. Turn it off with `lv network set <name> --allow-unfiltered-access-vlan-moves=false`;\n", len(found))
				fmt.Printf("see %s.\n", accessVLANMovesDocs)
				return nil
			})
		},
	}
}

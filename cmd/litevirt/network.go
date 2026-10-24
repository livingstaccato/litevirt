package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage networks",
	}
	cmd.AddCommand(
		newNetworkLsCmd(),
		newNetworkInspectCmd(),
		newNetworkCreateCmd(),
		newNetworkSetCmd(),
		newNetworkRmCmd(),
	)
	return cmd
}

func newNetworkLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List networks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNetworks(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("list networks: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tTYPE\tINTERFACE\tSUBNET\tGATEWAY\tDHCP\tVNI\tSTACK\tVMS\n")
				for _, n := range resp.Networks {
					dhcp := ""
					if n.Dhcp {
						dhcp = "yes"
					}
					vni := ""
					if n.Vni > 0 {
						vni = fmt.Sprintf("%d", n.Vni)
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n",
						n.Name, n.Type, n.Iface, n.Subnet, n.Gateway,
						dhcp, vni, n.StackName, n.VmCount,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newNetworkInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show network details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ni, err := c.GetNetwork(ctx, &pb.GetNetworkRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("get network: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "Name:\t%s\n", ni.Name)
				fmt.Fprintf(w, "Type:\t%s\n", ni.Type)
				fmt.Fprintf(w, "Interface:\t%s\n", ni.Iface)
				if ni.Subnet != "" {
					fmt.Fprintf(w, "Subnet:\t%s\n", ni.Subnet)
				}
				if ni.Gateway != "" {
					fmt.Fprintf(w, "Gateway:\t%s\n", ni.Gateway)
				}
				if ni.Dhcp {
					fmt.Fprintf(w, "DHCP:\tyes\n")
				}
				if ni.Vni > 0 {
					fmt.Fprintf(w, "VNI:\t%d\n", ni.Vni)
				}
				if ni.StackName != "" {
					fmt.Fprintf(w, "Stack:\t%s\n", ni.StackName)
				}
				fmt.Fprintf(w, "VMs:\t%d\n", ni.VmCount)
				if ni.GetAllowUnfilteredAccessVlanMoves() {
					fmt.Fprintf(w, "Unfiltered access-VLAN moves:\tallowed (access-VLAN VMs may be moved onto bridges that do not filter VLANs)\n")
				}
				return w.Flush()
			})
		},
	}
}

func newNetworkCreateCmd() *cobra.Command {
	var (
		ntype      string
		iface      string
		vlan       int
		vni        int
		underlay   string
		subnet     string
		dhcp       bool
		pf         string
		spoofCheck bool
		project    string
		netboxID   int
		gateway    string
		reserved   []string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a network",
		Long: `Create a standalone network.

Examples:
  lv network create mgmt --type bridge --interface br-mgmt
  lv network create backend --type isolated --subnet 172.16.0.0/24 --dhcp
  lv network create overlay --type vxlan --vni 3000 --underlay eth0
  lv network create fast --type sriov --pf enp4s0f0 --vlan 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ni, err := c.CreateNetwork(ctx, &pb.CreateNetworkRequest{
					Name:              args[0],
					Type:              ntype,
					Iface:             iface,
					Vlan:              int32(vlan),
					Vni:               int32(vni),
					Underlay:          underlay,
					Subnet:            subnet,
					Dhcp:              dhcp,
					Pf:                pf,
					SpoofCheck:        spoofCheck,
					Project:           project,
					NetboxPrefixId:    int32(netboxID),
					Gateway:           gateway,
					ReservedAddresses: reserved,
				})
				if err != nil {
					// The server's own message, not a wrapped rpc error. This
					// RPC reports PARTIAL SUCCESS — "network X was created and
					// its NetBox binding is SUSPENDED" — and `%w` prefixed that
					// with "create network:" plus grpc's "rpc error: code = ...
					// desc =", so the line said failure while the sentence
					// inside said the network exists. status.Convert gives the
					// server's sentence verbatim.
					return errors.New(status.Convert(err).Message())
				}

				owner := ni.Project
				if owner == "" {
					owner = "global"
				}
				fmt.Printf("Network %s created (type=%s, project=%s)\n", ni.Name, ni.Type, owner)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&ntype, "type", "bridge", "Network type: bridge | vxlan | isolated | sriov")
	cmd.Flags().StringVar(&iface, "interface", "", "Bridge/interface name on host")
	cmd.Flags().IntVar(&vlan, "vlan", 0, "VLAN tag")
	cmd.Flags().IntVar(&vni, "vni", 0, "VXLAN VNI")
	cmd.Flags().StringVar(&underlay, "underlay", "", "Underlay interface for VXLAN")
	cmd.Flags().StringVar(&subnet, "subnet", "", "Subnet CIDR (e.g. 172.16.0.0/24)")
	cmd.Flags().BoolVar(&dhcp, "dhcp", false, "Enable DHCP on this network")
	cmd.Flags().StringVar(&pf, "pf", "", "SR-IOV physical function")
	cmd.Flags().BoolVar(&spoofCheck, "spoof-check", false, "Enable SR-IOV spoof checking")
	cmd.Flags().StringVar(&project, "project", "", "Owning project (empty = global/shared, usable by all projects)")
	cmd.Flags().IntVar(&netboxID, "netbox-prefix-id", 0,
		"bind this network to a NetBox prefix, claiming VM addresses from it")
	cmd.Flags().StringVar(&gateway, "gateway", "",
		"the network's router when it is not litevirt's (e.g. the upstream router of an external bridge); no guest NIC may claim it")
	cmd.Flags().StringSliceVar(&reserved, "reserved-address", nil,
		"an infrastructure address on the network no guest NIC may claim (repeatable)")
	return cmd
}

func newNetworkSetCmd() *cobra.Command {
	var (
		gateway    string
		reserved   []string
		vlans      []int
		unfiltered bool
	)
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a network's gateway, reserved addresses or allowed trunk VLANs",
		Long: `Change what a network keeps from its NICs (needs network.update on it):

  --gateway            its router when it is not litevirt's own; no guest NIC may claim it
  --reserved-address   further infrastructure addresses no guest NIC may claim (repeatable; replaces the list)
  --allowed-vlans      the VLANs a NIC on the trunk: feature may carry (replaces the list)
  --allow-unfiltered-access-vlan-moves=true|false
                       let lv migrate and lv host drain move a VM with an access-VLAN NIC
                       (trunk: with one VLAN) on this network onto a host whose bridge does
                       not filter VLANs, onto that bridge's untagged segment. Off by default;
                       needs the admin role; audited; lv health and lv doctor access-vlan-moves
                       name the network while it is on. Starts there are refused regardless.

Only the flags given change; an empty value clears that setting.

On a flat bridge (a network name with no network row, whose NICs attach to a
bridge of that name) only --allowed-vlans can be set, and it needs
network.update at the cluster root: no project owns a flat bridge.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.SetNetworkGuardConfigRequest{Name: args[0]}
			if cmd.Flags().Changed("gateway") {
				req.SetGateway, req.Gateway = true, gateway
			}
			if cmd.Flags().Changed("reserved-address") {
				req.SetReservedAddresses, req.ReservedAddresses = true, reserved
			}
			if cmd.Flags().Changed("allowed-vlans") {
				req.SetAllowedVlans = true
				for _, v := range vlans {
					req.AllowedVlans = append(req.AllowedVlans, int32(v))
				}
			}
			if cmd.Flags().Changed("allow-unfiltered-access-vlan-moves") {
				req.SetAllowUnfilteredAccessVlanMoves, req.AllowUnfilteredAccessVlanMoves = true, unfiltered
			}
			if !req.SetGateway && !req.SetReservedAddresses && !req.SetAllowedVlans && !req.SetAllowUnfilteredAccessVlanMoves {
				return errors.New("nothing to set: give --gateway, --reserved-address, --allowed-vlans or --allow-unfiltered-access-vlan-moves")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ni, err := c.SetNetworkGuardConfig(ctx, req)
				if err != nil {
					return errors.New(status.Convert(err).Message())
				}
				if err := unfilteredMovesTookEffect(req, ni); err != nil {
					return err
				}
				fmt.Printf("Network %s updated\n", ni.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&gateway, "gateway", "", "the network's router when it is not litevirt's; empty clears it")
	cmd.Flags().StringSliceVar(&reserved, "reserved-address", nil, "an infrastructure address no guest NIC may claim (repeatable; replaces the list)")
	cmd.Flags().IntSliceVar(&vlans, "allowed-vlans", nil, "the VLANs a trunk NIC on this network may carry (comma-separated; replaces the list)")
	cmd.Flags().BoolVar(&unfiltered, "allow-unfiltered-access-vlan-moves", false,
		"let migrate and drain move this network's access-VLAN VMs onto bridges that do not filter VLANs (admin; off by default)")
	return cmd
}

// unfilteredMovesTookEffect checks the reply of a set that asked to change
// the unfiltered-moves opt-in: a server on a build before the field ignores
// it and answers false, which for a request to turn it on means nothing
// changed.
func unfilteredMovesTookEffect(req *pb.SetNetworkGuardConfigRequest, ni *pb.NetworkInfo) error {
	if !req.GetSetAllowUnfilteredAccessVlanMoves() || ni.GetAllowUnfilteredAccessVlanMoves() == req.GetAllowUnfilteredAccessVlanMoves() {
		return nil
	}
	return fmt.Errorf("network %s: the server did not apply --allow-unfiltered-access-vlan-moves=%t (it runs a build that does not know it); "+
		"any other setting given was applied. Retry against a node on this release", req.GetName(), req.GetAllowUnfilteredAccessVlanMoves())
}

func newNetworkRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"delete"},
		Short:   "Delete a network",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{
					Name:  args[0],
					Force: force,
				})
				if err != nil {
					return fmt.Errorf("delete network: %w", err)
				}

				fmt.Printf("Network %s deleted\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Delete even if VMs or containers are attached (each host tears it down once nothing there uses it)")
	return cmd
}

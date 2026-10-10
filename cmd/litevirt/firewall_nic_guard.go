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

// newFirewallNICGuardCmd manages NIC guards: per-NIC anti-spoofing (source
// MAC/IP, ARP and neighbour advertisements, DHCP and router-advertisement
// servers). A NIC created by this release is guarded by default; a NIC that
// existed before has no guard until one is set here.
func newFirewallNICGuardCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "nic-guard", Short: "Manage per-NIC anti-spoofing guards"}

	var (
		mac, network, mode string
		allow              []string
		dhcpServer, ra     bool
	)
	set := &cobra.Command{
		Use:   "set <vm>",
		Short: "Replace a VM NIC's guard (needs cluster-root network authority)",
		Long: `Replaces one VM NIC's guard. --mode on guards the NIC: it may send only
from its own MAC, from the addresses litevirt assigned it and the --allow list,
and may not answer DHCP or send router advertisements unless allowed. --mode off
turns the guard off. --allow replaces the whole list, so repeat every address
the guest needs (a VIP, a VRRP address, a static secondary address or a routed
prefix).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if mac == "" && network == "" {
				return fmt.Errorf("name the NIC with --mac or --network")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				g, err := c.SetNICGuard(ctx, &pb.SetNICGuardRequest{
					VmName: args[0], Mac: mac, NetworkName: network, Mode: mode,
					AllowedAddresses: allow, AllowDhcpServer: dhcpServer, AllowRouterAdvertisement: ra,
				})
				if err != nil {
					return err
				}
				fmt.Printf("NIC guard of %s %s: %s\n", g.VmName, g.Mac, g.Mode)
				return nil
			})
		},
	}
	set.Flags().StringVar(&mac, "mac", "", "the NIC's MAC address")
	set.Flags().StringVar(&network, "network", "", "the NIC's network (when the VM has one NIC on it)")
	set.Flags().StringVar(&mode, "mode", "on", "on | off")
	set.Flags().StringArrayVar(&allow, "allow", nil, "extra source address or prefix the guest may use (repeatable)")
	set.Flags().BoolVar(&dhcpServer, "allow-dhcp-server", false, "let the guest answer DHCP (v4 and v6)")
	set.Flags().BoolVar(&ra, "allow-router-advertisement", false, "let the guest send router advertisements and redirects")

	ls := &cobra.Command{
		Use:   "ls [vm]",
		Short: "List NIC guards and the source addresses each lets the NIC use",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ListNICGuardsRequest{}
			if len(args) == 1 {
				req.VmName = args[0]
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNICGuards(ctx, req)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "VM\tMAC\tNETWORK\tMODE\tIPV4\tIPV6\tALLOWED\tDHCP-SERVER\tROUTER-ADV")
				for _, g := range resp.Guards {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\t%t\n", g.VmName, g.Mac, g.NetworkName, g.Mode,
						guardFamily(g.Mode, g.EffectiveIpv4, g.Ipv4Unrestricted), guardFamily(g.Mode, g.EffectiveIpv6, g.Ipv6Unrestricted),
						strings.Join(g.AllowedAddresses, ","), g.AllowDhcpServer, g.AllowRouterAdvertisement)
				}
				return w.Flush()
			})
		},
	}
	cmd.AddCommand(set, ls)
	return cmd
}

// guardFamily renders the sources one address family may use.
func guardFamily(mode string, addrs []string, open bool) string {
	switch {
	case mode != "on":
		return "-"
	case open:
		return "any"
	}
	return strings.Join(addrs, ",")
}

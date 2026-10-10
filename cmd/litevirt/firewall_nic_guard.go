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
		mac, network, mode      string
		container, ctHost       string
		allow                   []string
		dhcpServer, ra, vlanTag bool
	)
	set := &cobra.Command{
		Use:   "set [vm]",
		Short: "Replace a VM or container NIC's guard (needs network authority over its network)",
		Long: `Replaces one VM NIC's guard. --mode on guards the NIC: it may send only
from its own MAC, from the addresses litevirt assigned it and the --allow list,
and may not answer DHCP or send router advertisements unless allowed. --mode off
turns the guard off. --allow replaces the whole list, so repeat every address
the guest needs (a VIP, a VRRP address, a static secondary address or a routed
prefix).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if mac == "" && network == "" {
				return fmt.Errorf("name the NIC with --mac or --network")
			}
			if (len(args) == 1) == (container != "") {
				return fmt.Errorf("name a VM as the argument, or a container with --container and --host")
			}
			req := &pb.SetNICGuardRequest{Mac: mac, NetworkName: network, Mode: mode,
				AllowedAddresses: allow, AllowDhcpServer: dhcpServer, AllowRouterAdvertisement: ra, AllowVlanTags: vlanTag}
			if container != "" {
				req.ContainerName, req.ContainerHost = container, ctHost
			} else {
				req.VmName = args[0]
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				g, err := c.SetNICGuard(ctx, req)
				if err != nil {
					return err
				}
				who := g.VmName
				if who == "" {
					who = g.ContainerHost + "/" + g.ContainerName
				}
				fmt.Printf("NIC guard of %s %s: %s\n", who, g.Mac, g.Mode)
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
	set.Flags().BoolVar(&vlanTag, "allow-vlan-tags", false, "let the guest send 802.1Q/802.1ad tagged frames (a trunk)")
	set.Flags().StringVar(&container, "container", "", "a container's NIC instead of a VM's (with --host)")
	set.Flags().StringVar(&ctHost, "host", "", "the container's host (with --container)")

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

// newFirewallEnforceCmd switches per-NIC enforcement between observe (count
// what would be dropped) and enforce, and reports it.
func newFirewallEnforceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enforce <on|off|status>",
		Short: "Enforce per-NIC firewall rules (on), only observe them (off), or show the state and would-drop counts",
		Long: `A cluster that upgraded to this release starts in observe mode: per-NIC rules
are installed with counters and drop nothing. "status" shows, per host, the
mode in force and what the rules would have dropped (per NIC and rule); once
those counts are what you expect, "on" enforces them. "off" goes back to
observing. Admin only; audited; applies to every host.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var st *pb.FirewallEnforcementStatus
				var err error
				switch args[0] {
				case "on":
					st, err = c.SetFirewallEnforcement(ctx, &pb.SetFirewallEnforcementRequest{Mode: "enforce"})
				case "off":
					st, err = c.SetFirewallEnforcement(ctx, &pb.SetFirewallEnforcementRequest{Mode: "observe"})
				case "status":
					st, err = c.GetFirewallEnforcement(ctx, &pb.GetFirewallEnforcementRequest{})
				default:
					return fmt.Errorf("want on, off or status, not %q", args[0])
				}
				if err != nil {
					return err
				}
				return printEnforcement(st)
			})
		},
	}
}

func printEnforcement(st *pb.FirewallEnforcementStatus) error {
	fmt.Printf("per-NIC enforcement: %s", st.Mode)
	if st.SetBy != "" {
		fmt.Printf(" (set by %s at %s)", st.SetBy, st.UpdatedAt)
	}
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tIN FORCE\tDEVICE\tWORKLOAD\tSIDE\tRULE\tWOULD-DROP PKTS\tERROR")
	for _, h := range st.Hosts {
		mode := h.AppliedMode
		if mode == "" {
			mode = "-"
		}
		if len(h.WouldDrops) == 0 {
			fmt.Fprintf(w, "%s\t%s\t\t\t\t\t\t%s\n", h.HostName, mode, h.Error)
		}
		for _, d := range h.WouldDrops {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", h.HostName, mode, d.Device, d.Workload, d.Side, d.Rule, d.Packets, h.Error)
		}
	}
	return w.Flush()
}

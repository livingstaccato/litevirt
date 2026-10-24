package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/pci"
)

// newHostMIGCmd attaches `lv host mig …` to the host group. Like `lv host
// ceph`, these are host-local: they run nvidia-smi on the host you are logged
// in to, as the user running lv (MIG changes need root). <gpu> is anything
// nvidia-smi -i takes: an index, a PCI bus ID or a GPU UUID.
func newHostMIGCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mig",
		Short: "Manage NVIDIA Multi-Instance GPU partitions on this host (nvidia-smi wrapper)",
	}
	cmd.AddCommand(
		newHostMIGLsCmd(),
		newHostMIGEnableCmd(),
		newHostMIGDisableCmd(),
		newHostMIGCreateCmd(),
		newHostMIGDestroyCmd(),
	)
	return cmd
}

func newHostMIGLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List this host's GPUs, their MIG mode and their MIG instances",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gpus, err := pci.ListMIGGPUs()
			if err != nil {
				return err
			}
			var instances []pci.MIGInstance
			for _, g := range gpus {
				if g.Current == "Enabled" {
					if instances, err = pci.ListMIGInstances(); err != nil {
						return err
					}
					break
				}
			}
			return printMIG(cmd.OutOrStdout(), gpus, instances)
		},
	}
}

func printMIG(out io.Writer, gpus []pci.MIGGPU, instances []pci.MIGInstance) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "GPU\tBUS ID\tNAME\tMIG\tPENDING")
	for _, g := range gpus {
		mode := g.Current
		if !g.MIGCapable() {
			mode = "unsupported"
		}
		pending := "-"
		if g.Pending != g.Current && g.MIGCapable() {
			pending = g.Pending + " (needs GPU reset)"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", g.Index, g.BusID, g.Name, mode, pending)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(instances) == 0 {
		return nil
	}
	fmt.Fprintln(out)
	w = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "GPU\tINSTANCE\tPROFILE\tPROFILE ID\tPLACEMENT")
	for _, in := range instances {
		fmt.Fprintf(w, "%d\t%d\t%s\t%d\t%s\n", in.GPUIndex, in.InstanceID, in.Profile, in.ProfileID, in.Placement)
	}
	return w.Flush()
}

func newHostMIGEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <gpu>",
		Short: "Enable MIG mode on a GPU (no process may be using it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := pci.EnableMIG(args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil
		},
	}
}

func newHostMIGDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <gpu>",
		Short: "Disable MIG mode on a GPU (destroy its MIG instances first)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := pci.DisableMIG(args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil
		},
	}
}

func newHostMIGCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <gpu> <profile>",
		Short: "Create a MIG instance of a profile (e.g. 3g.20gb) with its default compute instance",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := pci.CreateMIGInstance(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created MIG instance %d (%s) on GPU %d\n", in.InstanceID, in.Profile, in.GPUIndex)
			return nil
		},
	}
}

func newHostMIGDestroyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "destroy <gpu> <instance-id>",
		Short: "Destroy a MIG instance and its compute instances",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.Atoi(strings.TrimSpace(args[1]))
			if err != nil {
				return fmt.Errorf("instance id %q: %w", args[1], err)
			}
			if err := pci.DestroyMIGInstance(args[0], id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Destroyed MIG instance %d on GPU %s\n", id, args[0])
			return nil
		},
	}
}

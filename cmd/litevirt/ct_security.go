package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newCTInspectCmd shows one container, its security settings included.
func newCTInspectCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show a container: placement, limits, privilege mode and confinement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListContainers(ctx, &pb.ListContainersRequest{HostName: host})
				if err != nil {
					return err
				}
				var found []*pb.Container
				for _, ct := range resp.Containers {
					if ct.Name == args[0] {
						found = append(found, ct)
					}
				}
				switch len(found) {
				case 0:
					return fmt.Errorf("container %q not found", args[0])
				case 1:
					writeContainerInspect(os.Stdout, found[0])
					return nil
				}
				return fmt.Errorf("container %q exists on %d hosts; pass --host", args[0], len(found))
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Owning host (default: resolve by name)")
	return cmd
}

func writeContainerInspect(out io.Writer, ct *pb.Container) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Name:\t%s\n", ct.Name)
	fmt.Fprintf(w, "Host:\t%s\n", ct.HostName)
	fmt.Fprintf(w, "Project:\t%s\n", ct.Project)
	fmt.Fprintf(w, "State:\t%s\n", ct.State)
	if ct.StateDetail != "" {
		fmt.Fprintf(w, "State detail:\t%s\n", ct.StateDetail)
	}
	fmt.Fprintf(w, "Image:\t%s\n", ct.Image)
	fmt.Fprintf(w, "CPU limit:\t%d\n", ct.CpuLimit)
	fmt.Fprintf(w, "Memory (MiB):\t%d\n", ct.MemoryMib)
	if ct.Privileged {
		fmt.Fprintf(w, "Privileged:\tyes (root in the container is root on the host; move it: lv ct convert --unprivileged %s)\n", ct.Name)
	} else {
		fmt.Fprintf(w, "Privileged:\tno (ids %d-%d)\n", ct.IdmapBase, ct.IdmapBase+65535)
	}
	fmt.Fprintf(w, "Confinement:\t%s\n", ct.Confinement)
	fmt.Fprintf(w, "Created:\t%s\n", ct.CreatedAt)
}

// newCTConvertCmd changes a stopped container's security settings in place.
func newCTConvertCmd() *cobra.Command {
	var host, confinement string
	var unprivileged bool
	cmd := &cobra.Command{
		Use:   "convert <name>",
		Short: "Convert a stopped container: --unprivileged moves it into an id range of its own; --confinement default|legacy",
		Long: `Change a STOPPED container's security settings in place.

--unprivileged gives the container an id range of its own and shifts every file
of its rootfs into it (owners, ACLs, file capabilities); nothing is copied or
removed. Run on an unprivileged container, it moves it to a fresh range.
--confinement default sets LXC's generated AppArmor profile without nesting, its
common seccomp policy and the standard capability drop list; legacy (Admin only)
restores what earlier releases wrote.

A convert that is interrupted leaves the container refusing to start; run the
same command again to finish it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				ct, err := c.ConvertContainer(ctx, &pb.ConvertContainerRequest{
					Name: args[0], HostName: host, Unprivileged: unprivileged, Confinement: confinement,
				})
				if err != nil {
					return err
				}
				writeContainerInspect(os.Stdout, ct)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Owning host (default: resolve by name)")
	cmd.Flags().BoolVar(&unprivileged, "unprivileged", false, "Move the container into an id range of its own")
	cmd.Flags().StringVar(&confinement, "confinement", "", "default | legacy (legacy needs the Admin role)")
	return cmd
}

// privilegedContainers selects containers that run privileged or with legacy
// confinement, in list order.
func privilegedContainers(cts []*pb.Container) []*pb.Container {
	var out []*pb.Container
	for _, ct := range cts {
		if ct.Privileged || ct.Confinement != "default" {
			out = append(out, ct)
		}
	}
	return out
}

// newDoctorPrivilegedContainersCmd reports privileged and legacy-confined
// containers.
func newDoctorPrivilegedContainersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "privileged-containers",
		Short: "Report containers that run privileged or with legacy confinement",
		Long: `List containers whose root is the host's root (privileged: no user namespace)
or whose confinement is legacy (AppArmor nesting allowed, the template's seccomp
policy and capabilities). Containers created by earlier releases are both, and
keep running as they are.

Read-only. To move one over, stop it and run lv ct convert --unprivileged
--confinement default <name>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListContainers(ctx, &pb.ListContainersRequest{})
				if err != nil {
					return fmt.Errorf("list containers: %w", err)
				}
				found := privilegedContainers(resp.GetContainers())
				if len(found) == 0 {
					fmt.Println("every container is unprivileged with the default confinement")
					return nil
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "CONTAINER\tHOST\tPRIVILEGED\tCONFINEMENT")
				for _, ct := range found {
					fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", ct.Name, ct.HostName, ct.Privileged, ct.Confinement)
				}
				w.Flush()
				fmt.Printf("\n%d container(s). Move one over while it is stopped: lv ct convert --unprivileged --confinement default <name>\n", len(found))
				return nil
			})
		},
	}
}

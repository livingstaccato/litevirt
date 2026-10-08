package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newCTInspectCmd shows one container's detail: the container analogue of
// `lv inspect <vm>`.
func newCTInspectCmd() *cobra.Command {
	var host, output string
	var size bool
	cmd := &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show container details",
		Long: `Show one container: host, state, image, project, CPU and memory limits,
privilege mode (read from its LXC config on its host), NICs and addresses,
rootfs (and its size with --size), snapshots, backups and timestamps.

Each backup entry is checked on whichever host holds its repository: it is
available there, not found anywhere, or unknown when a host could not be
asked. Entries that cannot be tied to this container (for example a same-named
container in another project) are shown only to an admin. If the container's
host cannot be reached, the cluster view is shown and the host-local fields
are unknown.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("unknown output format %q (text or json)", output)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				d, err := c.InspectContainer(ctx, &pb.InspectContainerRequest{Name: args[0], HostName: host, MeasureRootfs: size})
				if err != nil {
					return fmt.Errorf("inspect container: %w", err)
				}
				if output == "json" {
					b, merr := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(d)
					if merr != nil {
						return merr
					}
					_, err := os.Stdout.Write(append(b, '\n'))
					return err
				}
				return printContainerDetail(d)
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Owning host (default: resolve by name)")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&size, "size", false, "Measure the rootfs size (walks the tree on the owning host)")
	return cmd
}

func printContainerDetail(d *pb.ContainerDetail) error {
	c := d.GetContainer()
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	field := func(k, v string) { fmt.Fprintf(w, "%s\t%s\n", k+":", v) }
	orDash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	field("Name", c.GetName())
	field("Host", c.GetHostName())
	state := c.GetState()
	if c.GetStateDetail() != "" {
		state += " (" + c.GetStateDetail() + ")"
	}
	field("State", state)
	field("Image", orDash(c.GetImage()))
	if d.GetTemplate() != "" || d.GetDistro() != "" {
		field("Template", strings.TrimSpace(strings.Join([]string{d.GetTemplate(), d.GetDistro(), d.GetRelease(), d.GetArch()}, " ")))
	}
	field("Project", orDash(c.GetProject()))
	cpu := "unlimited"
	if c.GetCpuLimit() > 0 {
		cpu = fmt.Sprintf("%d", c.GetCpuLimit())
	}
	field("CPU limit", cpu)
	mem := "unlimited"
	if c.GetMemoryMib() > 0 {
		mem = fmt.Sprintf("%d MiB", c.GetMemoryMib())
	}
	field("Memory", mem)
	field("Privilege", d.GetPrivilege())
	if d.GetIsTemplate() {
		field("Clone template", "yes")
	}
	if r := c.GetRestart(); r != nil && r.GetCondition() != "" && r.GetCondition() != "none" {
		field("Restart", r.GetCondition())
	}
	rootfs := orDash(d.GetRootfsPath())
	if d.GetRootfsBytes() >= 0 {
		rootfs += " (" + formatBytes(d.GetRootfsBytes()) + ")"
	}
	field("Rootfs", rootfs)
	field("Created", orDash(c.GetCreatedAt()))
	field("Updated", orDash(c.GetUpdatedAt()))
	if err := w.Flush(); err != nil {
		return err
	}
	if !d.GetHostDetail() {
		fmt.Printf("\n(host %s did not answer: privilege, rootfs and backup availability are unknown)\n", c.GetHostName())
	}

	fmt.Println("\nNetworks:")
	if len(d.GetInterfaces()) == 0 {
		fmt.Println("  none")
	} else {
		t := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(t, "  NIC\tNETWORK\tADDRESS\tMAC\tVETH")
		for _, n := range d.GetInterfaces() {
			net := n.GetNetworkName()
			if net == "" {
				net = "bridge:" + n.GetBridge()
			}
			addr := n.GetIp()
			if addr == "" {
				addr = "dhcp"
			}
			fmt.Fprintf(t, "  %s\t%s\t%s\t%s\t%s\n", orDash(n.GetName()), net, addr, orDash(n.GetMac()), orDash(n.GetVeth()))
		}
		if err := t.Flush(); err != nil {
			return err
		}
	}

	fmt.Println("\nSnapshots:")
	if len(d.GetSnapshots()) == 0 {
		fmt.Println("  none")
	} else {
		t := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(t, "  NAME\tSIZE\tCREATED")
		for _, s := range d.GetSnapshots() {
			fmt.Fprintf(t, "  %s\t%s\t%s\n", s.GetName(), formatBytes(s.GetSizeBytes()), s.GetCreatedAt())
		}
		if err := t.Flush(); err != nil {
			return err
		}
	}

	fmt.Println("\nBackups:")
	if len(d.GetBackups()) == 0 {
		fmt.Println("  none")
		return nil
	}
	t := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(t, "  REPO\tSIZE\tUPDATED\tSTATUS")
	for _, b := range d.GetBackups() {
		st := backupStatusText(b)
		fmt.Fprintf(t, "  %s\t%s\t%s\t%s\n", b.GetRepo(), formatBytes(b.GetTotalBytes()), orDash(b.GetUpdatedAt()), st)
	}
	return t.Flush()
}

func backupStatusText(b *pb.ContainerBackupRef) string {
	var st string
	switch b.GetStatus() {
	case "available":
		st = "available"
		if b.GetLocation() != "" {
			st += " on " + b.GetLocation()
		}
		return st
	case "not_found":
		st = "not found"
	case "foreign":
		st = "another project's"
	case "unknown":
		st = "unknown"
	default:
		// An older daemon sends only available + reason.
		if b.GetAvailable() {
			return "available"
		}
		st = "unavailable"
	}
	if b.GetUnavailableReason() != "" {
		st += ": " + b.GetUnavailableReason()
	}
	return st
}

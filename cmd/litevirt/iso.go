package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lv iso — installer ISO libraries (docs/storage.md, "Installer ISOs"). A VM
// names its ISO as <pool>/<file>.iso; these commands list, fill and empty the
// libraries those references point into.
func newISOCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iso",
		Short: "List and manage installer ISO libraries (<pool>/<file>.iso)",
	}
	cmd.AddCommand(newISOLsCmd(), newISOPullCmd(), newISORmCmd())
	return cmd
}

func newISOLsCmd() *cobra.Command {
	var host, project string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the ISOs a VM may name: your project libraries, then the global library",
		Long: `List the installer ISOs on a host, as the references VMSpec.iso, a compose file's iso: and the UI take:
your projects' libraries first, then the cluster-global library "isos".

In sync mode (lv cluster iso-library-mode), SYNC says whether this host's copy
of a global-library ISO matches the library: a VM starts only where it is "ok".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListISOs(ctx, &pb.ListISOsRequest{Host: host, Project: project})
				if err != nil {
					return fmt.Errorf("list ISOs: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "REF\tLIBRARY\tSIZE\tSYNC")
				for _, e := range resp.GetIsos() {
					lib := "global"
					if !e.GetGlobal() {
						lib = "project " + e.GetProject()
					}
					syncState := e.GetSyncState()
					if syncState == "" {
						syncState = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.GetRef(), lib, formatBytes(e.GetSizeBytes()), syncState)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host whose libraries to list (default: the connected host)")
	cmd.Flags().StringVar(&project, "project", "", "only this project's libraries (and the global one)")
	return cmd
}

func newISOPullCmd() *cobra.Command {
	var host, url, hostPath, checksum string
	cmd := &cobra.Command{
		Use:   "pull <pool>/<file>.iso",
		Short: "Copy an ISO into a library from a URL or a host path",
		Long: `Copy an ISO into a library under the given name.

  --url             download it, under the same limits as an image pull
                    (http/https only, the byte ceiling, the timeout and the
                    image_pull_blocked_cidrs network policy)
  --from-host-path  copy a file on the host (Admin only: it reads that file).
                    The file is copied, never linked, so a link such as
                    /usr/share/virtio-win/virtio-win.iso is fine to name.

The global library "isos" is written only by an Admin; a project library (a
pool your project owns with --option content=iso) by the project's operators.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (url == "") == (hostPath == "") {
				return fmt.Errorf("give exactly one of --url or --from-host-path")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.PullISO(ctx, &pb.PullISORequest{
					Ref: args[0], Host: host, Url: url, HostPath: hostPath, Checksum: checksum,
				})
				if err != nil {
					return fmt.Errorf("pull ISO: %w", err)
				}
				fmt.Printf("%s: %s, sha256 %s\n", resp.GetRef(), formatBytes(resp.GetSizeBytes()), resp.GetSha256())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host whose library receives it (default: the connected host)")
	cmd.Flags().StringVar(&url, "url", "", "http(s) URL to download")
	cmd.Flags().StringVar(&hostPath, "from-host-path", "", "absolute path of a file on that host to copy (Admin)")
	cmd.Flags().StringVar(&checksum, "checksum", "", "sha256 the copy must match")
	return cmd
}

func newISORmCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "rm <pool>/<file>.iso",
		Short: "Remove an ISO from a library",
		Long: `Remove an ISO from a library. In sync mode a removal from the global library
is recorded and every host removes its copy.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pool, file, ok := strings.Cut(args[0], "/")
			if !ok || pool == "" || file == "" || strings.Contains(file, "/") {
				return fmt.Errorf("%q is not <pool>/<file>.iso", args[0])
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{
					PoolName: pool, Host: host, Filename: file,
				}); err != nil {
					return fmt.Errorf("remove ISO: %w", err)
				}
				fmt.Printf("%s removed\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host whose library to remove it from (default: the connected host)")
	return cmd
}

// lv cluster iso-library-mode [sync|shared]
func newClusterISOLibraryModeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "iso-library-mode [sync|shared]",
		Short: "Show or set where the global ISO library lives",
		Long: `With no argument, show where the cluster-global ISO library ("isos") lives.

  sync    (the default) every host keeps a local copy. An upload or pull to
          one host is recorded with its sha256 and copied to every other host
          by the daemon, which verifies it; a VM starts only on a host whose
          copy matches.
  shared  the isos pool is on shared storage that every host mounts (create
          it on each host with 'lv pool create isos --driver nfs ...
          --option content=iso'), so every host already sees the same files.

Switching to sync records the files the connected host's library holds, so
they reach every other host. Changing it needs the admin role and refuses
until every host runs a release that knows it (failover_scope_v1).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var st *pb.ISOLibraryMode
				var err error
				if len(args) == 1 {
					st, err = c.SetISOLibraryMode(ctx, &pb.SetISOLibraryModeRequest{Mode: args[0]})
				} else {
					st, err = c.GetISOLibraryMode(ctx, &emptypb.Empty{})
				}
				if err != nil {
					return fmt.Errorf("ISO library mode: %w", err)
				}
				fmt.Printf("ISO library mode: %s\n", st.GetMode())
				if st.GetSetBy() != "" {
					fmt.Printf("Set by:           %s at %s\n", st.GetSetBy(), st.GetUpdatedAt())
				}
				if !st.GetSettable() {
					fmt.Println("Changeable:       no — failover_scope_v1 has not latched on every host yet")
				}
				return nil
			})
		},
	}
}

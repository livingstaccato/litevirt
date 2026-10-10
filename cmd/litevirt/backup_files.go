package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/filerestore/wire"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Single-file restore. The daemon reads the backup inside a throwaway
// restore VM (docs/design/backup-file-restore.md); these commands only
// browse and receive the result.

type backupFileTarget struct {
	repo, vm, ct, disk, ts string
}

func (b *backupFileTarget) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&b.repo, "repo", "", "Backup repo (registered name, or an absolute path as admin)")
	cmd.Flags().StringVar(&b.vm, "vm", "", "VM the backup is of")
	cmd.Flags().StringVar(&b.ct, "ct", "", "Container the backup is of (instead of --vm)")
	cmd.Flags().StringVar(&b.disk, "disk", "", "Disk name (default: root for a VM; a container has one, rootfs)")
	cmd.Flags().StringVar(&b.ts, "timestamp", "", "Backup timestamp (exact RFC3339, as `lv backup repo ls` shows)")
}

func (b *backupFileTarget) resolve() (name, disk string, err error) {
	switch {
	case b.repo == "" || b.ts == "":
		return "", "", errors.New("--repo and --timestamp are required")
	case (b.vm == "") == (b.ct == ""):
		return "", "", errors.New("name the backup with exactly one of --vm or --ct")
	case b.ct != "":
		disk = b.disk
		if disk == "" {
			disk = "rootfs"
		}
		return b.ct, disk, nil
	default:
		disk = b.disk
		if disk == "" {
			disk = "root"
		}
		return b.vm, disk, nil
	}
}

// printable escapes a name from a backup, which is guest data: control,
// C1 and bidi characters must not drive or spoof the terminal.
func printable(s string) string { return wire.Escape(s) }

func newBackupFileLsCmd() *cobra.Command {
	var t backupFileTarget
	cmd := &cobra.Command{
		Use:   "file-ls [path]",
		Short: "List files inside a backup without restoring it",
		Long: `List a directory inside a VM or container backup.

"/" (the default) lists the backup's volumes: each partition (vda1, vda2, …),
the whole disk (vda) when it has no partition table, or rootfs for a
container. Then list "/<volume>/<dir>".

The daemon reads the backup inside a throwaway restore VM — this host's
kernel, no network, the backup attached read-only — and never mounts it on the
host. It needs KVM and vhost-vsock on the daemon's host; without them it says
so, and a full restore (restore-from) still works. Supported filesystems: ext2/3/4,
xfs, btrfs, vfat, iso9660 on a disk or on its partitions (no LVM, LUKS or ZFS).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, disk, err := t.resolve()
			if err != nil {
				return err
			}
			path := "/"
			if len(args) == 1 {
				path = args[0]
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{
					RepoPath: t.repo, Name: name, DiskName: disk, Timestamp: t.ts, Path: path,
				})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "TYPE\tMODE\tSIZE\tMODIFIED\tNAME")
				for _, e := range resp.Entries {
					name := printable(e.Name)
					if e.Type == "symlink" && e.LinkTarget != "" {
						name += " -> " + printable(e.LinkTarget)
					}
					size := ""
					if e.Type == "file" {
						size = formatBytes(e.Size)
					}
					fmt.Fprintf(w, "%s\t%04o\t%s\t%s\t%s\n", e.Type, e.Mode, size,
						time.Unix(e.MtimeUnix, 0).UTC().Format("2006-01-02 15:04"), name)
				}
				if err := w.Flush(); err != nil {
					return err
				}
				if resp.Truncated {
					fmt.Fprintln(os.Stderr, "(listing truncated: the directory has more entries than one listing returns)")
				}
				if resp.Skipped > 0 {
					fmt.Fprintf(os.Stderr, "(%d entries left out: names that are invalid or not UTF-8)\n", resp.Skipped)
				}
				return nil
			})
		},
	}
	t.flags(cmd)
	return cmd
}

func newBackupFileRestoreCmd() *cobra.Command {
	var t backupFileTarget
	var output string
	var maxBytes string
	cmd := &cobra.Command{
		Use:   "file-restore <path>... -o <archive.tar>",
		Short: "Extract files from a backup as a tar archive",
		Long: `Extract files and directories from a VM or container backup.

Paths are as file-ls shows them ("/<volume>/<path>"). The result is a tar
archive written to -o (a new file; "-" for stdout); nothing is written on the
daemon's host. The archive holds only directories, regular files and symlinks,
with permission bits but no owners, setuid bits or extended attributes;
symlinks only with relative targets inside the archive (others are left out
and counted), and nothing under a symlink.

Extract each archive into a new, empty directory (GNU tar:
tar -xf files.tar --no-overwrite-dir -C <new dir>): two archives of the same
backup extracted into one directory could otherwise meet a symlink from the
first with a path from the second.

Needs the same permission as a full restore of the VM or container; every
extraction is audited (backup.file_restore).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, disk, err := t.resolve()
			if err != nil {
				return err
			}
			if output == "" {
				return errors.New("-o is required: a new archive file, or - for stdout")
			}
			limit, err := pbsstore.ParseSize(maxBytes)
			if err != nil {
				return fmt.Errorf("--max-bytes: %w", err)
			}
			var w io.Writer = os.Stdout
			var f *os.File
			if output != "-" {
				// Never over an existing file.
				f, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return err
				}
				w = f
			}
			ok := false
			defer func() {
				if f != nil {
					f.Close()
					if !ok {
						os.Remove(output)
					}
				}
			}()
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.RestoreBackupFiles(ctx, &pb.RestoreBackupFilesRequest{
					RepoPath: t.repo, Name: name, DiskName: disk, Timestamp: t.ts, Paths: args, MaxBytes: limit,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return errors.New("the daemon ended the extraction without a final frame")
					}
					if err != nil {
						return err
					}
					if len(p.Data) > 0 {
						if _, err := w.Write(p.Data); err != nil {
							return err
						}
					}
					if p.Done {
						ok = true
						fmt.Fprintf(os.Stderr, "[done] %s\n", p.Status)
						return nil
					}
				}
			})
		},
	}
	t.flags(cmd)
	cmd.Flags().StringVarP(&output, "output", "o", "", "Archive to write (a new file), or - for stdout")
	cmd.Flags().StringVar(&maxBytes, "max-bytes", "", "Stop after this many bytes of file data (e.g. 2G); can only lower the daemon's limit")
	return cmd
}

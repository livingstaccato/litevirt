package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup and restore VMs",
	}
	cmd.AddCommand(
		newBackupRepoCmd(),
		newBackupSnapshotCmd(),
		newBackupRestoreFromCmd(),
		newBackupRestoreLiveCmd(),
		newBackupFileLsCmd(),
		newBackupFileRestoreCmd(),
		newBackupScheduleCmd(),
	)
	return cmd
}

// newBackupScheduleCmd is the schedule surface — operators
// add/list/rm cron-driven schedules; the daemon scheduler ticks every
// minute and dispatches matching rows.
func newBackupScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage cron-driven backup schedules",
	}
	cmd.AddCommand(
		newBackupScheduleAddCmd(),
		newBackupScheduleListCmd(),
		newBackupScheduleRmCmd(),
	)
	return cmd
}

func newBackupScheduleAddCmd() *cobra.Command {
	var repo, cron, scope, poolName, projectName string
	var keepLast, keepDaily, keepWeekly, keepMonthly, keepYearly int32
	var disabled bool
	cmd := &cobra.Command{
		Use:   "add [vm]",
		Short: "Add or replace a backup schedule (per-VM, per-pool, per-project, or cluster-wide)",
		Long: `Schedules a backup on a cron. The default scope is a single VM (pass <vm>).
Use --pool to back up every VM whose disks live on a storage pool, --project for
every VM in a tenancy project, or --scope cluster for every VM in the cluster.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := ""
			if len(args) == 1 {
				vmName = args[0]
			}
			// Infer the scope from which target the operator supplied, unless
			// --scope was given explicitly.
			if scope == "" {
				switch {
				case poolName != "":
					scope = "pool"
				case projectName != "":
					scope = "project"
				case vmName != "":
					scope = "vm"
				default:
					return fmt.Errorf("specify a <vm>, --pool, --project, or --scope cluster")
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				req := &pb.CreateBackupScheduleRequest{
					VmName: vmName, Repo: repo, Cron: cron,
					Scope: scope, PoolName: poolName, ProjectName: projectName,
					KeepLast: keepLast, KeepDaily: keepDaily, KeepWeekly: keepWeekly,
					KeepMonthly: keepMonthly, KeepYearly: keepYearly,
					Enabled: !disabled,
				}
				s, err := c.CreateBackupSchedule(ctx, req)
				if err != nil {
					return fmt.Errorf("create schedule: %w", err)
				}
				fmt.Printf("schedule %s/%s added (scope=%s, cron=%q, enabled=%v)\n", s.VmName, s.Repo, s.Scope, s.Cron, s.Enabled)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "logical repo name (must match daemon backup_repos config)")
	cmd.Flags().StringVar(&cron, "cron", "", `5-field cron expression (e.g. "0 2 * * *")`)
	cmd.Flags().StringVar(&scope, "scope", "", "schedule scope: vm | pool | project | cluster (default: inferred)")
	cmd.Flags().StringVar(&poolName, "pool", "", "storage pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project", "", "tenancy project name (scope=project)")
	cmd.Flags().Int32Var(&keepLast, "keep-last", 0, "retention: keep N most-recent")
	cmd.Flags().Int32Var(&keepDaily, "keep-daily", 0, "retention: keep N daily")
	cmd.Flags().Int32Var(&keepWeekly, "keep-weekly", 0, "retention: keep N weekly")
	cmd.Flags().Int32Var(&keepMonthly, "keep-monthly", 0, "retention: keep N monthly")
	cmd.Flags().Int32Var(&keepYearly, "keep-yearly", 0, "retention: keep N yearly")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the schedule disabled")
	_ = cmd.MarkFlagRequired("repo")
	_ = cmd.MarkFlagRequired("cron")
	return cmd
}

func newBackupScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List configured backup schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListBackupSchedules(ctx, &pb.ListBackupSchedulesRequest{})
				if err != nil {
					return fmt.Errorf("list schedules: %w", err)
				}
				if len(resp.Schedules) == 0 {
					fmt.Println("(no schedules)")
					return nil
				}
				fmt.Printf("%-22s %-9s %-12s %-15s %-7s %-25s %s\n", "TARGET", "SCOPE", "REPO", "CRON", "ENABLED", "LAST RUN", "LAST ERR")
				for _, s := range resp.Schedules {
					fmt.Printf("%-22s %-9s %-12s %-15s %-7v %-25s %s\n",
						s.VmName, defaultStr(s.Scope, "vm"), s.Repo, s.Cron, s.Enabled, defaultStr(s.LastRunAt, "-"), defaultStr(s.LastRunErr, "-"))
				}
				return nil
			})
		},
	}
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func newBackupScheduleRmCmd() *cobra.Command {
	var repo, scope, poolName, projectName string
	cmd := &cobra.Command{
		Use:   "rm [vm]",
		Short: "Remove a backup schedule (per-VM, per-pool, per-project, or cluster-wide)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := ""
			if len(args) == 1 {
				vmName = args[0]
			}
			if scope == "" {
				switch {
				case poolName != "":
					scope = "pool"
				case projectName != "":
					scope = "project"
				case vmName != "":
					scope = "vm"
				default:
					return fmt.Errorf("specify a <vm>, --pool, --project, or --scope cluster")
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteBackupSchedule(ctx, &pb.DeleteBackupScheduleRequest{
					VmName: vmName, Repo: repo, Scope: scope, PoolName: poolName, ProjectName: projectName,
				}); err != nil {
					return fmt.Errorf("delete schedule: %w", err)
				}
				fmt.Printf("schedule removed (scope=%s, repo=%s)\n", scope, repo)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "logical repo name (required to disambiguate)")
	cmd.Flags().StringVar(&scope, "scope", "", "schedule scope: vm | pool | project | cluster (default: inferred)")
	cmd.Flags().StringVar(&poolName, "pool", "", "storage pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project", "", "tenancy project name (scope=project)")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

// newBackupSnapshotCmd is the gRPC-driven push: streams a VM's disk
// into a host-local backup repo via the daemon.
func newBackupSnapshotCmd() *cobra.Command {
	var disk, repo, ts, quiesce, bwlimit string
	var incremental bool
	cmd := &cobra.Command{
		Use:     "snapshot <vm>",
		Aliases: []string{"create"},
		Short:   "Push a VM's disk into a backup repo (PBS-equivalent dedup chunks)",
		Long: `Push a VM's disk into a backup repo as a content-addressed manifest.

--incremental looks up the most-recent manifest for this VM+disk in
the repo and reuses its chunk refs for clean regions. Requires a
parent manifest; the first --incremental push degrades to a full
backup. When the daemon has a libvirt dirty-bitmap provider wired,
the read I/O is skipped for clean regions too; without one, the
chunk store still dedups by content and the manifest chain stays
intact (but disk I/O is full).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo is required")
			}
			bps, err := pbsstore.ParseRate(bwlimit)
			if err != nil {
				return fmt.Errorf("--bwlimit: %w", err)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.BackupSnapshot(ctx, &pb.BackupSnapshotRequest{
					VmName: args[0], DiskName: disk, RepoPath: repo,
					Timestamp: ts, Incremental: incremental, Quiesce: quiesce,
					BwlimitBytesPerSec: bps,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					switch p.Phase {
					case pb.BackupSnapshotProgress_DONE:
						fmt.Printf("[done] manifest=%s chunks=%d bytes=%d\n", p.ManifestTs, p.ChunksTotal, p.BytesProcessed)
						if p.BytesProcessed > 0 {
							pct := 100 * float64(p.BytesRead) / float64(p.BytesProcessed)
							fmt.Printf("       read %s of %s off disk (%.1f%%) — saved %s\n",
								formatBytes(p.BytesRead), formatBytes(p.BytesProcessed), pct,
								formatBytes(p.BytesProcessed-p.BytesRead))
						}
						return nil
					default:
						if p.Status != "" {
							fmt.Printf("[%s] %s\n", p.Phase, p.Status)
						} else {
							fmt.Printf("[%s] chunks=%d (deduped=%d) bytes=%d\n",
								p.Phase, p.ChunksTotal, p.ChunksDeduped, p.BytesProcessed)
						}
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name (default: root)")
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path (host-local)")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Override snapshot timestamp (RFC3339)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "Push only chunks changed since the most-recent manifest in this repo")
	cmd.Flags().StringVar(&quiesce, "quiesce", "auto", "In-guest fs-freeze for an app-consistent backup: auto (freeze if guest agent present) | off")
	cmd.Flags().StringVar(&bwlimit, "bwlimit", "", "Bandwidth limit for this backup, per second (e.g. 50MiB, 512K); the repo's backup_bwlimits limit still applies")
	return cmd
}

// newBackupRestoreFromCmd streams a manifest's chunks back into a
// target disk path. `lv backup restore` is its alias.
func newBackupRestoreFromCmd() *cobra.Command {
	var repo, vm, disk, ts, target string
	var inPlace bool
	cmd := &cobra.Command{
		Use:     "restore-from",
		Aliases: []string{"restore"},
		Short:   "Restore a snapshot from a backup repo into a new file, or in place over the VM's stopped disk",
		// No positional argument: the retired `lv backup restore <file>`
		// form must fail, not restore from a repo with the file ignored.
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%s takes no argument (got %q): it restores from a backup repo, named by --repo, --vm, --disk and --timestamp; "+
					"a disk file is no longer restored from", cmd.CommandPath(), args[0])
			}
			return nil
		},
		Long: `Restore one disk from a backup manifest.

By default the daemon writes a new file of its own under <data_dir>/disks and
prints where. --in-place restores over the disk the VM's record names instead:
the VM must be in the backup's project, on the daemon's host, and stopped.
--target-path names the file to write; it requires the admin role, and an
existing file there is refused, never replaced — except exactly the file the
VM's record names for --disk, which is restored as --in-place restores it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for name, val := range map[string]string{
				"--repo": repo, "--vm": vm, "--disk": disk, "--timestamp": ts,
			} {
				if val == "" {
					return fmt.Errorf("%s is required", name)
				}
			}
			if inPlace && target != "" {
				return fmt.Errorf("--in-place and --target-path are exclusive")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.RestoreFromBackup(ctx, &pb.RestoreFromBackupRequest{
					RepoPath: repo, VmName: vm, DiskName: disk, Timestamp: ts, TargetPath: target,
					InPlace: inPlace,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					if p.Phase == pb.RestoreFromBackupProgress_DONE {
						fmt.Printf("[done] %d chunks, %d bytes restored to %s\n",
							p.ChunksDone, p.BytesWritten, p.TargetPath)
						return nil
					}
					fmt.Printf("[restore] %d/%d chunks (%d bytes)\n", p.ChunksDone, p.ChunksTotal, p.BytesWritten)
				}
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path")
	cmd.Flags().StringVar(&vm, "vm", "", "VM name (matches manifest)")
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Manifest timestamp (exact RFC3339)")
	cmd.Flags().StringVar(&target, "target-path", "", "File to write (admin only; never an existing file but the VM's own disk, then as --in-place). Default: a new file the daemon names")
	cmd.Flags().BoolVar(&inPlace, "in-place", false, "Restore over the disk the VM's record names (the VM must be stopped)")
	return cmd
}

// newBackupRestoreLiveCmd opens a streaming RPC that spawns an NBD
// server backed by the manifest's chunk reader, creates a qcow2
// overlay (a new file the daemon names, or --target-path for an admin),
// and prints the resulting NBD URL + overlay path. The stream stays open so the NBD server keeps
// serving until the operator hits Ctrl+C (or another agent closes
// the gRPC stream).
//
// Workflow:
//
//	# Terminal 1 — start the live-restore source
//	lv backup restore-live --repo /srv/backup --vm vm1 \
//	    --disk root --timestamp 2026-05-11T10:00:00Z
//
//	# Terminal 2 — boot qemu/libvirt against the overlay path
//	virsh define vm1.xml && virsh start vm1
//
//	# Optional: pull the data local
//	virsh blockpull vm1 vda --wait
//
// Once blockpull completes, Ctrl+C terminal 1 — the NBD server
// stops and the overlay is fully self-contained.
func newBackupRestoreLiveCmd() *cobra.Command {
	var repo, vm, disk, ts, target, bind, newName string
	var autoStart, blockpull, fromExisting, withoutDevices bool
	cmd := &cobra.Command{
		Use:   "restore-live",
		Short: "Serve a backup manifest as a live NBD source + qcow2 overlay",
		Long: `Spawn an NBD server backed by a manifest's chunk store and create a
qcow2 overlay backed by it. The VM can boot off the overlay
immediately; data migrates on-demand. Ctrl+C terminates the NBD
server when the operator has finished pulling data locally.

With --auto-start the daemon also defines and starts the VM against
the overlay (from the manifest's embedded spec, or --name for a
collision-avoiding rename). The backup's PCI passthrough devices are
attached from this host's inventory, and the restore is refused if one
is not available; --without-devices starts the VM without them instead. --blockpull then localizes the disk and
tears the NBD server down automatically when it completes.

The overlay is a new file the daemon names under <data_dir>/disks; the
READY line prints it. --target-path names it instead: admin only, and an
existing file there is refused, never replaced.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for name, val := range map[string]string{
				"--repo": repo, "--vm": vm, "--disk": disk, "--timestamp": ts,
			} {
				if val == "" {
					return fmt.Errorf("%s is required", name)
				}
			}
			if withoutDevices && !autoStart {
				return fmt.Errorf("--without-devices starts the restored VM without its PCI devices; it needs --auto-start")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.RestoreLive(ctx, &pb.RestoreLiveRequest{
					RepoPath: repo, VmName: vm, DiskName: disk, Timestamp: ts,
					TargetPath: target, BindAddr: bind,
					AutoStart: autoStart, NewName: newName,
					Blockpull: blockpull, FromExisting: fromExisting,
					WithoutDevices: withoutDevices,
				})
				if err != nil {
					return err
				}
				for {
					p, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					if p.VmName != "" {
						fmt.Printf("[%s] %s (vm=%s)\n", p.Phase, p.Status, p.VmName)
					} else {
						fmt.Printf("[%s] %s\n", p.Phase, p.Status)
					}
					if p.NbdUrl != "" {
						fmt.Printf("    nbd_url=%s overlay=%s\n", p.NbdUrl, p.TargetPath)
					}
					if p.Phase == pb.RestoreLiveProgress_DONE || p.Phase == pb.RestoreLiveProgress_LOCALIZED {
						return nil
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "Backup repo path")
	cmd.Flags().StringVar(&vm, "vm", "", "VM name (matches manifest)")
	cmd.Flags().StringVar(&disk, "disk", "", "Disk name")
	cmd.Flags().StringVar(&ts, "timestamp", "", "Manifest timestamp (exact RFC3339)")
	cmd.Flags().StringVar(&target, "target-path", "", "Overlay file to create (admin only; never an existing file). Default: a new file the daemon names")
	cmd.Flags().StringVar(&bind, "bind", "127.0.0.1:0", "NBD server bind addr (use 0.0.0.0:<port> for non-local qemu)")
	cmd.Flags().BoolVar(&autoStart, "auto-start", false, "Define and start the VM automatically against the overlay")
	cmd.Flags().StringVar(&newName, "name", "", "Rename the restored VM (avoids collision with the original)")
	cmd.Flags().BoolVar(&blockpull, "blockpull", false, "After start, localize the disk via blockpull then stop NBD")
	cmd.Flags().BoolVar(&fromExisting, "from-existing", false, "Fall back to an existing vms record for the spec")
	cmd.Flags().BoolVar(&withoutDevices, "without-devices", false, "With --auto-start: start the VM without the backup's PCI passthrough devices (removed from its spec, audited)")
	return cmd
}

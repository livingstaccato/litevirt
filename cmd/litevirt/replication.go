package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newReplicationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replication",
		Short: "Scheduled volume replication + failover promotion",
	}
	cmd.AddCommand(
		newReplicationScheduleCmd(),
		newReplicationPromoteCmd(),
		newReplicationReplicasCmd(),
	)
	return cmd
}

func newReplicationScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage cron-driven replication schedules",
	}
	cmd.AddCommand(
		newReplicationScheduleAddCmd(),
		newReplicationScheduleListCmd(),
		newReplicationScheduleRmCmd(),
	)
	return cmd
}

func newReplicationScheduleAddCmd() *cobra.Command {
	var cron, targetPool, targetHost, scope, poolName, projectName string
	var keepReplicas int32
	var disabled, incremental, autoPromote, container bool
	cmd := &cobra.Command{
		Use:   "add <vm|container>",
		Short: "Add or replace a replication schedule for a VM or container",
		Long: `Replicate a VM's disk to target-pool on a cron schedule, keeping the newest
--keep point-in-time copies. The target is an explicit --target-host, a shared
pool (nfs/ceph/iscsi), or — when neither — an auto-selected healthy peer with
the pool.

A running or paused VM's full copy is point-in-time: a backup session, else an
external disk-only snapshot that is committed back afterwards. Only when neither
can be made is it a qemu-img -U copy, recorded and reported as NOT point-in-time
and retried point-in-time at the next scheduler tick.

--incremental transfers only dirty extents (raw replicas; full-copy fallback for
a stopped VM or old libvirt). --auto-promote lets failover bring up the freshest
point-in-time replica if the VM's host is lost; a VM whose only replicas are not
point-in-time is held down unless its spec carries the label
litevirt.auto_promote_not_point_in_time=true.

--container replicates a container instead. A container has no storage pool, so
--target-host names the peer that holds the replica and --target-pool the backup
repo on it (a logical repo name that peer has in its backup_repos). The
container is archived frozen and only the chunks the peer lacks are sent. With
--auto-promote, failover restores the newest replica on that peer if the
container's host is lost, through the same recovery claim as a restore from
backup; the container needs a host-failure policy. --project-name picks the
container when the name exists in more than one project.

After a promotion, a failover or a migrate onto the replica host, the schedule
replicates back to the host the workload left (docs/backups.md, "Reverse
replication").`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if container {
				scope = "container"
			}
			if scope == "" {
				scope = "vm"
			}
			name := args[0]
			if scope == "container" {
				name = containerScheduleRef(projectName, name)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				s, err := c.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
					VmName: name, Cron: cron, TargetPool: targetPool, TargetHost: targetHost,
					KeepReplicas: keepReplicas, Enabled: !disabled, Scope: scope,
					PoolName: poolName, ProjectName: projectName,
					Incremental: incremental, AutoPromote: autoPromote,
				})
				if err != nil {
					return fmt.Errorf("create replication schedule: %w", err)
				}
				fmt.Printf("replication schedule %s → %s added (cron=%q, incremental=%v, auto-promote=%v, enabled=%v)\n",
					s.VmName, s.TargetPool, s.Cron, s.Incremental, s.AutoPromote, s.Enabled)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&cron, "cron", "", `5-field cron expression (e.g. "0 */4 * * *")`)
	cmd.Flags().BoolVar(&container, "container", false, "the schedule is for a container (same as --scope container)")
	cmd.Flags().StringVar(&targetPool, "target-pool", "", "destination storage pool (a container: the backup repo on --target-host)")
	cmd.Flags().StringVar(&targetHost, "target-host", "", "explicit destination host (else shared-pool/auto peer)")
	cmd.Flags().Int32Var(&keepReplicas, "keep", 0, "keep N newest replicas (0 = keep all)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "transfer only dirty extents (raw replicas)")
	cmd.Flags().BoolVar(&autoPromote, "auto-promote", false, "failover may promote the freshest replica on host loss")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the schedule disabled")
	cmd.Flags().StringVar(&scope, "scope", "vm", "schedule scope: vm | pool | cluster | project | container")
	cmd.Flags().StringVar(&poolName, "pool-name", "", "pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "project name (scope=project, or the container's project)")
	_ = cmd.MarkFlagRequired("cron")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

func newReplicationScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List configured replication schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
				if err != nil {
					return fmt.Errorf("list replication schedules: %w", err)
				}
				if len(resp.Schedules) == 0 {
					fmt.Println("(no replication schedules)")
					return nil
				}
				fmt.Printf("%-18s %-12s %-10s %-5s %-5s %-4s %-20s %s\n",
					"VM", "POOL", "HOST", "INCR", "AUTO", "KEEP", "LAST RUN", "LAST ERR")
				for _, s := range resp.Schedules {
					name := s.VmName
					if s.Scope == "container" {
						name = "ct:" + name
					}
					fmt.Printf("%-18s %-12s %-10s %-5v %-5v %-4d %-20s %s\n",
						name, s.TargetPool, defaultStr(s.TargetHost, "-"), s.Incremental, s.AutoPromote,
						s.KeepReplicas, defaultStr(s.LastRunAt, "-"), defaultStr(s.LastRunErr, "-"))
				}
				return nil
			})
		},
	}
}

func newReplicationScheduleRmCmd() *cobra.Command {
	var targetPool, scope, poolName, projectName string
	var container bool
	cmd := &cobra.Command{
		Use:   "rm <vm|container>",
		Short: "Remove a replication schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if container {
				scope = "container"
			}
			if scope == "" {
				scope = "vm"
			}
			name := args[0]
			if scope == "container" {
				name = containerScheduleRef(projectName, name)
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{
					VmName: name, TargetPool: targetPool, Scope: scope,
					PoolName: poolName, ProjectName: projectName,
				}); err != nil {
					return fmt.Errorf("delete replication schedule: %w", err)
				}
				fmt.Printf("replication schedule %s → %s removed\n", args[0], targetPool)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&container, "container", false, "the schedule is for a container (same as --scope container)")
	cmd.Flags().StringVar(&targetPool, "target-pool", "", "destination pool, or a container's backup repo (required to disambiguate)")
	cmd.Flags().StringVar(&scope, "scope", "vm", "schedule scope")
	cmd.Flags().StringVar(&poolName, "pool-name", "", "pool name (scope=pool)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "project name (scope=project, or the container's project)")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

// containerScheduleRef is what the CLI sends as a container schedule's vm_name:
// the schedule key, never the bare name. A daemon that predates container
// schedules reads an unknown scope's vm_name as a VM name; the key names no VM
// (a VM name cannot hold '@' or ':'), so such a daemon can never act on a VM's
// schedule of the same name. Without a project the key is the name-only form,
// which a current daemon matches in any project.
func containerScheduleRef(project, name string) string {
	if project != "" {
		return "@ct:" + project + "/" + name
	}
	return "@ct:" + name
}

func newReplicationReplicasCmd() *cobra.Command {
	var host, repo, projectName, restore string
	var remove []string
	var yes bool
	cmd := &cobra.Command{
		Use:   "replicas <container>",
		Short: "List a container's replicas on its replica host; restore one, or remove set-aside or orphaned ones",
		Long: `List the scheduled replicas of a container that a host holds in one backup
repo's replica namespace (--host, --target-pool: the schedule's target), with
the host and placement each was taken from and when it was captured.

A replica is SET ASIDE when a later replica arrived from a placement of the
container that is not proven to contain it: typically the container came back
after a host loss from its image or a backup rather than from this replica, so
a set-aside replica may hold the NEWEST copy of its data. It is never pruned by
its schedule and never promoted by failover. A replica is ORPHANED when no
schedule replicates the container into this host and repo any more.

--restore <timestamp> lays that replica down as the container, stopped, on the
replica host (admin). It is refused while the container lives anywhere, as a
row or as a runtime on some host, and while any member of the cluster cannot
be asked: deal with that copy, or bring the member back or remove it, first, so
there is never a second runnable copy.

--remove <timestamp> deletes a set-aside or orphaned replica (admin). It may be
the only copy of the data: it asks first unless --yes.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if restore != "" && len(remove) > 0 {
				return fmt.Errorf("--restore and --remove are separate requests")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if restore != "" {
					resp, err := c.RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
						Host: host, Repo: repo, Project: projectName, Name: args[0], Timestamp: restore,
					})
					if err != nil {
						return fmt.Errorf("restore replica: %w", err)
					}
					fmt.Printf("restored the replica of %s taken at %s, stopped, on %s\n", args[0], restore, resp.Host)
					return nil
				}
				list, err := c.ListContainerReplicas(ctx, &pb.ListContainerReplicasRequest{
					Host: host, Repo: repo, Project: projectName, Name: args[0],
				})
				if err != nil {
					return fmt.Errorf("list replicas: %w", err)
				}
				if len(remove) > 0 {
					byTS := map[string]*pb.ContainerReplica{}
					for _, r := range list.Replicas {
						byTS[r.Timestamp] = r
					}
					fmt.Println("About to delete, for good:")
					for _, ts := range remove {
						if r := byTS[ts]; r != nil {
							fmt.Printf("  %s  taken on %s, captured %s, %d bytes, %s\n", ts, r.Source, defaultStr(r.CapturedAt, "-"), r.TotalSize, replicaState(r))
						} else {
							fmt.Printf("  %s  (not listed)\n", ts)
						}
					}
					fmt.Println("A set-aside or orphaned replica may hold the newest copy of the container's data; --restore lays it down instead.")
					ok, err := confirmVoterChange(yes, "Delete these replicas?")
					if err != nil || !ok {
						return err
					}
					resp, err := c.RemoveContainerReplicas(ctx, &pb.RemoveContainerReplicasRequest{
						Host: host, Repo: repo, Project: projectName, Name: args[0], Timestamps: remove,
					})
					if err != nil {
						return fmt.Errorf("remove replicas: %w", err)
					}
					fmt.Printf("removed %d replica(s) of %s from %s on %s\n", resp.Removed, args[0], repo, defaultStr(host, "this host"))
					return nil
				}
				fmt.Printf("%-26s %-14s %-32s %-11s %-10s %s\n", "TAKEN", "FROM", "CAPTURED", "SIZE", "STATE", "WHY")
				for _, r := range list.Replicas {
					why := ""
					if r.SetAside {
						why = r.SetAsideReason
					}
					fmt.Printf("%-26s %-14s %-32s %-11d %-10s %s\n", r.Timestamp, r.Source, defaultStr(r.CapturedAt, "-"), r.TotalSize, replicaState(r), why)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the replica host (the schedule's --target-host)")
	cmd.Flags().StringVar(&repo, "target-pool", "", "the backup repo on that host (the schedule's --target-pool)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "the container's project (default _default)")
	cmd.Flags().StringVar(&restore, "restore", "", "restore the replica taken at this timestamp as the container, stopped (admin)")
	cmd.Flags().StringArrayVar(&remove, "remove", nil, "remove the SET-ASIDE or ORPHANED replica taken at this timestamp (repeatable; admin)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "remove without asking")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

// replicaState is how a listing shows one replica.
func replicaState(r *pb.ContainerReplica) string {
	switch {
	case r.SetAside:
		return "set-aside"
	case r.Orphaned:
		return "orphaned"
	}
	return "current"
}

func newReplicationPromoteCmd() *cobra.Command {
	var pool, host, replica, newName string
	var force, noLocalize, acceptNotPIT bool
	cmd := &cobra.Command{
		Use:   "promote <vm>",
		Short: "Bring up a VM from its replica (disaster recovery)",
		Long: `Promote a replica to a live VM. By default the newest replica of the VM's
root disk is located (from the VM's replication schedule, or --pool/--host),
copied into a self-contained live disk on the host holding it, and the VM is
defined + started there.

By default the original name is taken over (the host-loss case); pass --new-name
to bring it up alongside a still-running original. --force overrides the
split-brain guard. --no-localize boots off a fast overlay backed by the replica
instead of copying (pins the replica until you localize it).

A replica recorded as NOT point-in-time (copied with qemu-img convert -U while
the VM ran, after every point-in-time copy failed) may be inconsistent; promoting
one is refused with a warning unless --accept-not-point-in-time is given.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.PromoteReplica(ctx, &pb.PromoteReplicaRequest{
					VmName: args[0], TargetPool: pool, TargetHost: host, Replica: replica,
					NewName: newName, Force: force, NoLocalize: noLocalize,
					AcceptNotPointInTime: acceptNotPIT,
				})
				if err != nil {
					return err
				}
				for {
					p, rerr := stream.Recv()
					if rerr == io.EOF {
						return nil
					}
					if rerr != nil {
						return rerr
					}
					fmt.Printf("[%s] %s\n", p.Phase, p.Status)
				}
			})
		},
	}
	cmd.Flags().StringVar(&pool, "pool", "", "pool holding the replica (default: from the VM's replication schedule)")
	cmd.Flags().StringVar(&host, "host", "", "host holding the replica (default: auto-resolved)")
	cmd.Flags().StringVar(&replica, "replica", "", "one of the VM's recorded replicas, <disk>-<time>.<ext> (default: newest)")
	cmd.Flags().StringVar(&newName, "new-name", "", "promote under a new name (alongside the original)")
	cmd.Flags().BoolVar(&force, "force", false, "promote even if the original is on a healthy host")
	cmd.Flags().BoolVar(&noLocalize, "no-localize", false, "boot off an overlay backed by the replica (fast; pins it)")
	cmd.Flags().BoolVar(&acceptNotPIT, "accept-not-point-in-time", false, "promote a replica recorded as not point-in-time (a qemu-img -U copy of a running disk; may be inconsistent)")
	return cmd
}

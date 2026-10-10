package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Container replication.
//
// A container's data is a rootfs directory on one host. Replicating it is the
// container half of what a VM schedule does for a disk: on a cron schedule the
// owning host archives the container (frozen, point-in-time) and streams the
// result to a peer, which keeps the newest keep_replicas of them. Transport is
// the one container backups, migrations and failover relocations already use: the
// content-addressed chunk store, so a run sends only the chunks the peer does not
// hold (an unchanged container costs almost nothing, and a reversed direction
// never resends what the other side still has).
//
// A replica is a backup manifest in a repo on the TARGET host, marked with a
// containerReplicaMark. Promotion is not a second recovery path: when the host
// holding the container is fenced, the failover coordinator restores it through
// the ordinary restore-relocation, with the same proof, recovery claim and
// single-use token, preferring the newest replica on the target host (see
// RestoreContainerFromBackup). A replica is inert data, never a second running
// copy, so "one copy at every moment" is the relocation's property, unchanged.

// containerReplicaMark is carried in the manifest's embedded spec.
type containerReplicaMark struct {
	// Stream names one replication stream: a container's schedule into one repo.
	Stream string `json:"stream"`
	// Source is the host that produced the replica.
	Source string `json:"source"`
	// Epoch is the container's ownership generation (owner_epoch) when it was
	// taken. A relocation mints the next one, so a replica of the old owner's
	// data is recognisably an earlier generation whatever the clocks say.
	Epoch int64 `json:"epoch"`
	// Keep is how many replicas of this stream the target retains (0 = all).
	Keep int `json:"keep,omitempty"`
}

// ContainerReplicaStream is the stream name for a schedule's target repo.
func containerReplicaStream(repo string) string { return "ct-replica:" + repo }

func replicaMarkOf(m *pbsstore.Manifest) *containerReplicaMark {
	if m == nil || m.DiskName != containerBackupDisk || m.ContainerSpecJSON == "" {
		return nil
	}
	var spec containerBackupSpec
	if json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) != nil {
		return nil
	}
	return spec.Replica
}

func manifestSpec(m *pbsstore.Manifest) (containerBackupSpec, bool) {
	var spec containerBackupSpec
	if m == nil || m.ContainerSpecJSON == "" || json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) != nil {
		return spec, false
	}
	return spec, true
}

// sameReplicaStream reports whether other is a replica of the same container
// lineage in the same stream as m (both already known to carry marks).
func sameReplicaStream(m, other *pbsstore.Manifest) bool {
	a, b := replicaMarkOf(m), replicaMarkOf(other)
	if a == nil || b == nil || a.Stream != b.Stream {
		return false
	}
	sa, _ := manifestSpec(m)
	sb, _ := manifestSpec(other)
	if tenancy.NormalizeProject(sa.Project) != tenancy.NormalizeProject(sb.Project) {
		return false
	}
	oa, ob := corrosion.DecodeCreateSpec(sa.CreateSpec).OwnerID, corrosion.DecodeCreateSpec(sb.CreateSpec).OwnerID
	return oa == "" || ob == "" || oa == ob
}

func manifestTime(m *pbsstore.Manifest) time.Time {
	t, err := time.Parse(time.RFC3339Nano, m.Timestamp)
	if err != nil {
		return time.Time{}
	}
	return t
}

// replicaPeers returns the other replicas in repo of m's stream and lineage.
func replicaPeers(ctx context.Context, repo *pbsstore.Repo, m *pbsstore.Manifest) ([]pbsstore.Manifest, error) {
	all, err := repo.ManifestsFor(ctx, m.VMName, containerBackupDisk)
	if err != nil {
		return nil, err
	}
	var out []pbsstore.Manifest
	for i := range all {
		if all[i].Timestamp == m.Timestamp {
			continue
		}
		if sameReplicaStream(m, &all[i]) {
			out = append(out, all[i])
		}
	}
	return out, nil
}

// errStaleReplica is a replica that is an older copy than one the target holds.
var errStaleReplica = status.Error(codes.FailedPrecondition,
	"push-backup: refusing a container replica older than one this repo already holds")

// admitContainerReplica runs on the TARGET before a replica's manifest is
// written. It refuses a replica that is older than one already held: an earlier
// ownership generation (a previous owner's data arriving after the container was
// relocated), or, within one generation and source host, an older timestamp. The
// newer copy is never replaced by an older one. Anything that is not a replica
// passes untouched.
func admitContainerReplica(ctx context.Context, repo *pbsstore.Repo, m *pbsstore.Manifest) error {
	mark := replicaMarkOf(m)
	if mark == nil {
		return nil
	}
	peers, err := replicaPeers(ctx, repo, m)
	if err != nil {
		return status.Errorf(codes.Internal, "push-backup: read existing replicas: %v", err)
	}
	for i := range peers {
		pm := replicaMarkOf(&peers[i])
		switch {
		case pm.Epoch > mark.Epoch:
			return errStaleReplica
		case pm.Epoch == mark.Epoch && pm.Source == mark.Source && manifestTime(&peers[i]).After(manifestTime(m)):
			return errStaleReplica
		}
	}
	return nil
}

// settleContainerReplicas runs on the TARGET after a replica's manifest is
// written. It removes the replicas the new one supersedes: every earlier
// ownership generation, and, within one generation, another source host's (the
// container moved, and the new host's replica is the current one). It then keeps
// the newest Keep of the same generation and source. Only replicas of the same
// stream and lineage are ever touched: never a backup, never another container's.
// Chunks are reclaimed by the repo's own GC. Best-effort: a failure leaves extra
// replicas, never fewer than were pushed.
func settleContainerReplicas(ctx context.Context, repo *pbsstore.Repo, m *pbsstore.Manifest) {
	mark := replicaMarkOf(m)
	if mark == nil {
		return
	}
	peers, err := replicaPeers(ctx, repo, m)
	if err != nil {
		slog.Warn("container replica: read replicas to settle", "container", m.VMName, "error", err)
		return
	}
	var del []pbsstore.Manifest
	var same []pbsstore.Manifest
	for i := range peers {
		pm := replicaMarkOf(&peers[i])
		switch {
		case pm.Epoch < mark.Epoch, pm.Epoch == mark.Epoch && pm.Source != mark.Source:
			del = append(del, peers[i])
		case pm.Epoch == mark.Epoch:
			same = append(same, peers[i])
		}
	}
	if mark.Keep > 0 {
		sort.Slice(same, func(i, j int) bool { return manifestTime(&same[i]).After(manifestTime(&same[j])) })
		// m itself is one of the kept.
		if keepOthers := mark.Keep - 1; keepOthers < len(same) {
			del = append(del, same[keepOthers:]...)
		}
	}
	if len(del) == 0 {
		return
	}
	if err := pbsstore.ApplyPrune(repo, pbsstore.PrunePlan{Delete: del}); err != nil {
		slog.Warn("container replica: prune", "container", m.VMName, "error", err)
	}
}

// runContainerReplication is RunReplication for a container-scoped schedule: it
// archives the container (frozen while it runs) into a local staging repo and
// streams the manifest to the schedule's target host's repo, where the target
// applies admitContainerReplica and settleContainerReplicas.
func (s *Server) runContainerReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) (retErr error) {
	name, ok := corrosion.ContainerScheduleName(sched.VMName)
	if !ok {
		return fmt.Errorf("replication schedule %q is not a container schedule", sched.VMName)
	}
	project := tenancy.NormalizeProject(sched.ProjectName)
	cts, err := corrosion.ListContainers(ctx, s.db, s.hostName)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	var rec *corrosion.ContainerRecord
	for i := range cts {
		if cts[i].Name == name && tenancy.NormalizeProject(cts[i].Project) == project {
			rec = &cts[i]
			break
		}
	}
	if rec == nil {
		return nil // not ours; the owning host's scheduler runs it
	}
	repoName, target := sched.TargetPool, sched.TargetHost
	defer func() {
		if retErr != nil {
			s.audit(ctx, "ct.replicate", name, "project="+project+" → "+repoName+"@"+target, "error")
			s.notify(ctx, notify.Notification{
				Kind: "replication.failed", Severity: notify.SevError, Subject: name,
				Detail: fmt.Sprintf("container %s → %s@%s: %v", name, repoName, target, retErr),
			})
		}
	}()
	if repoName == "" || target == "" {
		return fmt.Errorf("container replication of %q needs a target host and a target repo", name)
	}
	if target == s.hostName {
		return fmt.Errorf("replica target %q is the host the container runs on, so the replica protects nothing; re-target the schedule (it follows a moved container on its own after a migrate or failover)", target)
	}
	th, err := corrosion.GetHost(ctx, s.db, target)
	if err != nil {
		return fmt.Errorf("look up target host %q: %w", target, err)
	}
	if th == nil || th.State != "active" {
		return fmt.Errorf("replica target host %q is not active", target)
	}
	if !corrosion.HostRunsContainers(*th) {
		return fmt.Errorf("replica target host %q cannot run containers (%s is not true), so a replica there could never be promoted", target, corrosion.LabelLXCCapable)
	}
	if s.containerRuntime == nil {
		return fmt.Errorf("container runtime not wired on this host")
	}

	unlock := s.lockVM("ct/" + name)
	defer unlock()

	staging, cleanup, err := s.newLocalStagingRepo()
	if err != nil {
		return err
	}
	defer cleanup()

	// Quiesce a running container so the archive is point-in-time. A freeze
	// failure never fails the run (BackupContainer's policy): the replica is then
	// crash-consistent.
	if rec.State == "running" {
		if ferr := s.containerRuntime.FreezeContainer(ctx, name); ferr != nil {
			slog.Warn("container replication: freeze unavailable; replica is crash-consistent", "container", name, "error", ferr)
		} else {
			defer func() {
				if uerr := s.containerRuntime.UnfreezeContainer(context.Background(), name); uerr != nil {
					slog.Warn("container replication: unfreeze failed", "container", name, "error", uerr)
				}
			}()
		}
	}

	mark := &containerReplicaMark{
		Stream: containerReplicaStream(repoName), Source: s.hostName,
		Epoch: rec.OwnerEpoch, Keep: sched.KeepReplicas,
	}
	manifest, err := s.archiveContainerAs(ctx, staging, rec, runAt.UTC().Format(time.RFC3339), mark, func(pbsstore.PushProgress) {})
	if err != nil {
		return fmt.Errorf("archive container: %w", err)
	}
	if err := s.pushManifestToPeerRepo(ctx, target, repoName, staging, manifest); err != nil {
		return fmt.Errorf("push replica to %s: %w", target, err)
	}
	s.audit(ctx, "ct.replicate", name, fmt.Sprintf("project=%s → %s@%s @ %s", project, repoName, target, manifest.Timestamp), "ok")
	return nil
}

// ctReplica is a promotable replica of a container, held by a host.
type ctReplica struct {
	Host, Repo, Timestamp string
}

// containerReplicationSchedules returns the container-scoped replication
// schedules of (name, project).
func (s *Server) containerReplicationSchedules(ctx context.Context, name, project string) []corrosion.BackupScheduleRecord {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil
	}
	var out []corrosion.BackupScheduleRecord
	for _, r := range rows {
		if r.Type != "replication" || r.Scope != "container" || r.VMName != corrosion.ContainerScheduleKey(name) {
			continue
		}
		if tenancy.NormalizeProject(r.ProjectName) != tenancy.NormalizeProject(project) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// containerReplicaFor finds the replica a failover may promote onto targetHost: a
// container-scoped schedule that allows auto-promote, targets that host, and
// whose repo there holds a replica of this container's lineage no older than the
// schedule's age bound. owner is the relocating row (nil when unreadable).
func (s *Server) containerReplicaFor(ctx context.Context, name string, owner *corrosion.ContainerRecord, targetHost string, now time.Time) (ctReplica, bool) {
	project := tenancy.Default
	var lineage corrosion.ContainerCreateSpec
	if owner != nil {
		project = tenancy.NormalizeProject(owner.Project)
		lineage = probeLineage(corrosion.DecodeCreateSpec(owner.CreateSpec))
	}
	for _, sched := range s.containerReplicationSchedules(ctx, name, project) {
		if !sched.Enabled || !sched.AutoPromote || sched.TargetHost != targetHost || sched.TargetPool == "" {
			continue
		}
		var probe *pb.ContainerBackupProbe
		if targetHost == s.hostName {
			probe = s.probeContainerBackupRepo(ctx, name, project, lineage, sched.TargetPool)
		} else {
			res, err := s.probePeerContainerBackups(ctx, targetHost, name, project, lineage, []string{sched.TargetPool})
			if err != nil || len(res) != 1 {
				slog.Warn("container failover: could not ask the replica host for its replicas", "container", name, "host", targetHost, "error", err)
				continue
			}
			probe = res[0]
		}
		if !probe.Attributed || probe.LatestTimestamp == "" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339Nano, probe.LatestTimestamp)
		if perr != nil {
			continue
		}
		if age := now.Sub(ts); age > autoPromoteAgeLimit(sched.Cron) {
			slog.Warn("container failover: the replica is too old to promote automatically",
				"container", name, "host", targetHost, "taken", probe.LatestTimestamp, "age", age.Round(time.Minute))
			continue
		}
		return ctReplica{Host: targetHost, Repo: sched.TargetPool, Timestamp: probe.LatestTimestamp}, true
	}
	return ctReplica{}, false
}

// resolveContainerForSchedule finds the one live container name of project
// (any project when empty). It refuses an ambiguous name: a container name is
// unique per host, not cluster-wide.
func (s *Server) resolveContainerForSchedule(ctx context.Context, name, project string) (*corrosion.ContainerRecord, error) {
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list containers: %v", err)
	}
	var found []corrosion.ContainerRecord
	for _, ct := range cts {
		if ct.Name != name {
			continue
		}
		if project != "" && tenancy.NormalizeProject(ct.Project) != tenancy.NormalizeProject(project) {
			continue
		}
		found = append(found, ct)
	}
	switch len(found) {
	case 0:
		return nil, status.Errorf(codes.NotFound, "container %q not found", name)
	case 1:
		return &found[0], nil
	}
	return nil, status.Errorf(codes.InvalidArgument,
		"container name %q exists on %d hosts or projects; name the project (project_name)", name, len(found))
}

// createContainerReplicationSchedule is CreateReplicationSchedule for scope
// "container": vm_name is the container, target_host the peer that holds the
// replica, and target_pool the backup repo there (a logical name that host
// resolves in its own config), since a container has no storage pool of its own.
func (s *Server) createContainerReplicationSchedule(ctx context.Context, req *pb.CreateReplicationScheduleRequest) (*pb.ReplicationSchedule, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "the container name is required (vm_name)")
	}
	if req.TargetPool == "" || req.Cron == "" || req.TargetHost == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a container schedule needs cron, target_host (the peer that holds the replica) and target_pool (the backup repo on it)")
	}
	if req.Incremental {
		return nil, status.Error(codes.InvalidArgument,
			"incremental replication transfers dirty disk extents of a VM; a container replica already sends only the chunks the target lacks")
	}
	if _, err := scheduler.ParseCron(req.Cron); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cron %q: %v", req.Cron, err)
	}
	ct, err := s.resolveContainerForSchedule(ctx, req.VmName, req.ProjectName)
	if err != nil {
		return nil, err
	}
	project := tenancy.NormalizeProject(ct.Project)
	if err := s.requirePermResolved(ctx, true, ctRBACPathFor(project, ct.Name), ctRBACPathFor("", ct.Name),
		"backup.schedule", "operator", containerWhat(ct.Name)); err != nil {
		return nil, err
	}
	if req.TargetHost == ct.HostName {
		return nil, status.Errorf(codes.InvalidArgument,
			"target_host %q is the host the container runs on; a replica there is lost with it", req.TargetHost)
	}
	th, err := corrosion.GetHost(ctx, s.db, req.TargetHost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up target host: %v", err)
	}
	if th == nil || th.State != "active" {
		return nil, status.Errorf(codes.FailedPrecondition, "target host %q is not an active host", req.TargetHost)
	}
	if !corrosion.HostRunsContainers(*th) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"target host %q cannot run containers (%s is not true), so a replica there could never be promoted", req.TargetHost, corrosion.LabelLXCCapable)
	}
	if req.AutoPromote && (ct.OnHostFailure == "" || ct.OnHostFailure == "none") {
		return nil, status.Errorf(codes.FailedPrecondition,
			"container %q has no host-failure policy, so failover never moves it and auto-promote would never run; set one first (its on_host_failure is %q)",
			ct.Name, ct.OnHostFailure)
	}
	// The target resolves the repo name in its own config; ask it, so a schedule
	// that could never push is not stored. A peer that cannot answer the question
	// (an older build) is not a reason to refuse.
	lineage := probeLineage(corrosion.DecodeCreateSpec(ct.CreateSpec))
	var res []*pb.ContainerBackupProbe
	var perr error
	if req.TargetHost == s.hostName {
		res = []*pb.ContainerBackupProbe{s.probeContainerBackupRepo(ctx, ct.Name, project, lineage, req.TargetPool)}
	} else {
		res, perr = s.probePeerContainerBackups(ctx, req.TargetHost, ct.Name, project, lineage, []string{req.TargetPool})
	}
	if perr == nil {
		if len(res) == 1 && !res[0].Opened && !res[0].Unreadable {
			return nil, status.Errorf(codes.FailedPrecondition, "backup repo %q is not available on %q: %s", req.TargetPool, req.TargetHost, res[0].Detail)
		}
	} else if status.Code(perr) != codes.Unimplemented {
		return nil, status.Errorf(codes.Unavailable, "cannot verify repo %q on %q: %v", req.TargetPool, req.TargetHost, perr)
	}

	rec := corrosion.BackupScheduleRecord{
		VMName:       corrosion.ContainerScheduleKey(ct.Name),
		ProjectName:  project,
		Scope:        "container",
		Repo:         req.TargetPool,
		Cron:         req.Cron,
		Enabled:      req.Enabled,
		Type:         "replication",
		TargetPool:   req.TargetPool,
		TargetHost:   req.TargetHost,
		KeepReplicas: int(req.KeepReplicas),
		AutoPromote:  req.AutoPromote,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert replication schedule: %v", err)
	}
	s.audit(ctx, "replication.schedule", ct.Name, "container target="+req.TargetHost+":"+req.TargetPool+" cron="+req.Cron, "ok")
	return replScheduleToPB(rec), nil
}

// deleteContainerReplicationSchedule removes a container schedule. The row is
// found by its key and repo and authorized on the project IT recorded, so a
// schedule outlives, and can still be removed after, its container.
func (s *Server) deleteContainerReplicationSchedule(ctx context.Context, req *pb.DeleteReplicationScheduleRequest) (*emptypb.Empty, error) {
	if req.VmName == "" || req.TargetPool == "" {
		return nil, status.Error(codes.InvalidArgument, "the container name (vm_name) and target_pool are required")
	}
	key := corrosion.ContainerScheduleKey(req.VmName)
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	var row *corrosion.BackupScheduleRecord
	for i := range rows {
		r := rows[i]
		if r.VMName != key || r.Repo != req.TargetPool || r.Type != "replication" {
			continue
		}
		if req.ProjectName != "" && tenancy.NormalizeProject(r.ProjectName) != tenancy.NormalizeProject(req.ProjectName) {
			continue
		}
		if row != nil {
			return nil, status.Errorf(codes.InvalidArgument, "more than one project has a schedule for %q into %q; name the project (project_name)", req.VmName, req.TargetPool)
		}
		row = &r
	}
	if row == nil {
		return &emptypb.Empty{}, nil // nothing to remove, as for a VM
	}
	project := tenancy.NormalizeProject(row.ProjectName)
	if err := s.requirePermResolved(ctx, true, ctRBACPathFor(project, req.VmName), ctRBACPathFor("", req.VmName),
		"backup.schedule", "operator", containerWhat(req.VmName)); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, key, req.TargetPool); err != nil {
		return nil, status.Errorf(codes.Internal, "delete replication schedule: %v", err)
	}
	return &emptypb.Empty{}, nil
}

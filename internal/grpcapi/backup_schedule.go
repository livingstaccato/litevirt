// backup-schedule RPC handlers — thin wrappers around the
// `backup_schedules` Corrosion table. The leader-gated minute-tick
// scheduler in `internal/scheduler/snapshots.go` reads the table and
// dispatches actual backups.

package grpcapi

import (
	"context"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/tenancy"
)

func (s *Server) CreateBackupSchedule(ctx context.Context, req *pb.CreateBackupScheduleRequest) (*pb.BackupSchedule, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.authorizeSchedule(ctx, scope, req.VmName, req.PoolName, req.ProjectName); err != nil {
		return nil, err
	}
	if req.Repo == "" || req.Cron == "" {
		return nil, status.Error(codes.InvalidArgument, "repo and cron are required")
	}
	if _, err := scheduler.ParseCron(req.Cron); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cron %q: %v", req.Cron, err)
	}

	// Validate the scope target. Exactly one target field is meaningful per scope.
	switch scope {
	case "vm":
		if req.VmName == "" {
			return nil, status.Error(codes.InvalidArgument, "vm_name required for vm-scoped schedule")
		}
		if vm, err := corrosion.GetVM(ctx, s.db, req.VmName); err != nil || vm == nil {
			return nil, status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
		}
	case "pool":
		if req.PoolName == "" {
			return nil, status.Error(codes.InvalidArgument, "pool_name required for pool-scoped schedule")
		}
	case "project":
		if req.ProjectName == "" {
			return nil, status.Error(codes.InvalidArgument, "project_name required for project-scoped schedule")
		}
	case "cluster":
		// no target
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown scope %q (want vm|pool|cluster|project)", scope)
	}

	rec := corrosion.BackupScheduleRecord{
		VMName:      corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName),
		PoolName:    req.PoolName,
		ProjectName: req.ProjectName,
		Scope:       scope,
		Repo:        req.Repo,
		Cron:        req.Cron,
		KeepLast:    int(req.KeepLast),
		KeepDaily:   int(req.KeepDaily),
		KeepWeekly:  int(req.KeepWeekly),
		KeepMonthly: int(req.KeepMonthly),
		KeepYearly:  int(req.KeepYearly),
		Enabled:     req.Enabled,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert schedule: %v", err)
	}
	return scheduleToPB(rec), nil
}

// scheduleRBACTarget returns the RBAC path a schedule of the given scope is
// checked against. For the vm scope it resolves the VM's tenancy project from
// its local row; known is false when that row is not here, and the caller then
// authorizes through requirePermResolved. It used to fall back to the
// _default-project path, which let a _default-only caller delete the schedule
// of a VM in any other project through a node the VM's row had not reached —
// the tombstone is keyed by VM name and relayed, so every node holding the
// schedule applied it.
func (s *Server) scheduleRBACTarget(ctx context.Context, scope, vmName, poolName, projectName string) (path string, known bool) {
	switch scope {
	case "pool":
		// Authorize against the PROJECT-scoped pool path (matching pool CRUD/content, which
		// moved to poolRBACPathFor); the legacy "/storage/pools/<name>" matched no
		// currently-issued grant. Resolve the owning project from the stored pool record,
		// and FAIL CLOSED to an unmatched sentinel when it can't be resolved to exactly one
		// project — never emit a guessed path (an empty project would compose the real
		// GLOBAL "/storage_pools/<name>" path a grant could match).
		pools, err := corrosion.ListAllStoragePools(ctx, s.db)
		if err != nil {
			return "/storage_pools/\x00invalid", true // can't verify → deny
		}
		projects := map[string]bool{}
		for _, p := range pools {
			if p.Name == poolName {
				projects[p.Project] = true // a found GLOBAL pool has Project "" — a valid, unique match
			}
		}
		if len(projects) != 1 {
			// 0 = unknown/deleted pool; ≥2 = same name across different projects (collision).
			return "/storage_pools/\x00invalid", true
		}
		var project string
		for pr := range projects {
			project = pr
		}
		return poolRBACPathFor(project, poolName), true
	case "project":
		return projectRBACBase(projectName), true
	case "cluster":
		return "/", true
	case "container":
		// A container schedule row records its container's project when it is
		// made, so it authorizes on the container's own path.
		p, name, ok := corrosion.ContainerScheduleName(vmName)
		if !ok {
			name = vmName // a request names the container itself
		}
		if p == "" {
			p = projectName
		}
		return ctRBACPathFor(tenancy.NormalizeProject(p), name), true
	default:
		if vm, err := corrosion.GetVM(ctx, s.db, vmName); err == nil && vm != nil {
			return vmRBACPath(vm), true
		}
		return "", false
	}
}

// authorizeSchedule checks backup.schedule on a schedule's target (see
// scheduleRBACTarget and requirePermResolved).
func (s *Server) authorizeSchedule(ctx context.Context, scope, vmName, poolName, projectName string) error {
	path, known := s.scheduleRBACTarget(ctx, scope, vmName, poolName, projectName)
	return s.requirePermResolved(ctx, known, path, vmRBACPathFor("", vmName), "backup.schedule", "operator", "vm "+strconv.Quote(vmName))
}

// canReadSchedule reports whether the caller may see a backup/replication
// schedule row — the read-side counterpart of authorizeSchedule, authorizing
// on the same scheduleRBACTarget path but with the backup.read verb (matched
// by Viewer/Auditor's "*.read" and by Operator/BackupOperator's "backup.*",
// so every role that could read a schedule's target resource keeps reading
// its schedules). A row whose project cannot be resolved here (an unreplicated
// or deleted target) permits only a cluster-root grant or the legacy
// no-bindings fallback — never a guess — matching requirePermResolved's rule,
// applied to a filter instead of a single error.
func (s *Server) canReadSchedule(ctx context.Context, r corrosion.BackupScheduleRecord) bool {
	scope := r.Scope
	if scope == "" {
		scope = "vm"
	}
	path, known := s.scheduleRBACTarget(ctx, scope, r.VMName, r.PoolName, r.ProjectName)
	if !known {
		return s.RequirePerm(ctx, "/", "backup.read", "viewer") == nil
	}
	return s.RequirePerm(ctx, path, "backup.read", "viewer") == nil
}

func (s *Server) ListBackupSchedules(ctx context.Context, _ *pb.ListBackupSchedulesRequest) (*pb.ListBackupSchedulesResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	resp := &pb.ListBackupSchedulesResponse{}
	for _, r := range rows {
		if r.Type == "replication" {
			continue // listed via ListReplicationSchedules
		}
		// ListBackupSchedules used to check only the cluster-wide viewer
		// floor above, so a caller scoped to one project could list every
		// VM/pool/project's backup schedules.
		if !s.canReadSchedule(ctx, r) {
			continue
		}
		resp.Schedules = append(resp.Schedules, scheduleToPB(r))
	}
	return resp, nil
}

func (s *Server) DeleteBackupSchedule(ctx context.Context, req *pb.DeleteBackupScheduleRequest) (*emptypb.Empty, error) {
	scope := req.Scope
	if scope == "" {
		scope = "vm"
	}
	if err := s.authorizeSchedule(ctx, scope, req.VmName, req.PoolName, req.ProjectName); err != nil {
		return nil, err
	}
	if req.Repo == "" {
		return nil, status.Error(codes.InvalidArgument, "repo required")
	}
	// Resolve the row identity key from the scope target. For vm scope this is
	// the VM name; for others it's the sentinel matching what create stored.
	key := corrosion.ScheduleKey(scope, req.VmName, req.PoolName, req.ProjectName)
	if key == "" {
		return nil, status.Error(codes.InvalidArgument, "schedule target required")
	}
	if err := s.deleteScheduleRow(ctx, key, req.Repo); err != nil {
		return nil, status.Errorf(codes.Internal, "delete schedule: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// schedulesKeptKey marks a DeleteVM whose VM's schedules stay
// (withSchedulesKept).
type schedulesKeptKey struct{}

// withSchedulesKept marks a delete that keeps the deleted workload's
// schedules: a blue-green cutover's delete of the blue, whose green serves in
// its place; a failed clone's removal of its staged copy; a compose
// container re-create's delete.
func withSchedulesKept(ctx context.Context) context.Context {
	return context.WithValue(ctx, schedulesKeptKey{}, true)
}

// schedulesKept reports whether ctx carries withSchedulesKept.
func schedulesKept(ctx context.Context) bool {
	kept, _ := ctx.Value(schedulesKeptKey{}).(bool)
	return kept
}

// deleteVMSchedules tombstones the vm-scoped schedules, backup and
// replication, of name: DeleteVM calls it once a plain delete of the VM has
// succeeded, so no schedule is left firing for a VM that is gone, or keeping
// a torn-down stack's backup repo registered (DeleteStackBackupRepos). A
// rebuild, re-create or cutover keeps them: the VM of the name comes back. A
// failure is logged and leaves the row: the orphan sweep
// (sweepScheduleOrphans) removes it when the VM was a torn-down stack's.
func (s *Server) deleteVMSchedules(ctx context.Context, name string) {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		slog.Warn("delete: could not read the deleted VM's schedules; the orphan sweep removes them", "vm", name, "error", err)
		return
	}
	for _, r := range rows {
		if r.Scope != "vm" || r.VMName != name {
			continue
		}
		if err := s.deleteScheduleRow(ctx, r.VMName, r.Repo); err != nil {
			slog.Warn("delete: could not remove the deleted VM's schedule; the orphan sweep removes it", "vm", name, "repo", r.Repo, "error", err)
			continue
		}
		slog.Info("delete: removed the deleted VM's schedule", "vm", name, "repo", r.Repo, "type", r.Type)
	}
}

// deleteContainerSchedules is deleteVMSchedules for a container: once a
// plain delete of container name in project has succeeded, and no live
// container of that project and name is left anywhere in this replica (a
// container name is unique per host, not cluster-wide), it tombstones the
// container's replication schedules, in either key form.
//
// host is the deleted container's host: its own row is not another holder,
// though this replica may still list it (a forwarded delete whose tombstone
// has not arrived here yet).
func (s *Server) deleteContainerSchedules(ctx context.Context, host, project, name string) {
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		slog.Warn("container delete: could not read whether another container holds the name; its schedules stay", "container", name, "error", err)
		return
	}
	for _, ct := range cts {
		if ct.Name == name && ct.HostName != host && tenancy.NormalizeProject(ct.Project) == tenancy.NormalizeProject(project) {
			slog.Info("container delete: another live container holds the name; its schedules stay",
				"container", name, "project", project, "deleted_on", host, "held_on", ct.HostName)
			return
		}
	}
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		slog.Warn("container delete: could not read the deleted container's schedules", "container", name, "error", err)
		return
	}
	for _, r := range rows {
		if !corrosion.ContainerScheduleIs(r, project, name) {
			continue
		}
		if err := s.deleteScheduleRow(ctx, r.VMName, r.Repo); err != nil {
			slog.Warn("container delete: could not remove the deleted container's schedule", "container", name, "repo", r.Repo, "error", err)
			continue
		}
		slog.Info("container delete: removed the deleted container's schedule", "container", name, "repo", r.Repo)
	}
}

// deletedContainerHost is the host a delete of container name acts on: the
// one named, or the host of its live row when none is (as DeleteContainer
// resolves it). "" when there is none.
func (s *Server) deletedContainerHost(ctx context.Context, host, name string) string {
	if host != "" {
		return host
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return ""
	}
	for _, ct := range cts {
		if ct.Name == name {
			return ct.HostName
		}
	}
	return ""
}

func scheduleToPB(r corrosion.BackupScheduleRecord) *pb.BackupSchedule {
	scope := r.Scope
	if scope == "" {
		scope = "vm"
	}
	return &pb.BackupSchedule{
		VmName:      r.VMName,
		Repo:        r.Repo,
		Cron:        r.Cron,
		KeepLast:    int32(r.KeepLast),
		KeepDaily:   int32(r.KeepDaily),
		KeepWeekly:  int32(r.KeepWeekly),
		KeepMonthly: int32(r.KeepMonthly),
		KeepYearly:  int32(r.KeepYearly),
		Enabled:     r.Enabled,
		LastRunAt:   r.LastRunAt,
		LastRunErr:  r.LastRunErr,
		Scope:       scope,
		PoolName:    r.PoolName,
		ProjectName: r.ProjectName,
	}
}

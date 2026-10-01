package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Backup repository maintenance: verify, garbage-collect, prune and sync a repo
// this daemon holds. `lv backup repo …` does the same to a local path with the
// invoking OS user's filesystem rights and no daemon; these RPCs are what the
// web UI's /backups actions call, so the page is held to RBAC and lands on the
// audit record. Before they existed the page ran pbsstore in-process behind
// nothing but a session with some role, and a Viewer could prune or GC.
//
// Every check is at `/`. A repo holds every project's backups and is named by
// daemon config, not owned by a project, so a project-scoped grant or token must
// not reach it (the same reasoning as images and security groups).
//
// Each verb is its own, so a binding can grant verify without prune. The four
// sit in the backup.* namespace, which Operator and BackupOperator hold and
// Viewer's *.read does not:
//
//   - backup.prune deletes manifests, and a manifest is what makes a pile of
//     chunks restorable. Operator floor: an operator can already make the
//     scheduler prune through a schedule's keep_* policy (backup.schedule).
//   - backup.gc deletes chunks no manifest references. It is the step that makes
//     a mistaken prune unrecoverable, so it is a write and not maintenance.
//   - backup.sync writes into the destination repo and copies every snapshot of
//     every project out of the source.
//   - backup.verify changes nothing, but reads and re-hashes every chunk in the
//     repo: unbounded disk I/O on the host, triggered at will. It is not a
//     *.read so a Viewer cannot start one.
//
// Each RPC writes one audit row: the caller, the repo, the outcome, and what
// the operation counted. A refusal is audited as "denied" — someone trying to
// prune backups they may not touch is worth a row.

const backupRepoRBACPath = "/"

// backupRepoAllowed checks verb at `/`, auditing a refusal against target.
// It runs before anything about the repo is resolved, so a caller without the
// verb learns nothing about which repos exist.
func (s *Server) backupRepoAllowed(ctx context.Context, verb, action, target string) error {
	err := s.RequirePerm(ctx, backupRepoRBACPath, verb, "operator")
	if err != nil && status.Code(err) == codes.PermissionDenied {
		s.audit(ctx, action, target, err.Error(), "denied")
	}
	return err
}

// openBackupRepoAudited resolves and opens repo (a registered name, or an
// absolute path for an admin), auditing a failure against target.
func (s *Server) openBackupRepoAudited(ctx context.Context, action, target, repo string) (*pbsstore.Repo, error) {
	path, err := s.resolveBackupRepoPath(ctx, repo)
	if err != nil {
		result := "error"
		if status.Code(err) == codes.PermissionDenied {
			result = "denied"
		}
		s.audit(ctx, action, target, fmt.Sprintf("repo %q: %v", repo, err), result)
		return nil, err
	}
	r, err := pbsstore.Open(path)
	if err != nil {
		s.audit(ctx, action, target, fmt.Sprintf("open repo %q: %v", repo, err), "error")
		return nil, status.Errorf(codes.FailedPrecondition, "open repo %q: %v", repo, err)
	}
	return r, nil
}

// openBackupRepoFor is the single-repo shape: check verb, then open repo.
func (s *Server) openBackupRepoFor(ctx context.Context, verb, action, repo string) (*pbsstore.Repo, error) {
	if err := s.backupRepoAllowed(ctx, verb, action, repo); err != nil {
		return nil, err
	}
	return s.openBackupRepoAudited(ctx, action, repo, repo)
}

func (s *Server) VerifyBackupRepo(ctx context.Context, req *pb.VerifyBackupRepoRequest) (*pb.VerifyBackupRepoResponse, error) {
	const action = "backup.repo.verify"
	repo, err := s.openBackupRepoFor(ctx, "backup.verify", action, req.GetRepo())
	if err != nil {
		return nil, err
	}
	stats, err := pbsstore.Verify(ctx, repo)
	if err != nil {
		s.audit(ctx, action, req.GetRepo(), err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "verify %q: %v", req.GetRepo(), err)
	}
	detail := fmt.Sprintf("chunks_checked=%d mismatched=%d missing=%d",
		stats.ChunksChecked, len(stats.Mismatches), len(stats.Missing))
	// The verify ran; what it found is in the detail. A repo with bit-rot is
	// still an "ok" verify, not an "error" one — the row records the action.
	s.audit(ctx, action, req.GetRepo(), detail, "ok")
	return &pb.VerifyBackupRepoResponse{
		ChunksChecked: int64(stats.ChunksChecked),
		Mismatched:    stats.Mismatches,
		Missing:       stats.Missing,
	}, nil
}

func (s *Server) GarbageCollectBackupRepo(ctx context.Context, req *pb.GarbageCollectBackupRepoRequest) (*pb.GarbageCollectBackupRepoResponse, error) {
	const action = "backup.repo.gc"
	repo, err := s.openBackupRepoFor(ctx, "backup.gc", action, req.GetRepo())
	if err != nil {
		return nil, err
	}
	// Always the default grace: it is what keeps a sweep from deleting the
	// chunks of a push whose manifest has not landed yet, on this host or any
	// other. `lv backup repo gc --grace` can lower it for a repo the operator
	// knows is idle; the RPC deliberately cannot.
	stats, err := pbsstore.GC(ctx, repo)
	if err != nil {
		s.audit(ctx, action, req.GetRepo(), fmt.Sprintf("chunks_deleted=%d bytes_reclaimed=%d: %v",
			stats.ChunksDeleted, stats.BytesReclaimed, err), "error")
		return nil, status.Errorf(codes.Internal, "gc %q: %v", req.GetRepo(), err)
	}
	s.audit(ctx, action, req.GetRepo(), fmt.Sprintf(
		"manifests_scanned=%d chunks_deleted=%d bytes_reclaimed=%d retained_young=%d manifests_invalid=%d",
		stats.ManifestsScanned, stats.ChunksDeleted, stats.BytesReclaimed,
		stats.ChunksSkippedYoung, stats.ManifestsInvalid), "ok")
	return &pb.GarbageCollectBackupRepoResponse{
		ManifestsScanned:    int64(stats.ManifestsScanned),
		ChunksReferenced:    int64(stats.ChunksReferenced),
		ChunksOnDisk:        int64(stats.ChunksOnDisk),
		ChunksDeleted:       int64(stats.ChunksDeleted),
		ChunksRetainedYoung: int64(stats.ChunksSkippedYoung),
		ManifestsInvalid:    int64(stats.ManifestsInvalid),
		BytesReclaimed:      stats.BytesReclaimed,
	}, nil
}

func toPbBackupRepoSnapshots(ms []pbsstore.Manifest) []*pb.BackupRepoSnapshot {
	out := make([]*pb.BackupRepoSnapshot, 0, len(ms))
	for _, m := range ms {
		out = append(out, &pb.BackupRepoSnapshot{
			Timestamp: m.Timestamp, VmName: m.VMName, DiskName: m.DiskName, TotalSize: m.TotalSize,
		})
	}
	return out
}

// PruneBackupRepo plans a retention prune and, with apply, carries it out. A
// plan is held to backup.prune as well: it is the preview of a prune, and only
// someone who may prune needs one. Only an applied prune is audited — a plan
// changes nothing — but a refused plan is, like any refusal.
func (s *Server) PruneBackupRepo(ctx context.Context, req *pb.PruneBackupRepoRequest) (*pb.PruneBackupRepoResponse, error) {
	const action = "backup.repo.prune"
	repo, err := s.openBackupRepoFor(ctx, "backup.prune", action, req.GetRepo())
	if err != nil {
		return nil, err
	}
	policy := pbsstore.RetentionPolicy{
		KeepLast:    int(req.GetKeepLast()),
		KeepDaily:   int(req.GetKeepDaily()),
		KeepWeekly:  int(req.GetKeepWeekly()),
		KeepMonthly: int(req.GetKeepMonthly()),
		KeepYearly:  int(req.GetKeepYearly()),
	}
	policyDetail := fmt.Sprintf("keep_last=%d keep_daily=%d keep_weekly=%d keep_monthly=%d keep_yearly=%d",
		policy.KeepLast, policy.KeepDaily, policy.KeepWeekly, policy.KeepMonthly, policy.KeepYearly)
	plan, err := pbsstore.PlanPrune(repo, policy)
	if err != nil {
		if req.GetApply() {
			s.audit(ctx, action, req.GetRepo(), policyDetail+": "+err.Error(), "error")
		}
		// PlanPrune refuses a policy that keeps nothing: the caller's mistake.
		if policy.KeepsNothing() {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "plan prune %q: %v", req.GetRepo(), err)
	}
	resp := &pb.PruneBackupRepoResponse{
		Keep:   toPbBackupRepoSnapshots(plan.Keep),
		Delete: toPbBackupRepoSnapshots(plan.Delete),
	}
	if !req.GetApply() {
		return resp, nil
	}
	if err := pbsstore.ApplyPrune(repo, plan); err != nil {
		s.audit(ctx, action, req.GetRepo(), fmt.Sprintf("%s planned_delete=%d: %v",
			policyDetail, len(plan.Delete), err), "error")
		return nil, status.Errorf(codes.Internal, "prune %q: %v", req.GetRepo(), err)
	}
	s.audit(ctx, action, req.GetRepo(), fmt.Sprintf("%s kept=%d deleted=%d",
		policyDetail, len(plan.Keep), len(plan.Delete)), "ok")
	resp.Applied = true
	return resp, nil
}

func (s *Server) SyncBackupRepo(ctx context.Context, req *pb.SyncBackupRepoRequest) (*pb.SyncBackupRepoResponse, error) {
	const action = "backup.repo.sync"
	target := req.GetSource() + " -> " + req.GetDestination()
	if err := s.backupRepoAllowed(ctx, "backup.sync", action, target); err != nil {
		return nil, err
	}
	if req.GetSource() == "" || req.GetDestination() == "" {
		return nil, status.Error(codes.InvalidArgument, "source and destination required")
	}
	src, err := s.openBackupRepoAudited(ctx, action, target, req.GetSource())
	if err != nil {
		return nil, err
	}
	dst, err := s.openBackupRepoAudited(ctx, action, target, req.GetDestination())
	if err != nil {
		return nil, err
	}
	if src.Root() == dst.Root() {
		return nil, status.Error(codes.InvalidArgument, "source and destination are the same repo")
	}
	stats, err := pbsstore.SyncRepo(ctx, src, dst)
	detail := fmt.Sprintf("manifests_copied=%d chunks_copied=%d chunks_skipped=%d bytes_copied=%d",
		stats.ManifestsCopied, stats.ChunksCopied, stats.ChunksSkipped, stats.BytesCopied)
	if err != nil {
		s.audit(ctx, action, target, detail+": "+err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "sync %s: %v", target, err)
	}
	s.audit(ctx, action, target, detail, "ok")
	return &pb.SyncBackupRepoResponse{
		ManifestsCopied: int64(stats.ManifestsCopied),
		ChunksCopied:    int64(stats.ChunksCopied),
		ChunksSkipped:   int64(stats.ChunksSkipped),
		BytesCopied:     stats.BytesCopied,
	}, nil
}

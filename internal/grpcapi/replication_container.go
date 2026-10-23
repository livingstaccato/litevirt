package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Container replication.
//
// A container's data is a rootfs directory on one host. Replicating it is the
// container half of what a VM schedule does for a disk: on a cron schedule the
// owning host archives the container (frozen, point-in-time) and streams the
// result to a peer. Transport is the one container backups, migrations and
// failover relocations already use: the content-addressed chunk store, so a run
// sends only the chunks the peer does not hold. A replica archive is cut into
// content-defined chunks (pbsstore/cdc.go), so a file that grew in the middle of
// the rootfs costs the chunks around it, not the rest of the archive.
//
// WHERE A REPLICA LIVES. In its own namespace, never among backups: a separate
// chunk store under the target repo (<repo>/.ct-replicas/<project>), named on
// the wire "ct-replicas:<project>:<repo>". Backup retention, `keep_last`, a
// backup restore's search and a repo prune never see it. A build that predates
// the namespace does not resolve that name, so it refuses a push rather than
// mixing a replica into a backup repo.
//
// WHAT A REPLICA IS. A manifest carrying a containerReplicaMark: the stream, the
// host it was taken on, that host's row incarnation (the container row's
// created_at, unique per row) and owner epoch, and the container's provenance
// chain: the points of its own history its current data descends from
// (replicaBase). A replica becomes a live copy only through failover promotion
// (RestoreContainerFromBackup), with the same proof, recovery claim and single-use
// token as a restore from backup; RestoreContainer refuses any other restore of
// a replica.
//
// NEVER LOSING THE NEWEST COPY. A run never deletes a replica it cannot prove is
// contained in the data it carries. Within one segment of the container's
// history (one host, one row incarnation) replicas are snapshots of one linear
// history, so keep_replicas trims the oldest of them. A replica of another
// segment goes only when the new replica's provenance chain names a point of
// that segment at or after it was taken. Anything else is SET ASIDE: kept,
// marked, reported once, never promoted automatically, and removed only by an
// operator (`lv replication replicas --remove`). That is the failover that did
// not restore from the replica: the restored container's chain does not reach
// the replica, so its newer data is never pruned by the next run.

// containerReplicaMark is carried in the manifest's embedded spec.
type containerReplicaMark struct {
	// Stream names one replication stream: a container's schedule into one repo.
	Stream string `json:"stream"`
	// Source is the host that produced the replica.
	Source string `json:"source"`
	// Placement is the source row's placement id (corrosion.WithNewPlacement):
	// with Source it names one segment of the container's history, and it is
	// never reused, however the container moves. "" for a row an earlier
	// build wrote: an unknown placement, in no segment, never trimmed.
	Placement string `json:"placement,omitempty"`
	// Incarnation is the source row's created_at. It identifies nothing for
	// trimming (a relocate-recreate and a re-key keep it); promotion uses it
	// only for a row with no placement id, which has not moved since.
	Incarnation string `json:"incarnation,omitempty"`
	// Epoch is that row's owner_epoch when the replica was taken.
	Epoch int64 `json:"epoch"`
	// Keep is how many replicas of this segment the target retains (0 = all).
	Keep int `json:"keep,omitempty"`
	// Bases is the container's provenance chain when the replica was taken
	// (replicaBase).
	Bases []replicaBase `json:"bases,omitempty"`
}

// replicaBase is one point of a container's history its current data descends
// from: the archive (replica, migration or backup) of segment (Source,
// Placement) captured at Taken that a restore laid down. Every replica of that
// segment captured at or before Taken is contained in the current data. Taken
// is the archive's capture instant (containerBackupSpec.CapturedAt), never its
// timestamp, which is a name a scheduler tick or an operator chose.
type replicaBase struct {
	Source    string `json:"source"`
	Placement string `json:"placement"`
	Taken     string `json:"taken"`
}

// maxReplicaBases bounds a provenance chain; the oldest points drop off, which
// only ever costs a proof (a replica set aside instead of removed).
const maxReplicaBases = 16

// containerReplicaStream is the stream name for a schedule's target repo.
func containerReplicaStream(repo string) string { return "ct-replica:" + repo }

// ctReplicaRepoPrefix marks a wire repo name as a replica namespace.
const ctReplicaRepoPrefix = "ct-replicas:"

// ctReplicaDir is the namespace's directory under its base repo.
const ctReplicaDir = ".ct-replicas"

// containerReplicaRepo is the wire name of project's replica namespace in repo.
func containerReplicaRepo(project, repo string) string {
	return ctReplicaRepoPrefix + tenancy.NormalizeProject(project) + ":" + repo
}

// parseReplicaRepo splits a replica namespace's wire name. ok is false for any
// other name.
func parseReplicaRepo(name string) (project, repo string, ok bool) {
	rest, found := strings.CutPrefix(name, ctReplicaRepoPrefix)
	if !found {
		return "", "", false
	}
	project, repo, found = strings.Cut(rest, ":")
	if !found || repo == "" || safename.ValidateName(project) != nil {
		return "", "", false
	}
	return project, repo, true
}

// replicaNamespacePath is project's replica namespace under a base repo path.
func replicaNamespacePath(basePath, project string) string {
	return filepath.Join(basePath, ctReplicaDir, project)
}

// lookupRepoPath resolves a logical backup repo name in this host's config or
// the cluster registry.
func (s *Server) lookupRepoPath(ctx context.Context, name string) (string, bool) {
	if p, ok := s.backupRepos[name]; ok {
		return p, true
	}
	if s.db != nil {
		if p, err := corrosion.GetBackupRepoPath(ctx, s.db, name); err == nil && p != "" {
			return p, true
		}
	}
	return "", false
}

// openReplicaNamespace opens (create: or initialises) the replica namespace a
// wire name names, refusing a base repo this host cannot resolve or one that is
// encrypted (a peer push stores plaintext chunks).
func (s *Server) openReplicaNamespace(ctx context.Context, wire string, create bool) (*pbsstore.Repo, error) {
	project, repoName, ok := parseReplicaRepo(wire)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "%q is not a replica namespace", wire)
	}
	base, ok := s.lookupRepoPath(ctx, repoName)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown backup repo %q", repoName)
	}
	if br, err := pbsstore.Open(base); err != nil {
		return nil, status.Errorf(codes.NotFound, "open repo %q: %v", repoName, err)
	} else if br.IsEncrypted() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"backup repo %q is encrypted, and a replica namespace in it would hold plaintext chunks; use a plaintext repo as the replica target", repoName)
	}
	path := replicaNamespacePath(base, project)
	if r, err := pbsstore.Open(path); err == nil {
		return r, nil
	} else if !create {
		return nil, status.Errorf(codes.NotFound, "repo %q holds no replicas of project %q", repoName, project)
	}
	r, err := pbsstore.Init(path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create replica namespace in %q: %v", repoName, err)
	}
	return r, nil
}

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
// lineage in the same stream as m (both already known to carry marks). A
// manifest that records no owner_id is NOT of a lineage that records one: a
// container deleted and re-created under the same name is another container,
// and an old lineage's replicas must neither block nor be pruned by its runs.
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
	return corrosion.DecodeCreateSpec(sa.CreateSpec).OwnerID == corrosion.DecodeCreateSpec(sb.CreateSpec).OwnerID
}

// sameSegment reports whether two marks were taken in one segment of the
// container's history: one host, one placement. A mark with no placement id (a
// row an earlier build wrote) is in no known segment.
func sameSegment(a, b *containerReplicaMark) bool {
	return a.Placement != "" && a.Source == b.Source && a.Placement == b.Placement
}

// capturedAt is when a manifest's archive was captured (after the freeze), and
// whether that is known. A manifest's timestamp is never used in its place: it
// is the name a scheduler tick, or an operator, gave it.
func capturedAt(m *pbsstore.Manifest) (time.Time, bool) {
	spec, ok := manifestSpec(m)
	if !ok || spec.CapturedAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, spec.CapturedAt)
	return t, err == nil
}

// containedIn reports whether the replica (mark pm, its manifest m) is proven
// contained in data whose provenance chain is bases: a point of the replica's
// own segment captured at or after it. Anything not known for certain (no
// placement, no capture instant) is not proven.
func containedIn(pm *containerReplicaMark, m *pbsstore.Manifest, bases []replicaBase) bool {
	at, ok := capturedAt(m)
	if pm.Placement == "" || !ok {
		return false
	}
	for _, b := range bases {
		taken, err := time.Parse(time.RFC3339Nano, b.Taken)
		if err == nil && b.Source == pm.Source && b.Placement == pm.Placement && !at.After(taken) {
			return true
		}
	}
	return false
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

// admitContainerReplica runs on the TARGET before a manifest pushed into a
// repo is written. A replica namespace takes replicas only, and a replica goes
// only to a replica namespace. A replica is refused when:
//   - the peer pushing it is not the host it says it was taken on;
//   - this host's own view says that host may not be the container's owner: it
//     is fenced or gone, or the container's live row is on another host, is
//     another incarnation, or has moved past the replica's owner epoch (a stale
//     or fenced source never adds a promotable copy);
//   - a replica with its timestamp is already held (a replica is never replaced);
//   - it is proven older than a replica already held: an earlier one of the same
//     segment, or one a held replica's provenance chain contains.
//
// caller is the pushing peer's certificate CN.
func (s *Server) admitContainerReplica(ctx context.Context, repo *pbsstore.Repo, m *pbsstore.Manifest, namespace bool, caller string) error {
	mark := replicaMarkOf(m)
	switch {
	case mark == nil && namespace:
		return status.Error(codes.InvalidArgument, "push-backup: a replica namespace holds container replicas only")
	case mark == nil:
		return nil
	case !namespace:
		return status.Error(codes.InvalidArgument,
			"push-backup: a container replica goes to its replica namespace, never among backups")
	}
	if caller != "" && caller != mark.Source {
		return status.Errorf(codes.PermissionDenied,
			"push-backup: a replica taken on %q pushed by %q", mark.Source, caller)
	}
	spec, _ := manifestSpec(m)
	if err := s.replicaSourceIsOwner(ctx, mark, tenancy.NormalizeProject(spec.Project), m.VMName); err != nil {
		return err
	}
	if existing, err := repo.GetManifest(m.VMName, m.Timestamp, containerBackupDisk); err == nil && existing != nil {
		return status.Errorf(codes.AlreadyExists, "push-backup: a replica of %s taken at %s is already held", m.VMName, m.Timestamp)
	}
	peers, err := replicaPeers(ctx, repo, m)
	if err != nil {
		return status.Errorf(codes.Internal, "push-backup: read existing replicas: %v", err)
	}
	mAt, mKnown := capturedAt(m)
	for i := range peers {
		pm := replicaMarkOf(&peers[i])
		if pAt, ok := capturedAt(&peers[i]); ok && mKnown && sameSegment(pm, mark) && pAt.After(mAt) {
			return errStaleReplica
		}
		if containedIn(mark, m, pm.Bases) {
			return errStaleReplica
		}
	}
	return nil
}

// replicaSourceIsOwner checks, against this host's own replica of the cluster
// state, that the host a replica was taken on may still be the container's
// owner. A container this host has no live row for is not judged (its view may
// lag the push); the owner's own checks and promotion's segment match cover it.
func (s *Server) replicaSourceIsOwner(ctx context.Context, mark *containerReplicaMark, project, name string) error {
	if s.db == nil {
		return nil
	}
	h, err := corrosion.GetHost(ctx, s.db, mark.Source)
	if err != nil {
		return status.Errorf(codes.Unavailable, "push-backup: read host %q: %v", mark.Source, err)
	}
	if h == nil || h.State == "fenced" || h.State == "removed" {
		return status.Errorf(codes.FailedPrecondition,
			"push-backup: refusing a replica from %q: that host is fenced or not a cluster member here", mark.Source)
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return status.Errorf(codes.Unavailable, "push-backup: read containers: %v", err)
	}
	for _, ct := range cts {
		if ct.Name != name || tenancy.NormalizeProject(ct.Project) != project {
			continue
		}
		// Aborted, not a failure: a container that has just moved, or a
		// target that has not seen the move yet. The owner's next run lands.
		rowPlacement := corrosion.PlacementOf(ct.CreateSpec)
		switch {
		case ct.HostName != mark.Source:
			return status.Errorf(codes.Aborted,
				"push-backup: refusing a replica of %s from %q: the container's row here is on %q", name, mark.Source, ct.HostName)
		case mark.Placement != "" && rowPlacement != "" && rowPlacement != mark.Placement:
			return status.Errorf(codes.Aborted,
				"push-backup: refusing a replica of %s from %q: it was taken in an earlier placement of the container", name, mark.Source)
		case ct.OwnerEpoch > mark.Epoch:
			return status.Errorf(codes.Aborted,
				"push-backup: refusing a replica of %s from %q at owner epoch %d: the row here is at %d", name, mark.Source, mark.Epoch, ct.OwnerEpoch)
		}
	}
	return nil
}

// setAsideRecord is the sidecar that marks a replica set aside.
type setAsideRecord struct {
	Timestamp    string `json:"timestamp"`
	Reason       string `json:"reason"`
	SupersededBy string `json:"superseded_by"`
	At           string `json:"at"`
}

func setAsidePath(repo *pbsstore.Repo, name, ts string) string {
	return filepath.Join(repo.Root(), "set-aside", name, strings.ReplaceAll(ts, ":", "-")+".json")
}

func readSetAside(repo *pbsstore.Repo, name, ts string) (setAsideRecord, bool) {
	b, err := os.ReadFile(setAsidePath(repo, name, ts))
	if err != nil {
		return setAsideRecord{}, false
	}
	var r setAsideRecord
	if json.Unmarshal(b, &r) != nil {
		return setAsideRecord{}, false
	}
	return r, true
}

// settleContainerReplicas runs on the TARGET after a replica's manifest is
// written. Within the new replica's segment it keeps the newest Keep. A replica
// of another segment that the new one's provenance chain contains is removed;
// any other is set aside (setAsideRecord) and returned, the first time only, so
// the caller reports it once. Only replicas of the same stream and lineage are
// touched. Chunks are reclaimed by the namespace's GC. Best-effort: a failure
// leaves extra replicas, never fewer.
func settleContainerReplicas(ctx context.Context, repo *pbsstore.Repo, m *pbsstore.Manifest) (setAside []pbsstore.Manifest) {
	mark := replicaMarkOf(m)
	if mark == nil {
		return nil
	}
	peers, err := replicaPeers(ctx, repo, m)
	if err != nil {
		slog.Warn("container replica: read replicas to settle", "container", m.VMName, "error", err)
		return nil
	}
	var del, same []pbsstore.Manifest
	for i := range peers {
		pm := replicaMarkOf(&peers[i])
		_, aside := readSetAside(repo, m.VMName, peers[i].Timestamp)
		_, captured := capturedAt(&peers[i])
		switch {
		case containedIn(pm, &peers[i], mark.Bases):
			// Proven contained in the data now replicated: it goes, set
			// aside or not.
			del = append(del, peers[i])
		case sameSegment(pm, mark) && !aside && captured:
			// One placement's own linear history: keep_replicas trims it.
			// A set-aside replica, or one whose capture is not known, is
			// never trimmed.
			same = append(same, peers[i])
		default:
			if aside || sameSegment(pm, mark) {
				continue // kept as it is
			}
			rec := setAsideRecord{
				Timestamp: peers[i].Timestamp, SupersededBy: m.Timestamp, At: time.Now().UTC().Format(time.RFC3339),
				Reason: fmt.Sprintf("a replica taken on %s is not proven to be contained in the container's data now replicated from %s; kept until removed",
					pm.Source, mark.Source),
			}
			b, _ := json.Marshal(rec)
			p := setAsidePath(repo, m.VMName, peers[i].Timestamp)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				slog.Warn("container replica: record set-aside", "container", m.VMName, "error", err)
				continue
			}
			if err := os.WriteFile(p, b, 0o640); err != nil {
				slog.Warn("container replica: record set-aside", "container", m.VMName, "error", err)
				continue
			}
			setAside = append(setAside, peers[i])
		}
	}
	if _, known := capturedAt(m); mark.Keep > 0 && known {
		sort.Slice(same, func(i, j int) bool {
			a, _ := capturedAt(&same[i])
			b, _ := capturedAt(&same[j])
			return a.After(b)
		})
		// m itself is one of the kept.
		if keepOthers := mark.Keep - 1; keepOthers < len(same) {
			del = append(del, same[keepOthers:]...)
		}
	}
	if len(del) > 0 {
		if err := pbsstore.ApplyPrune(repo, pbsstore.PrunePlan{Delete: del}); err != nil {
			slog.Warn("container replica: prune", "container", m.VMName, "error", err)
		} else {
			for _, d := range del {
				_ = os.Remove(setAsidePath(repo, m.VMName, d.Timestamp))
			}
		}
		if _, err := pbsstore.GC(ctx, repo); err != nil {
			slog.Warn("container replica: gc", "container", m.VMName, "error", err)
		}
	}
	return setAside
}

// containerBases is the container's provenance chain on this host: the one its
// last restore here recorded (recordContainerBases), when that restore laid
// down THIS placement. Anything else proves nothing: no record, or a record of
// another placement, including an earlier stay of the container on this host
// that a relocate-recreate or a re-key has since handed back (a new placement
// id each time). nil is the safe answer: it only costs a replica set aside
// instead of removed.
func (s *Server) containerBases(rec *corrosion.ContainerRecord) []replicaBase {
	placement := corrosion.PlacementOf(rec.CreateSpec)
	if placement == "" {
		return nil
	}
	b, err := os.ReadFile(s.containerBasesPath(rec.Project, rec.Name))
	if err != nil {
		return nil
	}
	var f containerBasesFile
	if json.Unmarshal(b, &f) != nil || f.Placement != placement {
		return nil
	}
	return f.Bases
}

// containerBasesFile is a container's provenance chain, host-local, bound to
// the placement the restore that recorded it laid down.
type containerBasesFile struct {
	Placement string        `json:"placement"`
	Bases     []replicaBase `json:"bases"`
}

func (s *Server) containerBasesPath(project, name string) string {
	return filepath.Join(s.dataDir, "ct-provenance", tenancy.NormalizeProject(project), name+".json")
}

// recordContainerBases records, after a restore laid down placement of
// project/name from an archive with spec, the container's provenance chain:
// that archive's own point (its source, its placement, its capture instant),
// then the chain it carried. An archive with no placement or no capture
// instant (an earlier build's, or one whose name an operator chose) adds no
// point of its own. It replaces any earlier record of the container here.
// Best-effort: a missing record only costs proofs.
func (s *Server) recordContainerBases(project, name, placement string, spec containerBackupSpec) {
	if safename.ValidateName(tenancy.NormalizeProject(project)) != nil || placement == "" {
		return
	}
	var bases []replicaBase
	if spec.Source != "" && spec.Placement != "" && spec.CapturedAt != "" {
		bases = append(bases, replicaBase{Source: spec.Source, Placement: spec.Placement, Taken: spec.CapturedAt})
	}
	bases = append(bases, spec.Bases...)
	if len(bases) > maxReplicaBases {
		bases = bases[:maxReplicaBases]
	}
	path := s.containerBasesPath(project, name)
	b, _ := json.Marshal(containerBasesFile{Placement: placement, Bases: bases})
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		slog.Warn("container restore: record provenance", "container", name, "error", err)
		return
	}
	if err := os.WriteFile(path, b, 0o640); err != nil {
		slog.Warn("container restore: record provenance", "container", name, "error", err)
	}
}

// errReplicationSuspended is a run that did not replicate because the workload
// runs on its own replica target: the replica would protect nothing. It is never
// a success.
var errReplicationSuspended = errors.New("replication suspended")

// runContainerReplication is RunReplication for a container-scoped schedule: it
// archives the container (frozen while it runs) into a local staging repo and
// streams the manifest to the target host's replica namespace, where the target
// applies admitContainerReplica and settleContainerReplicas.
func (s *Server) runContainerReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) (retErr error) {
	keyProject, name, ok := corrosion.ContainerScheduleName(sched.VMName)
	if !ok {
		return fmt.Errorf("replication schedule %q is not a container schedule", sched.VMName)
	}
	project := tenancy.NormalizeProject(keyProject)
	if keyProject == "" {
		project = tenancy.NormalizeProject(sched.ProjectName)
	}
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
	var detail string
	defer func() {
		s.replicationOutcome(ctx, sched, "container", name, project, target, repoName, detail, retErr)
	}()
	// A run writes container_replication's data (a replica in the target's
	// replica namespace), so it runs through this node's release-feature gate:
	// refused, with the gate's reason, until the release token has latched.
	return s.WithReleaseFeature(ctx, capabilities.FeatureContainerReplication,
		func(ctx context.Context, g capabilities.FeatureGrant) error {
			return s.replicateContainer(ctx, g, sched, rec, project, name, repoName, target, runAt, &detail)
		})
}

// replicateContainer is a container replication run past its release gate:
// it archives the container (rec, the row runContainerReplication found on
// this host) and pushes the archive to target's replica namespace of repo
// repoName, and sets *detail to describe the replica written.
func (s *Server) replicateContainer(ctx context.Context, g capabilities.FeatureGrant, sched corrosion.BackupScheduleRecord,
	rec *corrosion.ContainerRecord, project, name, repoName, target string, runAt time.Time, detail *string) error {
	if err := g.Check(capabilities.FeatureContainerReplication); err != nil {
		return err
	}
	if repoName == "" || target == "" {
		return fmt.Errorf("container replication of %q needs a target host and a target repo", name)
	}
	if target == s.hostName {
		return s.suspendedOnOwnTarget(sched, "container", name)
	}
	if err := s.mayReplicateAsOwner(ctx, rec); err != nil {
		return err
	}
	th, err := corrosion.GetHost(ctx, s.db, target)
	if err != nil {
		return fmt.Errorf("look up target host %q: %w", target, err)
	}
	if th == nil || th.State != "active" {
		return &replTargetDownError{host: target}
	}
	if !corrosion.HostRunsContainers(*th) {
		return fmt.Errorf("replica target host %q cannot run containers (%s is not true), so a replica there could never be promoted", target, corrosion.LabelLXCCapable)
	}
	if s.containerRuntime == nil {
		return fmt.Errorf("container runtime not wired on this host")
	}

	unlock := s.lockVMAs("ct/"+name, "container replication")
	defer unlock()
	if rec, err = s.placedContainerRow(ctx, project, rec); err != nil {
		return err
	}

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
		Placement: corrosion.PlacementOf(rec.CreateSpec), Incarnation: rec.CreatedAt,
		Epoch: rec.OwnerEpoch, Keep: sched.KeepReplicas, Bases: s.containerBases(rec),
	}
	// The run pushes into the target's backup repo repoName, so the repo's
	// backup_bwlimits entry on this host paces it, as it paces a backup into
	// that repo pushed to its host: the shared per-repo throttle, over the
	// archive read and the chunks sent. The schedule's own bandwidth limit is
	// one throttle shared by every run of the schedule here, and paces the
	// chunks sent; the lower of the two wins.
	readLim, sendLim := s.containerReplicationLimiters(ctx, sched, repoName)
	manifest, err := s.archiveContainerAs(ctx, staging, rec, runAt.UTC().Format(time.RFC3339), mark, readLim, func(pbsstore.PushProgress) {})
	if err != nil {
		return fmt.Errorf("archive container: %w", err)
	}
	if err := s.pushManifestToPeerRepo(ctx, target, containerReplicaRepo(project, repoName), staging, manifest, sendLim); err != nil {
		if status.Code(err) == codes.Unavailable {
			return &replTargetDownError{host: target, err: err}
		}
		return fmt.Errorf("push replica to %s: %w", target, err)
	}
	*detail = fmt.Sprintf("project=%s → %s@%s @ %s", project, repoName, target, manifest.Timestamp)
	return nil
}

// placedContainerRow re-reads rec's row under the container's lock, which
// every run of the container holds, and gives a row written before this build
// a placement id. Without one the row belongs to no segment: each run would
// set the previous run's replica aside and keep would never apply. The mint is
// a compare-and-set on the create spec (the same release gate replication
// needs lets the statement flow), so a run that loses it to another run of the
// container re-reads the row and takes the placement that run gave it. A run
// never archives under an empty placement, nor from a row that has changed
// owner or incarnation since mayReplicateAsOwner judged it: that is the next
// run's to replicate, and is reported as a move (Aborted), not a failure.
func (s *Server) placedContainerRow(ctx context.Context, project string, rec *corrosion.ContainerRecord) (*corrosion.ContainerRecord, error) {
	for attempt := 0; attempt < 3; attempt++ {
		row, err := corrosion.GetContainer(ctx, s.db, s.hostName, rec.Name)
		if err != nil {
			return nil, fmt.Errorf("re-read the container's row: %w", err)
		}
		if row == nil || tenancy.NormalizeProject(row.Project) != project ||
			row.CreatedAt != rec.CreatedAt || row.OwnerEpoch != rec.OwnerEpoch {
			return nil, status.Errorf(codes.Aborted, "container %s's row on this host changed during the run; the next run replicates it", rec.Name)
		}
		if corrosion.PlacementOf(row.CreateSpec) != "" {
			return row, nil
		}
		// The mint rewrites create_spec, part of the identity of a guarded
		// re-key or tombstone of this row that may still be in flight. A row
		// whose runtime has already left this host is such a row: leave it
		// as it is, and let the next run, on whichever host holds the
		// container, mint.
		if here, err := s.containerRuntime.ContainerExists(ctx, rec.Name); err != nil || !here {
			return nil, status.Errorf(codes.Aborted, "container %s's runtime is not on this host (%v), so no placement id is minted for it; the next run replicates it", rec.Name, err)
		}
		spec, applied, err := corrosion.MintContainerPlacementSpec(ctx, s.db, s.hostName, rec.Name, row.CreateSpec)
		if err != nil {
			return nil, fmt.Errorf("give the container a placement id: %w", err)
		}
		if applied {
			row.CreateSpec = spec
			return row, nil
		}
	}
	return nil, status.Errorf(codes.Aborted, "container %s has no placement id yet and this run could not give it one; the next run retries", rec.Name)
}

// mayReplicateAsOwner refuses a run on a host that may no longer be the
// container's owner: one that has self-fenced, lost the execution gate, is not
// an active member in its own view, or whose on-disk owner-epoch marker says
// its row is behind the runtime it holds. The target checks again on receipt
// against its own view (replicaSourceIsOwner); this keeps a stale host from
// even archiving.
func (s *Server) mayReplicateAsOwner(ctx context.Context, rec *corrosion.ContainerRecord) error {
	if reason, refused := s.execGateForAction(ctx, false); refused {
		return fmt.Errorf("this host may not act as the container's owner now (%s)", reason)
	}
	if h, err := corrosion.GetHost(ctx, s.db, s.hostName); err == nil && h != nil && h.State != "active" && h.State != "maintenance" {
		return fmt.Errorf("this host is %s, not an active member, so it does not replicate", h.State)
	}
	if s.containersRoot != "" {
		if marker, found, err := health.ReadContainerOwnerEpochMarker(s.containersRoot, rec.Name); err == nil && found && marker > rec.OwnerEpoch {
			return fmt.Errorf("the container's owner-epoch marker here (%d) is ahead of its row (%d); this host's view is not current", marker, rec.OwnerEpoch)
		}
	}
	return nil
}

// ctReplica is a promotable replica of a container, held by a host.
type ctReplica struct {
	Host, Repo, Timestamp string
	// CapturedAt is when it was captured (RFC3339Nano); Source and Placement
	// are the placement it was taken in.
	CapturedAt, Source, Placement string
}

// replicaOfRow reports whether a listed replica was taken from the row owner:
// the same host and placement id (for a row with none, which has not moved since
// this build, the same created_at), the same lineage.
func replicaOfRow(r *pb.ContainerReplica, owner *corrosion.ContainerRecord) bool {
	if r.Source != owner.HostName || r.OwnerId != corrosion.DecodeCreateSpec(owner.CreateSpec).OwnerID {
		return false
	}
	if p := corrosion.PlacementOf(owner.CreateSpec); p != "" {
		return r.Placement == p
	}
	return r.Placement == "" && r.Incarnation != "" && r.Incarnation == owner.CreatedAt
}

func replicaCaptured(r *pb.ContainerReplica) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, r.CapturedAt)
	return t, err == nil && r.CapturedAt != ""
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
		if r.Type == "replication" && corrosion.ContainerScheduleIs(r, project, name) {
			out = append(out, r)
		}
	}
	return out
}

// containerReplicaFor finds the replica a failover may promote onto targetHost:
// a container-scoped schedule that allows auto-promote and targets that host,
// whose namespace there holds a replica of this container's lineage taken from
// the very row being relocated (its host and incarnation), not set aside, and no
// older than the schedule's age bound. A replica of an earlier segment of the
// container's history, or one a stale host pushed, is never promoted. owner is
// the relocating row (nil when unreadable: then nothing is promotable).
func (s *Server) containerReplicaFor(ctx context.Context, name string, owner *corrosion.ContainerRecord, targetHost string, now time.Time) (ctReplica, bool) {
	if owner == nil {
		return ctReplica{}, false
	}
	project := tenancy.NormalizeProject(owner.Project)
	for _, sched := range s.containerReplicationSchedules(ctx, name, project) {
		if !sched.Enabled || !sched.AutoPromote || sched.TargetHost != targetHost || sched.TargetPool == "" {
			continue
		}
		reps, err := s.listContainerReplicasOn(ctx, targetHost, sched.TargetPool, project, name)
		if err != nil {
			slog.Warn("container failover: could not ask the replica host for its replicas", "container", name, "host", targetHost, "error", err)
			continue
		}
		var best *pb.ContainerReplica
		var bestAt time.Time
		for _, r := range reps {
			at, ok := replicaCaptured(r)
			if r.SetAside || !ok || !replicaOfRow(r, owner) {
				continue
			}
			if best == nil || at.After(bestAt) {
				best, bestAt = r, at
			}
		}
		if best == nil {
			continue
		}
		ts := bestAt
		if age := now.Sub(ts); age > autoPromoteAgeLimit(sched.Cron) {
			slog.Warn("container failover: the replica is too old to promote automatically",
				"container", name, "host", targetHost, "taken", best.Timestamp, "age", age.Round(time.Minute))
			continue
		}
		return ctReplica{Host: targetHost, Repo: containerReplicaRepo(project, sched.TargetPool), Timestamp: best.Timestamp,
			CapturedAt: best.CapturedAt, Source: best.Source, Placement: best.Placement}, true
	}
	return ctReplica{}, false
}

// listContainerReplicasOn lists project/name's replicas in repo's namespace on
// host (this one or a peer).
func (s *Server) listContainerReplicasOn(ctx context.Context, host, repo, project, name string) ([]*pb.ContainerReplica, error) {
	if host == s.hostName {
		return s.localContainerReplicas(ctx, repo, project, name)
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	resp, err := c.ListContainerReplicas(ctx, &pb.ListContainerReplicasRequest{Host: host, Repo: repo, Project: project, Name: name})
	if err != nil {
		return nil, err
	}
	return resp.GetReplicas(), nil
}

// localContainerReplicas lists project/name's replicas in this host's namespace
// of repo, oldest first. A namespace that does not exist holds none.
func (s *Server) localContainerReplicas(ctx context.Context, repo, project, name string) ([]*pb.ContainerReplica, error) {
	r, err := s.openReplicaNamespace(ctx, containerReplicaRepo(project, repo), false)
	if status.Code(err) == codes.NotFound {
		if _, ok := s.lookupRepoPath(ctx, repo); ok {
			return nil, nil // the repo is here; it holds no replicas of the project yet
		}
	}
	if err != nil {
		return nil, err
	}
	ms, err := r.ManifestsFor(ctx, name, containerBackupDisk)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list replicas: %v", err)
	}
	scheduled := s.replicasScheduledHere(ctx, repo, project, name)
	var out []*pb.ContainerReplica
	for i := range ms {
		mark := replicaMarkOf(&ms[i])
		if mark == nil {
			continue
		}
		spec, _ := manifestSpec(&ms[i])
		cr := &pb.ContainerReplica{
			Timestamp: ms[i].Timestamp, Source: mark.Source, Incarnation: mark.Incarnation,
			OwnerEpoch: mark.Epoch, TotalSize: ms[i].TotalSize, Stream: mark.Stream,
			OwnerId:   corrosion.DecodeCreateSpec(spec.CreateSpec).OwnerID,
			Placement: mark.Placement, CapturedAt: spec.CapturedAt, Orphaned: !scheduled,
		}
		if sa, ok := readSetAside(r, name, ms[i].Timestamp); ok {
			cr.SetAside, cr.SetAsideReason = true, sa.Reason
		}
		out = append(out, cr)
	}
	return out, nil
}

// replicasScheduledHere reports whether a schedule of project/name still
// replicates into repo on this host. When none does, its replicas here are
// orphans: nothing settles them any more, so an operator may remove them.
// Unreadable schedules count as scheduled (keep).
func (s *Server) replicasScheduledHere(ctx context.Context, repo, project, name string) bool {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return true
	}
	for _, r := range rows {
		if r.Type == "replication" && r.TargetHost == s.hostName && r.TargetPool == repo && corrosion.ContainerScheduleIs(r, project, name) {
			return true
		}
	}
	return false
}

// ListContainerReplicas lists a container's replicas in one repo's replica
// namespace on one host: each one's time, the host and row incarnation it was
// taken from, and whether it is set aside. A peer (failover choosing what to
// promote) or a caller who may read the container's backups.
func (s *Server) ListContainerReplicas(ctx context.Context, req *pb.ListContainerReplicasRequest) (*pb.ListContainerReplicasResponse, error) {
	if err := validateReplicaRequest(req.GetName(), req.GetProject(), req.GetRepo()); err != nil {
		return nil, err
	}
	project := tenancy.NormalizeProject(req.GetProject())
	if s.requirePeerCert(ctx) != nil {
		if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.GetName()), "backup.read", "viewer"); err != nil {
			return nil, err
		}
	}
	if host := req.GetHost(); host != "" && host != s.hostName {
		c, closeConn, err := s.dialPeer(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer closeConn()
		return c.ListContainerReplicas(ctx, req)
	}
	reps, err := s.localContainerReplicas(ctx, req.GetRepo(), project, req.GetName())
	if err != nil {
		return nil, err
	}
	return &pb.ListContainerReplicasResponse{Replicas: reps}, nil
}

// RemoveContainerReplicas removes SET-ASIDE replicas of a container from one
// repo's replica namespace on one host: the explicit operator action that is the
// only way a set-aside replica ever goes. A replica that is not set aside is
// refused (its schedule keeps it). Admin on the container, or a peer forwarding
// an admin's call.
func (s *Server) RemoveContainerReplicas(ctx context.Context, req *pb.RemoveContainerReplicasRequest) (*pb.RemoveContainerReplicasResponse, error) {
	if err := validateReplicaRequest(req.GetName(), req.GetProject(), req.GetRepo()); err != nil {
		return nil, err
	}
	if len(req.GetTimestamps()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "name the set-aside replicas to remove (timestamps)")
	}
	project := tenancy.NormalizeProject(req.GetProject())
	peer := s.requirePeerCert(ctx) == nil
	if !peer {
		if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.GetName()), "backup.prune", "admin"); err != nil {
			return nil, err
		}
	}
	// The operator who asked, carried to the host that removes, which writes
	// the audit row (a forwarded call arrives as the peer).
	actor := s.repairActor(ctx)
	if host := req.GetHost(); host != "" && host != s.hostName {
		c, closeConn, err := s.dialPeer(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer closeConn()
		return c.RemoveContainerReplicas(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req)
	}
	r, err := s.openReplicaNamespace(ctx, containerReplicaRepo(project, req.GetRepo()), false)
	if err != nil {
		return nil, err
	}
	// A replica a schedule still settles here goes only when set aside; once
	// no schedule targets this host and repo for the container (deleted,
	// re-targeted, reversed away), nothing settles its replicas here and any
	// of them may be removed.
	orphaned := !s.replicasScheduledHere(ctx, req.GetRepo(), project, req.GetName())
	var del []pbsstore.Manifest
	for _, ts := range req.GetTimestamps() {
		m, gerr := r.GetManifest(req.GetName(), ts, containerBackupDisk)
		if gerr != nil {
			return nil, status.Errorf(codes.NotFound, "no replica of %s taken at %s in %q", req.GetName(), ts, req.GetRepo())
		}
		if _, aside := readSetAside(r, req.GetName(), ts); !aside && !orphaned {
			return nil, status.Errorf(codes.FailedPrecondition,
				"the replica of %s taken at %s is not set aside and its schedule still targets this host; its keep_replicas decides when it goes", req.GetName(), ts)
		}
		del = append(del, *m)
	}
	if err := pbsstore.ApplyPrune(r, pbsstore.PrunePlan{Delete: del}); err != nil {
		return nil, status.Errorf(codes.Internal, "remove replicas: %v", err)
	}
	for _, m := range del {
		_ = os.Remove(setAsidePath(r, req.GetName(), m.Timestamp))
	}
	if _, err := pbsstore.GC(ctx, r); err != nil {
		slog.Warn("container replica: gc after removal", "container", req.GetName(), "error", err)
	}
	s.forgetBackupManifests(r.Root(), req.GetName())
	s.auditAs(ctx, actor, "ct.replica.remove", req.GetName(),
		fmt.Sprintf("project=%s repo=%s removed %d replica(s): %s", project, req.GetRepo(), len(del), strings.Join(req.GetTimestamps(), ", ")), "ok")
	return &pb.RemoveContainerReplicasResponse{Removed: int32(len(del))}, nil
}

func validateReplicaRequest(name, project, repo string) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := safename.ValidateName(tenancy.NormalizeProject(project)); err != nil {
		return status.Errorf(codes.InvalidArgument, "project: %v", err)
	}
	if repo == "" {
		return status.Error(codes.InvalidArgument, "repo required (the schedule's target_pool)")
	}
	return nil
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

// containerScheduleRequestName reads a container schedule request's vm_name: the
// container's name, or a schedule key (which a CLI sends so that a daemon that
// predates container schedules never takes the name for a VM's).
func containerScheduleRequestName(vmName, project string) (name, proj string) {
	if p, n, ok := corrosion.ContainerScheduleName(vmName); ok {
		if p != "" {
			project = p
		}
		return n, project
	}
	return vmName, project
}

// createContainerReplicationSchedule is CreateReplicationSchedule for scope
// "container": vm_name is the container, target_host the peer that holds the
// replica, and target_pool the backup repo there (a logical name that host
// resolves in its own config), since a container has no storage pool of its own.
func (s *Server) createContainerReplicationSchedule(ctx context.Context, req *pb.CreateReplicationScheduleRequest) (*pb.ReplicationSchedule, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	name, reqProject := containerScheduleRequestName(req.VmName, req.ProjectName)
	if name == "" {
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
	ct, err := s.resolveContainerForSchedule(ctx, name, reqProject)
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
	// The target resolves the repo in its own config: ask it for the replica
	// namespace, so a schedule that could never push is not stored. A peer that
	// cannot answer (an older build) cannot hold a replica either.
	if _, err := s.listContainerReplicasOn(ctx, req.TargetHost, req.TargetPool, project, ct.Name); err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.FailedPrecondition, "target host %q runs a build without container replication", req.TargetHost)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "backup repo %q is not usable for replicas on %q: %v", req.TargetPool, req.TargetHost, err)
	}
	// A limit the release gate refuses is refused before the schedule is
	// written, so no unlimited schedule is left behind.
	if err := s.precheckReplicationRate(ctx, req.BwlimitBytesPerSec); err != nil {
		return nil, err
	}
	key := corrosion.ContainerScheduleKey(project, ct.Name)
	// A schedule stored under the earlier name-only key keeps its identity.
	if rows, lerr := corrosion.ListBackupSchedules(ctx, s.db); lerr == nil {
		for _, r := range rows {
			if r.Repo == req.TargetPool && r.VMName != key && corrosion.ContainerScheduleIs(r, project, ct.Name) {
				key = r.VMName
			}
		}
	}
	rec := corrosion.BackupScheduleRecord{
		VMName:       key,
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
	// The row is container_replication's data: every host must understand it,
	// and this node's used record goes on its stream ahead of it. The gate's
	// refusal ("the cluster upgrade must finish first") is returned as it is.
	existed := s.scheduleRowLive(ctx, rec.VMName, rec.Repo)
	ran := false
	if err := s.WithReleaseFeature(ctx, capabilities.FeatureContainerReplication,
		func(ctx context.Context, g capabilities.FeatureGrant) error {
			ran = true
			return corrosion.UpsertContainerReplicationSchedule(ctx, s.db, g, rec)
		}); err != nil {
		if !ran {
			return nil, err
		}
		return nil, status.Errorf(codes.Internal, "upsert replication schedule: %v", err)
	}
	s.audit(ctx, "replication.schedule", ct.Name, "container project="+project+" target="+req.TargetHost+":"+req.TargetPool+" cron="+req.Cron, "ok")
	if err := s.applyReplicationRate(ctx, rec.VMName, rec.Repo, req.BwlimitBytesPerSec, existed); err != nil {
		return nil, err
	}
	out := replScheduleToPB(rec)
	out.BwlimitBytesPerSec = s.replicationRateOf(ctx, rec.VMName, rec.Repo)
	return out, nil
}

// deleteContainerReplicationSchedule removes a container schedule. The row is
// found by its container, project and repo, and authorized on the project IT
// recorded, so a schedule outlives, and can still be removed after, its
// container.
func (s *Server) deleteContainerReplicationSchedule(ctx context.Context, req *pb.DeleteReplicationScheduleRequest) (*emptypb.Empty, error) {
	name, project := containerScheduleRequestName(req.VmName, req.ProjectName)
	if name == "" || req.TargetPool == "" {
		return nil, status.Error(codes.InvalidArgument, "the container name (vm_name) and target_pool are required")
	}
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	var row *corrosion.BackupScheduleRecord
	for i := range rows {
		r := rows[i]
		if r.Repo != req.TargetPool || r.Type != "replication" || r.Scope != "container" {
			continue
		}
		rp, rn, ok := corrosion.ContainerScheduleName(r.VMName)
		if !ok || rn != name {
			continue
		}
		if rp == "" {
			rp = r.ProjectName
		}
		if project != "" && tenancy.NormalizeProject(rp) != tenancy.NormalizeProject(project) {
			continue
		}
		if row != nil {
			return nil, status.Errorf(codes.InvalidArgument, "more than one project has a schedule for %q into %q; name the project (project_name)", name, req.TargetPool)
		}
		row = &r
	}
	if row == nil {
		return &emptypb.Empty{}, nil // nothing to remove, as for a VM
	}
	rowProject := corrosion.ContainerScheduleProject(*row)
	if err := s.requirePermResolved(ctx, true, ctRBACPathFor(rowProject, name), ctRBACPathFor("", name),
		"backup.schedule", "operator", containerWhat(name)); err != nil {
		return nil, err
	}
	if err := s.deleteScheduleRow(ctx, row.VMName, req.TargetPool); err != nil {
		return nil, status.Errorf(codes.Internal, "delete replication schedule: %v", err)
	}
	s.audit(ctx, "replication.schedule.delete", name, "container project="+rowProject+" repo="+req.TargetPool, "ok")
	return &emptypb.Empty{}, nil
}

// notifyReplicaSetAside reports replicas a run set aside, once each.
func (s *Server) notifyReplicaSetAside(ctx context.Context, m *pbsstore.Manifest, aside []pbsstore.Manifest, repo string) {
	if len(aside) == 0 {
		return
	}
	var ts []string
	for _, a := range aside {
		ts = append(ts, a.Timestamp)
	}
	detail := fmt.Sprintf("%d replica(s) of container %s in %s were set aside, not removed: they are not proven to be contained in the data now replicated (%s). Inspect them with `lv replication replicas %s --host %s --target-pool <repo>`; they go only when removed: %s",
		len(aside), m.VMName, repo, m.Timestamp, m.VMName, s.hostName, strings.Join(ts, ", "))
	s.audit(ctx, "ct.replica.set_aside", m.VMName, detail, "ok")
	s.notify(ctx, notify.Notification{Kind: "replication.replica_set_aside", Severity: notify.SevWarn, Subject: m.VMName, Detail: detail})
}

// admitReplicaPromotion is RestoreContainer's rule for a manifest that is a
// scheduled replica: only a failover coordinator's restore-relocation over peer
// mTLS (its proof, or its attempt token before enforcement) may lay it down, and
// never a cold migrate or an operator restore. When the relocating row is visible
// here, the replica must have been taken from it: its host and row incarnation.
// (The coordinator chose it by the same rule from its own view: containerReplicaFor.)
func (s *Server) admitReplicaPromotion(ctx context.Context, req *pb.RestoreContainerRequest, mark *containerReplicaMark) error {
	if operatorReplicaRestore(ctx) {
		return nil // RestoreContainerReplica: an admin's explicit, audited restore
	}
	if !s.isPeerRelocation(ctx, req.Proof != nil) || s.migrateSourceFromPeer(ctx) != "" {
		return status.Error(codes.PermissionDenied,
			"a container replica becomes a live copy only through failover promotion of the container it was taken from; restore a backup instead")
	}
	token := relocateTokenFromMD(ctx)
	if token == "" && req.Proof != nil {
		token = req.Proof.GetRelocationToken()
	}
	row, err := s.relocatingContainer(ctx, req.Name, s.hostName, token)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the relocating container: %v", err)
	}
	if row != nil && !replicaOfRow(&pb.ContainerReplica{
		Source: mark.Source, Placement: mark.Placement, Incarnation: mark.Incarnation,
		OwnerId: corrosion.DecodeCreateSpec(row.CreateSpec).OwnerID,
	}, row) {
		return status.Errorf(codes.FailedPrecondition,
			"the replica of %s taken at %s is from %s, not from the container being relocated (on %s); it is not promoted",
			req.Name, req.Timestamp, mark.Source, row.HostName)
	}
	return nil
}

// operatorReplicaRestoreKey marks RestoreContainerReplica's own call into
// RestoreContainer: an in-process context value, never set from the wire.
type operatorReplicaRestoreKey struct{}

func operatorReplicaRestore(ctx context.Context) bool {
	v, _ := ctx.Value(operatorReplicaRestoreKey{}).(bool)
	return v
}

// localRestoreStream collects RestoreContainer's progress for an in-process
// caller.
type localRestoreStream struct {
	grpc.ServerStream
	ctx  context.Context
	last *pb.RestoreContainerProgress
}

func (l *localRestoreStream) Context() context.Context { return l.ctx }
func (l *localRestoreStream) Send(p *pb.RestoreContainerProgress) error {
	l.last = p
	return nil
}

// RestoreContainerReplica lays one replica down as the container, stopped, on
// the host that holds it: an operator's way back to a set-aside replica, or to
// any replica of a schedule failover does not promote. Admin on the container,
// audited as the operator. It is refused while a live container of that name
// exists in the project anywhere: the restore must never make a second
// runnable copy. The restore is RestoreContainer's own (admission, lineage,
// provenance), so the restored container's next replicas prove the ones it
// came from.
func (s *Server) RestoreContainerReplica(ctx context.Context, req *pb.RestoreContainerReplicaRequest) (*pb.RestoreContainerReplicaResponse, error) {
	if err := validateReplicaRequest(req.GetName(), req.GetProject(), req.GetRepo()); err != nil {
		return nil, err
	}
	if req.GetTimestamp() == "" {
		return nil, status.Error(codes.InvalidArgument, "the replica to restore is required (timestamp)")
	}
	project := tenancy.NormalizeProject(req.GetProject())
	if s.requirePeerCert(ctx) != nil {
		if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.GetName()), "backup.restore", "admin"); err != nil {
			return nil, err
		}
	}
	actor := s.repairActor(ctx)
	if host := req.GetHost(); host != "" && host != s.hostName {
		c, closeConn, err := s.dialPeer(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer closeConn()
		var hdr metadata.MD
		resp, err := c.RestoreContainerReplica(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req, grpc.Header(&hdr))
		if left := hdr.Get(firewallTagsLeftMD); err == nil && len(left) == 1 {
			_ = grpc.SetHeader(ctx, metadata.Pairs(firewallTagsLeftMD, left[0]))
		}
		return resp, err
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read containers: %v", err)
	}
	for _, ct := range cts {
		if ct.Name == req.GetName() && tenancy.NormalizeProject(ct.Project) == project {
			return nil, status.Errorf(codes.FailedPrecondition,
				"container %s of project %s exists on %s; restoring its replica would make a second runnable copy: remove that one first",
				req.GetName(), project, ct.HostName)
		}
	}
	// This host's view can lag (a migrate's new row and the old row's
	// tombstone arrive on independent streams, and a replica arrives by a
	// direct push, ahead of the row it is of): the hosts that could hold the
	// container must say, positively, that they see no live copy of it.
	source, err := s.replicaSourceOf(ctx, project, req.GetRepo(), req.GetName(), req.GetTimestamp())
	if err != nil {
		return nil, err
	}
	if err := s.confirmNoLiveCopy(ctx, project, req.GetName(), source); err != nil {
		return nil, err
	}
	// The restored container is a new one, with no firewall identity: what the
	// deleted container of this name left is read before its row lands.
	tagsLeft := s.firewallTagsLeftNote(ctx, corrosion.TagMemberCT, project, req.GetName(), s.hostName)
	rctx := context.WithValue(ctx, operatorReplicaRestoreKey{}, true)
	st := &localRestoreStream{ctx: rctx}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		RepoPath: containerReplicaRepo(project, req.GetRepo()), Name: req.GetName(),
		Timestamp: req.GetTimestamp(), HostName: s.hostName, Start: false,
	}, st); err != nil {
		s.auditAs(ctx, actor, "ct.replica.restore", req.GetName(),
			fmt.Sprintf("project=%s repo=%s replica=%s: %v", project, req.GetRepo(), req.GetTimestamp(), err), "error")
		return nil, err
	}
	s.auditAs(ctx, actor, "ct.replica.restore", req.GetName(),
		fmt.Sprintf("project=%s repo=%s replica=%s restored stopped on %s", project, req.GetRepo(), req.GetTimestamp(), s.hostName), "ok")
	if tagsLeft != "" {
		_ = grpc.SetHeader(ctx, metadata.Pairs(firewallTagsLeftMD, tagsLeft))
	}
	return &pb.RestoreContainerReplicaResponse{Host: s.hostName}, nil
}

// replicaSourceOf is the host the replica (repo, ts) of project/name was taken
// on, as its manifest records it. It is known without any row of the
// container, which is why it is always asked.
func (s *Server) replicaSourceOf(ctx context.Context, project, repo, name, ts string) (string, error) {
	r, err := s.openReplicaNamespace(ctx, containerReplicaRepo(project, repo), false)
	if err != nil {
		return "", err
	}
	m, err := r.GetManifest(name, ts, containerBackupDisk)
	if err != nil {
		return "", status.Errorf(codes.NotFound, "no replica of %s taken at %s in %q", name, ts, repo)
	}
	mark := replicaMarkOf(m)
	if mark == nil || mark.Source == "" {
		return "", status.Errorf(codes.FailedPrecondition,
			"the replica of %s taken at %s records no host it was taken on, so no host can be asked whether it still runs the container", name, ts)
	}
	return mark.Source, nil
}

// noLiveCopyAskTimeout bounds each host's answer to confirmNoLiveCopy.
const noLiveCopyAskTimeout = 15 * time.Second

// confirmNoLiveCopy is the positive "no live copy anywhere" a replica restore
// needs. This host's own rows have already been checked, and they can lag: a
// row and its tombstone travel on different hosts' streams, and a replica
// arrives by a direct push ahead of the row it is of. So it asks
//
//   - source, the host the replica was taken on (known with no row at all);
//   - every host that holds a row of the name in this view, tombstones
//     included: a row is evidence that host had it, whichever is newest;
//   - every other member that has not been removed, and every voter: a
//     migrate onto a host whose row reached nobody else leaves the container
//     on a host only it knows about,
//
// and every one of them must answer, each from its own view and its own
// runtime (this host answers for its runtime too):
//
//   - its rows: no live row of the container, on any host;
//   - its runtime: no container of the name on it, unless its own live row
//     there is another project's container of that name (runtime names are
//     not project-scoped). A container that runs with no live row anywhere (a
//     stale delete tombstoned it, or a create, migrate or import stopped
//     between the runtime and the row) is a live copy, and may hold newer data
//     than the replica.
//
// Any host that holds or sees a live copy refuses. Any host that cannot answer
// refuses, with the reason and the remedy: no answer is never absence, and an
// inventory that is incomplete, or holds the name in a state it could not
// read, is no answer. A host removed from the cluster (`lv host rm`) is
// neither asked nor counted: removing it is the operator's statement that it
// runs nothing, and there is no majority for it to count in, since every other
// member must answer.
//
// The cost: one member that cannot be reached (down, partitioned, or behind a
// firewall) blocks every replica restore until it is back or removed. Each
// restore asks each member twice, for its unpaged container list and for its
// runtime of this one container, all in parallel within noLiveCopyAskTimeout.
func (s *Server) confirmNoLiveCopy(ctx context.Context, project, name, source string) error {
	required := map[string]string{source: "the host the replica was taken on"}
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT host_name, COALESCE(project, '_default') AS project FROM containers WHERE name = ?`, name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read which hosts held %s: %v", name, err)
	}
	for _, r := range rows {
		if tenancy.NormalizeProject(r.String("project")) != project {
			continue
		}
		if h := r.String("host_name"); required[h] == "" {
			required[h] = "a host that held a row of it"
		}
	}
	voters, err := corrosion.VoterSet(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the voter set: %v", err)
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the cluster's members: %v", err)
	}
	ask := map[string]bool{}
	for h := range required {
		ask[h] = true
	}
	for h := range voters {
		ask[h] = true
	}
	stateOf := map[string]string{}
	for _, h := range hosts {
		ask[h.Name] = true
		stateOf[h.Name] = h.State
	}
	delete(ask, s.hostName) // this host: its rows were checked by the caller, its runtime below
	for h := range ask {
		removed, rerr := corrosion.HostRemoved(ctx, s.db, h)
		if rerr != nil {
			return status.Errorf(codes.Unavailable, "read whether %s was removed: %v", h, rerr)
		}
		if removed || stateOf[h] == "removed" {
			delete(ask, h)
		}
	}

	type answer struct {
		host, copyOf string
		err          error
	}
	actx, cancel := context.WithTimeout(ctx, noLiveCopyAskTimeout)
	defer cancel()
	results := make(chan answer, len(ask))
	for h := range ask {
		go func(h string) {
			copyOf, err := s.liveCopySeenBy(actx, h, project, name)
			results <- answer{host: h, copyOf: copyOf, err: err}
		}(h)
	}
	missing := map[string]error{}
	var live []string
	record := func(a answer) {
		switch {
		case a.copyOf != "":
			live = append(live, a.copyOf)
		case a.err != nil:
			missing[a.host] = a.err
		}
	}
	selfCopy, selfErr := s.localRuntimeCopy(ctx, project, name)
	record(answer{host: s.hostName, copyOf: selfCopy, err: selfErr})
	for range ask {
		record(<-results)
	}
	if len(live) > 0 {
		sort.Strings(live)
		return status.Errorf(codes.FailedPrecondition,
			"%s; restoring its replica would make a second runnable copy", strings.Join(live, "; "))
	}
	if len(missing) == 0 {
		return nil
	}
	var silent []string
	for h := range missing {
		silent = append(silent, h)
	}
	sort.Strings(silent)
	h := silent[0]
	role := required[h]
	if role == "" {
		role = "a member of the cluster"
	}
	switch _, known := stateOf[h]; {
	case h == s.hostName:
		return status.Errorf(codes.FailedPrecondition,
			"cannot confirm with %s (this host) that it holds no live %s (%v): its own runtime must be readable before a replica is restored onto it",
			h, name, missing[h])
	case !known:
		return status.Errorf(codes.FailedPrecondition,
			"cannot confirm with %s (%s), which this cluster has no record of, that it holds no live %s (%v): it must rejoin the cluster before this replica can be restored",
			h, role, name, missing[h])
	}
	return status.Errorf(codes.FailedPrecondition,
		"cannot confirm with %s (%s) that it holds no live %s (%v): bring it back, or remove it from the cluster (lv host rm), before restoring a replica",
		h, role, name, missing[h])
}

// liveCopySeenBy asks host for its own view of project/name, rows and
// runtime: a phrase naming the live copy it holds or sees, or "" for a
// positive none.
func (s *Server) liveCopySeenBy(ctx context.Context, host, project, name string) (string, error) {
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return "", err
	}
	defer closeConn()
	otherHere := false
	token := ""
	for {
		resp, err := c.ListContainers(ctx, &pb.ListContainersRequest{PageToken: token})
		if err != nil {
			return "", err
		}
		for _, ct := range resp.GetContainers() {
			if ct.GetName() != name {
				continue
			}
			if tenancy.NormalizeProject(ct.GetProject()) == project {
				return fmt.Sprintf("%s still sees %s live on %s", host, name, ct.GetHostName()), nil
			}
			if ct.GetHostName() == host {
				otherHere = true
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			break
		}
	}
	inv, err := c.GetRuntimeInventory(ctx, &pb.GetRuntimeInventoryRequest{
		Kind: corrosion.WorkloadContainer, Name: name, ContainersOnly: true})
	if err != nil {
		return "", fmt.Errorf("read its runtime: %w", err)
	}
	return runtimeCopyOn(host, project, name, inventoryFromProto(inv), otherHere)
}

// localRuntimeCopy is liveCopySeenBy's runtime half for this host. Its import
// would refuse to lay a container over an existing one anyway; this says why.
func (s *Server) localRuntimeCopy(ctx context.Context, project, name string) (string, error) {
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return "", fmt.Errorf("read its containers: %w", err)
	}
	otherHere := false
	for _, ct := range cts {
		if ct.Name == name && ct.HostName == s.hostName && tenancy.NormalizeProject(ct.Project) != project {
			otherHere = true
		}
	}
	return runtimeCopyOn(s.hostName, project, name, s.collectContainerRuntime(ctx, name), otherHere)
}

// runtimeCopyOn reads host's runtime inventory for project's container name:
// a phrase naming the copy when the host holds one, "" for a positive none, or
// an error when the inventory cannot vouch. otherHere says host's own live row
// of that name on itself is another project's container, which is then what
// its runtime of that name is, unless the runtime's own owner record says it
// is project's (a ghost row of the other project over our orphan), or cannot
// be read. A runtime with no owner record (an earlier build made it) is taken
// to be the row's, as before the record existed.
//
// Absence is proven by a complete inventory, or by a container listing that
// succeeded (ContainersComplete, from a containers-only ask): a VM probe or
// another container's marker that failed says nothing about this name.
func runtimeCopyOn(host, project, name string, inv runtimeInventory, otherHere bool) (string, error) {
	w, found := inv.find(corrosion.WorkloadContainer, name)
	switch {
	case found && otherHere && w.OwnerStatus == OwnerUnreadable:
		return "", fmt.Errorf("its runtime %s sits under another project's live row of that name, and its owner record cannot be read (%s), so whose it is is unproven",
			name, w.OwnerError)
	case found && otherHere && !(w.OwnerStatus == OwnerValid && w.OwnerProject == project):
		return "", nil
	case found && (w.ProbeError == probeNoLXCTooling || w.ProbeError == probeUnlistedDirectory):
		return fmt.Sprintf("%s holds %s with no live row of it (%s), a copy that may hold newer data than the replica",
			host, name, w.ProbeError), nil
	case found && otherHere:
		return fmt.Sprintf("%s runs %s, whose owner record says it is %s's, under another project's live row of that name: an orphaned runtime that may hold newer data than the replica (see %s)",
			host, name, project, health.CondCTOrphanRuntime), nil
	case found && (w.State == health.RuntimeRunning || w.State == health.RuntimeDefinedStopped):
		return fmt.Sprintf("%s runs %s with no live row of it, an orphaned runtime that may hold newer data than the replica (see %s)",
			host, name, health.CondCTOrphanRuntime), nil
	case found:
		detail := w.State
		if w.ProbeError != "" {
			detail += ": " + w.ProbeError
		}
		return "", fmt.Errorf("its runtime holds %s in a state it could not read (%s)", name, detail)
	case !inv.Complete && !inv.ContainersComplete:
		return "", fmt.Errorf("its runtime inventory is incomplete, so absence is unproven (%s)", strings.Join(inv.Errors, "; "))
	}
	return "", nil
}

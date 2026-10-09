package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Container files are chosen by their recorded owner, never by name alone.
//
// A container's name is per host and reusable: delete one in project acme and
// create another of the same name in project beta, and every file keyed by
// (host, name) — the snapshot tars and their records, the backups in a repo —
// read as beta's. The owner record is the project plus the create spec's
// owner_id (minted at create and clone, kept by migrate, relocation and
// restore). A file with no owner record, or a container with none (both from
// an earlier build), matches as before: records only add proof.

// snapshotOwner is the owner record kept beside a snapshot tar.
type snapshotOwner struct {
	Project string `json:"project"`
	OwnerID string `json:"owner_id,omitempty"`
}

func snapshotOwnerPath(tar string) string { return tar + ".owner" }

// writeSnapshotOwner records rec as the owner of the snapshot at tar.
func writeSnapshotOwner(tar string, rec *corrosion.ContainerRecord) error {
	b, _ := json.Marshal(snapshotOwner{
		Project: tenancy.NormalizeProject(rec.Project),
		OwnerID: corrosion.DecodeCreateSpec(rec.CreateSpec).OwnerID,
	})
	return os.WriteFile(snapshotOwnerPath(tar), b, 0o600)
}

// readSnapshotOwner returns the snapshot's owner record, nil when it has none.
func readSnapshotOwner(tar string) (*snapshotOwner, error) {
	b, err := os.ReadFile(snapshotOwnerPath(tar))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o snapshotOwner
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// snapshotForeignProject returns the project a snapshot was taken in when that
// is not the container's project (""), judged by its owner record. An
// unreadable record is foreign: it cannot prove the snapshot is the
// container's. Within one project a snapshot stays the container's, as it was.
func snapshotForeignProject(tar string, rec *corrosion.ContainerRecord) string {
	o, err := readSnapshotOwner(tar)
	if err != nil {
		return "(unreadable owner record)"
	}
	if o == nil || o.Project == "" {
		return ""
	}
	if o.Project != tenancy.NormalizeProject(rec.Project) {
		return o.Project
	}
	return ""
}

// ownerStrictMDKey marks a call an entry node forwards for a caller WITHOUT
// the admin role, so the owning host applies the owner rules a forwarded
// (peer) call would otherwise be exempt from as a cluster node.
const ownerStrictMDKey = "x-litevirt-owner-strict"

// ownerStrict reports whether the owner rules bind this caller: not an admin,
// or a peer forwarding for one.
func (s *Server) ownerStrict(ctx context.Context) bool {
	if s.isRemotePeer(ctx) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(ownerStrictMDKey); len(v) > 0 && v[0] == "1" {
				return true
			}
		}
		return false
	}
	return RequireRole(ctx, "admin") != nil
}

// ownerStrictOutgoing carries ownerStrict to the owning host on a forward.
func (s *Server) ownerStrictOutgoing(ctx context.Context) context.Context {
	if s.ownerStrict(ctx) {
		return metadata.AppendToOutgoingContext(ctx, ownerStrictMDKey, "1")
	}
	return ctx
}

// refuseForeignSnapshot refuses an owner-bound caller acting on a snapshot
// another project's container took.
func (s *Server) refuseForeignSnapshot(ctx context.Context, tar, snap string, rec *corrosion.ContainerRecord) error {
	p := snapshotForeignProject(tar, rec)
	if p == "" || !s.ownerStrict(ctx) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied,
		"snapshot %q was taken of an earlier container named %q in project %q; it is not this container's", snap, rec.Name, p)
}

// manifestOwnedBy reports whether a container backup manifest can be rec's:
// its embedded project, and owner_id where both carry one, match. A manifest
// with no project (an earlier build's) matches by name, as before. A restore
// given a new owner_id also owns its parent lineage's backups up to the one
// it was restored from (relineageRestored), never the parent's later ones.
func manifestOwnedBy(m *pbsstore.Manifest, rec *corrosion.ContainerRecord) bool {
	if rec == nil || m.ContainerSpecJSON == "" {
		return true
	}
	var spec containerBackupSpec
	if json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) != nil {
		return false
	}
	if spec.Project != "" && tenancy.NormalizeProject(spec.Project) != tenancy.NormalizeProject(rec.Project) {
		return false
	}
	theirs := corrosion.DecodeCreateSpec(spec.CreateSpec).OwnerID
	mine := corrosion.DecodeCreateSpec(rec.CreateSpec).OwnerID
	if theirs == "" || mine == "" || theirs == mine {
		return true
	}
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	return cs.RestoredFromOwnerID != "" && theirs == cs.RestoredFromOwnerID &&
		cs.RestoredFromTS != "" && timestampAtOrBefore(m.Timestamp, cs.RestoredFromTS)
}

// timestampAtOrBefore compares two backup timestamps as times (RFC3339, any
// offset, fractional seconds), falling back to the string order when either
// does not parse.
func timestampAtOrBefore(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if errA != nil || errB != nil {
		return a <= b
	}
	return !ta.After(tb)
}

// relocationLineage is a relocating container's lineage as its failover
// coordinator read it off the row it marked: its owner_id and any
// restored-from parent. The coordinator sends it in the restore request,
// because the target's own replica need not have seen the mark yet.
type relocationLineage struct {
	ownerID, restoredFromOwnerID, restoredFromTS string
}

// relocationLineageOf is row's lineage; none for a nil row (the backup was
// picked by name) or a row that records no owner_id.
func relocationLineageOf(row *corrosion.ContainerRecord) relocationLineage {
	if row == nil {
		return relocationLineage{}
	}
	cs := corrosion.DecodeCreateSpec(row.CreateSpec)
	if cs.OwnerID == "" {
		return relocationLineage{}
	}
	return relocationLineage{cs.OwnerID, cs.RestoredFromOwnerID, cs.RestoredFromTS}
}

// on sets the lineage on a restore request, and returns it.
func (l relocationLineage) on(req *pb.RestoreContainerRequest) *pb.RestoreContainerRequest {
	req.OwnerId, req.RestoredFromOwnerId, req.RestoredFromTs = l.ownerID, l.restoredFromOwnerID, l.restoredFromTS
	return req
}

// withLineage is createSpec carrying l in place of its own lineage.
func (l relocationLineage) withLineage(createSpec string) string {
	cs := corrosion.DecodeCreateSpec(createSpec)
	cs.OwnerID, cs.RestoredFromOwnerID, cs.RestoredFromTS = l.ownerID, l.restoredFromOwnerID, l.restoredFromTS
	return corrosion.EncodeCreateSpec(cs)
}

// relocatedLineage is the lineage a host-loss relocation lays down: the
// relocating container's own (its owner_id and any restored-from parent), not
// the lineage of the backup it was rebuilt from. A copy restored from its
// parent's backup and then relocated from that same backup stays the copy;
// taking the manifest's would make it a second holder of the parent's
// owner_id.
//
// The caller has established that the restore is a peer relocation
// (isPeerRelocation); no other restore reaches here, so no other restore can
// set a lineage through the request. The lineage comes from, in order:
//   - the request, which the coordinator fills from the row it marked;
//   - the relocating row in this host's replica (a coordinator that sends no
//     lineage: an earlier build, or a backup picked by name);
//   - the manifest, as before owner records, when neither is there (WARN).
func (s *Server) relocatedLineage(ctx context.Context, req *pb.RestoreContainerRequest, createSpec string) string {
	if req.GetOwnerId() != "" {
		return relocationLineage{req.GetOwnerId(), req.GetRestoredFromOwnerId(), req.GetRestoredFromTs()}.withLineage(createSpec)
	}
	token := relocateTokenFromMD(ctx)
	if token == "" && req.Proof != nil {
		token = req.Proof.GetRelocationToken()
	}
	row, err := s.relocatingContainer(ctx, req.Name, s.hostName, token)
	if err != nil {
		slog.Warn("container relocation: could not read the relocating row; keeping the backup's lineage", "name", req.Name, "error", err)
		return createSpec
	}
	if row == nil {
		slog.Warn("container relocation: no relocating row found here (not replicated yet?); keeping the backup's lineage", "name", req.Name)
		return createSpec
	}
	l := relocationLineageOf(row)
	if l.ownerID == "" {
		return createSpec
	}
	return l.withLineage(createSpec)
}

// relocatingContainer is the row the failover coordinator marked for a
// restore-relocation of name to target under token, or nil when no row is so
// marked. A read error is returned, never read as "no row": a nil owner would
// match backups by name alone.
func (s *Server) relocatingContainer(ctx context.Context, name, target, token string) (*corrosion.ContainerRecord, error) {
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil, err
	}
	want := corrosion.RelocateRestoreDetail(target, token)
	for i := range cts {
		if cts[i].Name == name && cts[i].StateDetail == want {
			return &cts[i], nil
		}
	}
	return nil, nil
}

// stampContainerOwner writes the container's on-disk owner record (project and
// owner_id) when the runtime keeps one. Best-effort: the record only adds
// proof, and a container without one is matched by name as before.
func (s *Server) stampContainerOwner(name, project, createSpec string) {
	st, ok := s.containerRuntime.(lxc.OwnerStamper)
	if !ok {
		return
	}
	o := lxc.ContainerOwner{Project: tenancy.NormalizeProject(project), OwnerID: corrosion.DecodeCreateSpec(createSpec).OwnerID}
	if err := st.StampOwner(name, o); err != nil {
		slog.Warn("container: could not stamp its owner record; its files match by name", "name", name, "error", err)
	}
}

// heldBesideRestore reports whether a live container other than the one an
// operator restore of name lays down here (this host, name) records what holds
// says. It is the one test of "another container still holds this" for a
// restore: of the backed-up id range (remapRestoredRange) and of the
// backed-up lineage (relineageRestored).
func (s *Server) heldBesideRestore(rows []corrosion.ContainerRecord, name string, holds func(corrosion.ContainerCreateSpec) bool) bool {
	for _, r := range rows {
		if r.HostName == s.hostName && r.Name == name {
			continue
		}
		if holds(corrosion.DecodeCreateSpec(r.CreateSpec)) {
			return true
		}
	}
	return false
}

// relineageRestored gives an operator-restored container a new owner_id when
// another live container records the backed-up one: the original lives on
// (or its row does, on a dead or fenced host), and the restore is a copy
// beside it. Keeping the original's lineage would make the copy's later
// backups the original's, and failover could rebuild the original from the
// copy's data. With no live holder (the original is gone) the restore is the
// same lineage coming back and keeps it. A migrate or relocation never comes
// here: it is the same container moving.
//
// A new owner_id records its parent: the backed-up lineage and fromTS, the
// timestamp of the backup restored. manifestOwnedBy accepts that lineage's
// backups up to fromTS as the copy's own starting point, so the copy can be
// rebuilt from them before it has a backup of its own, and never from the
// parent's later data.
//
// When the rows cannot be read the restore still goes ahead, as a new
// lineage with its parent recorded: that can never hand failover another
// container's data, and keeps the backup it came from.
func (s *Server) relineageRestored(ctx context.Context, name, createSpec, fromTS string) string {
	cs := corrosion.DecodeCreateSpec(createSpec)
	rows, err := corrosion.ListContainers(ctx, s.db, "")
	switch {
	case err != nil:
		slog.Warn("container restore: could not read the cluster's containers; the restore is given a lineage of its own", "name", name, "error", err)
	case !s.heldBesideRestore(rows, name, func(o corrosion.ContainerCreateSpec) bool { return o.OwnerID == cs.OwnerID }):
		return createSpec
	default:
		slog.Info("container restore: the backed-up container lives on; the restore is a copy with a lineage of its own", "name", name, "backed_up_owner_id", cs.OwnerID)
	}
	cs.RestoredFromOwnerID, cs.RestoredFromTS = cs.OwnerID, fromTS
	cs.OwnerID = randid.New()
	return corrosion.EncodeCreateSpec(cs)
}

// withOwnerID returns createSpec with an owner_id, minting one when it has none.
func withOwnerID(createSpec string) string {
	cs := corrosion.DecodeCreateSpec(createSpec)
	if cs.OwnerID != "" {
		return createSpec
	}
	cs.OwnerID = randid.New()
	return corrosion.EncodeCreateSpec(cs)
}

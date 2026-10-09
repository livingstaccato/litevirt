package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
// with no project (an earlier build's) matches by name, as before.
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
	return theirs == "" || mine == "" || theirs == mine
}

// relocatingContainer is the row the failover coordinator marked for a
// restore-relocation of name to target under token, or nil.
func (s *Server) relocatingContainer(ctx context.Context, name, target, token string) *corrosion.ContainerRecord {
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil
	}
	want := corrosion.RelocateRestoreDetail(target, token)
	for i := range cts {
		if cts[i].Name == name && cts[i].StateDetail == want {
			return &cts[i]
		}
	}
	return nil
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

// withOwnerID returns createSpec with an owner_id, minting one when it has none.
func withOwnerID(createSpec string) string {
	cs := corrosion.DecodeCreateSpec(createSpec)
	if cs.OwnerID != "" {
		return createSpec
	}
	cs.OwnerID = randid.New()
	return corrosion.EncodeCreateSpec(cs)
}

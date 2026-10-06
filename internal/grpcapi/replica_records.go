package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Replica records.
//
// A global pool is one directory every project uses. Replicas used to sit in
// it as "<vm>-<disk>-<time>.<ext>" and were found by that name prefix, so the
// files of VM "web" disk "1" and VM "web-1" disk "root" were the same set to
// every path that looked: a project's pruning deleted another project's
// replicas (and live disks of the same shape), its promotion booted another
// project's file, and its incremental replica was forked from one.
//
// Now each replica is selected by a record, and the record by the caller's
// own VM:
//
//	<pool>/.replicas/<owner>/<disk>-<time>.<ext>        the replica
//	<pool>/.replicas/<owner>/<disk>-<time>.<ext>.json   its record
//
// <owner> is a hash of (project, vm), so a VM's directory is reachable only
// from that VM's own record, and the record names its project, VM, disk and
// the schedule that wrote it. Listing, pruning, the incremental fork base and
// promotion read only that VM's directory and only files with a record that
// matches; a file with no record there is never read, forked from or
// deleted. No pool-content RPC reaches the area: uploads refuse dotted names,
// listings skip directories, and content paths are single components.
//
// Only the daemon writes here: the local runner, and a peer's replica upload or
// incremental push, both host-cert only.

const replicaAreaDir = ".replicas"

var replicaTakenRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)

// replicaRecord is the on-disk record, and the internal form of
// pb.ReplicaRecord.
type replicaRecord struct {
	Project  string `json:"project"`
	VM       string `json:"vm"`
	Disk     string `json:"disk"`
	Schedule string `json:"schedule"`
	File     string `json:"file"`
	Format   string `json:"format"`
	Taken    string `json:"taken"`
	// SizeBytes is filled in on listing, never stored.
	SizeBytes int64 `json:"-"`
}

func newReplicaRecord(project, vm, disk, schedule, taken, format string) replicaRecord {
	return replicaRecord{
		Project: tenancy.NormalizeProject(project), VM: vm, Disk: disk,
		Schedule: schedule, Format: format, Taken: taken,
		File: replicaFileName(disk, taken, format),
	}
}

// replicaFileName is the replica's base name in its owner directory.
func replicaFileName(disk, taken, format string) string {
	return fmt.Sprintf("%s-%s.%s", disk, taken, format)
}

// replicaScheduleKey identifies the schedule a run came from: the schedule
// row's own vm_name (a fan-out row's sentinel, not the VM it fanned out to)
// and its repo. Two schedules replicating one VM into one pool therefore
// never prune each other's replicas.
func replicaScheduleKey(sched corrosion.BackupScheduleRecord) string {
	row := sched.Origin
	if row == "" {
		row = sched.VMName
	}
	return row + "/" + sched.Repo
}

// validate checks a record received from a peer or read from disk.
func (r replicaRecord) validate() error {
	if r.Project == "" || r.Project != tenancy.NormalizeProject(r.Project) {
		return fmt.Errorf("replica record: project %q is not normalized", r.Project)
	}
	for what, n := range map[string]string{"vm": r.VM, "disk": r.Disk} {
		if err := safename.ValidateName(n); err != nil {
			return fmt.Errorf("replica record: %s: %w", what, err)
		}
	}
	if r.Schedule == "" || strings.ContainsAny(r.Schedule, "\x00\n") {
		return fmt.Errorf("replica record: bad schedule %q", r.Schedule)
	}
	if r.Format != "qcow2" && r.Format != "raw" {
		return fmt.Errorf("replica record: format %q", r.Format)
	}
	if !replicaTakenRE.MatchString(r.Taken) {
		return fmt.Errorf("replica record: taken %q", r.Taken)
	}
	if r.File != replicaFileName(r.Disk, r.Taken, r.Format) {
		return fmt.Errorf("replica record: file %q does not match its disk, time and format", r.File)
	}
	return nil
}

func (r replicaRecord) toPB() *pb.ReplicaRecord {
	return &pb.ReplicaRecord{
		Project: r.Project, Vm: r.VM, Disk: r.Disk, Schedule: r.Schedule,
		File: r.File, Format: r.Format, Taken: r.Taken, SizeBytes: r.SizeBytes,
	}
}

func replicaRecordFromPB(p *pb.ReplicaRecord) (replicaRecord, error) {
	if p == nil {
		return replicaRecord{}, errors.New("replica record missing")
	}
	r := replicaRecord{
		Project: p.GetProject(), VM: p.GetVm(), Disk: p.GetDisk(), Schedule: p.GetSchedule(),
		File: p.GetFile(), Format: p.GetFormat(), Taken: p.GetTaken(), SizeBytes: p.GetSizeBytes(),
	}
	return r, r.validate()
}

// replicaOwnerDir is (project, vm)'s directory in the replica area of poolDir.
func replicaOwnerDir(poolDir, project, vm string) string {
	sum := sha256.Sum256([]byte(tenancy.NormalizeProject(project) + "\x00" + vm))
	return filepath.Join(poolDir, replicaAreaDir, hex.EncodeToString(sum[:16]))
}

// listReplicaRecords returns (project, vm)'s recorded replicas in poolDir:
// every record in the owner directory that names exactly that project and VM
// and whose file is a regular file there. Oldest first.
func listReplicaRecords(poolDir, project, vm string) ([]replicaRecord, error) {
	project = tenancy.NormalizeProject(project)
	dir := replicaOwnerDir(poolDir, project, vm)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []replicaRecord
	for _, e := range ents {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var r replicaRecord
		if json.Unmarshal(data, &r) != nil || r.validate() != nil {
			continue
		}
		if r.Project != project || r.VM != vm || name != r.File+".json" {
			continue
		}
		fi, err := os.Lstat(filepath.Join(dir, r.File))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		r.SizeBytes = fi.Size()
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Taken != out[j].Taken {
			return out[i].Taken < out[j].Taken
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

// writeReplicaRecord makes the record for a replica already placed in dir.
// It is created no-clobber and synced, the directory after it: a replica is
// selectable only once its record is durable.
func writeReplicaRecord(dir string, r replicaRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".repl-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // gone after a successful place
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := placeNoClobber(tmp, filepath.Join(dir, r.File+".json")); err != nil {
		return err
	}
	return syncPath(dir)
}

// publishRecordedReplica writes a new replica of r into poolDir's replica area:
// the file through publishReplica (temp, synced, placed no-clobber), then its
// record. If the record cannot be written the file is withdrawn, so a replica
// is never left selectable-by-name-only. Returns the replica's path.
func publishRecordedReplica(ctx context.Context, poolDir string, r replicaRecord, write func(tmp string) error) (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	dir := replicaOwnerDir(poolDir, r.Project, r.VM)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("replica directory: %w", err)
	}
	dst := filepath.Join(dir, r.File)
	if err := publishReplica(ctx, dst, write); err != nil {
		return "", err
	}
	if err := writeReplicaRecord(dir, r); err != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("record replica: %w", err)
	}
	return dst, nil
}

// recordedReplica returns the record of file among (project, vm)'s replicas in
// poolDir, with the file's path. ok is false when there is none.
func recordedReplica(poolDir, project, vm, file string) (replicaRecord, string, bool) {
	recs, err := listReplicaRecords(poolDir, project, vm)
	if err != nil {
		return replicaRecord{}, "", false
	}
	for _, r := range recs {
		if r.File == file {
			return r, filepath.Join(replicaOwnerDir(poolDir, project, vm), r.File), true
		}
	}
	return replicaRecord{}, "", false
}

// replicaPoolDir resolves a local file-based pool for the replica paths,
// through the one write check every pool use passes (checkPoolForWrite): a
// refused pool — shared, weakly mounted, a legacy area — is neither listed nor
// written nor pruned.
func (s *Server) replicaPoolDir(ctx context.Context, pool string) (string, error) {
	ref, ok := s.resolvePool(ctx, pool)
	if !ok {
		return "", status.Errorf(codes.NotFound, "pool %q not configured on host %q", pool, s.hostName)
	}
	if !isFileBasedDriver(ref.Driver) {
		return "", status.Errorf(codes.FailedPrecondition, "pool %q (%s) is not file-based", pool, ref.Driver)
	}
	return s.poolDirForWrite(ctx, pool, ref)
}

// replicaRecordsOn lists (project, vm)'s recorded replicas in pool on host:
// read locally, or asked of the peer with this host's certificate (the
// scheduler and the failover coordinator run unauthenticated). Any failure is
// an empty list.
func (s *Server) replicaRecordsOn(ctx context.Context, pool, host, project, vm string) []replicaRecord {
	if host == "" || host == s.hostName {
		dir, err := s.replicaPoolDir(ctx, pool)
		if err != nil {
			return nil
		}
		recs, _ := listReplicaRecords(dir, project, vm)
		return recs
	}
	client, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil
	}
	defer closeConn()
	resp, err := client.ListReplicas(ctx, &pb.ListReplicasRequest{
		PoolName: pool, Host: host, Project: tenancy.NormalizeProject(project), Vm: vm,
	})
	if err != nil {
		return nil
	}
	var out []replicaRecord
	for _, p := range resp.GetReplicas() {
		r, err := replicaRecordFromPB(p)
		if err != nil || r.Project != tenancy.NormalizeProject(project) || r.VM != vm {
			continue
		}
		out = append(out, r)
	}
	return out
}

// pruneRecordedReplicas keeps the newest keep replicas that schedule recorded
// for (project, vm, disk) in pool on this host and deletes the older ones.
// It deletes only files with such a record, after the pool's write check, and
// never one a VM disk references (as its file, a backing file or a linked
// clone's base) — e.g. the overlay a --no-localize promotion boots from. The
// record goes first, so a failure leaves an unrecorded file nothing selects,
// not a record of a missing file. keep <= 0 keeps all. Returns the count
// deleted.
func (s *Server) pruneRecordedReplicas(ctx context.Context, pool, project, vm, disk, schedule string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	poolDir, err := s.replicaPoolDir(ctx, pool)
	if err != nil {
		return 0, err
	}
	recs, err := listReplicaRecords(poolDir, project, vm)
	if err != nil {
		return 0, err
	}
	var mine []replicaRecord
	for _, r := range recs {
		if r.Disk == disk && r.Schedule == schedule {
			mine = append(mine, r)
		}
	}
	if len(mine) <= keep {
		return 0, nil
	}
	dir := replicaOwnerDir(poolDir, project, vm)
	deleted := 0
	for _, r := range mine[:len(mine)-keep] {
		path := filepath.Join(dir, r.File)
		owners, oerr := s.liveDiskOwners(ctx, s.hostName, path)
		if oerr != nil || len(owners) > 0 {
			continue
		}
		if err := os.Remove(path + ".json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
			deleted++
		}
	}
	return deleted, nil
}

// ListReplicas is the peer side of replicaRecordsOn. Host certificate only:
// the records are the daemon's, and an operator reaches them through
// PromoteReplica on a VM they are authorized for.
func (s *Server) ListReplicas(ctx context.Context, req *pb.ListReplicasRequest) (*pb.ListReplicasResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidatePoolName(req.GetPoolName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := safename.ValidateName(req.GetVm()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "vm: %v", err)
	}
	host := req.GetHost()
	if host != "" && host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.ListReplicas(ctx, req)
	}
	dir, err := s.replicaPoolDir(ctx, req.GetPoolName())
	if err != nil {
		return nil, err
	}
	recs, err := listReplicaRecords(dir, req.GetProject(), req.GetVm())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list replicas: %v", err)
	}
	resp := &pb.ListReplicasResponse{}
	for _, r := range recs {
		resp.Replicas = append(resp.Replicas, r.toPB())
	}
	return resp, nil
}

// PruneReplicas is the peer side of a cross-host prune. Host certificate only.
func (s *Server) PruneReplicas(ctx context.Context, req *pb.PruneReplicasRequest) (*pb.PruneReplicasResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidatePoolName(req.GetPoolName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	for what, n := range map[string]string{"vm": req.GetVm(), "disk": req.GetDisk()} {
		if err := safename.ValidateName(n); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%s: %v", what, err)
		}
	}
	if req.GetSchedule() == "" {
		return nil, status.Error(codes.InvalidArgument, "schedule required")
	}
	host := req.GetHost()
	if host != "" && host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.PruneReplicas(ctx, req)
	}
	n, err := s.pruneRecordedReplicas(ctx, req.GetPoolName(), req.GetProject(), req.GetVm(), req.GetDisk(), req.GetSchedule(), int(req.GetKeep()))
	if err != nil {
		return nil, err
	}
	return &pb.PruneReplicasResponse{Deleted: int32(n)}, nil
}

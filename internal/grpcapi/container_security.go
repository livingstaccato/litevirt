package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/safename"
)

// Container security: confinement and unprivileged id ranges.
//
// A new container is unprivileged, in a range of lxc.IDMapSize host ids of
// its own, with the default confinement. --privileged and --confinement
// legacy restore what earlier builds did and are the Admin's. A container an
// earlier build created keeps its settings until an operator converts it
// (ConvertContainer). The settings live in the container's LXC config, which
// travels with it, and in its create spec, from which a recreate rebuilds them
// and every node reports them.

// containerSecurer is the runtime half (LXCRuntimeAdapter, the fakes).
type containerSecurer interface {
	ContainerSecurity(name string) (lxc.Security, error)
	ConvertContainerSecurity(ctx context.Context, name string, to lxc.ConvertOpts) error
}

// Defaults for the id ranges containers are allocated from: 30000 ranges of
// 65536 from 1,000,000,000 (ending below 2^31 + 2^30, well clear of the
// host's own ids and of the conventional 100000 subordinate range).
const (
	defaultIDMapBase   int64 = 1_000_000_000
	defaultIDMapRanges       = 30000
)

// SetContainerIDMapRange sets where container id ranges are allocated from
// (containers.idmap_base, containers.idmap_ranges). It must be the same on
// every node: ranges are allocated cluster-wide.
func (s *Server) SetContainerIDMapRange(base int64, ranges int) {
	s.idmapBase, s.idmapRanges = base, ranges
}

func (s *Server) idmapConfig() (int64, int) {
	base, n := s.idmapBase, s.idmapRanges
	if base <= 0 {
		base = defaultIDMapBase
	}
	if n <= 0 {
		n = defaultIDMapRanges
	}
	return base, n
}

func (s *Server) idmapSlotBase(slot int) int64 {
	base, _ := s.idmapConfig()
	return base + int64(slot)*lxc.IDMapSize
}

// idmapStartSlot is where this host starts looking for a free range. Hosts
// start at different points (a hash of the host name), so two hosts
// allocating at the same moment, before either sees the other's row, almost
// never pick the same range; StartContainer refuses the rare overlap that
// still reaches one host.
func (s *Server) idmapStartSlot() int {
	_, n := s.idmapConfig()
	h := fnv.New32a()
	_, _ = h.Write([]byte(s.hostName))
	return int(h.Sum32() % uint32(n))
}

// idmapLedgerFile records the ranges this host allocated, so a range is not
// handed out twice while the container that has it is not yet in a row (a
// create in flight, or a replica that has not caught up).
const idmapLedgerFile = "ct-idmap-ledger"

// idmapLedgerTTL is how long a ledger entry holds a range with no row naming
// it: far longer than any create, and than replication lag.
const idmapLedgerTTL = 24 * time.Hour

type idmapLedgerEntry struct {
	Base int64     `json:"base"`
	Name string    `json:"name"`
	At   time.Time `json:"at"`
}

func (s *Server) readIDMapLedger() []idmapLedgerEntry {
	b, err := os.ReadFile(filepath.Join(s.dataDir, idmapLedgerFile))
	if err != nil {
		return nil
	}
	var out []idmapLedgerEntry
	for _, line := range strings.Split(string(b), "\n") {
		var e idmapLedgerEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.Base != 0 {
			out = append(out, e)
		}
	}
	return out
}

// allocateIDMapBase picks a range no container uses: not one any live row in
// the cluster records, not one this host's ledger holds, and not one any
// container on this host's disk is configured with. The pick is ledgered
// before it is returned. A host with no data directory (a test rig) keeps no
// ledger.
func (s *Server) allocateIDMapBase(ctx context.Context, name string) (int64, error) {
	s.idmapMu.Lock()
	defer s.idmapMu.Unlock()
	used := map[int64]bool{}
	rows, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return 0, status.Errorf(codes.Internal, "read container id ranges: %v", err)
	}
	for _, r := range rows {
		if b := corrosion.DecodeCreateSpec(r.CreateSpec).IDMapBase; b != 0 {
			used[b] = true
		}
	}
	now := time.Now()
	ledger := []idmapLedgerEntry{}
	if s.dataDir != "" {
		for _, e := range s.readIDMapLedger() {
			if now.Sub(e.At) < idmapLedgerTTL {
				used[e.Base] = true
				ledger = append(ledger, e)
			}
		}
	}
	for _, sec := range s.localContainerSecurity(ctx) {
		if sec.IDMap != nil {
			used[sec.IDMap.Base] = true
		}
		// An unfinished convert's target is taken while its marker exists,
		// however long ago the ledger entry was written: it resumes into it.
		if sec.Converting && sec.ConvertTo != nil && sec.ConvertTo.IDMap != nil {
			used[sec.ConvertTo.IDMap.Base] = true
		}
	}
	_, n := s.idmapConfig()
	start := s.idmapStartSlot()
	for i := 0; i < n; i++ {
		b := s.idmapSlotBase((start + i) % n)
		if used[b] {
			continue
		}
		if s.dataDir != "" {
			ledger = append(ledger, idmapLedgerEntry{Base: b, Name: name, At: now})
			var sb strings.Builder
			for _, e := range ledger {
				line, _ := json.Marshal(e)
				sb.Write(line)
				sb.WriteByte('\n')
			}
			tmp := filepath.Join(s.dataDir, idmapLedgerFile+".tmp")
			if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
				return 0, status.Errorf(codes.Internal, "record container id range: %v", err)
			}
			if err := os.Rename(tmp, filepath.Join(s.dataDir, idmapLedgerFile)); err != nil {
				return 0, status.Errorf(codes.Internal, "record container id range: %v", err)
			}
		}
		return b, nil
	}
	return 0, status.Errorf(codes.ResourceExhausted,
		"every container id range is in use (%d ranges); raise containers.idmap_ranges on every node", n)
}

// localContainerSecurity reads the security of every container on this host's
// disk, by name (nil when the runtime keeps none).
func (s *Server) localContainerSecurity(ctx context.Context) map[string]lxc.Security {
	sc, ok := s.containerRuntime.(containerSecurer)
	if !ok || s.containerRuntime == nil {
		return nil
	}
	names, err := s.containerRuntime.ListContainers(ctx)
	if err != nil {
		return nil
	}
	out := map[string]lxc.Security{}
	for _, n := range names {
		if sec, err := sc.ContainerSecurity(n); err == nil {
			out[n] = sec
		}
	}
	return out
}

// containerSecurityRequest validates a create's or convert's confinement and
// privilege request, on the node that took it (only there is the caller
// real). The opt-outs are the Admin's.
func containerSecurityRequest(ctx context.Context, privileged bool, confinement string) error {
	// Carried over from the container a compose recreate replaces: not an
	// opt-out anyone asked for, and the replaced container had it already.
	inherited := securityInherited(ctx)
	switch confinement {
	case "", lxc.ConfinementDefault:
	case lxc.ConfinementLegacy:
		if err := RequireRole(ctx, "admin"); err != nil && !inherited {
			return status.Error(codes.PermissionDenied,
				"confinement legacy (AppArmor nesting allowed, the template's seccomp and capabilities) requires the admin role")
		}
	default:
		return status.Errorf(codes.InvalidArgument, "confinement %q: want %q or %q", confinement, lxc.ConfinementDefault, lxc.ConfinementLegacy)
	}
	if privileged {
		if err := RequireRole(ctx, "admin"); err != nil && !inherited {
			return status.Error(codes.PermissionDenied,
				"a privileged container (no user namespace: root inside is root on the host) requires the admin role")
		}
	}
	return nil
}

// refuseOverlappingRange refuses to start an unprivileged container whose range
// overlaps another container's on this host. Allocation avoids every range
// the cluster records, but two hosts allocating at once (each before seeing
// the other's row) can pick one range, and a migrate can then bring both
// here: two containers sharing host ids could reach each other's files.
func (s *Server) refuseOverlappingRange(ctx context.Context, name string) error {
	all := s.localContainerSecurity(ctx)
	mine, ok := all[name]
	if !ok || mine.IDMap == nil {
		return nil
	}
	for other, sec := range all {
		if other == name || sec.IDMap == nil {
			continue
		}
		a, b := mine.IDMap, sec.IDMap
		if a.Base < b.Base+b.Size && b.Base < a.Base+a.Size {
			return status.Errorf(codes.FailedPrecondition,
				"container %q's id range (%d+%d) overlaps container %q's on this host; move it to a fresh range first: lv ct convert --unprivileged %s",
				name, a.Base, a.Size, other, name)
		}
	}
	return nil
}

// ConvertContainer changes a stopped container's security settings in place:
// --unprivileged moves it into a fresh id range (shifting its files; the data
// stays where it is), --confinement sets default or legacy (the latter the
// Admin's). An unfinished convert leaves the container refusing to start
// until the same convert is run again.
func (s *Server) ConvertContainer(ctx context.Context, req *pb.ConvertContainerRequest) (*pb.Container, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if !req.Unprivileged && req.Confinement == "" {
		return nil, status.Error(codes.InvalidArgument, "nothing to convert: pass --unprivileged and/or --confinement")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name), "ct.update", "operator", containerWhat(req.Name)); err != nil {
		s.audit(ctx, "ct.convert", req.Name, "project="+project, "denied")
		return nil, err
	}
	if err := containerSecurityRequest(ctx, false, req.Confinement); err != nil {
		s.audit(ctx, "ct.convert", req.Name, "project="+project+" confinement="+req.Confinement, "denied")
		return nil, err
	}
	host, _, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, closer, derr := s.dialPeer(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward convert: %v", derr)
		}
		defer closer()
		fwd := proto.Clone(req).(*pb.ConvertContainerRequest)
		fwd.HostName = host
		return c.ConvertContainer(ctx, fwd)
	}
	sc, ok := s.containerRuntime.(containerSecurer)
	if s.containerRuntime == nil || !ok {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	unlock := s.LockContainer(req.Name)
	defer unlock()
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read container: %v", err)
	}
	if rec == nil {
		return nil, status.Errorf(codes.NotFound, "container %q not found on host %q", req.Name, s.hostName)
	}
	// Offline only: the files of a running container cannot be shifted under it.
	if st, serr := s.containerRuntime.StateContainer(ctx, req.Name); serr != nil || !strings.EqualFold(st, "stopped") {
		got := st
		if serr != nil {
			got = serr.Error()
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"container %q must be stopped to convert (lv ct stop %s); it is %s", req.Name, req.Name, got)
	}
	spec := corrosion.DecodeCreateSpec(rec.CreateSpec)
	to := lxc.ConvertOpts{Confinement: req.Confinement}
	// An interrupted convert is finished to the range it recorded, never a
	// fresh one: part of the rootfs is already there (the runtime resumes to
	// it whatever we ask, so the row must name it too).
	if cur, cerr := sc.ContainerSecurity(req.Name); cerr == nil && cur.Converting && cur.ConvertTo != nil && cur.ConvertTo.IDMap != nil {
		to.IDMap = cur.ConvertTo.IDMap
		if to.Confinement == "" {
			to.Confinement = cur.ConvertTo.Confinement
		}
	} else if req.Unprivileged {
		base, aerr := s.allocateIDMapBase(ctx, req.Name)
		if aerr != nil {
			return nil, aerr
		}
		to.IDMap = &lxc.IDMap{Base: base, Size: lxc.IDMapSize}
	}
	s.audit(ctx, "ct.convert", req.Name, fmt.Sprintf("project=%s unprivileged=%v confinement=%s", project, req.Unprivileged, req.Confinement), "started")
	if err := sc.ConvertContainerSecurity(ctx, req.Name, to); err != nil {
		s.audit(ctx, "ct.convert", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal,
			"convert %q: %v (the container refuses to start until the same lv ct convert succeeds; its data is untouched)", req.Name, err)
	}
	// The row records what the container now IS (its config), never the
	// request: a resumed convert finishes to the marker's target first.
	done, derr := sc.ContainerSecurity(req.Name)
	if derr != nil {
		return nil, status.Errorf(codes.Internal, "converted, but reading the result back failed: %v", derr)
	}
	spec.IDMapBase = 0
	if done.IDMap != nil {
		spec.IDMapBase = done.IDMap.Base
	}
	spec.Confinement = done.Confinement
	rec.CreateSpec = corrosion.EncodeCreateSpec(spec)
	if err := corrosion.UpsertContainer(ctx, s.db, *rec); err != nil {
		return nil, status.Errorf(codes.Internal, "converted, but recording it failed (lv ct inspect may show the old settings): %v", err)
	}
	s.audit(ctx, "ct.convert", req.Name, fmt.Sprintf("project=%s idmap_base=%d confinement=%s", project, spec.IDMapBase, spec.Confinement), "ok")
	return toPbContainer(*rec), nil
}

// remapRestoredRange gives an operator-restored unprivileged container a fresh
// range when another live container records the one it was backed up with
// (its original lives on, or the range was reallocated since). A migrate or
// relocation is the same container moving and keeps its range.
func (s *Server) remapRestoredRange(ctx context.Context, name, createSpec string) (string, error) {
	spec := corrosion.DecodeCreateSpec(createSpec)
	if spec.IDMapBase == 0 {
		return createSpec, nil
	}
	rows, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return "", status.Errorf(codes.Internal, "read container id ranges: %v", err)
	}
	taken := false
	for _, r := range rows {
		if !(r.HostName == s.hostName && r.Name == name) && corrosion.DecodeCreateSpec(r.CreateSpec).IDMapBase == spec.IDMapBase {
			taken = true
			break
		}
	}
	if !taken {
		return createSpec, nil
	}
	sc, ok := s.containerRuntime.(containerSecurer)
	if !ok {
		return createSpec, nil
	}
	base, err := s.allocateIDMapBase(ctx, name)
	if err != nil {
		return "", err
	}
	if err := sc.ConvertContainerSecurity(ctx, name, lxc.ConvertOpts{IDMap: &lxc.IDMap{Base: base, Size: lxc.IDMapSize}}); err != nil {
		return "", status.Errorf(codes.Internal, "move the restored container to a fresh id range: %v", err)
	}
	slog.Info("container restore: its id range is another container's; moved to a fresh one", "name", name, "from", spec.IDMapBase, "to", base)
	spec.IDMapBase = base
	return corrosion.EncodeCreateSpec(spec), nil
}

// containerSecurityOf reports a row's recorded settings for the API.
func containerSecurityOf(r corrosion.ContainerRecord) (privileged bool, confinement string, base int64) {
	spec := corrosion.DecodeCreateSpec(r.CreateSpec)
	confinement = spec.Confinement
	if confinement == "" {
		confinement = lxc.ConfinementLegacy
	}
	return spec.IDMapBase == 0, confinement, spec.IDMapBase
}

// droppedAttrsTaker is the runtime half of an import's dropped attributes
// (lxc.LxcRunner.TakeDroppedAttrs).
type droppedAttrsTaker interface {
	TakeDroppedAttrs(name string) ([]string, error)
}

// reportDroppedAttrs records, as a container event and a warning, the
// attributes the last import of name dropped because this host's filesystem
// does not support them (a dropped ACL narrowed the file's group bits).
func (s *Server) reportDroppedAttrs(ctx context.Context, name, op string) {
	t, ok := s.containerRuntime.(droppedAttrsTaker)
	if !ok {
		return
	}
	dropped, err := t.TakeDroppedAttrs(name)
	if err != nil || len(dropped) == 0 {
		return
	}
	detail := op + " dropped attributes this filesystem does not support (a dropped ACL narrowed the file's group bits): " + strings.Join(dropped, "; ")
	slog.Warn("container "+op+": attributes dropped", "container", name, "dropped", dropped)
	s.audit(ctx, "ct."+op, name, detail, "warning")
	if s.events != nil {
		s.events.Publish(events.Event{Action: "ct.attrs.dropped", Target: name, Detail: detail})
	}
}

// idRangeEnsurer is the runtime half of PrepareContainerTarget.
type idRangeEnsurer interface {
	EnsureContainerIDRange(base, size int64) error
}

// PrepareContainerTarget is a migrate's preflight on the target, peer only:
// root's subordinate range is made to cover the container's id range here,
// before the source is stopped, so a target that cannot take it refuses the
// migrate while the source still runs untouched.
func (s *Server) PrepareContainerTarget(ctx context.Context, req *pb.PrepareContainerTargetRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := s.validatePreparedRange(ctx, req); err != nil {
		return nil, err
	}
	e, ok := s.containerRuntime.(idRangeEnsurer)
	if !ok {
		return &emptypb.Empty{}, nil
	}
	if err := e.EnsureContainerIDRange(req.IdmapBase, req.IdmapSize); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "host %q cannot give root the subordinate range %d+%d: %v", s.hostName, req.IdmapBase, req.IdmapSize, err)
	}
	return &emptypb.Empty{}, nil
}

// prepareMigrateTarget runs PrepareContainerTarget on target for an
// unprivileged container. An older target (Unimplemented) cannot do it and is
// not refused: its start will say so, as before.
func (s *Server) prepareMigrateTarget(ctx context.Context, target string, rec *corrosion.ContainerRecord) error {
	base := corrosion.DecodeCreateSpec(rec.CreateSpec).IDMapBase
	if base == 0 {
		return nil
	}
	c, closer, err := s.dialPeer(ctx, target)
	if err != nil {
		return status.Errorf(codes.Unavailable, "reach target %q to prepare it: %v", target, err)
	}
	defer closer()
	if _, err := c.PrepareContainerTarget(ctx, &pb.PrepareContainerTargetRequest{
		IdmapBase: base, IdmapSize: lxc.IDMapSize, Name: rec.Name, SourceHost: rec.HostName,
	}); err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Warn("migrate: the target predates PrepareContainerTarget; root's subordinate range there is not ensured", "target", target, "container", rec.Name)
			return nil
		}
		return status.Errorf(codes.FailedPrecondition, "migrate refused before the source was touched: prepare target %q: %v", target, err)
	}
	return nil
}

// keepRecordedSecurity makes a container's on-disk config carry the privilege
// mode, range and confinement its row records, converting it back when a
// restore of an older copy (a snapshot revert) laid down different ones. The
// row is the authority: it is what lv ct inspect and lv doctor report and what
// range allocation counts. A row from an earlier build records nothing, and
// whatever the copy carries stays. A privileged row over an unprivileged copy
// cannot be undone by a convert (it only tightens) and is left, logged.
func (s *Server) keepRecordedSecurity(ctx context.Context, rec *corrosion.ContainerRecord) error {
	sc, ok := s.containerRuntime.(containerSecurer)
	if !ok {
		return nil
	}
	spec := corrosion.DecodeCreateSpec(rec.CreateSpec)
	if spec.IDMapBase == 0 && spec.Confinement == "" {
		return nil
	}
	cur, err := sc.ContainerSecurity(rec.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read the restored container's security: %v", err)
	}
	var to lxc.ConvertOpts
	if spec.IDMapBase != 0 && (cur.IDMap == nil || cur.IDMap.Base != spec.IDMapBase) {
		to.IDMap = &lxc.IDMap{Base: spec.IDMapBase, Size: lxc.IDMapSize}
	}
	if spec.IDMapBase == 0 && cur.IDMap != nil {
		slog.Warn("container: the restored copy is unprivileged but the container is recorded privileged; left unprivileged",
			"container", rec.Name, "range", cur.IDMap.Base)
	}
	if spec.Confinement != "" && cur.Confinement != spec.Confinement {
		to.Confinement = spec.Confinement
	}
	if to.IDMap == nil && to.Confinement == "" {
		return nil
	}
	if err := sc.ConvertContainerSecurity(ctx, rec.Name, to); err != nil {
		return status.Errorf(codes.Internal,
			"restore the container's recorded privilege mode after the revert: %v (it refuses to start until this finishes: %s)", err, lxc.ConvertCommand(rec.Name, &to))
	}
	return nil
}

// revertConverter is the runtime half of a revert that marks the restored
// copy converting to the container's recorded security before the swap
// (lxc.LxcRunner.RevertContainerConverting).
type revertConverter interface {
	RevertContainerConverting(ctx context.Context, name string, r io.Reader, to lxc.ConvertOpts) error
}

// revertKeepingSecurity reverts rec from r. When the row records a security
// and the runtime can, the restored copy is marked converting to it before it
// is swapped in, so a crash before keepRecordedSecurity's convert leaves a
// container that refuses to start (and lv ct convert resumes to the recorded
// range), never one running with the snapshot's older mode.
func (s *Server) revertKeepingSecurity(ctx context.Context, rec *corrosion.ContainerRecord, r io.Reader) error {
	spec := corrosion.DecodeCreateSpec(rec.CreateSpec)
	rc, ok := s.containerRuntime.(revertConverter)
	if !ok || (spec.IDMapBase == 0 && spec.Confinement == "") {
		return s.containerRuntime.RevertContainer(ctx, rec.Name, r)
	}
	to := lxc.ConvertOpts{Confinement: spec.Confinement}
	if spec.IDMapBase != 0 {
		to.IDMap = &lxc.IDMap{Base: spec.IDMapBase, Size: lxc.IDMapSize}
	}
	return rc.RevertContainerConverting(ctx, rec.Name, r, to)
}

// validatePreparedRange admits only a container range: lxc.IDMapSize ids at a
// slot of the configured span, which no container other than the one being
// migrated records. A trusted peer is not thereby trusted to append any
// root: line to /etc/subuid.
func (s *Server) validatePreparedRange(ctx context.Context, req *pb.PrepareContainerTargetRequest) error {
	base, n := s.idmapConfig()
	if req.IdmapSize != lxc.IDMapSize {
		return status.Errorf(codes.InvalidArgument, "idmap_size %d: a container range is %d ids", req.IdmapSize, lxc.IDMapSize)
	}
	off := req.IdmapBase - base
	if req.IdmapBase < base || off%lxc.IDMapSize != 0 || off/lxc.IDMapSize >= int64(n) {
		return status.Errorf(codes.InvalidArgument,
			"idmap_base %d is not a container range of this cluster (%d ranges from %d)", req.IdmapBase, n, base)
	}
	rows, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return status.Errorf(codes.Unavailable, "read container id ranges: %v", err)
	}
	for _, r := range rows {
		if r.HostName == req.SourceHost && r.Name == req.Name {
			continue
		}
		if corrosion.DecodeCreateSpec(r.CreateSpec).IDMapBase == req.IdmapBase {
			return status.Errorf(codes.FailedPrecondition,
				"id range %d is container %s/%s's; it cannot be prepared for %s", req.IdmapBase, r.HostName, r.Name, req.Name)
		}
	}
	return nil
}

package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// PromoteReplica brings an inert replica online for disaster recovery: it
// locates the chosen (or newest) replica of a VM's root disk, ensures it runs
// on the host that physically holds the replica file, builds a self-contained
// live disk from it, then defines + starts the VM there and persists the
// record. The VM's durable record (replicated via Corrosion) supplies the spec,
// so promotion works even after the original host is gone.
func (s *Server) PromoteReplica(req *pb.PromoteReplicaRequest, stream grpc.ServerStreamingServer[pb.PromoteReplicaProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" {
		return status.Error(codes.InvalidArgument, "vm_name required")
	}
	// A carried proof (a relayed/automated promote) must come from a known cluster
	// host — operator promotes go through RBAC below and carry no proof.
	if req.Proof != nil {
		if err := s.requirePeerCert(ctx); err != nil {
			return status.Error(codes.PermissionDenied, "promote proof requires a peer cert")
		}
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q has no durable record to reconstruct from", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.create", "operator"); err != nil {
		return err
	}
	return s.promoteResolved(ctx, req, vm, false /*operator*/, stream.Send)
}

// requireProofGradeFence verifies fenceEpoch proves a proof-grade power-off of the
// old owner, for a shared-disk cross-host transfer, mapping the shared
// corrosion.CheckProofGradeFence tri-state to gRPC: RETRY ⇒ Unavailable (the
// referenced fencing_log row rides the same replication as the carried proof, so
// right after a fence the executor may not have it yet); REJECT ⇒ FailedPrecondition
// with the storage_unverified refusal reason.
func (s *Server) requireProofGradeFence(ctx context.Context, fenceEpoch, oldOwner string) error {
	switch verdict, detail := corrosion.CheckProofGradeFence(ctx, s.db, fenceEpoch, oldOwner, corrosion.SharedDiskFenceWindow); verdict {
	case corrosion.FenceOK:
		return nil
	case corrosion.FenceRetry:
		return status.Errorf(codes.Unavailable, "shared-disk promote: %s — retry", detail)
	default: // FenceReject
		s.noteGateRefused(corrosion.ActionPromote, health.ReasonStorageUnverified)
		return status.Errorf(codes.FailedPrecondition, "shared-disk promote refused: %s (storage_unverified)", detail)
	}
}

// AutoPromoteReplica is the failover coordinator's trusted, non-streaming entry
// point: after a host is fenced, promote the freshest replica of vmName onto a
// healthy peer so a VM on lost local storage can resume. Returns an error when
// there is no replica to promote, so the coordinator can fall back to a
// reschedule. fenceEpoch binds the carried proof to the proof-grade fence of the
// old owner that authorizes this transfer (see the shared-disk gate below).
//
// Force is RETAINED on auto-promote — a deliberate, ratified deviation from the
// plan's §8 "remove Force" cherry-pick (see TODO §8). It keeps TWO behaviors, both
// by design:
//  1. Bypass the healthy-owner guard: that guard reads the executor's REPLICATED
//     hosts.state, so fence-state gossip lag would false-refuse and strand a
//     local-disk DR VM (which has no shared-write hazard). The shared-disk
//     split-brain protection is instead the fence_epoch gate in doPromoteLocal,
//     re-verified against the append-only fencing_log — robust to that lag.
//  2. Destroy-on-collision: a pre-existing same-name domain on the replica host is
//     destroyed+rebuilt rather than refused. Retained for crash-recovery of a
//     half-built promotion; a running domain that is OUR OWN prior promotion is
//     still ADOPTED (never destroyed) via the promote marker / started checkpoint.
func (s *Server) AutoPromoteReplica(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64) error {
	return s.autoPromote(ctx, vmName, fenceEpoch, leaseTerm, "")
}

// errReplicaOutOfRegion refuses an automatic promotion whose replica is held
// by a host outside the region region-scoped failover keeps the recovery in.
var errReplicaOutOfRegion = errors.New("replica is held outside the region recovery must stay in")

// AutoPromoteReplicaInRegion is AutoPromoteReplica for region-scoped failover
// (failover.RegionScopedPromoter): the promotion runs only if the host holding
// the replica is in region. Otherwise it returns errReplicaOutOfRegion before
// any proof is persisted or any request relayed, and the coordinator falls
// back to its region-constrained reschedule.
func (s *Server) AutoPromoteReplicaInRegion(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64, region string) error {
	return s.autoPromote(ctx, vmName, fenceEpoch, leaseTerm, region)
}

func (s *Server) autoPromote(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64, region string) error {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return fmt.Errorf("vm %q not found", vmName)
	}
	// Automated promotion must never act on a disputed workload: the fenced host
	// is only one of the condition's holders, and defining + starting the replica
	// while the other side may still be live adds a writer. The coordinator also
	// refuses at plan time; this guards the direct callers and races where the
	// condition lands between plan and execute. An OPERATOR PromoteReplica stays
	// available as the deliberate manual override. Fail closed on a read error.
	if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, s.db, "vm", vmName); cerr != nil {
		return status.Errorf(codes.Unavailable,
			"cannot read health conditions before auto-promote of %q (fail closed): %v", vmName, cerr)
	} else if disputed {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q has an active ownership condition (%s); automated promotion refused — resolve the dispute first", vmName, code)
	}
	req := &pb.PromoteReplicaRequest{VmName: vmName, Force: true}
	// Split-brain hardening (Phase 1): once enforced, mint a durable single-use
	// proof so the executing (possibly relayed) host validates + claims it before
	// the destructive define+start — preventing a duplicate/retried promote from
	// running the VM twice. The coordinator already gated the decision (DecisionGate).
	if s.gateActive(ctx) {
		// Build the carried proof now, but DON'T write the durable row until the dest
		// host is resolved in promoteResolved — writing it dest-empty here would
		// persist a row that fails the exact dest binding (and INSERT OR IGNORE would
		// then keep the empty-dest row over the carried full proof).
		req.Proof = &pb.RuntimeActionProof{
			Id: randid.New(), Action: corrosion.ActionPromote, TargetKind: "vm",
			TargetName: vmName, Coordinator: s.hostName, LeaseHolder: s.hostName,
			OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10),
			FenceEpoch: fenceEpoch,
		}
		// The coordinator's tenure. It always had one to give -- it holds the
		// failover lease -- and stamping it is what lets promote join
		// leaseTermRequiredActions, so a promote proof arriving unstamped is a
		// defect rather than a lease-less producer's normal output.
		//
		// The key is the CONSTANT, not a parameter: the failover coordinator is
		// promote's only proof-carrying producer, so there is no other key it
		// could be, and a stamp site that a reader (or
		// TestProofLeaseKeyProducible) cannot resolve to a known constant
		// cannot be vouched for.
		//
		// Both halves or neither. judgeProofLeaseTerm recognises exactly two
		// shapes -- a positive term with a producible key, or the legacy
		// sentinel (0, "") -- and the half-set (0, "failover") is refused
		// outright, so a pre-ledger coordinator must stamp nothing at all.
		if leaseTerm > 0 {
			req.Proof.LeaseTerm = leaseTerm
			req.Proof.LeaseKey = corrosion.LeaseKeyFailover
		}
	}
	return s.promoteResolvedIn(ctx, req, vm, true /*automated*/, region, func(*pb.PromoteReplicaProgress) error { return nil })
}

// promoteResolved is the shared promotion core (no RBAC): resolve the replica's
// pool + host, then run locally or relay to the holding host. `automated` distinguishes
// the coordinator's AutoPromoteReplica (must carry a proof under enforcement) from an
// operator PromoteReplica (RBAC-gated manual override, may run proofless).
func (s *Server) promoteResolved(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, automated bool, send func(*pb.PromoteReplicaProgress) error) error {
	return s.promoteResolvedIn(ctx, req, vm, automated, "", send)
}

// promoteResolvedIn is promoteResolved with an optional region the replica's
// host must be in ("" = anywhere). Only region-scoped automatic promotion sets
// it; an operator promotion never does.
func (s *Server) promoteResolvedIn(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, automated bool, requireRegion string, send func(*pb.PromoteReplicaProgress) error) error {
	// A replica carries only disk data — not the VM's UEFI NVRAM or swtpm state.
	// Promoting a Secure-Boot/vTPM VM from one would boot it with a fresh TPM and
	// silently brick BitLocker, so refuse rather than recover it half-formed.
	// Recovery of such a VM is an explicit restore from a backup that captured the
	// firmware (G1).
	if usesFirmwareState(vm.Spec) {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q uses Secure Boot / vTPM; its firmware state isn't in the disk replica, so promotion can't recover it — restore from a backup that captured firmware", req.VmName)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	src := pickReplicaSource(disks)
	if src == nil {
		return status.Errorf(codes.FailedPrecondition, "vm %q has no disk records", req.VmName)
	}

	// Resolve the target pool: explicit, else inferred from the VM's
	// replication schedule.
	pool := req.TargetPool
	schedHost := req.TargetHost
	if pool == "" {
		sp, sh, ok := s.replicationTargetForVM(ctx, req.VmName)
		if !ok {
			return status.Errorf(codes.FailedPrecondition,
				"no target_pool given and vm %q has no replication schedule to infer one", req.VmName)
		}
		pool = sp
		if schedHost == "" {
			schedHost = sh
		}
	}

	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_RESOLVING, VmName: req.VmName,
		Status: "locating replica of disk " + src.DiskName + " in pool " + pool,
	})

	host, replicas, err := s.findReplicaHost(ctx, req, vm, src.DiskName, pool, schedHost)
	if err != nil {
		return err
	}
	replica := replicas[0]
	// Region-scoped failover keeps a recovery in the fenced host's region. The
	// replica's host is known only now, so this is the first point it can be
	// checked, and it is before any proof is persisted or relayed. An unknown
	// host is refused: its region cannot be shown to match.
	if requireRegion != "" {
		hr, herr := corrosion.GetHost(ctx, s.db, host)
		if herr != nil || hr == nil || hr.Region != requireRegion {
			got := "unknown"
			if hr != nil {
				got = hr.Region
			}
			return fmt.Errorf("%w: vm %q's replica is on %s (region %s), recovery stays in %s",
				errReplicaOutOfRegion, req.VmName, host, got, requireRegion)
		}
	}
	// Before any proof is persisted or any request relayed: a stale replica is
	// refused at the point it is chosen, not after the destination has been
	// told to expect it.
	//
	// Returned unwrapped rather than as a gRPC status: `automated` is only ever
	// the in-process AutoPromoteReplica call, and a status would drop the
	// errReplicaTooOld chain that says WHY recovery fell back to a reschedule.
	var ageLimit time.Duration
	if automated {
		sched, _ := s.replicationScheduleForVM(ctx, req.VmName)
		ageLimit = autoPromoteAgeLimit(sched.Cron)
		if err := checkAutoPromoteReplicaAge(replica, time.Now(), ageLimit); err != nil {
			return err
		}
	}
	// Bind the proof to the resolved executor (the replica-holding host) so it
	// validates dest_host == self, then persist the durable row NOW (with the
	// correct dest) — before relaying/executing — so the replicated row and the
	// carried proof agree on the exact action/target/dest binding.
	if req.Proof != nil {
		// The lease-term stamp is validated FIRST: before the destination probes,
		// and above all before the seed below.
		//
		// claimCarriedProof also validates it, but that call is several hundred
		// lines later, inside doPromoteLocal. The seed below commits the presented
		// proof and relays the batch, so a key that fails validation down there has
		// already become the row every peer holds — and the row, not the proto, is
		// what enforcement reads afterwards. A malformed stamp is also malformed
		// regardless of what the destination advertises, so it costs nothing to
		// refuse it before spending a Fresh-Ping on it.
		if err := validateProofTermStamp(req.Proof); err != nil {
			s.noteGateRefused(corrosion.ActionPromote, health.ReasonProofConflict)
			return err
		}
		// Fresh-Ping the resolved destination: never stamp a proof for a target that
		// no longer advertises the gate (a regressed/replaced replica host that
		// couldn't honor it). Fail closed — refuse rather than promote there ungated.
		if !s.destSupportsGate(ctx, host) {
			s.noteGateRefused(corrosion.ActionPromote, health.ReasonUnsupportedCapability)
			return status.Errorf(codes.FailedPrecondition,
				"promote refused: destination %q does not advertise the split-brain gate", host)
		}
		// If THIS node enforces the shared-storage fence, the destination must also
		// advertise the token so it will honor the proof-grade requirement on execute
		// — a regressed/replaced dest that lost it would otherwise run the shared-disk
		// transfer ungated. Fresh-Ping, fail closed.
		if s.sharedStorageFenceActive(ctx) && !s.destSupportsSharedStorageFence(ctx, host) {
			s.noteGateRefused(corrosion.ActionPromote, health.ReasonUnsupportedCapability)
			return status.Errorf(codes.FailedPrecondition,
				"promote refused: destination %q does not advertise the shared-storage fence gate", host)
		}
		req.Proof.DestHost = host
		// Claim before mint (docs/design/recovery-claims.md §3.13): the promote
		// proof's destination is known only now, so this — not the coordinator
		// before it called AutoPromoteReplica — is where the promote is
		// claimed. Only the coordinator's automated promotion claims; an
		// operator PromoteReplica is a deliberate manual override (§2).
		if automated && s.RecoveryClaimEnforced(ctx) {
			if err := s.claimPromote(ctx, vm, req.Proof); err != nil {
				return err
			}
		}
		// WriteActionProofValidated, not WriteActionProof: req.Proof may be
		// CALLER-SUPPLIED. This block is gated on req.Proof != nil, not on
		// `automated`, so a peer-mTLS caller's proof lands here too.
		//
		// Seeding through the unvalidated writer defeated the divergence check
		// entirely on this path. It committed the presented statement to
		// mutation_log — which relays the whole batch, so a local no-op still
		// ships — and then claimCarriedProof compared the presented proof
		// against the row this line had just written from it, found them equal
		// by construction, and claimed it. ErrProofDiverges could never fire on
		// promote: the most destructive action in the tree, and the one case
		// b122f70 exists to close.
		if err := corrosion.WriteActionProofValidated(ctx, s.db, proofFromPB(req.Proof)); err != nil {
			if errors.Is(err, corrosion.ErrProofDiverges) {
				s.noteGateRefused(corrosion.ActionPromote, health.ReasonProofConflict)
				return status.Errorf(codes.FailedPrecondition,
					"persisted proof %s does not match the presented promote proof (divergent/seeded row)",
					req.Proof.GetId())
			}
			return status.Errorf(codes.Unavailable, "persist promote proof: %v", err) // fail closed
		}
	}

	// Project isolation: the VM's project may promote a replica only from a pool
	// that is global or one it owns — checked against the RESOLVED replica host
	// before relaying, so a cross-project promote is rejected at the entry. (Safe
	// for the trusted failover path: a VM's own replica lives in its own/global
	// pool, and pre-v37 pools are all global.)
	if err := s.admitVMPoolUse(ctx, vm, host, pool); err != nil {
		return err
	}

	// The replica file + libvirt live on `host`; forward there if it isn't us.
	// When the chosen replica turns out to be missing or unreadable there, the
	// next-older one on the same host is tried (the proof is bound to that
	// host). A replica the operator named is the only candidate
	// (findReplicaHost), so it is never swapped for another.
	var lastErr error
	for i, replica := range replicas {
		if i > 0 {
			if automated {
				if err := checkAutoPromoteReplicaAge(replica, time.Now(), ageLimit); err != nil {
					return fmt.Errorf("%w (a newer replica was unavailable: %v)", err, lastErr)
				}
			}
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_RESOLVING, VmName: req.VmName, Host: host, Replica: replica,
				Status: "newer replica unavailable; trying " + replica,
			})
		}
		if host != s.hostName {
			fwd := &pb.PromoteReplicaRequest{
				VmName: req.VmName, TargetPool: pool, TargetHost: host, Replica: replica,
				NewName: req.NewName, Force: req.Force, NoLocalize: req.NoLocalize,
				Proof: req.Proof, // carry the full single-use proof to the executor
			}
			err = s.relayPromote(ctx, host, fwd, send)
		} else {
			err = s.doPromoteLocal(ctx, req, vm, src, pool, replica, automated, send)
		}
		if err == nil || !replicaUnavailable(err) {
			return err
		}
		slog.Warn("promote: replica unavailable; trying the next-older one", "vm", req.VmName, "host", host, "replica", replica, "error", err)
		lastErr = err
	}
	return lastErr
}

// errReplicaTooOld marks an automatic promotion refused because the newest
// replica is older than autoPromoteMaxReplicaAge, or carries no timestamp this
// code can read.
var errReplicaTooOld = errors.New("newest replica is too old for automatic promotion")

// autoPromoteMaxReplicaAge bounds how old a replica AUTOMATIC promotion will use.
//
// There was no bound at all. A schedule that had been failing for days left a
// replica exactly as promotable as one from ten minutes ago, and failover would
// replace a VM running on current data with a disk from last week and report a
// recovery. The coordinator falls back to a plain reschedule on any promote
// error, so a refusal here costs nothing that having no replica would not.
//
// This is the FALLBACK, used when the VM's schedule cannot be read; normally
// the bound follows the schedule (autoPromoteAgeLimit). 48 hours because a
// daily schedule's newest replica is legitimately up to 24 hours old at the
// moment of failure, and one missed run should not by itself turn automatic
// recovery off. Manual promotion is NOT
// bounded — an operator who has looked at the age and chosen it anyway is
// making a different decision.
//
// A var, not a const, only so tests can move it; nothing in production
// reassigns it.
var autoPromoteMaxReplicaAge = 48 * time.Hour

// replicaTimestamp reads the UTC run time out of a replica's file name, which
// the replication runner writes (and its record names) as
// `<disk>-<YYYYMMDD-HHMMSS>.<qcow2|raw>`. A disk name may itself contain
// dashes, so the stamp is taken from the END of the name. Only a replica
// already selected by its record is ever read this way.
func replicaTimestamp(name string) (time.Time, bool) {
	const layout = "20060102-150405"
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".qcow2"), ".raw")
	if len(base) < len(layout) {
		return time.Time{}, false
	}
	ts, err := time.Parse(layout, base[len(base)-len(layout):])
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// checkAutoPromoteReplicaAge refuses a replica too old — or too unreadable —
// for automatic promotion. Unreadable fails closed: a replica whose age cannot
// be established cannot be shown to be within the bound.
func checkAutoPromoteReplicaAge(replica string, now time.Time, limit time.Duration) error {
	ts, ok := replicaTimestamp(replica)
	if !ok {
		return fmt.Errorf("%w: cannot read a timestamp from %q", errReplicaTooOld, replica)
	}
	// A stamp in the future (beyond clock skew) was not written by a
	// replication run: its age cannot be shown to be within the bound.
	if ts.After(now.Add(replicaStampSkew)) {
		return fmt.Errorf("%w: %q is stamped in the future (%s)", errReplicaTooOld, replica, ts.Format(time.RFC3339))
	}
	if age := now.Sub(ts); age > limit {
		return fmt.Errorf("%w: %q is %s old (limit %s); promote it manually if it is still the best available",
			errReplicaTooOld, replica, age.Round(time.Minute), limit)
	}
	return nil
}

// replicationTargetForVM returns the (pool, host) of the VM's first vm-scoped
// replication schedule, used to infer where its replicas live.
func (s *Server) replicationTargetForVM(ctx context.Context, vmName string) (pool, host string, ok bool) {
	r, ok := s.replicationScheduleForVM(ctx, vmName)
	if !ok {
		return "", "", false
	}
	return r.TargetPool, r.TargetHost, true
}

// replicationScheduleForVM is the VM's first vm-scoped replication schedule.
func (s *Server) replicationScheduleForVM(ctx context.Context, vmName string) (corrosion.BackupScheduleRecord, bool) {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return corrosion.BackupScheduleRecord{}, false
	}
	for _, r := range rows {
		if r.Type == "replication" && r.VMName == vmName && r.TargetPool != "" {
			return r, true
		}
	}
	return corrosion.BackupScheduleRecord{}, false
}

// findReplicaHost locates the host holding the chosen (req.replica) or newest
// replica of vm's disk in pool, and returns that host's replicas of it,
// newest first (only req.Replica when one is named). Candidates come from an
// explicit target host, the schedule's host, or every active host that has
// the pool.
//
// Replicas come from two places, both selected by the VM's own records and
// never by a name another VM's merely shares a prefix with:
//
//   - the VM's directory of the pool's replica area (replicaRecordsOn:
//     replica_records.go), where replication runs write every replica now;
//   - the top level of the pool (replicaNames: replica_match.go), where
//     replicas written before that live — by their pool record, or an
//     unrecorded one by its exact name.
//
// Remote hosts are asked with this host's certificate, not through an
// RBAC-gated handler: AutoPromoteReplica runs from the failover coordinator
// with an unauthenticated context, which the handler's RequireRole would
// reject.
func (s *Server) findReplicaHost(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, diskName, pool, schedHost string) (host string, replicas []string, err error) {
	var candidates []string
	switch {
	case req.TargetHost != "":
		candidates = []string{req.TargetHost}
	case schedHost != "":
		candidates = []string{schedHost}
	default:
		hs, herr := corrosion.HostsWithPool(ctx, s.db, pool, "")
		if herr != nil || len(hs) == 0 {
			// Fall back to this host (a same-host/shared pool).
			candidates = []string{s.hostName}
		} else {
			candidates = hs
		}
	}

	k := replicaKeyOf(vm, diskName)
	// A replica the operator names may be any file an admin names, or one its
	// project owns (explicitReplicaOK); the newest is chosen by record.
	admin := req.Replica != "" && s.RequirePerm(ctx, "/", verbStorageHostPath, "admin") == nil
	byHost := map[string][]string{}
	bestHost, bestName := "", ""
	for _, h := range candidates {
		var names []string
		for _, r := range s.replicaRecordsOn(ctx, pool, h, vm.Project, vm.Name) {
			if r.Disk != diskName {
				continue
			}
			if req.Replica != "" && r.File == req.Replica {
				return h, []string{r.File}, nil
			}
			names = append(names, r.File)
		}
		top := s.replicaNames(ctx, pool, h, k, req.Replica, admin)
		if req.Replica != "" {
			if slices.Contains(top, req.Replica) {
				return h, []string{req.Replica}, nil
			}
			continue
		}
		names = append(names, top...)
		sortReplicasOldestFirst(names)
		byHost[h] = names
		// Each host's list is oldest first, by the run time in the names.
		if len(names) > 0 && (bestName == "" || replicaOlder(bestName, names[len(names)-1])) {
			bestName, bestHost = names[len(names)-1], h
		}
	}
	if req.Replica != "" {
		return "", nil, status.Errorf(codes.NotFound, "replica %q of vm %q disk %q not found in pool %q", req.Replica, req.VmName, diskName, pool)
	}
	if bestHost == "" {
		return "", nil, status.Errorf(codes.NotFound, "no replica of %q disk %q found in pool %q", req.VmName, diskName, pool)
	}
	newestFirst := slices.Clone(byHost[bestHost])
	slices.Reverse(newestFirst)
	return bestHost, newestFirst, nil
}

// relayPromote forwards a PromoteReplica stream to the host that holds the
// replica and relays its progress back to the caller.
func (s *Server) relayPromote(ctx context.Context, host string, req *pb.PromoteReplicaRequest, send func(*pb.PromoteReplicaProgress) error) error {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
	}
	defer conn.Close()
	up, err := client.PromoteReplica(ctx, req)
	if err != nil {
		return status.Errorf(codes.Unavailable, "promote on %q: %v", host, err)
	}
	for {
		msg, rerr := up.Recv()
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		if err := send(msg); err != nil {
			return err
		}
	}
}

// liveDiskBacking is replicaPath when the promoted live disk is an overlay on
// it (--no-localize, or no qemu-img), "" when it was localized. Recorded as
// the disk's backing_disk, it is what keeps replica pruning — and pool content
// delete — off the replica a running VM reads through (DisksReferencingPath).
func liveDiskBacking(livePath, replicaPath string) string {
	if info, err := qcow2.Info(livePath); err == nil && info.BackingFile == replicaPath {
		return replicaPath
	}
	return ""
}

// createOverlayNoClobber creates a qcow2 at path backed by backing, as a new
// file: qcow2 publishes it exclusively, refusing an existing path.
func createOverlayNoClobber(path, backing, backingFmt string) error {
	if err := qcow2.CreateWithBackingFormat(path, backing, backingFmt, 0, nil); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return existAsAlreadyExists(err)
		}
		return status.Errorf(codes.Internal, "create overlay: %v", err)
	}
	return nil
}

// doPromoteLocal performs the promotion on the host that holds the replica:
// build a self-contained live disk from the replica, define + start the VM, and
// persist it. Runs only when this host owns the replica file + libvirt.
// Promote markers — a host-local, PROOF-INDEPENDENT record that this host has promoted a
// domain under `name` (analogous to the container restore marker). Written before
// StartDomain, removed once the re-homed row persists. It exists because every failover
// cycle mints a FRESH proof, so the proof-keyed step_state can't tell a NEW proof's retry
// that a RUNNING domain under this name is our own prior promotion — without it, the
// force-takeover path would destroy+rebuild a running promoted VM and discard its writes.
func (s *Server) promoteMarkerPath(name string) string {
	return filepath.Join(s.dataDir, "promote-markers", name)
}
func (s *Server) promoteMarkerPresent(name string) bool {
	_, err := os.Stat(s.promoteMarkerPath(name))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	// Indeterminate stat (permission / I/O) → fail CLOSED: assume the marker MAY be present so
	// a retry adopts a possibly-ours running domain rather than destroy+rebuild it (mirrors the
	// fail-closed readRestoreMarker discipline for a safety marker).
	slog.Warn("promoteMarkerPresent: indeterminate stat, assuming present (fail closed)", "name", name, "error", err)
	return true
}
func (s *Server) writePromoteMarker(name, proofID string) error {
	if err := os.MkdirAll(filepath.Join(s.dataDir, "promote-markers"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.promoteMarkerPath(name), []byte(proofID), 0o600)
}
func (s *Server) removePromoteMarker(name string) { _ = os.Remove(s.promoteMarkerPath(name)) }

// promoteDomainAlreadyStarted decides whether a prior promotion of this domain is already
// running and must be ADOPTED (never destroyed+rebuilt). A domain counts as started only
// if it actually EXISTS and is RUNNING, and either this proof's own start_attempted
// checkpoint is set (same-proof crash after libvirt-start) or the host-local promote
// marker is present (CROSS-proof — each failover cycle mints a fresh proof, so step_state
// alone can't recognize our own prior promotion).
//
// Adoption REQUIRES the domain to actually exist and be RUNNING now: a checkpoint or marker
// only proves the domain is OURS (so a retry mustn't destroy+rebuild a stranger), not that
// it's still alive. A prior 'started' whose domain has since DIED must NOT be adopted — that
// would persist a dead domain as running and skip the rebuild; it falls through to the
// (re)build/(re)start path instead.
func promoteDomainAlreadyStarted(startedStep, startAttemptedStep, markerPresent, domainExists, domainRunning bool) bool {
	return domainExists && domainRunning && (startedStep || startAttemptedStep || markerPresent)
}

// promoteDiskBuilt honors the disk_built checkpoint only when the live disk actually
// exists — step_state is forward-only but error paths remove the disk, and livePath
// embeds the replica timestamp (which can change between attempts), so the checkpoint
// must be confirmed against the real artifact or a retry would define a domain with no
// disk and loop.
func promoteDiskBuilt(diskBuiltStep, livePathExists bool) bool {
	return diskBuiltStep && livePathExists
}

func (s *Server) doPromoteLocal(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, src *corrosion.DiskRecord, pool, replica string, automated bool, send func(*pb.PromoteReplicaProgress) error) (retErr error) {
	if s.virt == nil {
		return status.Error(codes.FailedPrecondition, "no libvirt backend on this host")
	}
	// Split-brain gate (Phase 1), EXECUTE side: the replica host must itself have
	// local quorum to promote (a runtime-ownership action). A carried proof MARKER
	// forces the gate even if THIS host hasn't latched enforcement — an asymmetric
	// partition can deliver a valid proof to a target that locally lacks quorum, and
	// it must not promote. Fail-open only for a proofless promote before activation.
	if reason, refused := s.execGateForAction(ctx, req.Proof != nil); refused {
		s.noteGateRefused(corrosion.ActionPromote, reason)
		return status.Error(codes.FailedPrecondition, s.gateRefusal(ctx, "promote", reason, returnToServiceHint))
	}
	// Under active enforcement an AUTOMATED (coordinator/relayed) promote MUST carry a
	// proof — a proofless automated promote is refused. This keys off `automated`, NOT
	// `Force`: the operator override (`promote --force`) also sets Force but is a
	// separate RBAC-gated manual entry that the plan explicitly permits to run proofless
	// (it still passed execGateForAction above, so it holds local quorum). Keying the
	// refusal off Force silently broke the documented operator override under enforcement
	// (there's no manual fence-confirm replacement until Phase 5).
	if automated && req.Proof == nil && s.gateActive(ctx) {
		s.noteGateRefused(corrosion.ActionPromote, health.ReasonProofMissing)
		return status.Error(codes.FailedPrecondition, "auto-promote refused: proof required under enforcement")
	}
	// Split-brain hardening (Phase 1): validate + claim the single-use promote proof
	// before the destructive define+start. claimCarriedProof validates the
	// coordinator's assertions (action/target/dest==self), upserts the FULL carried
	// proof (no dependence on replication), and claims it single-holder — a
	// retried/duplicate promote re-claims idempotently while in_progress and is
	// REFUSED once terminal, so the VM can't be promoted twice.
	proofID, err := s.claimCarriedProof(ctx, req.Proof, corrosion.ActionPromote, "vm", vm.Name)
	if err != nil {
		return err
	}
	// Shared-disk split-brain gate: an automated cross-host TRANSFER (a coordinator
	// promote carries a proof; an operator override does not) of a VM with a writable
	// SHARED disk (nfs/ceph/rbd/iscsi) may start only once the OLD OWNER is PROVEN
	// powered off — a best-effort SSH "fence" never confirms that, and the shared disk
	// is writable from both hosts, so a double-run corrupts it. A local-disk transfer
	// (a replica is a different image) keeps the existing quorum/proof gate above. Fail
	// closed once enforced; kill-switch (enforcement.shared_storage_fence) restores legacy.
	if req.Proof != nil && s.sharedStorageFenceActive(ctx) {
		disks, derr := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if derr != nil {
			return status.Errorf(codes.Unavailable, "shared-disk fence check — list disks: %v", derr)
		}
		if corrosion.VMHasWritableSharedDisk(disks) {
			if err := s.requireProofGradeFence(ctx, req.Proof.GetFenceEpoch(), vm.HostName); err != nil {
				return err
			}
		}
	}
	// Durable step-resume: promote is a multi-step, partly-destructive sequence
	// (build disk → define → start → persist). We checkpoint each step in the
	// proof's step_state so a retry after a crash resumes PAST completed steps
	// instead of re-running them — critically, it must NOT destroy+rebuild a domain
	// this proof already started. `steps` is the checkpoint set from a prior attempt.
	var steps string
	if proofID != "" {
		if pr, ok, _ := corrosion.GetActionProof(ctx, s.db, proofID); ok {
			steps = pr.StepState
		}
		defer func() {
			// On success mark terminal (single-use); on error leave in_progress —
			// promote errors are largely retryable and the coordinator falls back to
			// reschedule, and a fresh attempt mints a new proof.
			if retErr == nil {
				if err := corrosion.CompleteActionProof(ctx, s.db, proofID, s.hostName); err != nil {
					slog.Warn("promote: complete proof", "vm", vm.Name, "proof", proofID, "error", err)
				}
			}
		}()
	}
	stepDone := func(step string) bool { return corrosion.ProofStepDone(steps, step) }
	recordStep := func(step string) {
		if proofID != "" {
			if err := corrosion.AppendProofStep(ctx, s.db, proofID, step); err != nil {
				slog.Warn("promote: record step", "vm", vm.Name, "step", step, "error", err)
			}
		}
	}
	// Defense in depth: the pool lives on this host, so re-check project ownership
	// locally — a relayed/peer-direct call must not promote from a foreign pool.
	if err := s.admitVMPoolUse(ctx, vm, s.hostName, pool); err != nil {
		return err
	}
	poolRef, ok := s.resolvePool(ctx, pool)
	if !ok {
		return status.Errorf(codes.FailedPrecondition, "pool %q not configured on host %q", pool, s.hostName)
	}
	if !isFileBasedDriver(poolRef.Driver) {
		return status.Errorf(codes.FailedPrecondition, "pool %q (%s) is not file-based", pool, poolRef.Driver)
	}
	poolDir, err := s.poolDirForWrite(ctx, pool, poolRef)
	if err != nil {
		return err
	}
	// The replica is looked up again HERE, among this VM's own records on this
	// host: a relayed or peer-direct request names a file, and a name is never
	// enough to read one. A replica in the VM's directory of the pool's replica
	// area is selected by its record there; one at the pool's top level,
	// written before replicas moved into that area, by its pool record or, an
	// unrecorded one, by its exact name (localReplicaNames) — the same lists
	// findReplicaHost chose from.
	replicaRec, replicaPath, ok := recordedReplica(poolDir, vm.Project, vm.Name, replica)
	if ok && replicaRec.Disk != src.DiskName {
		return status.Errorf(codes.NotFound, "replica %q is not a recorded replica of vm %q disk %q in pool %q on %q",
			replica, vm.Name, src.DiskName, pool, s.hostName)
	}
	if !ok {
		k := replicaKeyOf(vm, src.DiskName)
		// Only a replica the operator named (findReplicaHost) may be any file
		// an admin names; one chosen for the VM, or merely passed in, must be
		// the VM's own.
		admin := req.Replica != "" && req.Replica == replica && s.RequirePerm(ctx, "/", verbStorageHostPath, "admin") == nil
		if !slices.Contains(s.localReplicaNames(ctx, poolDir, k, "", false), replica) &&
			!slices.Contains(s.localReplicaNames(ctx, poolDir, k, replica, admin), replica) {
			return status.Errorf(codes.NotFound, "replica %q is not a replica of vm %q disk %q in pool %q on %q",
				replica, vm.Name, src.DiskName, pool, s.hostName)
		}
		replicaPath = s.namedReplicaPath(poolDir, replica)
		if err := replicaReadable(replicaPath); err != nil {
			return status.Errorf(codes.NotFound, "%s: %q on %q: %v", errReplicaUnavailable, replica, s.hostName, err)
		}
		// An admin's named file that another project owns alone is taken, as
		// on main — and said so, in the log and on the VM's events.
		if admin {
			if uploads, err := s.loadPoolUploads(ctx, s.poolContentDirs(poolDir)...); err == nil {
				if owner, ok := s.anotherProjectsOwner(ctx, uploads, replicaPath, k); ok {
					slog.Warn("promote: an admin named a replica another project owns", "vm", vm.Name, "replica", replica, "owner_project", owner)
					s.recordVMEvent(ctx, vm.Name, "replica.foreign", "warning", fmt.Sprintf(
						"promoting %s, named by an admin, which project %q owns, not this VM's project", replica, owner))
				}
			}
		}
		// A replica taken although its record had not arrived from its writer
		// (lateReplicaOK) is said so, by name, on the VM's events.
		if uploads, err := s.loadPoolUploads(ctx, filepath.Dir(replicaPath)); err == nil {
			if _, st := s.recordState(uploads, replicaPath); st == recNone && !s.isLegacyUnrecorded(ctx, replicaPath) {
				s.recordVMEvent(ctx, vm.Name, "replica.unrecorded", "warning", fmt.Sprintf(
					"promoting %s, whose record had not arrived from %s, the VM's host, before it stopped answering", replica, vm.HostName))
			}
		}
		// Its format is what replication wrote it as: an incremental replica
		// is raw, a full one qcow2. Never probed.
		replicaRec = replicaRecord{VM: vm.Name, Disk: src.DiskName, File: replica, Format: "qcow2"}
		if strings.HasSuffix(replica, ".raw") {
			replicaRec.Format = "raw"
		}
	}

	targetName := vm.Name
	renamed := false
	if req.NewName != "" && req.NewName != vm.Name {
		targetName = req.NewName
		renamed = true
	}
	if !validRestoreName(targetName) {
		return status.Errorf(codes.InvalidArgument, "invalid promotion name %q", targetName)
	}

	// Reconstruct the spec from the durable record BEFORE admission: the host
	// lease must cover the spec's complete CPU and memory, and a record that
	// cannot even be parsed should refuse before any disk or domain mutation.
	var spec pb.VMSpec
	if vm.Spec == "" {
		return status.Errorf(codes.FailedPrecondition, "vm %q record has no spec to define from", vm.Name)
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		return status.Errorf(codes.Internal, "parse vm spec: %v", err)
	}
	spec.Name = targetName

	// A RENAMED promotion writes a SECOND VM row from this spec, with fresh MACs
	// and no claim, while the original still holds its addresses — a guaranteed
	// duplicate on a NetBox-bound network. Refused before the define/start below.
	//
	// A TAKEOVER promotion (same name) is deliberately untouched: it re-homes the
	// existing row, keeping the uuid and the MACs, so the identity behind every
	// claim survives and no new address is needed. It is also the automated
	// failover path, and refusing that would leave a fenced host's VMs down on
	// exactly the networks an external IPAM manages.
	if renamed {
		if err := s.refuseIfBound(ctx, "promote --new-name", specNetworkNames(spec.Network)); err != nil {
			return err
		}
	}
	// Project isolation. A RENAMED promotion writes a second VM with new NIC rows
	// — a new attachment — so each network must be one the VM's project may use
	// (same project on both sides: a raw bridge is carried, a managed network
	// another project owns is refused). A TAKEOVER re-homes the existing VM and
	// its existing NICs; like the bound-network refusal above it must not block,
	// since refusing would leave a fenced host's VM down without removing the
	// attachment. It warns and audits instead. Keyed on renamed, not automated:
	// automated is lost through relayPromote, which re-enters as a manual call.
	var foreignNets []string // recorded only once the takeover has committed
	if renamed {
		if err := s.admitCopiedNetworks(ctx, "promote", vm.Project, vm.Project, specNetworkNames(spec.Network)); err != nil {
			return err
		}
	} else {
		foreignNets = s.foreignNetworks(ctx, "vm.promote", targetName, vm.Project, specNetworkNames(spec.Network))
	}

	// Adoption gate (fail-closed, no-op pre-latch): under the active hardware_v2 regime a
	// "blocked" VM (hardware failed its per-VM compatibility audit) must not be brought
	// back up. A takeover promote (same name) carries the original VM's adoption state, so
	// refuse it BEFORE the destructive define/start below rather than resurrect a VM the
	// operator must repair + re-audit first; a renamed promotion has no prior adoption row
	// (→ no-op). This is the gate half of PrepareHardwareForStart applied directly: the PCI
	// start-preflight half is deliberately NOT run on promote — promote materializes the
	// live disk then defines-then-persists the disk/vm rows AFTER StartDomain, so the
	// preflight's reconcile-from-authoritative-tables step would read not-yet-written rows;
	// and a disk replica does not carry the source host's physical passthrough devices.
	if err := s.hardwareAdoptionRefused(ctx, targetName); err != nil {
		return err
	}

	// Crash-idempotent resume: a domain RUNNING under targetName from a prior
	// attempt of THIS proof must never be torn down. We record "start_attempted"
	// durably BEFORE StartDomain, so if we crash after libvirt starts the VM but
	// before the "started" checkpoint, a retry still recognizes the running domain
	// as ours (artifact observation) and skips destroy/rebuild/restart → persist.
	// A RUNNING domain under targetName from a prior promotion attempt must never be
	// destroyed+rebuilt (that discards writes it accepted). Recognize it as ours via THIS
	// proof's start_attempted checkpoint (same-proof crash after libvirt-start) OR —
	// CROSS-proof, since each failover cycle mints a fresh proof and would otherwise see
	// empty step_state — via the host-local promote marker. Adopt it: skip destroy/rebuild/
	// define/start and fall through to persist the row.
	domExists := s.virt.DomainExists(targetName)
	domRunning := false
	if domExists {
		if st, serr := s.virt.DomainState(targetName); serr == nil && st == "running" {
			domRunning = true
		}
	}
	started := promoteDomainAlreadyStarted(stepDone("started"), stepDone("start_attempted"), s.promoteMarkerPresent(targetName), domExists, domRunning)

	// Split-brain guard. Taking over the original name while the original is
	// still on a healthy host (and not force) would double-run the VM.
	if !req.Force {
		if renamed {
			if rec, _ := corrosion.GetVM(ctx, s.db, targetName); rec != nil {
				return status.Errorf(codes.AlreadyExists, "vm %q already exists; choose another --new-name", targetName)
			}
		} else if vm.HostName != "" && vm.HostName != s.hostName {
			if h, _ := corrosion.GetHost(ctx, s.db, vm.HostName); h != nil && h.State == "active" {
				return status.Errorf(codes.FailedPrecondition,
					"vm %q still owned by healthy host %q; fence it or pass --force/--new-name to avoid split-brain", vm.Name, vm.HostName)
			}
		}
	}
	// Admission (fail-closed), BEFORE any disk build, domain destruction,
	// definition, or start. A promotion defines and starts a full-sized VM — the
	// same consumption a create of that VM would have — so it passes the same
	// local host admission every other residency path passes, against this
	// host's fresh inventory. Coordinator planning telemetry is advisory: even
	// when planning degraded during a read failure, this executing host refuses
	// an unsafe or over-capacity promotion using its own state.
	//
	// A crash-recovery retry adopting a running domain this host positively
	// identifies as its own prior promotion (checkpoint/marker + running) does
	// NOT reserve again — the runtime consumption already exists, and charging
	// it a second time would refuse exactly the recovery the marker exists to
	// protect. It still runs workload safety: an active ownership condition
	// refuses the adoption. A foreign same-name domain never gets the
	// exception (promoteDomainAlreadyStarted).
	var promoteQuotaLease *reservationLease
	if started {
		if err := s.checkHostSafety(ctx, s.hostName, corrosion.WorkloadVM, targetName, false, false); err != nil {
			return err
		}
	} else {
		// A same-name takeover of a VM the ledger already counts as RUNNING ON
		// THIS HOST (a same-host rebuild) re-homes consumption headroom already
		// accounts for; charging the full size again would refuse a legal
		// recovery. Every other fresh promotion is a full-sized VM appearing
		// here. The zero-delta admission still runs the residency safety gate.
		admitCPU, admitMem := int(spec.Cpu), int(spec.MemoryMib)
		if !renamed && vm.HostName == s.hostName && vm.State == "running" {
			admitCPU, admitMem = 0, 0
		}
		hostLease, aerr := s.admitHostWithReservation(ctx, "PromoteReplica", s.hostName, vm.Project, "vm:"+targetName, admitCPU, admitMem, intentVMResident)
		if aerr != nil {
			return aerr
		}
		defer hostLease.release(ctx)
		if renamed {
			// A renamed promotion writes a SECOND allocation alongside the
			// original — a new allocation the project does not yet carry — so
			// it also reserves project quota for the full absolute size and
			// target identity. The lease is held until persistence completes
			// and carries the authority commit fence checked before the insert.
			qLease, qerr := s.admitQuotaWithReservation(ctx, "PromoteReplica", s.hostName, vm.Project,
				corrosion.WorkloadVM, targetName,
				corrosion.QuotaAmount{VCPU: int(spec.Cpu), MemMiB: int(spec.MemoryMib)},
				corrosion.QuotaAmount{VCPU: int(spec.Cpu), MemMiB: int(spec.MemoryMib)}, intentVMResident)
			if qerr != nil {
				return qerr
			}
			defer qLease.release(ctx)
			promoteQuotaLease = qLease
		}
	}

	if s.virt.DomainExists(targetName) && !started {
		// (If this proof already reached "started", the existing domain is OUR OWN
		// prior promotion — never destroy it on resume; fall through to persist.)
		if !req.Force {
			return status.Errorf(codes.AlreadyExists, "domain %q already defined on %q; pass --force or --new-name", targetName, s.hostName)
		}
		// Force takeover: the domain may be actively running on THIS host
		// (same-host promote). Stop it first — UndefineDomain alone only drops
		// the persistent config, leaving the live domain to collide on UUID at
		// DefineDomain. (In a real failover the VM ran on the fenced host, so
		// the promotion host has no such domain and this is a no-op.)
		_ = s.virt.DestroyDomain(targetName)
		_ = s.virt.UndefineDomain(targetName, false)
	}

	// Build the live disk from the replica.
	ts := strings.TrimSuffix(strings.TrimSuffix(replica, ".qcow2"), ".raw")
	livePath := filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s.qcow2", targetName, ts))
	// Honor the disk_built checkpoint only if the artifact actually EXISTS at livePath:
	// step_state is forward-only, but every error path after the build does
	// os.Remove(livePath), so a same-proof retry would otherwise see disk_built, skip the
	// rebuild, define a domain whose disk is gone, fail StartDomain, remove again, and
	// loop forever. livePath also embeds the replica timestamp, so if the chosen replica
	// changed between attempts the recorded step doesn't correspond to this path either.
	// Verify the file before trusting the checkpoint (artifact observation).
	_, livePathStatErr := os.Stat(livePath)
	diskBuilt := promoteDiskBuilt(stepDone("disk_built"), livePathStatErr == nil)
	// Skip the (re)build if a prior attempt already built the live disk (and definitely if
	// it already STARTED the domain off it — rebuilding would overwrite a running VM's disk).
	if !diskBuilt && !started {
		// A file already at livePath that this proof did not build is not ours:
		// targetName is the caller's choice, so in a shared pool the name can be
		// another VM's disk. Refused before anything is written, and so before
		// any of the error paths below that remove livePath.
		if err := refuseExistingFile(livePath); err != nil {
			return err
		}
		if req.NoLocalize {
			backingFmt := replicaRec.Format
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
				Status: "creating overlay backed by replica (fast; pins the replica)",
			})
			if err := createOverlayNoClobber(livePath, replicaPath, backingFmt); err != nil {
				return err
			}
		} else if !qemuImgAvailable() && strings.HasSuffix(replica, ".raw") {
			// Localize would convert raw→qcow2, but without qemu-img convertQcow2
			// falls back to a verbatim byte copy — landing raw bytes in a
			// qcow2-declared file → an unbootable/corrupt promoted VM (bug-sweep #9).
			// Degrade to a correct qcow2 overlay backed by the raw replica
			// (backingFmt=raw), like the NoLocalize path; it pins the replica but
			// boots correctly. Full localization needs qemu-img on the host.
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
				Status: "qemu-img unavailable — overlay over raw replica (pins replica; install qemu-img to localize)",
			})
			if err := createOverlayNoClobber(livePath, replicaPath, "raw"); err != nil {
				return err
			}
			slog.Warn("promote: localized via raw-backed overlay (qemu-img absent) — replica is pinned",
				"vm", targetName, "replica", replica)
		} else {
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
				Status: "copying replica into a self-contained live disk",
			})
			emit := func(p *pb.MoveVolumeProgress) error {
				return send(&pb.PromoteReplicaProgress{
					Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName, Replica: replica,
					Status: fmt.Sprintf("copying replica… %.0f%%", p.CopyPct),
				})
			}
			// Copy into a .promote-*.tmp then atomically rename, so a crash
			// mid-copy leaves a sweepable temp (SweepStaleStaging) rather than an
			// orphan live disk — the qemu-img child survives KillMode=process and
			// would otherwise complete a final-named qcow2 with no domain.
			// A fresh, unpredictable temp (O_EXCL): qemu-img convert follows a
			// symlink at its output, so the name must not be one anything
			// else could have planted.
			tf, terr := os.CreateTemp(poolDir, ".promote-*.tmp")
			if terr != nil {
				return status.Errorf(codes.Internal, "create live-disk temp: %v", terr)
			}
			tmpLive := tf.Name()
			_ = tf.Close()
			// The replica's format comes from its record, never a probe: an
			// incremental replica is raw GUEST content, and a probe would
			// obey a qcow2 header the guest wrote into it. A qcow2 replica
			// must be standalone (nil: no backing at all). convertImage
			// pre-checks the input and requires a standalone output.
			if err := convertImage(ctx, replicaPath, replicaRec.Format, nil, tmpLive, emit); err != nil {
				os.Remove(tmpLive)
				return status.Errorf(codes.Internal, "copy replica: %v", err)
			}
			if err := placeNoClobber(tmpLive, livePath); err != nil {
				os.Remove(tmpLive)
				return err
			}
		}
		recordStep("disk_built")
	}

	multiDiskNote := ""
	if len(spec.Disks) > 1 {
		multiDiskNote = fmt.Sprintf(" (only root disk promoted; %d data disk(s) not recovered)", len(spec.Disks)-1)
	}

	// Rebuild the promoted disk's bus/controller from the stored spec (not
	// hardcoded virtio) so an imported scsi/sata guest boots after promotion
	// instead of stalling on a missing controller (G1 cross-cutting fix).
	promBus, promCtrl := "virtio", ""
	for _, ds := range spec.Disks {
		if ds.Name == src.DiskName {
			if ds.Bus != "" {
				promBus = ds.Bus
			}
			promCtrl = ds.ControllerModel
			break
		}
	}
	diskCfg := []lv.DiskConfig{{Name: src.DiskName, Path: livePath, Bus: promBus, ControllerModel: promCtrl}}
	diskRecords := []corrosion.DiskRecord{{
		VMName: targetName, DiskName: src.DiskName, HostName: s.hostName,
		Path: livePath, SizeBytes: src.SizeBytes, StorageType: poolRef.Driver,
		StorageVolume: pool, TargetDev: lv.DiskDevName(promBus, 0), Bus: promBus,
		BackingDisk: liveDiskBacking(livePath, replicaPath),
	}}

	var netCfg []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	var nicRecords []corrosion.NICRecord // v42 dual-write alongside ifaceRecords (vm_nics); only persisted on the renamed (new-row) path below
	for i, n := range spec.Network {
		mac := n.Mac
		if renamed || mac == "" {
			mac = lv.GenerateMAC()
		}
		bridge := n.Name
		if err := s.ensureBridge(bridge); err != nil {
			os.Remove(livePath)
			return status.Errorf(codes.FailedPrecondition, "network bridge %q unavailable on %q: %v", bridge, s.hostName, err)
		}
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac})
		// The groups go on the legacy row as well as the vm_nics one: a peer on
		// an older build renders this NIC's chain from vm_interfaces alone.
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: targetName, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: n.Ip,
			SecurityGroups: n.SecurityGroups,
		})
		nicRecords = append(nicRecords, corrosion.NICRecord{
			VMName:         targetName,
			ID:             corrosion.DeterministicNICID(targetName, mac),
			NetworkName:    n.Name,
			Model:          n.Model,
			MAC:            mac,
			Ordinal:        i,
			IP:             n.Ip,
			TapDevice:      "",
			SecurityGroups: encodeSecurityGroups(n.SecurityGroups),
		})
	}

	// Define + start — skipped on a resume where the domain was already started by
	// this proof (guarded above at the destroy step); persist below is idempotent.
	if !started {
		domXML, err := lv.GenerateDomainXML(lv.VMConfig{
			Name: targetName, CPU: int(spec.Cpu), CPUMode: spec.CpuMode, CPUModel: spec.CpuModel,
			MemoryMiB: int(spec.MemoryMib), Machine: spec.Machine, Firmware: spec.Firmware,
			GuestAgent: spec.GuestAgent, EnableVNC: !spec.DisableVnc, EnableSPICE: spec.EnableSpice,
			Disks: diskCfg, Networks: netCfg, Boot: spec.Boot,
		})
		if err != nil {
			os.Remove(livePath)
			return status.Errorf(codes.Internal, "generate domain XML: %v", err)
		}

		_ = send(&pb.PromoteReplicaProgress{
			Phase: pb.PromoteReplicaProgress_DEFINING, VmName: targetName, Host: s.hostName,
			Replica: replica, DiskPath: livePath, Status: "defining domain" + multiDiskNote,
		})
		if err := s.virt.DefineDomain(domXML); err != nil {
			os.Remove(livePath)
			return status.Errorf(codes.Internal, "define domain: %v", err)
		}
		s.ensureSparePCIeRootPorts(targetName)
		// Durable checkpoints BEFORE the start, so a crash between StartDomain and the
		// "started" checkpoint still lets a retry recognize the running domain as ours
		// (via the running-domain observation above) instead of destroying it. The
		// proof-keyed step covers a SAME-proof retry; the host-local promote marker covers
		// a CROSS-proof retry (each failover cycle mints a fresh proof). Written before the
		// start (fail closed on a marker error — nothing is running yet).
		// The start checkpoint doubles as the abandonment fence
		// (docs/design/recovery-claims.md §3.12): a destination abandons only a
		// proof that never started, so the checkpoint is appended only if this
		// host has not abandoned the proof — decided in one transaction, which
		// is what makes "abandon only what never ran" exact.
		if proofID != "" {
			if err := corrosion.AppendProofStepUnlessAbandoned(ctx, s.db, proofID, "start_attempted"); err != nil {
				os.Remove(livePath)
				_ = s.virt.UndefineDomain(targetName, false)
				if errors.Is(err, corrosion.ErrProofAbandoned) {
					s.noteGateRefused(corrosion.ActionPromote, health.ReasonClaimLost)
					return status.Errorf(codes.FailedPrecondition,
						"promote of %s refused: this host abandoned proof %s and will never execute it", vm.Name, proofID)
				}
				return status.Errorf(codes.Unavailable, "record the start checkpoint of proof %s: %v", proofID, err)
			}
		}
		if err := s.writePromoteMarker(targetName, proofID); err != nil {
			os.Remove(livePath)
			return status.Errorf(codes.Internal, "record promote marker: %v", err)
		}
		if err := s.virt.StartDomain(targetName); err != nil {
			_ = s.virt.UndefineDomain(targetName, false) // wipe by design: half-built promote
			os.Remove(livePath)
			// Don't leak the marker: we tore the half-built domain down, so a later --force
			// retry must not treat a same-name stranger as our adopted prior promotion.
			s.removePromoteMarker(targetName)
			return status.Errorf(codes.Internal, "start domain: %v", err)
		}
		recordStep("started") // checkpoint: never destroy/rebuild this domain on a retry
		_ = send(&pb.PromoteReplicaProgress{
			Phase: pb.PromoteReplicaProgress_STARTED, VmName: targetName, Host: s.hostName,
			Replica: replica, DiskPath: livePath, Status: "VM started off the promoted replica",
		})
	}

	// Persist. Takeover (same name) re-homes the existing record; a renamed
	// promotion writes a fresh VM alongside the original.
	// Same as create/import: the define above resolved any alias on THIS host,
	// so persist the concrete type rather than letting the promoted VM carry an
	// alias that a later move would re-resolve elsewhere.
	s.pinMachineFromDomain(&spec)
	specJSON, _ := json.Marshal(&spec)
	if renamed {
		// The quota-authority commit fence, immediately BEFORE the durable
		// write — the narrower the gap, the smaller the window in which
		// authority can move. If it refuses after the domain was started,
		// unwind everything THIS attempt created — the just-started domain,
		// the newly materialized live disk, the promote marker — and return
		// the fence error. The original durable VM is untouched, and nothing
		// was persisted. (An adopted retry holds no quota lease; the nil
		// lease's fence allows, matching the no-second-reservation rule.)
		if err := promoteQuotaLease.allowCommit(ctx); err != nil {
			_ = s.virt.DestroyDomain(targetName)
			_ = s.virt.UndefineDomain(targetName, false)
			os.Remove(livePath)
			s.removePromoteMarker(targetName)
			return err
		}
		// Inserted "creating": assignOwnerEpochAtCreate publishes it running
		// only once it holds a positive epoch and a marker names it.
		rec := corrosion.VMRecord{
			Name: targetName, HostName: s.hostName, Spec: string(specJSON),
			State: "creating", CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib),
			Project: vm.Project,
		}
		// adopt=false: a promotion best-effort-populates vm_nics from its rebuilt
		// network attachments, but does not self-certify adoption — there is no
		// PCI passthrough to carry (a disk replica has no hostdev record, so
		// pciIntents is always nil here), and hardware_adoption_state stays at
		// its schema default 'pending' for the Phase-6 backfill audit to confirm.
		if err := corrosion.InsertVMWithHardware(ctx, s.db, rec, ifaceRecords, diskRecords, nicRecords, nil, false); err != nil {
			return status.Errorf(codes.Internal, "persist promoted vm: %v", err)
		}
		// This branch and the transfer below are mutually EXCLUSIVE: a renamed
		// promotion inserts a fresh row and no transfer ever follows it, so
		// nothing here mints a generation; this assigns the first one, marks it,
		// and publishes the row running.
		s.assignOwnerEpochAtCreate(ctx, targetName, true)
	} else {
		// Phase 4: promotion commit is an ownership transition (fresh-read CAS + increment).
		if err := s.publishRunningMinted(ctx, targetName, func(ctx context.Context) error {
			return corrosion.TransferVMOwnerFresh(ctx, s.db, targetName, s.hostName, "running")
		}); err != nil {
			return status.Errorf(codes.Internal, "re-home vm record: %v", err)
		}
		if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, targetName, src.DiskName, s.hostName, livePath); err != nil {
			return status.Errorf(codes.Internal, "update disk record: %v", err)
		}
		_ = corrosion.UpdateDiskStorage(ctx, s.db, targetName, src.DiskName, poolRef.Driver, pool)
	}
	// Row persisted (the durable record now exists) → drop the host-local promote marker;
	// a future retry would see the re-homed row and not re-promote.
	s.removePromoteMarker(targetName)

	s.recordVMEvent(ctx, targetName, "vm.promoted", "ok",
		fmt.Sprintf("from replica %s on %s%s", replica, s.hostName, multiDiskNote))
	s.audit(ctx, "replica.promote", targetName, "replica="+replica+" host="+s.hostName, "ok")
	s.recordForeignNetworks(ctx, "vm.promote", targetName, foreignNets)
	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_DONE, VmName: targetName, Host: s.hostName,
		Replica: replica, DiskPath: livePath, Status: "promotion complete" + multiDiskNote,
	})
	return nil
}

// autoPromoteAgeLimit is the bound for a VM replicated on schedule cron: two of
// the schedule's longest intervals, plus an hour for the copy itself. One
// missed run is tolerated, two are not.
//
// The fixed 48 hours refused every weekly schedule's newest replica for most of
// each week — automatic recovery silently off for a schedule working exactly
// as configured — while letting an hourly one promote a replica two days
// behind. An unreadable or never-firing schedule keeps the fixed bound.
func autoPromoteAgeLimit(cron string) time.Duration {
	gap, ok := longestCronGap(cron)
	if !ok {
		return autoPromoteMaxReplicaAge
	}
	return 2*gap + time.Hour
}

// longestCronGap is the longest wait between consecutive runs of cron, found by
// walking every minute of a fixed 93-day window — long enough for a monthly
// schedule to fire more than once, and fixed so the answer does not depend on
// when it is asked. The longest gap, not the typical one: a weekday schedule's
// replica is legitimately three days old on a Monday morning.
func longestCronGap(expr string) (time.Duration, bool) {
	c, err := scheduler.ParseCron(expr)
	if err != nil {
		return 0, false
	}
	start := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC) // a Monday
	var prev time.Time
	var longest time.Duration
	for t := start; t.Before(start.AddDate(0, 0, 93)); t = t.Add(time.Minute) {
		if !c.Matches(t) {
			continue
		}
		if !prev.IsZero() && t.Sub(prev) > longest {
			longest = t.Sub(prev)
		}
		prev = t
	}
	return longest, longest > 0
}

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

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/storage"
)

// PromoteReplica brings an inert replica online for disaster recovery: it
// locates the chosen (or newest) replica of a VM's root disk, ensures it runs
// on the host that physically holds the replica file, builds a self-contained
// live disk from it and from the replica of each other disk of the same set
// (replica_set.go), then defines + starts the VM there and persists the
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

	// A replica recorded as not point-in-time (pit_copy.go, layer 3) is the
	// last choice. Automatic promotion never uses one while a point-in-time
	// replica exists, and uses one at all only for a VM that opted in
	// (LabelAutoPromoteNotPointInTime); otherwise it holds the VM down and
	// says how to promote it by hand. A manual promotion of one needs
	// accept_not_point_in_time.
	acceptNotPIT := req.AcceptNotPointInTime
	promotedNotPIT := false
	host, replicas, notPIT, err := s.findReplicaHostPIT(ctx, req, vm, src.DiskName, pool, schedHost, automated)
	if automated && status.Code(err) == codes.NotFound {
		h, reps, marks, aerr := s.findReplicaHostPIT(ctx, req, vm, src.DiskName, pool, schedHost, false)
		if aerr == nil && len(reps) > 0 && marks[reps[0]] {
			if !vmAllowsAutoPromoteNotPIT(vm) {
				return s.holdNotPointInTime(ctx, vm, pool, h, reps[0])
			}
			host, replicas, notPIT, err = h, reps, marks, nil
			acceptNotPIT, promotedNotPIT = true, true
		}
	}
	if err != nil {
		return err
	}
	replica := replicas[0]
	if notPIT[replica] && !acceptNotPIT {
		if req.Proof != nil {
			// An automated promotion relayed here (a main-build coordinator
			// during a rolling upgrade knows nothing of the mark): held, as
			// loudly as this build's own coordinator holds it.
			return status.Errorf(codes.FailedPrecondition, "%v", s.holdNotPointInTime(ctx, vm, pool, host, replica))
		}
		return status.Errorf(codes.FailedPrecondition,
			"replica %s of vm %q (pool %s on %s) is NOT point-in-time: it was copied with qemu-img convert -U while the VM ran, after every point-in-time copy failed, and may be inconsistent. Promote it only if nothing better exists, with --accept-not-point-in-time (a CLI older than this daemon lacks the flag: upgrade it)",
			replica, req.VmName, pool, host)
	}
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
	// A replica held on a witness. A witness runs no workloads, so the VM cannot
	// be started there: an OPERATOR's promote still takes the VM over, as the
	// only copy may be there, but leaves it defined and stopped
	// (witnessPromote) for `lv migrate <vm> <worker> --cold`. The failover
	// coordinator never does: a promote that does not start the VM recovers
	// nothing, and a silent stranded copy is worse than a loud hold.
	if hr, herr := corrosion.GetHost(ctx, s.db, host); herr == nil && hr != nil && hr.IsWitness() {
		if automated || req.Automated {
			held := s.holdReplicaOnWitness(ctx, vm, pool, host, replica)
			if automated {
				return held // unwrapped: the coordinator matches ErrPromoteHeld
			}
			return status.Errorf(codes.FailedPrecondition, "%v", held)
		}
		if req.NewName != "" && req.NewName != vm.Name {
			return status.Errorf(codes.FailedPrecondition,
				"vm %q's replica is on host %q, a witness (role: %s) that runs no workloads: it can only be promoted there under the VM's own name (no --new-name), which takes over the VM and is for a VM whose host is down; it is left stopped, and then moved to a worker with `lv migrate %s <worker-host> --cold`",
				req.VmName, host, hr.Role, req.VmName)
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
			// The newest point-in-time replica is too old. If a newer one
			// exists that is not point-in-time, say why nothing is promoted:
			// it is held, not merely stale.
			if h, reps, marks, aerr := s.findReplicaHostPIT(ctx, req, vm, src.DiskName, pool, schedHost, false); aerr == nil && len(reps) > 0 && marks[reps[0]] && !acceptNotPIT {
				return fmt.Errorf("%w; and %w", err, s.holdNotPointInTime(ctx, vm, pool, h, reps[0]))
			}
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
			if notPIT[replica] && !acceptNotPIT {
				return fmt.Errorf("%w (the next-older replica %s is not point-in-time; promote it with --accept-not-point-in-time)", lastErr, replica)
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
				Proof:                req.Proof, // carry the full single-use proof to the executor
				AcceptNotPointInTime: acceptNotPIT,
				Automated:            automated || req.Automated,
			}
			err = s.relayPromote(ctx, host, fwd, send)
		} else {
			err = s.doPromoteLocal(ctx, req, vm, src, pool, replica, automated, send)
		}
		if err == nil && promotedNotPIT {
			s.reportPromotedNotPointInTime(ctx, vm, pool, host, replica)
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
	host, replicas, _, err = s.findReplicaHostPIT(ctx, req, vm, diskName, pool, schedHost, false)
	return host, replicas, err
}

// findReplicaHostPIT is findReplicaHost that also returns which of the
// chosen host's replicas are not point-in-time, and with skipNotPIT leaves
// those out of the choice altogether. A replica is not point-in-time when its
// record says so, or — a top-level copy main's runner name gives it
// (replica_mirror.go) — when a record of that disk taken at the same time on
// that host says so: the mirror is the same bytes under another name.
func (s *Server) findReplicaHostPIT(ctx context.Context, req *pb.PromoteReplicaRequest, vm *corrosion.VMRecord, diskName, pool, schedHost string, skipNotPIT bool) (host string, replicas []string, notPIT map[string]bool, err error) {
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
	admin := req.Replica != "" && s.namedReplicaAdmin(ctx)
	byHost := map[string][]string{}
	marksByHost := map[string]map[string]bool{}
	bestHost, bestName := "", ""
	for _, h := range candidates {
		var names []string
		marks := map[string]bool{}
		markedTaken := map[string]bool{}
		recs := s.replicaRecordsOn(ctx, pool, h, vm.Project, vm.Name)
		for _, r := range recs {
			if r.Disk == diskName && r.NotPointInTime {
				marks[r.File], markedTaken[r.Taken] = true, true
			}
		}
		for _, r := range recs {
			if r.Disk != diskName {
				continue
			}
			if req.Replica != "" && r.File == req.Replica {
				return h, []string{r.File}, marks, nil
			}
			names = append(names, r.File)
		}
		top := s.replicaNames(ctx, pool, h, k, req.Replica, admin)
		for _, n := range top {
			if ts, ok := replicaTimestamp(n); ok && markedTaken[ts.UTC().Format("20060102-150405")] {
				marks[n] = true
			}
			// A copy lv replicate-volume made with -U, promoted by name.
			// Its record is read on the host that holds it, which is
			// where a relayed promotion is decided.
			if (h == "" || h == s.hostName) && s.poolCopyNotPIT(ctx, pool, n) {
				marks[n] = true
			}
		}
		if req.Replica != "" {
			if slices.Contains(top, req.Replica) {
				return h, []string{req.Replica}, marks, nil
			}
			continue
		}
		names = append(names, top...)
		if skipNotPIT {
			names = slices.DeleteFunc(names, func(n string) bool { return marks[n] })
		}
		sortReplicasOldestFirst(names)
		byHost[h] = names
		marksByHost[h] = marks
		// Each host's list is oldest first, by the run time in the names.
		if len(names) > 0 && (bestName == "" || replicaOlder(bestName, names[len(names)-1])) {
			bestName, bestHost = names[len(names)-1], h
		}
	}
	if req.Replica != "" {
		return "", nil, nil, status.Errorf(codes.NotFound, "replica %q of vm %q disk %q not found in pool %q", req.Replica, req.VmName, diskName, pool)
	}
	if bestHost == "" {
		what := "replica"
		if skipNotPIT {
			what = "point-in-time replica"
		}
		return "", nil, nil, status.Errorf(codes.NotFound, "no %s of %q disk %q found in pool %q", what, req.VmName, diskName, pool)
	}
	newestFirst := slices.Clone(byHost[bestHost])
	slices.Reverse(newestFirst)
	return bestHost, newestFirst, marksByHost[bestHost], nil
}

// errReplicaNotPointInTime marks an automatic promotion held because the
// VM's only replicas are not point-in-time and the VM has not opted in.
var errReplicaNotPointInTime = fmt.Errorf("the only replica is not point-in-time; %w", corrosion.ErrPromoteHeld)

// vmEventFailoverHeld is the event a held automatic promotion records;
// InspectVM shows the newest one as failover_held while the VM's host is down.
const vmEventFailoverHeld = "vm.failover.held"

// vmAllowsAutoPromoteNotPIT reports whether vm opted in, with
// corrosion.LabelAutoPromoteNotPointInTime=true in its spec's labels, to
// automatic promotion of a not-point-in-time replica when no point-in-time
// one exists. A build that does not know the label ignores it, which is the
// default: off.
func vmAllowsAutoPromoteNotPIT(vm *corrosion.VMRecord) bool {
	var spec struct {
		Labels map[string]string `json:"labels"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.Labels[corrosion.LabelAutoPromoteNotPointInTime] == "true"
}

// holdReplicaOnWitness refuses an automatic promotion whose replica is held by
// a witness, loudly and without touching anything: an event (which InspectVM
// shows), a notification, and the steps that recover the VM by hand. It wraps
// corrosion.ErrPromoteHeld, so the coordinator holds the VM down (and audits
// the skip) instead of rescheduling it onto a host that does not have its disk.
func (s *Server) holdReplicaOnWitness(ctx context.Context, vm *corrosion.VMRecord, pool, host, replica string) error {
	worker := s.exampleWorker(ctx, host)
	cmd := fmt.Sprintf("lv replication promote %s --pool %s --host %s --replica %s", vm.Name, pool, host, replica)
	detail := fmt.Sprintf("automatic promotion held: the replica (%s in pool %s) is on %s, a witness that runs no workloads, so the VM cannot be started there. The VM stays down and the replica is untouched. %s (it is left defined and stopped on %s); then `lv migrate %s %s --cold` and `lv start %s`",
		replica, pool, host, s.promoteByHandSteps(ctx, vm, cmd), host, vm.Name, worker, vm.Name)
	slog.Error("failover: automatic promotion held; the replica is on a witness", "vm", vm.Name, "replica", replica, "host", host)
	s.recordVMEventSeverity(ctx, vm.Name, vmEventFailoverHeld, "error", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.promote_held", Severity: notify.SevError, Subject: vm.Name, Detail: detail,
	})
	return fmt.Errorf("%w: %s", errReplicaOnWitness, detail)
}

// errReplicaOnWitness marks an automatic promotion held because its replica is
// on a witness.
var errReplicaOnWitness = corrosion.ErrReplicaOnWitness

// exampleWorker is the name of an active worker host other than skip, for the
// command an operator is told to run; a placeholder when none can be read.
func (s *Server) exampleWorker(ctx context.Context, skip string) string {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err == nil {
		for _, h := range hosts {
			if h.Name != skip && !h.IsWitness() && h.State == "active" {
				return h.Name
			}
		}
	}
	return "<worker-host>"
}

// holdNotPointInTime refuses an automatic promotion whose only replica is
// not point-in-time, loudly: an event (which InspectVM shows), a
// notification, and the commands that promote it by hand, which work as
// printed (promoteByHandSteps). The replica is not touched, and the VM's
// record is not changed.
func (s *Server) holdNotPointInTime(ctx context.Context, vm *corrosion.VMRecord, pool, host, replica string) error {
	cmd := fmt.Sprintf("lv replication promote %s --pool %s --host %s --replica %s --accept-not-point-in-time", vm.Name, pool, host, replica)
	detail := fmt.Sprintf("automatic promotion held: the only replica is not point-in-time (%s in pool %s on %s, copied with qemu-img convert -U after every point-in-time copy failed). The VM stays down and the replica is untouched. %s. To let failover do so for this VM, set the label %s=true",
		replica, pool, host, s.promoteByHandSteps(ctx, vm, cmd), corrosion.LabelAutoPromoteNotPointInTime)
	slog.Error("failover: automatic promotion held; the only replica is not point-in-time", "vm", vm.Name, "replica", replica, "pool", pool, "host", host)
	s.recordVMEventSeverity(ctx, vm.Name, vmEventFailoverHeld, "error", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.promote_held", Severity: notify.SevError, Subject: vm.Name, Detail: detail,
	})
	return fmt.Errorf("%w: %s", errReplicaNotPointInTime, detail)
}

// promoteByHandSteps is the instruction to promote vm by hand with cmd, a
// same-name `lv replication promote` without --force: the split-brain guard
// (promoteSplitBrainRefusal) lets it through only once vm's host is proven
// off, so when it is not, the instruction names `lv host fence-confirm`
// first. One whose proof cannot be read now names it too: a confirmation of
// a host already proven off records nothing new.
func (s *Server) promoteByHandSteps(ctx context.Context, vm *corrosion.VMRecord, cmd string) string {
	owner := vm.HostName
	if owner == "" || owner == s.hostName {
		return "To promote it anyway: " + cmd
	}
	h, provedOff, err := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, owner)
	if err == nil {
		if ok, _ := corrosion.SharedDiskOwnerVerdict(owner, h, provedOff, nil); ok {
			return "To promote it anyway: " + cmd
		}
	}
	why := "whether it is proven off cannot be read"
	if err == nil {
		why = promoteOwnerNotProvenOff(owner, h)
	}
	return fmt.Sprintf("To promote it anyway, once %s is powered off (%s): lv host fence-confirm %s, then %s",
		owner, why, owner, cmd)
}

// reportPromotedNotPointInTime is the event and notification of an automatic
// promotion that used a not-point-in-time replica (the VM opted in).
func (s *Server) reportPromotedNotPointInTime(ctx context.Context, vm *corrosion.VMRecord, pool, host, replica string) {
	detail := fmt.Sprintf("automatic promotion used a NOT point-in-time replica (%s in pool %s on %s): no point-in-time replica existed and the VM has %s=true. The guest may find its disk inconsistent",
		replica, pool, host, corrosion.LabelAutoPromoteNotPointInTime)
	slog.Error("failover: promoted a not-point-in-time replica", "vm", vm.Name, "replica", replica)
	s.recordVMEventSeverity(ctx, vm.Name, "vm.promoted_not_point_in_time", "warning", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.promoted_not_point_in_time", Severity: notify.SevError, Subject: vm.Name, Detail: detail,
	})
}

// failoverHeldReason is the newest held-promotion event's detail while vm's
// host is down and nothing has promoted it since; "" otherwise.
func (s *Server) failoverHeldReason(ctx context.Context, vm *corrosion.VMRecord) string {
	if h, err := corrosion.GetHost(ctx, s.db, vm.HostName); err == nil && h != nil && h.State == "active" {
		return ""
	}
	evs, err := corrosion.ListVMEvents(ctx, s.db, vm.Name, 100, "")
	if err != nil {
		return ""
	}
	for _, e := range evs { // newest first
		switch e.Type {
		case vmEventFailoverHeld:
			return e.Detail
		case "vm.promoted", "vm.promoted_not_point_in_time":
			return ""
		}
	}
	return ""
}

// namedReplicaAdmin reports whether the operator who named a replica may name
// any file: storage.hostpath at the cluster root. A promotion relayed from the
// entry node arrives under that node's host certificate, which authenticates
// as admin; the operator is the bearer it relays (pki.FwdBearerMDKey),
// resolved here, never the relaying certificate. With forwarded identity
// enforced the context is already the operator's. A relayed call with no
// bearer is the daemon's own or an admin's bearerless certificate, as for
// pool content (poolContentCallerOf). A bearer that does not authenticate
// here is no admin.
func (s *Server) namedReplicaAdmin(ctx context.Context) bool {
	if s.requirePeerCert(ctx) == nil && callerAuthMethod(ctx) == authMethodMTLS {
		if fwd := fwdBearerFromCtx(ctx); fwd != "" {
			uctx, err := s.awaitForwardedBearer(ctx, fwd)
			if err != nil {
				return false
			}
			ctx = uctx
		}
	}
	return s.RequirePerm(ctx, "/", verbStorageHostPath, "admin") == nil
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
	// The promote defines (and may first destroy and undefine) a domain of
	// the VM's name here: not one a live firmware move's record names
	// (spec §6.9). Refused before any proof is claimed.
	if err := s.firmwareMoveRefusal("promote", vm); err != nil {
		return err
	}
	// Split-brain gate (Phase 1), EXECUTE side: the replica host must itself have
	// local quorum to promote (a runtime-ownership action). A carried proof MARKER
	// forces the gate even if THIS host hasn't latched enforcement — an asymmetric
	// partition can deliver a valid proof to a target that locally lacks quorum, and
	// it must not promote. Fail-open only for a proofless promote before activation.
	// A witness takes an operator's promote as a takeover that starts nothing
	// (witnessPromote): the gate it answers is the one for a host holding a
	// workload without running it - quorum and fence, not the worker role.
	witnessPromote := false
	if self, herr := corrosion.GetHost(ctx, s.db, s.hostName); herr == nil && self != nil && self.IsWitness() {
		if automated || req.Automated || req.Proof != nil {
			return status.Errorf(codes.FailedPrecondition,
				"promote refused: host %q is a witness and runs no workloads; an automatic promotion is never executed here", s.hostName)
		}
		// Active only: a promote lands a VM, which a witness being drained or
		// in maintenance is not taking on.
		if self.State != "active" {
			return status.Errorf(codes.FailedPrecondition,
				"promote refused: witness %q is %s, not active, and takes on no VM: %s",
				s.hostName, self.State, returnToServiceHint(s.hostName, self.State))
		}
		witnessPromote = true
	}
	var gateReason string
	var gateRefused bool
	if witnessPromote {
		gateReason, gateRefused = s.drainGateRefused(ctx)
	} else {
		gateReason, gateRefused = s.execGateForAction(ctx, req.Proof != nil)
	}
	if gateRefused {
		s.noteGateRefused(corrosion.ActionPromote, gateReason)
		return status.Error(codes.FailedPrecondition, s.gateRefusal(ctx, "promote", gateReason, returnToServiceHint))
	}
	if witnessPromote && req.NewName != "" && req.NewName != vm.Name {
		return status.Errorf(codes.FailedPrecondition,
			"promote of %s refused: host %q is a witness; it is promoted there only under its own name, which takes over the VM and is for a VM whose host is down", vm.Name, s.hostName)
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
	//
	// "Shared" is the one definition the promotion's reattach uses too
	// (vmHasSharedDisk: storage type or pool driver). fenceProven records that
	// this executor itself verified a proof-grade fence of the old owner for
	// this promotion — the only thing that lets an automated promotion
	// reattach a shared data disk as-is (sharedReattachVerdict).
	fenceProven := false
	if req.Proof != nil && s.sharedStorageFenceActive(ctx) {
		disks, derr := corrosion.GetVMDisks(ctx, s.db, vm.Name)
		if derr != nil {
			return status.Errorf(codes.Unavailable, "shared-disk fence check — list disks: %v", derr)
		}
		if s.vmHasSharedDisk(ctx, disks) {
			if err := s.requireProofGradeFence(ctx, req.Proof.GetFenceEpoch(), vm.HostName); err != nil {
				return err
			}
			fenceProven = true
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
		admin := req.Replica != "" && req.Replica == replica && s.namedReplicaAdmin(ctx)
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
	// A promotion to a new name makes a VM of that name here: no create of
	// the name runs on this host while it does (beginCreate).
	setFlightUUID := func(string) {}
	if renamed {
		endFlight, set, ferr := s.beginCreate(targetName)
		if ferr != nil {
			return ferr
		}
		defer endFlight()
		setFlightUUID = set
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
	// A promotion to a new name is a second VM beside the original, so it
	// gets its own identity, as a clone does: never the original's uuid,
	// which NIC guards, the seed stamp and replicas key on, and which libvirt
	// refuses for a second domain while the original's runs on this host.
	if renamed {
		spec.Uuid = uuid.NewString()
	}
	// The stored tuning is validated again (and dropped before the gate opens)
	// so a record from before a rollback cannot define what the cluster refuses.
	ioR, err := s.restrictRestoredTuning(ctx, &spec)
	if err != nil {
		return err
	}
	ioG := ioR.grant
	if ioR.stripped {
		// The domain below is defined from the stripped spec. A takeover keeps the
		// row's own spec, so the two differ until the next redefine renders it.
		slog.Warn("promote: disk/NIC tuning is not applied to the defined domain",
			"vm", targetName, "why", ioR.why())
	}
	// The limits, hot-add band and USB devices are restricted the same way
	// (never refusing the promotion); their grants are taken once the
	// promotion's refusals have passed (relR.grant, below), so the renamed
	// copy's row is written through the one writer that checks every grant
	// its spec needs.
	relR := s.restrictPromotedReleaseFeatures(&spec, renamed)
	mtuR := s.restrictRestoredNICMTU(ctx, &spec)
	if mtuR.stripped || len(mtuR.invalid) > 0 {
		slog.Warn("promote: NIC MTUs are not applied to the defined domain",
			"vm", targetName, "stripped", mtuR.stripped, "invalid", mtuR.invalid)
	}

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
	// A renamed promotion mints its uuid and MACs on every attempt, so a
	// retry that adopts the domain an earlier attempt started takes that
	// domain's uuid, and its MACs by position (the spec's NICs, in order, are
	// the domain's), for the row, the NIC rows and the NIC guards: the row and
	// the domain never name two identities. One whose uuid or NICs cannot be
	// read is not adopted now; one with a NIC that names no MAC, NICs not the
	// spec's in number, or a NIC not on its spec NIC's bridge is never
	// adopted, and the refusal names the way out.
	var adoptedMACs []string
	if renamed && started {
		x, xerr := s.virt.DumpXML(targetName)
		du := domainUUIDFromXML(x)
		nics, nerr := domainNICsFromXML(x)
		if xerr != nil || du == "" {
			return status.Errorf(codes.Unavailable,
				"promote of %s to %s: the domain an earlier attempt started cannot be identified (%v); nothing was changed",
				vm.Name, targetName, xerr)
		}
		if nerr != nil {
			return status.Errorf(codes.Unavailable,
				"promote of %s to %s: the NICs of the domain an earlier attempt started cannot be read (%v); nothing was changed",
				vm.Name, targetName, nerr)
		}
		why := ""
		if len(nics) != len(spec.Network) {
			why = fmt.Sprintf("has %d NICs, the VM's spec %d", len(nics), len(spec.Network))
		}
		for i := 0; why == "" && i < len(nics); i++ {
			want := network.FlatBridgeName(spec.Network[i].Name)
			switch {
			case nics[i].MAC == "":
				why = fmt.Sprintf("names no MAC for NIC %d", i)
			case nics[i].Bridge != want:
				why = fmt.Sprintf("has NIC %d on bridge %q, the VM's spec on %q (network %s)", i, nics[i].Bridge, want, spec.Network[i].Name)
			}
		}
		if why != "" {
			return status.Errorf(codes.FailedPrecondition,
				"promote of %s to %s: the domain an earlier attempt started %s, so it is not this promotion's to adopt; "+
					"stop and remove it on %s (`virsh destroy %s`, then `virsh undefine %s`), or retry with another --new-name; nothing was changed",
				vm.Name, targetName, why, s.hostName, targetName, targetName)
		}
		spec.Uuid = du
		for _, n := range nics {
			adoptedMACs = append(adoptedMACs, n.MAC)
		}
	}

	// Checked under this promotion's create flight of the name (above).
	if err := s.promoteSplitBrainRefusal(ctx, vm, targetName, renamed, req.Force); err != nil {
		return err
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
		// A same-name takeover of a VM the ledger already counts ON THIS HOST
		// (running or starting, countedAgainstHost: a same-host rebuild) re-homes consumption headroom already
		// accounts for; charging the full size again would refuse a legal
		// recovery. Every other fresh promotion is a full-sized VM appearing
		// here. The zero-delta admission still runs the residency safety gate.
		admitCPU, admitMem := int(spec.Cpu), int(spec.MemoryMib)
		if !renamed && vm.HostName == s.hostName && countedAgainstHost(vm.State) {
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

	// An operator's same-name promotion is serialized with failover's recovery
	// of the same VM (review PB-F1; promote_serialize.go): it refuses while a
	// recovery of it is in flight at its current owner epoch, and, with
	// recovery claims enforced, claims the VM's recovery just before it starts
	// the domain. The coordinator's own promotion carries a proof and is
	// claimed where it is minted (claimPromote); a relay the coordinator
	// marked is its too.
	operatorPromote := !renamed && req.Proof == nil && !automated && !req.Automated && !started
	if operatorPromote {
		if err := s.refuseWhileRecoveryInFlight(ctx, vm); err != nil {
			return err
		}
	}
	// A domain already defined here under the name is replaced only with
	// --force, and only just before the new one is defined: every refusal and
	// every failure on the way there — a live disk already at the root's
	// path, a disk that cannot be built, a bridge that cannot be had — leaves
	// it exactly as it was. Destroying it first, as before, left a VM
	// undefined by a promotion that then refused.
	// (If this proof already reached "started", the existing domain is OUR OWN
	// prior promotion — never destroy it on resume; fall through to persist.)
	replaceDomain := false
	replaceVerdict := func() (bool, error) {
		own, du, _, ierr := s.domainIsVMsOwn(ctx, targetName, spec.Uuid, "")
		if spec.Uuid == "" && ierr == nil && !renamed {
			own = true // a VM from before uuids were minted: judged as before
		}
		if own {
			return true, nil
		}
		active, aerr := s.virt.DomainIsActive(targetName)
		if aerr == nil && !active {
			return false, nil
		}
		why := "it is running"
		if aerr != nil {
			why = fmt.Sprintf("whether it runs cannot be read (%v)", aerr)
		}
		if ierr != nil {
			du = fmt.Sprintf("unidentified: %v", ierr)
		}
		// The way out: stop the domain, then retry.
		out := fmt.Sprintf("no VM of the name exists, so stop it with `virsh destroy %s` on %s", targetName, s.hostName)
		switch {
		case renamed:
		case vm.HostName == s.hostName:
			out = fmt.Sprintf("stop it with `lv stop %s`", targetName)
		default:
			out = fmt.Sprintf("%s owns the VM: if the domain is a superseded copy of this VM, this host's reconciler stops it "+
				"once a recovery claim certifies the move there; otherwise stop it with `virsh destroy %s` on %s", vm.HostName, targetName, s.hostName)
		}
		return false, status.Errorf(codes.FailedPrecondition,
			"domain %q on %s is not this VM's (uuid %s, the VM's is %s) and %s; --force replaces only the VM's own "+
				"domain or a stopped one; %s, then retry; nothing was changed", targetName, s.hostName, du, spec.Uuid, why, out)
	}
	if s.virt.DomainExists(targetName) && !started {
		if !req.Force {
			return status.Errorf(codes.AlreadyExists, "domain %q already defined on %q; pass --force or --new-name", targetName, s.hostName)
		}
		// --force replaces the VM's own domain (its uuid: domainIsVMsOwn),
		// running or not, and any other domain of the name only when it is
		// positively stopped, keeping that one's NVRAM and vTPM state (its
		// disks are not touched), as a create removes a stopped domain with
		// no record. One that runs, or whose state cannot be read, is another
		// guest, never this promotion's to stop. For a renamed promotion no
		// row of the name exists (checked above) and the VM's identity is the
		// fresh uuid minted for it, so only a stopped leftover is replaced.
		// The verdict is taken again just before the replace (replaceVerdict).
		if _, verr := replaceVerdict(); verr != nil {
			return verr
		}
		replaceDomain = true
	}
	// A VM an earlier promotion brought to this host runs from live disks it
	// built from replicas, and has written to them since: those writes are in
	// no replica here (the replicas this host holds are of the host the VM
	// left). Rebuilding over them from a replica discards them, so a
	// same-name promotion over such a VM is refused, --force or not.
	if !renamed && !started && vm.HostName == s.hostName {
		if err := s.refuseRebuildOverPromotedDisks(ctx, vm, replica); err != nil {
			return err
		}
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
		if err := s.buildPromotedDisk(ctx, req, targetName, poolDir, replica, replicaPath, replicaRec.Format, livePath, send); err != nil {
			return err
		}
		recordStep("disk_built")
	}

	// Every other disk of the VM that has a replica here is recovered too
	// (replica_set.go): the replica of the root's run, else the newest from
	// before it. A disk on shared storage is never rebuilt from a replica: it
	// is reattached as-is. One that cannot be recovered never stops the
	// promotion — main promoted the root alone — it is named in the manifest
	// and the VM is marked partial.
	rootTaken := replicaRec.Taken
	if rootTaken == "" {
		if t, ok := replicaTimestamp(replica); ok {
			rootTaken = t.UTC().Format("20060102-150405")
		}
		// An admin-named file with no stamp has no run time: no other disk's
		// replica can be matched to it, so none is taken (partial). Its
		// mtime is not its data's time (a copy of a replica is newer).
	}
	vmDisks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		if !started {
			os.Remove(livePath)
		}
		return status.Errorf(codes.Unavailable, "list the disks of %s: %v", vm.Name, err)
	}
	autoPath := automated || req.Proof != nil
	acceptNotPIT := req.AcceptNotPointInTime || (autoPath && vmAllowsAutoPromoteNotPIT(vm))
	var otherAgeLimit time.Duration
	if autoPath {
		// The bound the root's replica passed applies to every disk's.
		sched, _ := s.replicationScheduleForVM(ctx, vm.Name)
		otherAgeLimit = autoPromoteAgeLimit(sched.Cron)
	}
	others := chooseSetReplicas(poolDir, vm.Project, vm.Name, rootTaken, replicaSetOthers(vmDisks, src),
		func(d corrosion.DiskRecord) bool { return s.diskOnSharedStorage(ctx, d) }, acceptNotPIT, otherAgeLimit, time.Now())
	// A crash-recovery adoption attaches only what the running domain has.
	adoptedXML := ""
	if started {
		adoptedXML, _ = s.virt.DumpXML(targetName)
	}
	inAdopted := func(path string) bool {
		return adoptedXML != "" && (strings.Contains(adoptedXML, "'"+path+"'") || strings.Contains(adoptedXML, `"`+path+`"`))
	}
	// Whether a shared disk may be reattached as-is (sharedReattachVerdict),
	// judged per disk by the host ITS OWN row names (review R3-I1): after a
	// partial promotion the VM is this host's while its shared disk's row
	// still names the old owner, so the VM's owner says nothing about who
	// may still be writing the disk. Each distinct owner is read once.
	type sharedOwner struct {
		host      *corrosion.HostRecord
		provedOff bool
		err       error
	}
	owners := map[string]sharedOwner{}
	ownerOf := func(name string) sharedOwner {
		if o, ok := owners[name]; ok {
			return o
		}
		var o sharedOwner
		// A `fenced` state is proof only over a proof-grade fence record
		// (corrosion.HostProvedOff's rule, colonelpanik/litevirt#253), and a
		// removed host, or one with no row, is no proof at all (review
		// R3-I2): `lv host rm --force` needs no fence, and a host whose
		// daemon died may still run its qemu. fencing_log rows outlive the
		// tombstone, and `lv host fence-confirm` records one for a removed host.
		// For a removed host only a fence of its LAST life counts (review
		// R4-I1). The one reading every start built from the disk rows shares
		// (corrosion.JudgeSharedDiskRows, review R4-I2).
		o.host, o.provedOff, o.err = corrosion.SharedDiskOwnerProvedOff(ctx, s.db, name)
		owners[name] = o
		return o
	}
	// Automated: the coordinator's own call, a carried proof, or a relay the
	// coordinator marked. A relay without either (an operator through another
	// node, local-root lv, an older coordinator) gets the manual rule.
	sharedAutomated := autoPath || req.Automated
	// reattachVerdict also returns the host the disk was refused for, which
	// the partial report's remedy names (review R4-m2): not the disk row's
	// host when that one passed, and "" when no host failed.
	reattachVerdict := func(d corrosion.DiskRecord) (bool, string, string) {
		judged, ok := sharedDiskOwners(d.HostName, vm.HostName, s.hostName)
		switch {
		case !ok:
			judged = []string{""}
		case len(judged) == 0:
			judged = []string{s.hostName}
		}
		for _, owner := range judged {
			var o sharedOwner
			if owner != "" && owner != s.hostName {
				o = ownerOf(owner)
			}
			if ok, why := sharedReattachVerdict(renamed, sharedAutomated, fenceProven, vm.HostName,
				owner, s.hostName, o.host, o.provedOff, o.err); !ok {
				return false, why, owner
			}
		}
		return true, "", ""
	}
	for i := range others {
		d := &others[i]
		if d.shared {
			switch {
			case renamed:
				d.missing = "a renamed promotion never shares a writable disk with the original"
			case started:
				// Adopting: attached exactly when the running domain has it.
				if inAdopted(d.row.Path) {
					d.livePath = d.row.Path
				} else {
					d.missing = "not attached by the attempt that started the domain"
				}
			default:
				if ok, why, owner := reattachVerdict(d.row); !ok {
					d.missing, d.unproven = why, owner
				} else if serr := statWithin(s.hostDiskFile(d.row.Path), sharedDiskStatTimeout); serr != nil {
					d.missing = fmt.Sprintf("not reachable from %s: %v", s.hostName, serr)
				} else {
					d.livePath = d.row.Path
				}
			}
			continue
		}
		if !d.recovered() {
			continue
		}
		d.livePath = filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s.qcow2", targetName,
			strings.TrimSuffix(strings.TrimSuffix(d.replica.File, ".qcow2"), ".raw")))
		// The step names the file this proof built and the replica it built
		// it from (reviews N4, R2-m2): a retry reuses that file only when it
		// was built from the replica chosen now, and never any other file —
		// one at the canonical name this proof did not build is never reused
		// nor removed, and one built from another replica is left and a new
		// one built beside it.
		if built, from, ok := builtStepPath(steps, d.row.DiskName); ok && from == d.replica.File {
			d.livePath = filepath.Join(poolDir, built)
		}
		step := builtStep(d.row.DiskName, filepath.Base(d.livePath), d.replica.File)
		_, statErr := os.Stat(d.livePath)
		if started {
			// Adopting a domain an earlier attempt started: the disk counts
			// only if its built file is there and the domain has it.
			if statErr != nil || !inAdopted(d.livePath) {
				d.missing = "not built or not attached by the attempt that started the domain"
				d.livePath = ""
			}
			continue
		}
		if promoteDiskBuilt(stepDone(step), statErr == nil) {
			continue
		}
		if statErr == nil {
			// Something is at the name — a crashed earlier attempt's file, or
			// anyone's. Never removed and never reused: the live disk is
			// built beside it under a fresh name.
			alt := strings.TrimSuffix(d.livePath, ".qcow2") + "-" + randid.New() + ".qcow2"
			slog.Warn("promote: a file is already where the live disk would go; left alone, building beside it",
				"vm", vm.Name, "disk", d.row.DiskName, "path", d.livePath, "instead", alt)
			d.livePath = alt
			step = builtStep(d.row.DiskName, filepath.Base(alt), d.replica.File)
		}
		if err := s.buildPromotedDisk(ctx, req, targetName, poolDir, d.replica.File, d.replicaPath, d.replica.Format, d.livePath, send); err != nil {
			slog.Error("promote: a disk of the replica set could not be built; promoting without it",
				"vm", vm.Name, "disk", d.row.DiskName, "replica", d.replica.File, "error", err)
			d.missing = fmt.Sprintf("its replica %s could not be built into a live disk: %v", d.replica.File, err)
			d.livePath = ""
			continue
		}
		recordStep(step)
	}
	// Every live disk this promotion built, for the error paths below. A
	// shared disk is never removed.
	removeLive := func() {
		os.Remove(livePath)
		for _, d := range others {
			if d.built() {
				os.Remove(d.livePath)
			}
		}
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
	rootDev := lv.DiskDevName(promBus, 0)
	// The other attached disks, each on its own bus and controller and at
	// its own target device — its stored one unless that collides — so the
	// guest finds each where it was, also when a disk between them is missing.
	for i := range others {
		d := &others[i]
		d.bus, d.ctrl = d.row.Bus, d.row.ControllerModel
		for _, ds := range spec.Disks {
			if ds.Name == d.row.DiskName {
				if ds.Bus != "" {
					d.bus = ds.Bus
				}
				if ds.ControllerModel != "" {
					d.ctrl = ds.ControllerModel
				}
				break
			}
		}
		if d.bus == "" {
			d.bus = "virtio"
		}
	}
	assignTargetDevs(rootDev, others)
	setDisks := func() ([]lv.DiskConfig, []corrosion.DiskRecord) {
		cfg := []lv.DiskConfig{{Name: src.DiskName, Path: livePath, Bus: promBus, ControllerModel: promCtrl, TargetDev: rootDev}}
		recs := []corrosion.DiskRecord{{
			VMName: targetName, DiskName: src.DiskName, HostName: s.hostName,
			Path: livePath, SizeBytes: src.SizeBytes, StorageType: poolRef.Driver,
			StorageVolume: pool, TargetDev: rootDev, Bus: promBus,
			BackingDisk: liveDiskBacking(livePath, replicaPath),
		}}
		for _, d := range others {
			if !d.recovered() {
				continue
			}
			cfg = append(cfg, lv.DiskConfig{Name: d.row.DiskName, Path: d.livePath, Bus: d.bus, ControllerModel: d.ctrl, TargetDev: d.dev})
			if d.shared {
				continue // its row stays exactly as it was
			}
			recs = append(recs, corrosion.DiskRecord{
				VMName: targetName, DiskName: d.row.DiskName, HostName: s.hostName,
				Path: d.livePath, SizeBytes: d.row.SizeBytes, StorageType: poolRef.Driver,
				StorageVolume: pool, TargetDev: d.dev, Bus: d.bus, ControllerModel: d.ctrl,
				BackingDisk: liveDiskBacking(d.livePath, d.replicaPath),
			})
		}
		return cfg, recs
	}
	diskCfg, diskRecords := setDisks()
	_, partialNote := promotionManifest(src.DiskName, replica, rootTaken, s.hostName, vm.Name, targetName, others)
	multiDiskNote := ""
	if partialNote != "" {
		multiDiskNote = " (" + partialNote + ")"
	}

	// The release grants for what the spec still carries, now that every
	// refusal of the promotion has passed (relR.grant): a refused promotion
	// records no use.
	relR.grant(ctx, s, &spec)

	var netCfg []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	var nicRecords []corrosion.NICRecord // v42 dual-write alongside ifaceRecords (vm_nics); only persisted on the renamed (new-row) path below
	// A takeover keeps the VM's NIC rows and guard records, so its domain
	// carries exactly its live NICs (MergedVMNICs): the spec still lists a
	// detached NIC, whose guard record is retired, and lacks a hot-attached one.
	var takeoverNICs []corrosion.NICRecord
	if !renamed {
		var nerr error
		if takeoverNICs, nerr = corrosion.MergedVMNICs(ctx, s.db, vm.Name); nerr != nil {
			removeLive()
			return status.Errorf(codes.Internal, "read the NICs of %q: %v", vm.Name, nerr)
		}
	}
	// Each NIC's model is the one it was recorded with, as every other
	// builder takes it (compose.NICModels): the merged row reads virtio for a
	// VM created before v42, whose vm_nics row the backfill wrote as virtio.
	var takeoverModels *compose.NICModels
	if len(takeoverNICs) > 0 {
		rowModels, reattached, merr := corrosion.NICModelSources(ctx, s.db, vm.Name, takeoverNICs, compose.SpecNICModelsByMAC(&spec))
		if merr != nil {
			removeLive()
			return status.Errorf(codes.Internal, "read the NIC models of %q: %v", vm.Name, merr)
		}
		takeoverModels = compose.NewNICModels(&spec, rowModels, reattached)
	}
	for _, n := range takeoverNICs {
		bridge := network.FlatBridgeName(n.NetworkName)
		if err := s.ensureBridge(bridge); err != nil {
			removeLive()
			return status.Errorf(codes.FailedPrecondition, "network bridge %q unavailable on %q: %v", bridge, s.hostName, err)
		}
		model := takeoverModels.Model(n.MAC, n.NetworkName, n.Ordinal, n.Model)
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: model, MAC: n.MAC, SpecOrdinal: n.Ordinal + 1,
			RateMBps: compose.NICRate(&spec, n.MAC, n.Ordinal, n.NetworkName)})
	}
	// A renamed promotion is a second VM: its NICs are the spec's, with fresh
	// MACs.
	var renamedNICs []*pb.NetworkAttachment
	if renamed {
		renamedNICs = spec.Network
	}
	macs := s.newMACAllocator()
	for i, n := range renamedNICs {
		var mac string
		if adoptedMACs != nil {
			mac = adoptedMACs[i] // the running guest's NIC
		} else {
			var merr error
			if mac, merr = macs.next(ctx); merr != nil {
				removeLive()
				return merr
			}
		}
		// The spec records the NIC's real MAC (as a clone does), so its queues
		// are matched at every later redefine, not lost to the source's MAC.
		n.Mac = mac
		bridge := network.FlatBridgeName(n.Name)
		if err := s.ensureBridge(bridge); err != nil {
			removeLive()
			return status.Errorf(codes.FailedPrecondition, "network bridge %q unavailable on %q: %v", bridge, s.hostName, err)
		}
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac, RateMBps: n.RateMbSec})
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

	// The operator's claim, after every other refusal and the disk builds and
	// just before anything is destroyed or started: decided, it holds the
	// VM's recovery at this owner epoch, so a coordinator recovering the same
	// VM learns it and stands down; a recovery already decided, or in flight,
	// refuses this promotion instead. Only a takeover of a VM recorded on
	// another host: no coordinator recovers a VM off a host that is up, and a
	// voter never certifies the eviction of the host asking.
	// A claim that never gets as far as starting the VM is released on the
	// way out (review I2), so the failover coordinator can move past it;
	// the start fence just before StartDomain makes it unreleasable.
	var opClaim *operatorClaim
	if operatorPromote && vm.HostName != "" && vm.HostName != s.hostName && s.RecoveryClaimEnforced(ctx) {
		oc, err := s.claimOperatorPromote(ctx, vm)
		if err != nil {
			removeLive()
			return err
		}
		opClaim = oc
		defer func() {
			if retErr != nil {
				s.releaseOperatorClaim(context.WithoutCancel(ctx), opClaim, retErr.Error())
			}
		}()
	}

	// A renamed promotion is a second VM with fresh MACs: its NICs are new and
	// guarded by default, as a clone's are (copyNICGuards).
	var guardRecords []corrosion.NICGuardRecord
	if renamed {
		guardRecords = copyNICGuards(targetName, spec.Uuid, ifaceRecords, func(n string) string { return guardUnenforcedOnNetwork(ctx, s.db, n) })
		if err := s.writeNewNICGuards(ctx, guardRecords); err != nil {
			removeLive()
			return err
		}
	}

	// Define + start — skipped on a resume where the domain was already started by
	// this proof (guarded above at the destroy step); persist below is idempotent.
	compose.ApplyDiskTuning(diskCfg, &spec)
	if renamed {
		compose.ApplyNICTuningByPosition(netCfg, &spec)
	} else {
		compose.ApplyNICTuning(netCfg, &spec)
	}
	if !started {
		if replaceDomain {
			// Force takeover, now that nothing is left to refuse: the domain
			// may be actively running on THIS host (same-host promote). Stop it
			// first — UndefineDomain alone only drops the persistent config,
			// leaving the live domain to collide on UUID at DefineDomain. (In a
			// real failover the VM ran on the fenced host, so the promotion
			// host has no such domain and this is a no-op.)
			// The verdict is taken again first: the build took time, and a
			// stopped domain that is not the VM's may run by now. One that is
			// not the VM's is never sent a stop, and keeps its NVRAM and vTPM
			// state.
			if s.virt.DomainExists(targetName) {
				own, verr := replaceVerdict()
				if verr != nil {
					removeLive()
					return verr
				}
				if own {
					_ = s.virt.DestroyDomain(targetName)
					_ = s.virt.UndefineDomain(targetName, false)
				} else {
					_ = s.virt.UndefineDomainPreservingState(targetName)
				}
			}
		}
		// attempt defines and starts the domain on disks; stage names the
		// step that failed.
		attempt := func(disks []lv.DiskConfig) (string, error) {
			cfg := lv.VMConfig{
				Name: targetName, CPU: int(spec.Cpu), CPUMode: spec.CpuMode, CPUModel: spec.CpuModel,
				// The domain carries the VM's identity, as every definer does,
				// so a later rebuild or --force retry knows it for the VM's own.
				UUID:      spec.Uuid,
				MemoryMiB: int(spec.MemoryMib), Machine: spec.Machine, Firmware: spec.Firmware,
				GuestAgent: spec.GuestAgent, EnableVNC: !spec.DisableVnc, EnableSPICE: spec.EnableSpice,
				Disks: disks, Networks: netCfg, Boot: spec.Boot,
				CloudInitISO: s.stampedSeedFor(targetName, spec.Uuid),
				// Memory hot-add carried, as every definer does (domainconfig.go).
				HotplugBaseMiB: int(spec.MemoryHotplugBaseMib), HotplugMaxMiB: int(spec.MemoryHotplugMaxMib),
				CPULimit: spec.CpuLimit, CPUShares: int(spec.CpuShares),
			}
			s.withNICMTU(&cfg)
			domXML, err := lv.GenerateDomainXML(cfg)
			if err != nil {
				return "generate domain XML", err
			}
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_DEFINING, VmName: targetName, Host: s.hostName,
				Replica: replica, DiskPath: livePath, Status: "defining domain" + multiDiskNote,
			})
			s.forgetMoveRecords(ctx, targetName) // the promoted domain takes the name
			setFlightUUID(spec.Uuid)
			if err := s.setAsideStaleLibvirtVars(targetName); err != nil {
				return "set aside stale UEFI vars", err
			}
			if err := s.virt.DefineDomain(domXML); err != nil {
				return "define domain", err
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
					_ = s.virt.UndefineDomain(targetName, false)
					return "checkpoint", err
				}
			}
			if err := s.writePromoteMarker(targetName, proofID); err != nil {
				return "marker", err
			}
			if opClaim != nil {
				if err := s.fenceOperatorStart(ctx, opClaim); err != nil {
					_ = s.virt.UndefineDomain(targetName, false)
					s.removePromoteMarker(targetName)
					return "operator claim", err
				}
			}
			if witnessPromote {
				// Defined, never started: a witness runs no workloads. The
				// ownership commit below records it stopped.
				return "", nil
			}
			releaseGuard, gerr := s.guardSharedDiskStart(ctx, targetName, domXML)
			if gerr != nil {
				_ = s.virt.UndefineDomain(targetName, false)
				s.removePromoteMarker(targetName)
				if opClaim != nil {
					s.unfenceOperatorStart(opClaim)
				}
				return "shared disk released", status.Error(codes.FailedPrecondition, gerr.Error())
			}
			if eerr := health.NoteStartEvent(ctx, s.db, s.hostName, targetName); eerr != nil {
				slog.Warn("promote: recording the start event failed", "vm", targetName, "error", eerr)
			}
			startErr := s.virt.StartDomain(targetName)
			releaseGuard()
			if err := startErr; err != nil {
				_ = s.virt.UndefineDomain(targetName, false) // wipe by design: half-built promote
				// Don't leak the marker: we tore the half-built domain down, so a later --force
				// retry must not treat a same-name stranger as our adopted prior promotion.
				s.removePromoteMarker(targetName)
				// Nothing runs: the claim may be released again — but only on
				// libvirt's positive answer (review I-1). A dropped connection
				// can fail the start after qemu was launched, and fails every
				// read after it; the fence then stays, and the claim with it.
				if opClaim != nil && s.domainPositivelyInactive(targetName) {
					s.unfenceOperatorStart(opClaim)
				}
				return "start domain", err
			}
			return "", nil
		}
		if renamed {
			// The new row is written once the domain runs; until then the
			// firewall renders its NICs from here (nic_firewall_arming.go).
			defer s.pendingNICs(targetName, spec.Uuid, ifaceRecords, nil)()
			// So are its NICs' VLANs, put on its taps before it runs
			// (NICStartGuard); a takeover's row exists, and they are read
			// from it.
			defer s.pendingTapVLANsFor(ctx, targetName, &spec, ifaceRecords)()
		}
		stage, err := attempt(diskCfg)
		// A NIC MTU this host cannot carry is not the other disks' doing.
		if err != nil && len(diskCfg) > 1 && !lv.IsNICMTUError(err) && (stage == "generate domain XML" || stage == "define domain" || stage == "start domain") {
			// The other disks may be why: the root alone is what main
			// promoted, so that is tried before giving up — never a fall back
			// to a reschedule where main's promotion would have succeeded.
			slog.Error("promote: the domain failed with the other disks of the set; retrying with the root disk alone",
				"vm", vm.Name, "stage", stage, "error", err)
			_ = s.virt.UndefineDomain(targetName, false)
			for i := range others {
				d := &others[i]
				if !d.recovered() {
					continue
				}
				if d.built() {
					os.Remove(d.livePath)
				}
				d.missing = fmt.Sprintf("the domain failed to %s with it (%v), so it was promoted with the root disk alone", strings.TrimSuffix(stage, " domain"), err)
				if stage == "generate domain XML" {
					d.missing = fmt.Sprintf("the domain XML could not be generated with it (%v), so it was promoted with the root disk alone", err)
				}
				d.livePath = ""
			}
			diskCfg, diskRecords = setDisks()
			// The rebuilt set keeps its stored disk tuning, as the first attempt's did.
			compose.ApplyDiskTuning(diskCfg, &spec)
			stage, err = attempt(diskCfg)
		}
		if err != nil {
			removeLive()
			switch stage {
			case "checkpoint":
				if errors.Is(err, corrosion.ErrProofAbandoned) {
					s.noteGateRefused(corrosion.ActionPromote, health.ReasonClaimLost)
					return status.Errorf(codes.FailedPrecondition,
						"promote of %s refused: this host abandoned proof %s and will never execute it", vm.Name, proofID)
				}
				return status.Errorf(codes.Unavailable, "record the start checkpoint of proof %s: %v", proofID, err)
			case "marker":
				return status.Errorf(codes.Internal, "record promote marker: %v", err)
			case "operator claim", "shared disk released":
				return err
			case "generate domain XML":
				return renderStatus(stage, err)
			default:
				return status.Errorf(codes.Internal, "%s: %v", stage, err)
			}
		}
		if witnessPromote {
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_LOCALIZING, VmName: targetName, Host: s.hostName,
				Replica: replica, DiskPath: livePath, Status: "VM defined, not started: this host is a witness",
			})
		} else {
			recordStep("started") // checkpoint: never destroy/rebuild this domain on a retry
			_ = send(&pb.PromoteReplicaProgress{
				Phase: pb.PromoteReplicaProgress_STARTED, VmName: targetName, Host: s.hostName,
				Replica: replica, DiskPath: livePath, Status: "VM started off the promoted replica",
			})
		}
	}
	manifest, partial := promotionManifest(src.DiskName, replica, rootTaken, s.hostName, vm.Name, targetName, others)
	multiDiskNote = ""
	if partial != "" {
		multiDiskNote = " (" + partial + ")"
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
			removeLive()
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
		gs := vmSpecGrants{tuning: ioG, passthrough: relR.passthrough, limits: relR.limits, mtu: mtuR.grant}
		if err := s.insertVMWithGrants(ctx, &spec, gs, rec, ifaceRecords, diskRecords, nicRecords, nil, false); err != nil {
			return status.Errorf(codes.Internal, "persist promoted vm: %v", err)
		}
		// This branch and the transfer below are mutually EXCLUSIVE: a renamed
		// promotion inserts a fresh row and no transfer ever follows it, so
		// nothing here mints a generation; this assigns the first one, marks it,
		// and publishes the row running.
		s.assignOwnerEpochAtCreate(ctx, targetName, true)
		// The guards apply from the first reconcile that sees the row.
		if len(guardRecords) > 0 {
			s.reconcileLocal(ctx)
		}
	} else {
		// The disks as they are before the commit re-homes them: what the
		// promotion leaves on the host the VM left (noteDisksLeftByPromote).
		disksBefore, disksBeforeErr := corrosion.GetVMDisks(ctx, s.db, targetName)
		// Phase 4: promotion commit is an ownership transition (fresh-read CAS + increment).
		if witnessPromote {
			// Stopped, so nothing publishes it running.
			if err := corrosion.TransferVMOwnerFresh(ctx, s.db, targetName, s.hostName, "stopped"); err != nil {
				return status.Errorf(codes.Internal, "re-home vm record: %v", err)
			}
		} else if err := s.publishRunningMinted(ctx, targetName, func(ctx context.Context) error {
			return corrosion.TransferVMOwnerFresh(ctx, s.db, targetName, s.hostName, "running")
		}); err != nil {
			return status.Errorf(codes.Internal, "re-home vm record: %v", err)
		}
		if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, targetName, src.DiskName, s.hostName, livePath); err != nil {
			return status.Errorf(codes.Internal, "update disk record: %v", err)
		}
		_ = corrosion.UpdateDiskStorage(ctx, s.db, targetName, src.DiskName, poolRef.Driver, pool)
		for _, d := range others {
			if !d.built() {
				continue // a shared disk's row stays exactly as it was
			}
			if err := corrosion.UpdateDiskHostAndPath(ctx, s.db, targetName, d.row.DiskName, s.hostName, d.livePath); err != nil {
				return status.Errorf(codes.Internal, "update disk record %s: %v", d.row.DiskName, err)
			}
			_ = corrosion.UpdateDiskStorage(ctx, s.db, targetName, d.row.DiskName, poolRef.Driver, pool)
		}
		// The VM now runs on its replica target: replicate back to the host it left.
		s.reverseReplicationAfterMove(ctx, "vm", targetName, "", vm.HostName, s.hostName)
		if !automated { // the failover coordinator records its own promotions
			s.noteDisksLeftByPromote(ctx, vm, disksBefore, disksBeforeErr)
		}
	}
	// Row persisted (the durable record now exists) → drop the host-local promote marker;
	// a future retry would see the re-homed row and not re-promote.
	s.removePromoteMarker(targetName)

	// The manifest: every disk and the replica it came from, or why not.
	s.recordVMEvent(ctx, targetName, "vm.promoted", "ok", manifest)
	if partial != "" {
		s.reportPromotedPartial(ctx, targetName, s.hostName, partial)
	} else {
		s.clearPromotedPartial(ctx, targetName)
	}
	s.audit(ctx, "replica.promote", targetName, "replica="+replica+" host="+s.hostName, "ok")
	op := "promote"
	if automated {
		op = "failover"
	}
	s.auditTuningDropped(ctx, ioR, targetName, op)
	relR.audit(ctx, s, targetName, op)
	s.recordForeignNetworks(ctx, "vm.promote", targetName, foreignNets)
	done := "promotion complete" + multiDiskNote
	if witnessPromote {
		done = fmt.Sprintf("promotion complete%s: %s is defined but NOT started on %s, a witness that runs no workloads. Move it to a worker and start it there: `lv migrate %s %s --cold`, then `lv start %s`",
			multiDiskNote, targetName, s.hostName, targetName, s.exampleWorker(ctx, s.hostName), targetName)
		s.recordVMEventSeverity(ctx, targetName, "vm.promoted_on_witness", "warning", "error", done)
	}
	_ = send(&pb.PromoteReplicaProgress{
		Phase: pb.PromoteReplicaProgress_DONE, VmName: targetName, Host: s.hostName,
		Replica: replica, DiskPath: livePath, Status: done,
	})
	return nil
}

// builtStep is the proof step recording that disk's live disk was built as
// file (a bare name in the pool) from the replica named from:
// "disk_built:<disk>=<file>,<replica>".
func builtStep(disk, file, from string) string {
	return "disk_built:" + disk + "=" + file + "," + from
}

// builtStepPath is the file and source replica the proof's step records for
// disk's built live disk, if one does. Both must be bare file names.
func builtStepPath(steps, disk string) (file, from string, ok bool) {
	for _, f := range strings.Fields(steps) {
		v, found := strings.CutPrefix(f, "disk_built:"+disk+"=")
		if !found {
			continue
		}
		file, from, _ = strings.Cut(v, ",")
		if file == "" || from == "" || filepath.Base(file) != file || filepath.Base(from) != from {
			continue
		}
		return file, from, true
	}
	return "", "", false
}

// buildPromotedDisk builds the live disk at livePath from the replica at
// replicaPath (recorded as format): a copy into a self-contained qcow2, or,
// with --no-localize or no qemu-img for a raw replica, an overlay on it. It
// refuses a file already at livePath, and leaves nothing there on a failure.
func (s *Server) buildPromotedDisk(ctx context.Context, req *pb.PromoteReplicaRequest, targetName, poolDir, replica, replicaPath, format, livePath string, send func(*pb.PromoteReplicaProgress) error) error {
	// A file already at livePath that this proof did not build is not ours:
	// targetName is the caller's choice, so in a shared pool the name can be
	// another VM's disk. Refused before anything is written, and so before
	// any of the error paths below that remove livePath.
	if err := refuseExistingFile(livePath); err != nil {
		return err
	}
	if req.NoLocalize {
		backingFmt := format
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
		tf, terr := storage.CreatePoolTemp(poolDir, ".promote-*.tmp")
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
		if err := convertImage(ctx, replicaPath, format, nil, tmpLive, emit); err != nil {
			os.Remove(tmpLive)
			return status.Errorf(codes.Internal, "copy replica: %v", err)
		}
		if err := placeNoClobber(tmpLive, livePath); err != nil {
			os.Remove(tmpLive)
			return err
		}
	}
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

// promoteSplitBrainRefusal is the split-brain guard of a promotion of vm to
// targetName. A same-name takeover without --force goes ahead only when the
// original's host is proven powered off the way a shared disk's owner is
// (corrosion.SharedDiskOwnerProvedOff and SharedDiskOwnerVerdict): fenced over
// a proof-grade fence, or removed (a tombstoned row, or none here) with a
// proof-grade fence of its last life. Removing a host does not power it off,
// and a row may not have replicated here yet. Any other host may still run
// the guest, and a takeover then would double-run the VM.
// A promotion to a new name never replaces another VM, --force or not:
// --force is for a same-name takeover of a VM still on a host that may run
// it. With it, a rename onto a live VM's name stopped and undefined that
// VM's domain here and then failed on its row (dupcreate re-review). A read
// either check needs that fails refuses the promotion as retryable: what it
// would have shown is unknown.
func (s *Server) promoteSplitBrainRefusal(ctx context.Context, vm *corrosion.VMRecord, targetName string, renamed, force bool) error {
	if renamed {
		rec, err := corrosion.GetVM(ctx, s.db, targetName)
		if err != nil {
			return status.Errorf(codes.Unavailable,
				"promote of %s to %s: whether a VM of that name exists cannot be read (%v); nothing was changed; retry",
				vm.Name, targetName, err)
		}
		if rec != nil {
			return status.Errorf(codes.AlreadyExists,
				"vm %q already exists; choose another --new-name (--force never replaces another VM); nothing was changed", targetName)
		}
	}
	if !force && !renamed && vm.HostName != "" && vm.HostName != s.hostName {
		h, provedOff, err := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, vm.HostName)
		if err != nil {
			return status.Errorf(codes.Unavailable,
				"promote of %s: whether its host %s is proven powered off cannot be read (%v); nothing was changed; retry",
				vm.Name, vm.HostName, err)
		}
		if ok, _ := corrosion.SharedDiskOwnerVerdict(vm.HostName, h, provedOff, nil); !ok {
			return status.Errorf(codes.FailedPrecondition,
				"vm %q may still be running on its host: %s; fence it (`lv host fence %s`, or "+
					"`lv host fence-confirm %s` once it is powered off) or pass --force/--new-name to avoid split-brain",
				vm.Name, promoteOwnerNotProvenOff(vm.HostName, h), vm.HostName, vm.HostName)
		}
	}
	return nil
}

// promoteOwnerNotProvenOff says why owner (h, nil for no live row) is not
// shown unable to run a VM, for a promotion's refusal: the shared-disk
// verdict's reasons, in words about the VM rather than a disk.
func promoteOwnerNotProvenOff(owner string, h *corrosion.HostRecord) string {
	switch {
	case h == nil || h.State == "removed":
		return fmt.Sprintf("%s is no longer a member of the cluster, but not proven powered off: removing a host "+
			"does not power it off, and its newest fence is not an IPMI power-off or an operator's confirmation", owner)
	case h.State == "fenced":
		return fmt.Sprintf("%s is fenced, but not proven powered off: its newest fence is not an IPMI power-off or "+
			"an operator's confirmation", owner)
	default:
		return fmt.Sprintf("%s is %s, not fenced (and no proof-grade fence was verified)", owner, h.State)
	}
}

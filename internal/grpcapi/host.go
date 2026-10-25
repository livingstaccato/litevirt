package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/hooks"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/randid"
)

func (s *Server) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}

	// Single query for all VM counts instead of per-host N+1.
	vmCounts, _ := corrosion.CountVMsByHost(ctx, s.db)
	// Aggregate CPU/memory allocated per host, containers included.
	resUsage := s.hostUsageWithContainers(ctx)

	resp := &pb.ListHostsResponse{}
	for _, h := range hosts {
		usage := resUsage[h.Name]
		pools := s.storagePoolsForHost(ctx, h.Name)
		diskUsed, diskTotal := hostDiskFromPools(pools, int64(h.DiskTotal))
		host := &pb.Host{
			Name:             h.Name,
			Address:          h.Address,
			State:            hostStateToPB(h.State),
			CpuTotal:         int32(h.CPUTotal),
			MemTotalMib:      int32(h.MemTotal),
			DiskTotalGib:     diskTotal,
			CpuUsed:          int32(usage.CpuUsed),
			MemUsedMib:       int32(usage.MemUsedMiB),
			DiskUsedGib:      diskUsed,
			DiskAllocatedGib: int64(usage.DiskAllocatedGiB),
			VmCount:          int32(vmCounts[h.Name]),
			Labels:           h.Labels,
			Version:          h.Version,
			StoragePools:     pools,
			// `lv doctor fence` and the UI health page name the SSH-only
			// hosts from this list; empty, every host read as best-effort.
			FenceStrategy: h.FenceStrategy,
			Region:        h.Region,
			CertSerial:    h.CertSerial,
			CreatedAt:     parseTimestamp(h.CreatedAt),
			UpdatedAt:     parseTimestamp(h.UpdatedAt),
		}
		resp.Hosts = append(resp.Hosts, host)
	}

	return resp, nil
}

func (s *Server) InspectHost(ctx context.Context, req *pb.InspectHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get host: %v", err)
	}
	if h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}

	vms, _ := corrosion.ListVMs(ctx, s.db, "", h.Name)

	// Sum allocated CPU/memory and declared disk size from VMs on this host.
	cpuUsed, memUsed, diskAllocated := s.hostAllocatedResources(ctx, h.Name)
	pools := s.storagePoolsForHost(ctx, h.Name)
	diskUsed, diskTotal := hostDiskFromPools(pools, int64(h.DiskTotal))
	reservations, reservedCPU, reservedMem, reservationsErr := s.hostReservations(ctx, h.Name)
	hostPressure, pressureAt := s.inspectPressure(h.Name)

	return &pb.Host{
		Name:                h.Name,
		Address:             h.Address,
		State:               hostStateToPB(h.State),
		CpuTotal:            int32(h.CPUTotal),
		MemTotalMib:         int32(h.MemTotal),
		DiskTotalGib:        diskTotal,
		CpuUsed:             cpuUsed,
		MemUsedMib:          memUsed,
		DiskUsedGib:         diskUsed,
		DiskAllocatedGib:    diskAllocated,
		VmCount:             int32(len(vms)),
		Labels:              h.Labels,
		Version:             h.Version,
		StoragePools:        pools,
		FenceStrategy:       h.FenceStrategy,
		IpmiAddress:         h.IPMIAddress,
		RedfishEndpoint:     h.Redfish.Endpoint,
		RedfishSystemId:     h.Redfish.SystemID,
		RedfishAuth:         h.Redfish.Auth,
		RedfishCaConfigured: h.Redfish.CACert != "",
		WatchdogDev:         h.WatchdogDev,
		Region:              h.Region,
		CertSerial:          h.CertSerial,
		CreatedAt:           parseTimestamp(h.CreatedAt),
		UpdatedAt:           parseTimestamp(h.UpdatedAt),
		Reservations:        reservations,
		ReservedCpu:         reservedCPU,
		ReservedMemMib:      reservedMem,
		ReservationsError:   reservationsErr,
		ReservationsPartial: reservationsErr != "",
		Pressure:            hostPressure,
		PressureObservedAt:  pressureAt,
	}, nil
}

func (s *Server) Ping(ctx context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	// Evaluated ONCE. advertisedCapabilities consults selfFenced() and
	// walQuarantinedNow(), both written from elsewhere: calling it twice lets the
	// watchdog trip between them, so Capabilities could carry the full list while
	// NotEnforcing was computed from an empty one — and a reader would pass the
	// advertise-check on stale data and conclude the node is enforcing. It is
	// also not cheap (with enforcement.owner_epoch on it walks the runtime
	// inventory), and Ping is on the health checker's hot path.
	advertised := s.advertisedCapabilities()
	// Enforcement posture is disclosed only to a caller holding a HOST
	// certificate. Ping is in skipAuth, so it never reaches the identity
	// interceptor and carries no role: without this, the distributable lv-cli
	// certificate — issued to every operator, and explicitly NOT a peer
	// credential (see isTrustedHostCN) — could enumerate which security
	// kill-switches are off on every node in the fleet, with no session and
	// none of the `viewer` role GetFenceReadiness requires for the same facts.
	//
	// This was never world-readable: the listener is RequireAndVerifyClientCert,
	// so every caller already presented a CA-issued certificate. The boundary
	// being drawn is peer-versus-operator-CLI, and ServerAuth is the same
	// CA-attested discriminator isTrustedHostCN falls through to — a client
	// cannot assert it, because issuing one needs the CA key. It is used here
	// INSTEAD of the full peer classification because that takes a hosts-table
	// read under the client read lock, and Ping is on the health checker's hot
	// path. The gap that leaves is a decommissioned host's certificate, which
	// still reads posture until it is re-issued; it also still reads
	// `capabilities`, so nothing is disclosed to it that it did not already have.
	disclosePosture := callerCertHasServerAuth(ctx)
	// SchemaVersion here is the BINARY const, deliberately — self-upgrade reads
	// it to decide "which binary to adopt" (a binary question), not "do my
	// columns exist" (the DB-applied question the replication handshake uses).
	// Sourcing it from the DB-applied schema would make every node report the
	// pre-staged forward version before any binary swap and wrongly think it's
	// behind, defeating pre-stage. See corrosion.EffectiveDBSchema.
	return &pb.PingResponse{
		HostName:      s.hostName,
		Version:       s.version,
		SchemaVersion: int32(corrosion.CurrentSchemaVersion),
		// Split-brain-hardening feature tokens this build supports. Read via a
		// fresh Ping to compute cluster-wide activation of fail-closed checks.
		Capabilities: advertised,
		// WALL clock, not the HLC: the caller uses it to detect NTP drift, and an
		// HLC value would compare against its own wall clock as nonsense skew.
		WallClock: time.Now().UTC().Format(time.RFC3339Nano),
		// Self-report of degradation: see PingResponse.wal_quarantined. A peer
		// records our isolation on the strength of this, because we cannot
		// record it ourselves.
		WalQuarantined: s.walQuarantinedNow(),
		// Release probation is its own state (N1): this node refuses its own
		// replicated writes but is not a rollback below anything known to be
		// used, keeps advertising, and must not be isolated for it.
		ReleaseProbation: s.db != nil && s.db.InReleaseProbation(),
		// The voter generation this node has adopted, from memory (the last
		// adoption pass), so Ping stays off the database: a rolled-back peer in
		// probation counts against it when its own is older (I-R4-2).
		VoterGeneration: s.adoptedVoterGen.Load(),
		// The other self-report: tokens advertised above but NOT acted on,
		// because their kill-switch is off here. DIAGNOSTIC ONLY — see
		// PingResponse.not_enforcing and notEnforcingTokens.
		NotEnforcing: s.notEnforcingIf(disclosePosture, advertised),
		// True on this binary for a caller allowed to see posture, so an empty
		// NotEnforcing above reads as "nothing unenforced" rather than "too old
		// to say". FALSE for a caller that is not, which lands in the same
		// UNKNOWN bucket as an old binary — the fail-closed reading, and the
		// honest one: that caller was told nothing either way.
		PostureReported: disclosePosture,
		// This build checks a migration's expect_* preconditions (failback.go).
		MigratePreconditions: !s.pingWithoutMigratePreconditionsForTest,
		// This build force-stops inside DeleteVM (DeleteVMRequest.force).
		DeleteForce: true,
		// This build honours AbortVMOperationRequest.operation_id.
		AbortScoped: true,
		// This build reads UpdateVMRequest.nic_by_list_position (nic_index.go).
		NicListPosition: !s.pingWithoutNICListPositionForTest,
	}, nil
}

// notEnforcingTokens lists capability tokens this node advertises but does not
// act on, because the matching `enforcement.*` / `auth.*` config flag is false.
//
// Advertising and enforcing are deliberately separate here (see
// advertisedCapabilities): a node advertises so the cluster can LATCH a token,
// while its own kill-switch decides whether it honours it. The consequence is
// that a token can be latched cluster-wide while members silently skip it, and
// until this list existed nothing could observe that — not a peer, not an
// operator. safe_fence_default_v1 is the shape: a latched cluster where one
// node still best-effort-fences looks, from every other node, exactly like a
// cluster that requires proof.
//
// It does NOT cover shared_storage_fence_v1, and cannot: that token is
// advertised conditionally, so a node with the flag off drops out of
// `advertised` and its absence — not this list — is the posture signal. See
// postureFromPing, which reads it that way.
//
// This is a self-report of DEGRADATION, trustworthy for the same reason
// wal_quarantined is: a node misreporting its posture would claim to enforce,
// not to skip. It must stay diagnostic — no enforcement decision may read it,
// in either direction.
//
// The list is scoped to what this node ADVERTISES, which has a consequence the
// consumer must handle rather than this function: a self-fenced or
// WAL-quarantined node advertises nothing, so its list is empty and says nothing
// about its kill-switches. Reading that emptiness as "enforces everything" would
// give exactly the most degraded node the cleanest posture. postureFromPing
// therefore treats an EMPTY advertised set as unknown, and only reads a missing
// token as not-enforcing when the node advertised something else.
//
// Scoping to Supported() instead would not fix that and would add noise:
// tokenEnabled's default is false — correct fail-closed behaviour for the
// decisions it actually gates — so every supported token with no kill-switch
// case (hardware_v2 today) would be reported unenforced on every node forever.
func (s *Server) notEnforcingTokens() []string {
	return s.notEnforcingWith(s.advertisedCapabilities())
}

// notEnforcingWith is notEnforcingFrom plus the one report it cannot make: a
// token this node has LATCHED but withholds because its flag is off.
//
// A conditionally-advertised token drops out of `advertised` the moment its
// flag goes off, which is what keeps a fresh latch from forming across the
// node — so notEnforcingFrom, scoped to what is advertised, never sees it. For
// recovery_claim_v1 that silence is the dangerous case: the node has latched
// the protocol with its peers, stopped claiming and verifying, and is now the
// uncertified second owner a partial stand-down produces
// (docs/design/recovery-claims.md §5.2, §5.6). Its enforcing peers raise
// ha_degraded because it no longer advertises; this is the self-report beside
// it, so the posture reads the same from either end.
func (s *Server) notEnforcingWith(advertised []string) []string {
	out := notEnforcingFrom(advertised, s.tokenEnabled)
	// console_password_v1 with its flag on is still not enforced in full on a
	// host whose QEMU cannot do VNC passwords (FIPS): it sets none, and the
	// daemon logs why. The latch is unaffected — this host presents every
	// password a guest it holds has — so it is reported, not withheld.
	if s.enfConsolePassword.Load() && s.vncPasswordUnavailable() != "" &&
		slices.Contains(advertised, capabilities.ConsolePasswordV1) && !slices.Contains(out, capabilities.ConsolePasswordV1) {
		out = append(out, capabilities.ConsolePasswordV1)
	}
	return append(out, s.withheldStandDowns(advertised)...)
}

// withheldStandDowns lists latched tokens this node withholds because its own
// flag is off. Only tokens whose stand-down a peer must be told about are
// considered.
func (s *Server) withheldStandDowns(advertised []string) []string {
	gt := s.gateV()
	if gt == nil {
		return nil
	}
	var out []string
	for _, tok := range []string{capabilities.RecoveryClaimV1, capabilities.PartitionPauseV1} {
		if !s.tokenEnabled(tok) && !slices.Contains(advertised, tok) && gt.Latched(tok) {
			out = append(out, tok)
		}
	}
	return out
}

// notEnforcingIf is the disclosure gate, taking the same decision that sets
// PingResponse.posture_reported so the two cannot drift apart. Populating the
// list while reporting posture_reported=false would be worse than either
// consistent answer: postureFromPing reads the flag first and would discard a
// list it had already been handed, so the disclosure would happen with none of
// the benefit.
func (s *Server) notEnforcingIf(disclose bool, advertised []string) []string {
	if !disclose {
		return nil
	}
	return s.notEnforcingWith(advertised)
}

// tokensWithoutKillSwitch have no enforcement.* flag at all, so tokenEnabled
// returns its fail-closed default for them — correct for the decisions it gates,
// wrong as a posture claim. Reporting them would put a permanent, unactionable
// entry in every node's list and teach operators to skim past the field.
//
// hardware_v2 is documented as "the one capability with no kill switch"
// (docs/diagnostics.md); token_enabled_test.go pins the same gap.
var tokensWithoutKillSwitch = map[string]bool{
	capabilities.HardwareV2: true,
}

// notEnforcingFrom is the pure half of notEnforcingTokens, taking the advertised
// set so a caller that already computed it does not evaluate it twice.
func notEnforcingFrom(advertised []string, enabled func(string) bool) []string {
	out := make([]string, 0, len(advertised))
	for _, token := range advertised {
		if tokensWithoutKillSwitch[token] {
			continue
		}
		if !enabled(token) {
			out = append(out, token)
		}
	}
	return out
}

// PeerCapabilities fresh-Pings a peer (or short-circuits for self) and returns
// its advertised split-brain-hardening capability tokens. It is injected into
// the health checker (SetPeerPinger) so cluster-wide activation is computed from
// live reachability, never from stale replicated rows. An unreachable peer
// returns an error so the caller can fail closed.
// It also returns the peer's WALL clock so the health checker can detect NTP
// drift without a second RPC. A peer that predates the field reports the zero
// time, which the caller must read as "unknown", never as skew. Self returns the
// zero time too: a node cannot be skewed against itself. The peer's adopted
// voter generation is recorded (PeerVoterGeneration).
func (s *Server) PeerCapabilities(ctx context.Context, host string) ([]string, time.Time, error) {
	if host == s.hostName {
		return s.advertisedCapabilities(), time.Time{}, nil
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer closeConn()
	resp, err := c.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return nil, time.Time{}, err
	}
	s.notePeerWALQuarantined(host, resp.GetWalQuarantined())
	s.notePeerVoterGeneration(host, resp.GetVoterGeneration(), time.Now())
	peerWall := time.Time{}
	if s := resp.GetWallClock(); s != "" {
		if parsed, perr := time.Parse(time.RFC3339Nano, s); perr == nil {
			peerWall = parsed
		}
	}
	return resp.GetCapabilities(), peerWall, nil
}

// DrainHost marks the host as draining and migrates all its VMs to healthy hosts.
// Uses a worker pool of size req.Parallel (default 2) for concurrent migrations.
// Running VMs with shared storage use live migration; other running VMs are shut
// down and reassigned. A stopped VM moves as `lv migrate --cold` moves it, with its
// host-local disks (drainStoppedVM); one that cannot move stays here, is reported,
// and the drain ends incomplete.
func (s *Server) DrainHost(req *pb.DrainHostRequest, stream pb.LiteVirt_DrainHostServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "admin"); err != nil {
		return err
	}

	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	// The entry node takes the caught-up check; the drained host itself, which
	// every entry node forwards to, takes only its own-row hold — refusing
	// there could not be helped by running it elsewhere.
	if req.Name != s.hostName {
		if err := s.hostOperatorWriteAllowed(ctx, "drain", req.Name); err != nil {
			return err
		}
	} else if err := s.db.OwnRowWritable(req.Name); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s cannot drain itself: %v", s.hostName, err)
	}

	// Drain must run ON the host being drained: only there is this daemon the SOURCE
	// of the host's VMs, so it can STOP each VM before reassigning ownership (a
	// reassign WITHOUT a source stop is split-brain) and gate on the source's local
	// quorum. Forward the whole stream to req.Name if we're not it.
	if req.Name != s.hostName {
		client, conn, cerr := s.peerClient(ctx, req.Name)
		if cerr != nil {
			return status.Errorf(codes.Unavailable, "cannot reach drain host %s: %v", req.Name, cerr)
		}
		defer conn.Close()
		remote, rerr := client.DrainHost(ctx, req)
		if rerr != nil {
			return rerr
		}
		for {
			msg, rerr := remote.Recv()
			if rerr != nil {
				if rerr == io.EOF {
					return nil
				}
				return rerr
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}

	// Split-brain gate (Phase 1): draining moves this host's VMs to peers (runtime-
	// ownership moves), so the SOURCE must hold local quorum once enforced — else an
	// isolated host could evacuate its VMs onto peers without quorum. Checked before
	// marking "draining" so a refusal is a clean no-op. Fail-open until cluster-wide.
	// The drain gate, not ExecutionGate: a re-run on a host already draining
	// retries what an earlier drain left, and must not be refused for the state
	// that drain put the host in.
	if reason, refused := s.drainGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Errorf(codes.FailedPrecondition, "drain refused: %s", reason)
	}

	if err := corrosion.UpdateHostState(ctx, s.db, req.Name, "draining"); err != nil {
		return status.Errorf(codes.Internal, "mark draining: %v", err)
	}
	s.publish("host.draining", req.Name, "")
	s.audit(ctx, "host.drain", req.Name, "", "ok")

	vms, _ := corrosion.ListVMs(ctx, s.db, "", req.Name)
	slog.Info("draining host", "host", req.Name, "vms", len(vms))

	// Collect migratable VMs.
	var toMigrate []corrosion.VMRecord
	var inFlight []string
	for _, vm := range vms {
		switch vm.State {
		case "running", "stopped":
			toMigrate = append(toMigrate, vm)
		case "migrating":
			// A move of it is in flight — an earlier drain's finishing in the
			// background, or an `lv migrate`. Nothing may start another.
			inFlight = append(inFlight, vm.Name)
			if err := stream.Send(&pb.DrainProgress{VmName: vm.Name, Status: "skipped", Strategy: notMoved,
				Error: s.inFlightMoveAdvice(ctx, vm.Name)}); err != nil {
				s.drainEndedBeforeAnyMove(ctx, req.Name, err)
				return err
			}
		}
	}
	if len(toMigrate) == 0 {
		// Nothing to move, but the host may still hold a VM in another state
		// (a move in progress or parked by an earlier drain): it is not drained.
		s.judgeDrainTimeouts(ctx, req.Name, nil, true)
		return s.drainOutcome(ctx, req.Name, nil, nil, inFlight, inFlightDetail(inFlight))
	}
	// Highest compose migrate.priority first, ties in name order: targets are
	// chosen, and the moves handed to the workers, in this order, so a
	// higher-priority VM starts moving — and takes a target's room — before a
	// lower one. Every move is still refused or admitted on its own.
	corrosion.SortVMsByMigratePriority(toMigrate)

	// Use placement engine to select targets per VM, respecting constraints.
	// Build placement requests from each VM's stored spec.
	type drainJob struct {
		vm     corrosion.VMRecord
		target corrosion.HostRecord
	}
	var drainJobs []drainJob
	// failed names each VM whose frame was failed or error, with its reason.
	var failed []string
	vlanView := s.readAccessVLANMoveView(ctx)
	for _, vm := range toMigrate {
		placementReq := buildDrainPlacementRequest(vm, req.Name, s.capacity)
		// A guarded VM drains only onto a host that enforces NIC guards
		// until every host does (re-review m8).
		s.requireGuardHost(ctx, &placementReq, vm.Name)
		// An access-VLAN VM drains only onto a host whose bridge for it
		// filters VLANs: the target refuses it otherwise.
		vlanView.exclude(&placementReq, vm)

		// Ensure the drained host is excluded via anti-affinity on itself.
		// placement.Select() excludes non-active hosts, and we already set the host to "draining".

		targetName, err := placement.Select(ctx, s.db, placementReq)
		if err != nil {
			slog.Warn("drain: no placement target for VM", "vm", vm.Name, "error", err)
			if err := stream.Send(&pb.DrainProgress{
				VmName:   vm.Name,
				Status:   "failed",
				Strategy: notMoved,
				Error:    fmt.Sprintf("no eligible target: %v", err),
			}); err != nil {
				s.drainEndedBeforeAnyMove(ctx, req.Name, err)
				return err
			}
			failed = append(failed, vm.Name+" (no eligible target)")
			continue
		}

		targetHost, err := corrosion.GetHost(ctx, s.db, targetName)
		if err != nil || targetHost == nil {
			continue
		}
		drainJobs = append(drainJobs, drainJob{vm: vm, target: *targetHost})
	}

	if len(drainJobs) == 0 {
		s.judgeDrainTimeouts(ctx, req.Name, nil, true)
		return s.drainOutcome(ctx, req.Name, failed, nil, inFlight, inFlightDetail(inFlight))
	}

	// Worker pool for parallel migrations.
	parallel := int(req.Parallel)
	if parallel <= 0 {
		parallel = 2
	}

	// record is the drain record job of a finished move, with the placement
	// the worker read as the move ended: the record describes this move, not a
	// later one made while it waits behind the release gate.
	type drainResult struct {
		progress *pb.DrainProgress
		record   drainRecordJob
	}
	jobs := make(chan drainJob, len(drainJobs))
	results := make(chan drainResult, len(drainJobs))

	// Start workers.
	for w := 0; w < parallel; w++ {
		go func() {
			for job := range jobs {
				progress := s.drainOneVM(ctx, job.vm, job.target)
				var record drainRecordJob
				if progress.Status == "done" && progress.Error == "" {
					record = s.drainRecordJobFor(ctx, progress.VmName, req.Name, progress.TargetHost)
				}
				results <- drainResult{progress, record}
			}
		}()
	}

	// Enqueue jobs.
	for _, job := range drainJobs {
		jobs <- job
	}
	close(jobs)

	// Collect results and stream progress.
	// notStarted: VMs moved off the host that did not start on their target
	// (a `done` frame carrying an Error). They left the host, but the drain
	// did not do what it was asked for them, so it does not end clean.
	var notStarted []string
	// timedOut: VMs whose live move was aborted at their migration policy's
	// timeout. They keep running here.
	var timedOut []string
	// cancelled: VMs whose live move an operator aborted (lv operation abort).
	var cancelled []string
	// background: of timedOut and cancelled, those whose move was handed to a
	// background owner (libvirt did not answer the abort).
	var background []string
	// Drain records (failback.go) are written off this loop, after each frame:
	// the release gate can take seconds, and a drain never waits for it.
	addRecord, recordsQueued := s.startDrainRecords(ctx, len(drainJobs))
	defer recordsQueued()
	for i := range drainJobs {
		res := <-results
		progress := res.progress
		record := false
		if progress.Status == "error" || progress.Status == "failed" {
			failed = append(failed, fmt.Sprintf("%s (%s: %s)", progress.VmName, progress.Status, progress.Error))
			if isDrainTimedOut(progress) {
				timedOut = append(timedOut, progress.VmName)
			} else if strings.HasPrefix(progress.Error, drainLiveAbortedPrefix) {
				cancelled = append(cancelled, progress.VmName)
			}
			if (isDrainTimedOut(progress) || strings.HasPrefix(progress.Error, drainLiveAbortedPrefix)) &&
				strings.Contains(progress.Error, drainBackgroundMarker) {
				background = append(background, progress.VmName)
			}
		} else if progress.Status == "done" && progress.Error != "" {
			notStarted = append(notStarted, progress.VmName)
		} else if progress.Status == "done" {
			record = true // so that undrain can move it back
		}
		serr := stream.Send(progress)
		if record {
			addRecord(res.record)
		}
		if serr != nil {
			// The client went away; the moves already handed to the workers
			// go on. Their outcomes are still judged, recorded and audited, once
			// all have ended, so the drain does not end silently.
			left := len(drainJobs) - i - 1
			dctx := context.WithoutCancel(ctx)
			slog.Warn("drain: the client went away; moves already started finish, queued ones are not started",
				"host", req.Name, "error", serr, "unreported", left+1)
			s.publish("host.drain.cancelled", req.Name, "the drain's client went away")
			outcomes := []string{drainOutcome(progress)}
			go func(seen []string) {
				for ; left > 0; left-- {
					r := <-results
					outcomes = append(outcomes, drainOutcome(r.progress))
					switch {
					case isDrainTimedOut(r.progress):
						seen = append(seen, r.progress.VmName)
					case r.progress.Status == "done" && r.progress.Error == "":
						// So that undrain can move it back, as a move the client saw.
						s.recordDrainOriginBounded(dctx, r.record)
					}
					s.recordVMEvent(dctx, r.progress.VmName, "vm.drain", drainEventResult(r.progress),
						"after the drain's client left: "+drainOutcome(r.progress))
				}
				s.judgeDrainTimeouts(dctx, req.Name, seen, true)
				detail := "the drain's client went away; " + strings.Join(outcomes, "; ")
				slog.Warn("drain: ended after its client went away", "host", req.Name, "outcomes", strings.Join(outcomes, "; "))
				s.audit(dctx, "host.drain", req.Name, detail, "cancelled")
			}(timedOut)
			// This VM's move ended before the client was found gone: its
			// outcome is the one the client did not receive.
			s.recordVMEvent(dctx, progress.VmName, "vm.drain", drainEventResult(progress),
				"not reported to the drain's client, which went away: "+drainOutcome(progress))
			return serr
		}
	}
	recordsQueued()
	s.judgeDrainTimeouts(ctx, req.Name, timedOut, true)

	// What the drain's own live moves left here, in words: aborted at their
	// timeout, cancelled by an operator, or still finishing in the background.
	var parts []string
	if d := inFlightDetail(inFlight); d != "" {
		parts = append(parts, d)
	}
	inBackground := func(v string) bool { return slices.Contains(background, v) }
	if aborted := slices.DeleteFunc(slices.Clone(timedOut), inBackground); len(aborted) > 0 {
		parts = append(parts, "the live move of "+strings.Join(aborted, ", ")+
			" reached its migration policy timeout and was aborted, and each keeps running here")
	}
	if bg := slices.DeleteFunc(slices.Clone(timedOut), func(v string) bool { return !inBackground(v) }); len(bg) > 0 {
		parts = append(parts, "the timed-out move of "+strings.Join(bg, ", ")+
			" is finishing in the background, and each ends here or on its target")
	}
	if aborted := slices.DeleteFunc(slices.Clone(cancelled), inBackground); len(aborted) > 0 {
		parts = append(parts, "the live move of "+strings.Join(aborted, ", ")+
			" was cancelled by `lv operation abort`, and each stays here")
	}
	if bg := slices.DeleteFunc(slices.Clone(cancelled), func(v string) bool { return !inBackground(v) }); len(bg) > 0 {
		parts = append(parts, "the cancelled move of "+strings.Join(bg, ", ")+
			" is finishing in the background, and each ends here or on its target")
	}
	return s.drainOutcome(ctx, req.Name, failed, notStarted, append(slices.Clone(inFlight), background...), strings.Join(parts, "; "))
}

// inFlightDetail is a drain's word on the VMs it found with a move in flight,
// "" when none.
func inFlightDetail(inFlight []string) string {
	if len(inFlight) == 0 {
		return ""
	}
	return fmt.Sprintf("%d VM(s) have a move in flight (%s); re-run drain once it ends", len(inFlight), strings.Join(inFlight, ", "))
}

// drainOutcome is a drain's terminal result. The host is drained only when no
// VM row names it any more and every move the drain made ended clean. Every
// row still on the host counts, whatever its state: a VM skipped or refused,
// one whose move is still running in the background, parked, or left
// `migrating`, each still has its guest, or may have, on this host, and
// powering it off then could lose that guest (K-7). failed names the moves
// that failed or ended in error; notStarted the VMs moved that did not start;
// moving the VMs with a move in flight, which the drain did not try to move
// and must not be told to remove; moves says what the drain's own live moves
// left here (timed out, cancelled, finishing in the background), "" when
// nothing.
func (s *Server) drainOutcome(ctx context.Context, host string, failed, notStarted, moving []string, moves string) error {
	remaining, err := corrosion.ListVMs(ctx, s.db, "", host)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"drain incomplete: cannot confirm that no VM remains on host %q: %v", host, err)
	}
	if len(remaining) > 0 {
		here := make([]string, 0, len(remaining))
		var untried []string
		for _, vm := range remaining {
			here = append(here, fmt.Sprintf("%s (%s)", vm.Name, vm.State))
			if vm.State != "running" && vm.State != "stopped" && !slices.Contains(moving, vm.Name) {
				untried = append(untried, vm.Name)
			}
		}
		next := ""
		if len(untried) > 0 {
			// A drain moves only running and stopped VMs, so these have no
			// result of their own to read.
			next = fmt.Sprintf("; the drain did not try to move %s (neither running nor stopped): "+
				"start each with `lv start <vm>` and drain again, or remove it with `lv rm <vm>`; "+
				"a VM a live firmware move left `migrating` is resolved with `lv doctor firmware-move <vm>`",
				strings.Join(untried, ", "))
		}
		if moves != "" {
			next += "; " + moves
		}
		return status.Errorf(codes.FailedPrecondition,
			"drain incomplete: %d VM(s) remain on host %q (pinned, no eligible target, not movable, or a move still running or parked; "+
				"see each VM's result and `lv events <vm>`): %s%s",
			len(remaining), host, strings.Join(here, ", "), next)
	}
	if len(notStarted) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"drain incomplete: every VM left host %q, but %d did not start on its target (%s); start each with `lv start <vm>`",
			host, len(notStarted), strings.Join(notStarted, ", "))
	}
	if len(failed) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"drain incomplete: every VM left host %q, but %d move(s) did not end clean: %s; see `lv events <vm>`",
			host, len(failed), strings.Join(failed, "; "))
	}
	return nil
}

// buildDrainPlacementRequest constructs a placement request for a VM leaving
// drainHost, honoring the constraints in its stored spec. A spec pin to the
// draining host itself is dropped — the VM has to leave.
func buildDrainPlacementRequest(vm corrosion.VMRecord, drainHost string, capacity corrosion.CapacityPolicy) placement.Request {
	placementReq := placement.Request{
		VMName:       vm.Name,
		CPUNeeded:    vm.CPUActual,
		MemMiBNeeded: vm.MemActual,
		Capacity:     capacity,
	}
	if vm.Spec == "" {
		return placementReq
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return placementReq
	}
	// A raw USB device binds the VM to the host being drained, so it has no
	// target; a mapped one restricts it to the mapping's hosts.
	applyUSBPlacement(&placementReq, spec, vm.HostName)
	if p := spec.Placement; p != nil {
		// Override PinHost — cannot pin to the host being drained.
		if p.Host != "" && p.Host != drainHost {
			placementReq.PinHost = p.Host
		}
		placementReq.AntiAffinity = p.AntiAffinity
		placementReq.Affinity = p.Affinity
		placementReq.RequireLabels = p.Require
		placementReq.PreferLabels = p.Prefer
		placementReq.Spread = p.Spread
	}
	// The same conversion CreateVM makes, so the target honours every
	// selector: a mapping, an exact address, a model, SR-IOV and its parent.
	for _, dev := range spec.Devices {
		placementReq.Devices = append(placementReq.Devices, placement.DeviceRequestFor(dev))
	}
	// A Secure-Boot/vTPM VM may only drain onto a capable host (G1).
	addCapabilityLabels(&placementReq, spec)
	// A running one moves live only onto a host labelled for the live
	// firmware move (spec §13): such a host is preferred, not required, so a
	// cluster without one keeps today's placement and the VM is skipped.
	if vm.State == "running" && (spec.SecureBoot || spec.Tpm) {
		if placementReq.PreferLabels == nil {
			placementReq.PreferLabels = map[string]string{}
		}
		placementReq.PreferLabels[corrosion.LabelFwLiveMigrate] = "true"
	}
	return placementReq
}

// notMoved is the Strategy of a drain frame for a VM the drain did not try to
// move — refused or skipped before any move began. Without it the frame would
// carry the enum's zero value, MIGRATE_LIVE, and `lv host drain` printed
// [MIGRATE_LIVE] for a stopped VM that would have moved cold.
const notMoved = pb.MigrateStrategy_MIGRATE_NONE

// drainOneVM migrates a single VM to the target host. Returns progress message.
//
// A running VM whose disks are all on shared storage is live-migrated; a
// running Secure Boot / vTPM VM only by the live firmware move, or not at all
// (drainRunningFirmwareVM). Every other VM moves the way `lv migrate --cold`
// moves a stopped one, with its host-local disks: a stopped VM as it is
// (drainStoppedVM), a running one shut down first and started again on the
// target (drainRunningVMCold), which is also where a failed live migration
// falls back to. No VM is moved by its row alone.
func (s *Server) drainOneVM(ctx context.Context, vm corrosion.VMRecord, target corrosion.HostRecord) *pb.DrainProgress {
	// Acquire per-VM lock to avoid migrating while a backup is in progress (#54).
	// It is MigrateVM's lock discipline: a migration that outlives this step
	// takes the lock with it (migrateOwnedVM's adoption), and then this step
	// must not release it.
	lockUnlock, skip := s.drainLockVM(ctx, vm.Name, target.Name)
	if skip != nil {
		return skip
	}
	unlock := releaseOnce(lockUnlock)
	if ctx.Err() != nil {
		// The drain was cancelled (its client went away) before this job ran:
		// start nothing, and say so rather than "VM no longer exists".
		unlock()
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: "the drain was cancelled before this VM's move started; it keeps running here"}
	}
	// From here this VM's move has started: it runs to its end — moved, or
	// rolled back as its own failure paths do — even if the drain's client
	// goes away. A move on the request's context died with it: a cold move
	// shut the guest down, failed its next read, and started it again here.
	// It is not unbounded: a stalled disk copy is aborted (streamColdDisk), and
	// `lv operation abort <vm> --force` cancels the move (cancelDrainMove).
	ctx, cancelMove := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelMove()
	defer s.trackDrainMove(vm.Name, cancelMove)()
	adopted := false
	defer func() {
		if !adopted {
			unlock()
		}
	}()

	// Re-read under lock and act on the CURRENT row, not the queued snapshot:
	// ownership or state may have changed since the drain job was queued, and a stale
	// snapshot could otherwise live-migrate / cold-move a VM this daemon no longer
	// owns (split-brain). Everything below uses `fresh`.
	fresh, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || fresh == nil {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: "VM no longer exists"}
	}
	if fresh.State == "backing-up" {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: "active backup in progress — re-run drain after backup completes"}
	}
	// Only drain a VM we still OWN, in a drainable state. Never act on one that moved
	// off this host (or changed state) after the job was queued — a move of a VM
	// running elsewhere would double-run it.
	if fresh.HostName != s.hostName {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: "VM no longer owned by this host (moved since drain was queued)"}
	}
	if fresh.State != "running" && fresh.State != "stopped" {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: fmt.Sprintf("VM is %s — not drainable", fresh.State)}
	}

	// A RUNNING Secure-Boot/vTPM VM's NVRAM and swtpm state are host-local even
	// on shared disks: neither drain's raw live-migrate nor its cold move (which
	// would shut it down) carries them. It moves only by the live firmware move
	// (drainRunningFirmwareVM, below), and only when it may (spec §13); any
	// other is skipped, left running, with the routes that move it stopped. A
	// STOPPED one takes the cold path below (drainStoppedVM), with its refusals.
	fwRunning := fresh.State == "running" && usesFirmwareState(fresh.Spec)
	if fwRunning {
		if why := s.firmwareLiveMoveIneligible(ctx, fresh, s.hostName, target.Name); why != "" {
			return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
				Error: firmwareDrainSkipText(vm.Name, why)}
		}
	}

	// Split-brain gate, PER-VM re-check: DrainHost gated once up front, but drain is
	// long-running and batch-oriented, so quorum can be lost between VMs. Re-check on
	// the source right before THIS VM's irreversible move (a live migration, or a
	// cold move's handoff) so a mid-drain quorum loss stops further moves. Placed
	// after the fresh-row read and before any runtime/ownership mutation. Fail-open
	// until split_brain_gate_v1 is cluster-wide. The drain gate: this host is
	// draining by now, and moving its VMs away is what draining is for.
	if reason, refused := s.drainGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: notMoved,
			Error: "drain refused: " + reason,
		}
	}

	// A STOPPED VM moves as `lv migrate --cold` moves it: its host-local disks
	// with it, its domain defined on the target, and the source cleaned up only
	// after the handoff commits.
	if fresh.State == "stopped" {
		return s.drainStoppedVM(ctx, fresh, target, unlock, &adopted)
	}
	if fwRunning {
		return s.drainRunningFirmwareVM(ctx, fresh, target, unlock, &adopted)
	}

	// A running VM with a host-local disk (local or dir storage, or a legacy
	// row with none — isHostLocalDisk) cannot be live-migrated by drain, which
	// copies no storage: it is cold-moved, shut down only once every check of
	// that move has passed. A disk list that
	// cannot be read is treated as holding one — the cold path reads it again
	// and refuses with the reason, leaving the VM running.
	disks, derr := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	hostLocal := derr != nil
	for _, d := range disks {
		if isHostLocalDisk(d) {
			hostLocal = true
			break
		}
	}
	// A VM with USB passthrough is never moved live (as on Proxmox VE): a
	// mapped device is re-resolved on the target by the cold move, and a raw
	// one has no target at all (placement keeps it on its host).
	if hostLocal || len(parseSpecOrNil(fresh.Spec).GetUsbDevices()) > 0 {
		return s.drainRunningVMCold(ctx, fresh, target, unlock, &adopted)
	}

	// Destination admission for the live migration, before anything
	// irreversible: a drain is an OPERATOR-initiated move and lands the same
	// full-sized VM on the target an explicit migrate would — placement.Select is
	// a read-only filter over replicated data, not an admission. The decision
	// belongs to the DESTINATION daemon (fresh local inventory, ownership
	// conditions, serialized reserve-then-verify), exactly like MigrateVM. The
	// lease is released before a cold fallback, which takes its own.
	// An operator's abort (cancelDrainMove) that lands before libvirt is
	// asked is reported as the abort it is, not as the step it interrupted.
	abortedBeforeStart := func() *pb.DrainProgress {
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "failed",
			Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			Error: fmt.Sprintf("%s by `lv operation abort %s --force` before libvirt started it; %s keeps running on %s",
				drainLiveAbortedPrefix, vm.Name, vm.Name, s.hostName)}
	}
	migLease, aerr := s.acquireDestinationHostLease(ctx, "DrainHost", target.Name, fresh.Project,
		"vm:"+vm.Name, fresh.CPUActual, fresh.MemActual, intentVMResident)
	if aerr != nil {
		if ctx.Err() != nil {
			return abortedBeforeStart()
		}
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "skipped",
			Strategy: pb.MigrateStrategy_MIGRATE_LIVE, Error: "target admission refused: " + aerr.Error()}
	}
	// The lease goes with a move handed to a background owner.
	leaseHeld := true
	defer func() {
		if leaseHeld {
			migLease.release(ctx)
		}
	}()

	// Live migrate — every disk is on shared storage. (Ownership confirmed above.)
	progress := &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE}
	// What `lv migrate` puts on the target first, through the same helper:
	// the VM's networks and its cloud-init ISO. libvirt checks both on the
	// destination, and without them every cloud-init VM's live drain failed
	// and fell back to a cold move that waits for the guest to shut down.
	s.prepareMigrationTarget(ctx, fresh, target.Name)
	// The target's qemu opens the installer ISO from its own filesystem: the
	// target judges that file first (EnsureDisks with no stubs does only that).
	// Where it resolves the ISO to another file (a link, a library
	// directory), the destination definition carries that file.
	srcTLS := s.migrationNetwork != "" && s.migrationTLSReady()
	ens, ierr := s.ensureDisksOnTargetNet(ctx, target.Name, vm.Name, nil, srcTLS, true)
	if ierr != nil {
		// The guest never left: take back the ISO this attempt put there.
		s.cleanupFailedMigrationTarget(context.WithoutCancel(ctx), vm.Name, target.Name, nil)
		if ctx.Err() != nil {
			return abortedBeforeStart()
		}
		progress.Status = "error"
		progress.Error = "target refused the move: " + ierr.Error()
		return progress
	}
	cdromSources, targetCgroup := ens.remap, ens.cgroupMode
	// The same arming every live move goes through (re-review R2-I3): the
	// target puts the guest's NIC guards in force before it arrives.
	armed, aerr := s.armMigrationTarget(ctx, &target, vm.Name)
	if aerr != nil {
		// The guest never left: take back what this attempt put on the
		// target (its cloud-init ISO), and nothing that was there before.
		s.cleanupFailedMigrationTarget(context.WithoutCancel(ctx), vm.Name, target.Name, nil)
		if ctx.Err() != nil {
			return abortedBeforeStart()
		}
		progress.Status = "error"
		progress.Error = "target refused: " + aerr.Error()
		return progress
	}
	route := s.chooseMigrationRoute(ctx, vm.Name, target, ens.migAddr, routeMemory, s.memoryTLSGap(srcTLS, ens, target.Name))
	dconnuri := fmt.Sprintf("qemu+tls://%s/system", corrosion.URIHost(target.Address))
	// The VM's own migration policy, as `lv migrate` reads it, its timeout
	// included (drainLiveMigrate).
	tuning := migrationTuningFor(fresh, true)
	mp := libvirt.MigrateParams{
		Live: true, CDROMSources: cdromSources,
		BandwidthMiB: tuning.bandwidthMiB, AutoConverge: tuning.autoConverge, MaxDowntimeMS: tuning.maxDowntimeMS,
		SharesWeight: s.vmSharesWeight(ctx, vm.Name), TargetCgroup: targetCgroup,
		StripVNCPassword: ens.vncPasswordUnavailable,
		RBDLocators:      s.rbdLocatorsOf(ctx, vm.Name),
		NICBridges:       s.migrationNICBridges(ctx, vm.Name, ens.netDevices),
	}
	if route.direct {
		mp.Direct, mp.TLS = true, true
		mp.TargetAddress = corrosion.URIHost(route.addr)
		mp.TLSDestination = target.Address
	}
	hspec := vmHooks(fresh)
	pbVM := &pb.VM{Name: vm.Name, HostName: fresh.HostName, State: pb.VMState_VM_RUNNING}
	// The row says migrating while libvirt may move the guest, as `lv migrate`
	// writes it: the reconciler and the owner assertion leave such a row,
	// and a commit after the cut-over that declines re-points it to the
	// target (RepointMigratedVM). A `running` row whose domain libvirt has
	// moved away would be restarted here — after a daemon restart, or a
	// declined commit — while the guest runs on the target.
	if err := corrosion.UpdateVMState(ctx, s.db, vm.Name, "migrating", "→ "+target.Name); err != nil {
		s.cleanupFailedMigrationTarget(context.WithoutCancel(ctx), vm.Name, target.Name, nil)
		if ctx.Err() != nil {
			return abortedBeforeStart()
		}
		s.noteStateWriteFail(corrosion.OpVMState, err)
		return &pb.DrainProgress{VmName: vm.Name, TargetHost: target.Name, Status: "error",
			Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			Error:    "could not record the move as in flight, so it was not started; the VM keeps running here: " + err.Error()}
	}
	// Not cut by an abort: post_migrate runs whatever happens next, so its
	// pre_migrate runs whole. drainLiveMigrate sees the abort before libvirt.
	hooks.Run(context.WithoutCancel(ctx), hooks.PreMigrate, pbVM, hspec)
	// The target's NIC guards are armed for the guest (armMigrationTarget).
	armed.apply(&mp)
	logVNCPasswordStrip(vm.Name, target.Name, mp.StripVNCPassword)
	lerr, stopped, pending := s.drainLiveMigrate(ctx, vm.Name, dconnuri, mp, tuning.policy.GetTimeoutSec())
	if stopped == liveAborted {
		// The move's context is cancelled: what follows (the record of where
		// the guest ended, the target's cleanup) must still run.
		ctx = context.WithoutCancel(ctx)
	}
	// Why the move was stopped, in its frame's words.
	why := fmt.Sprintf("%s%ds, the VM's migration policy timeout_sec", drainTimedOutPrefix, tuning.policy.GetTimeoutSec())
	if stopped == liveAborted {
		why = drainLiveAbortedPrefix + " by `lv operation abort " + vm.Name + " --force`"
	}
	if stopped == liveUnanswered {
		why = "libvirt did not answer the live move"
	}
	if pending != nil {
		// libvirt has not answered the abort: the live job may still cut
		// over. Its outcome goes to a background owner, which takes the VM's
		// lock with it and records where the guest ends (adoptAbandonedMigration,
		// as for an `lv migrate` that stopped waiting). Nothing here may act
		// on the move — no target cleanup, no cold move — while it can still
		// complete: the guest would then run on two hosts.
		adopted, leaseHeld = true, false
		s.adoptAbandonedMigration(context.WithoutCancel(ctx), fresh, target.Name, false, disks, pending, unlock,
			migrationFinish{target: &target, pbVM: pbVM, hspec: hspec, armed: armed, lease: migLease, drainFrom: s.hostName})
		detail := fmt.Sprintf("%s, and libvirt did not answer its abort within %s; "+
			"the move is left to %s, and %s ends running on %s or on %s, never on both (watch `lv events %s`)",
			why, s.drainAbortGraceOrDefault(), drainBackgroundMarker,
			vm.Name, s.hostName, target.Name, vm.Name)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "error", "drain: "+detail)
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "failed", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			Error: detail,
		}
	}
	if stopped == liveUnanswered {
		// Where the guest runs is not known. The lease stays until the guest
		// is seen running here, so a daemon that dies asking keeps it, as a
		// killed process would.
		leaseHeld = false
		if st, serr := s.sourceDomainState(vm.Name); serr != nil || st != "running" {
			// It may run on the target: the row stays migrating on this host,
			// the lease and the target's copy with it, and nothing here
			// starts or moves it.
			detail := fmt.Sprintf("%s, and %s is not running on %s (%v): it may run on %s, "+
				"so its record is left migrating and nothing is started or moved (%s; %s)",
				why, vm.Name, s.hostName, lerr, target.Name, condMigrationUnresolved, settleMigratingAdvice(vm.Name))
			slog.Warn("drain: the live move ended without libvirt's answer and the guest is not running here; its record is left migrating",
				"vm", vm.Name, "target", target.Name, "state", st, "state_error", serr)
			s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "error", "drain: "+detail)
			leaseID := ""
			if migLease != nil {
				leaseID = migLease.id
			}
			s.raiseMigrationUnresolved(context.WithoutCancel(ctx), vm.Name, target.Name, leaseID, detail)
			return &pb.DrainProgress{
				VmName: vm.Name, TargetHost: target.Name, Status: "failed", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
				Error: detail,
			}
		}
		leaseHeld = true
	}
	if lerr == nil {
		// libvirt cut over: the only copy runs on the target. What follows runs
		// detached from the drain's request — a client that went away (Ctrl-C)
		// must not leave the row migrating on the source, which nothing heals.
		dctx := context.WithoutCancel(ctx)
		var err error
		if s.drainCommitFault != nil && testing.Testing() {
			err = s.drainCommitFault(vm.Name)
		}
		if err == nil {
			// Phase 4: drain move is an ownership transition (fresh-read CAS + increment).
			//runningcheck:allow ownership handoff — this commit names the TARGET host while
			// running on the source, whose domain MigrateToTarget has already undefined
			// (MigrateUndefineSource). A marker written here would describe a runtime that
			// no longer exists; the destination's convergence marks the one that does.
			err = corrosion.TransferVMOwnerFresh(dctx, s.db, vm.Name, target.Name, "running")
		}
		if err != nil {
			// The re-point `lv migrate` falls back to: the VM row only, from
			// this move's own (source, migrating).
			//runningcheck:allow ownership handoff after cutover, as above.
			moved, rerr := corrosion.RepointMigratedVM(dctx, s.db, vm.Name, s.hostName, target.Name, "running")
			if rerr != nil || !moved {
				slog.Error("drain: post-migration ownership write failed", "vm", vm.Name, "to", target.Name,
					"error", err, "repoint_error", rerr)
				s.noteStateWriteFail(corrosion.OpVMHost, err)
				progress.Status = "error"
				progress.Error = "migrated but recording new owner failed: " + err.Error()
				// The guest runs on the target even though its row says otherwise.
				s.runDrainPostMigrate(dctx, pbVM, hspec, target.Name, pb.VMState_VM_RUNNING)
				if herr := armed.finish(dctx); herr != nil {
					progress.Error += "; " + herr.Error()
				}
				return progress
			}
			slog.Warn("drain: ownership commit failed after the cut-over; re-pointed the VM row to the target",
				"vm", vm.Name, "to", target.Name, "error", err)
		}
		// What follows a cut-over for `lv migrate` follows it here, in its
		// order: reverse replication first (right after the ownership commit,
		// before the hand-over can fail), the NetBox mirror, GARP, DNS, LB
		// backends, VXLAN FDB, the post_migrate hook, the target's notify, the
		// source's own cloud-init ISO, and last the hand-over of a guest moved
		// paused once the target has its guards in force (re-review R3-I2).
		if herr := s.finishMigrationOnTarget(dctx, fresh, migrationFinish{target: &target, pbVM: pbVM, hspec: hspec, armed: armed}); herr != nil {
			progress.Status = "error"
			progress.Error = "migrated; " + herr.Error()
			return progress
		}
		s.recordVMEvent(dctx, vm.Name, "vm.drain", "ok",
			fmt.Sprintf("drain of %s: moved live to %s", s.hostName, target.Name))
		progress.Status = "done"
		progress.ProgressPct = 100
		return progress
	}
	if stopped == liveNotStopped {
		slog.Warn("live migration failed during drain, falling back to a cold move",
			"vm", vm.Name, "error", lerr)
	} else {
		slog.Warn("drain: live move stopped; no cold move follows, and the VM stays on this host",
			"vm", vm.Name, "reason", why, "error", lerr)
	}
	// libvirt ended the move with the guest here: the row leaves migrating
	// (running while its domain runs, else error), as a failed `lv migrate`.
	runningHere := s.restoreSourceStateAfterFailedMigration(context.WithoutCancel(ctx), vm.Name,
		fmt.Sprintf("drain move to %s failed: %v", target.Name, lerr), lerr.Error())
	// The guest stayed here: take back the ISO this attempt put on the target,
	// which only the attempt that made it may remove. The cold move puts its
	// own there, and one that fails before it does would otherwise leave this
	// one behind for a VM the target does not run.
	s.cleanupFailedMigrationTarget(ctx, vm.Name, target.Name, nil)
	// One lease per move: the cold move takes the destination's lease itself.
	migLease.release(ctx)

	// A live move aborted at its migration policy's timeout, or by an
	// operator, is not followed by a cold move: the policy bounds how long the
	// move may take, an abort ends it, and a cold move shuts the guest down.
	// The guest stays here.
	if stopped != liveNotStopped {
		where := fmt.Sprintf("%s keeps running on %s", vm.Name, s.hostName)
		if !runningHere {
			where = fmt.Sprintf("%s is not running on %s, and its record there says error (watch `lv events %s`)",
				vm.Name, s.hostName, vm.Name)
		}
		how := "the move was aborted"
		if stopped == liveUnanswered {
			how = "no cold move follows"
		}
		detail := fmt.Sprintf("%s; %s and %s (%v)", why, how, where, lerr)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "error", "drain: "+detail)
		s.runDrainPostMigrate(ctx, pbVM, hspec, s.hostName, s.drainVMStateHere(ctx, vm.Name))
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "failed", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			Error: detail,
		}
	}

	// Split-brain gate, re-check before the COLD fallback: a failed live migration
	// above can run long enough to lose quorum, and a cold move shuts the VM down
	// and hands it over (irreversible). Re-check so a quorum loss during the live
	// attempt stops the fallback. On refusal the VM is left running on the source
	// (live migration failure leaves the source domain up).
	if reason, refused := s.drainGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		s.runDrainPostMigrate(ctx, pbVM, hspec, s.hostName, s.drainVMStateHere(ctx, vm.Name))
		return &pb.DrainProgress{
			VmName: vm.Name, TargetHost: target.Name, Status: "skipped", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			Error: "drain refused: " + reason,
		}
	}
	cold := s.drainRunningVMCold(ctx, fresh, target, unlock, &adopted)
	// pre_migrate ran before the live attempt, so post_migrate runs once, with
	// where the VM ended: on the target after a cold move (stopped there if it
	// did not start), or here when the cold move failed too.
	switch {
	case cold.Status == "done" && cold.Error == "":
		s.runDrainPostMigrate(ctx, pbVM, hspec, target.Name, pb.VMState_VM_RUNNING)
	case cold.Status == "done":
		s.runDrainPostMigrate(ctx, pbVM, hspec, target.Name, pb.VMState_VM_STOPPED)
	default:
		s.runDrainPostMigrate(ctx, pbVM, hspec, s.hostName, s.drainVMStateHere(ctx, vm.Name))
	}
	return cold
}

// drainTimedOutPrefix begins the Error of a drain frame for a live move
// aborted at its migration policy's timeout (drainLiveMigrate).
const drainTimedOutPrefix = "live move did not finish within "

// drainLiveAbortedPrefix begins the Error of a drain frame for a live move an
// operator aborted (drainLiveMigrate).
const drainLiveAbortedPrefix = "live move was cancelled"

// drainLockWait bounds how long a drain waits for a VM's lock held by an
// ordinary operation. A var so tests can shorten it.
var drainLockWait = 10 * time.Minute

// drainLockPoll is how often a drain waiting on a VM's lock tries it again
// (and reads the VM's row to see whether a move of it went in flight).
const drainLockPoll = 250 * time.Millisecond

// drainLockVM takes vm's lock for a drain. A VM whose move is in flight (its
// row migrating: a move finishing in the background holds the lock until
// libvirt ends it) is skipped at once. Any other holder — a scheduled
// snapshot, a replication run, a hotplug, a backup — is waited for, up to
// drainLockWait, after which the VM is skipped. skip is the frame then.
func (s *Server) drainLockVM(ctx context.Context, vm, target string) (unlock func(), skip *pb.DrainProgress) {
	cancelled := func() *pb.DrainProgress {
		return &pb.DrainProgress{VmName: vm, TargetHost: target, Status: "skipped", Strategy: notMoved,
			Error: "the drain was cancelled before this VM's move started; it keeps running here"}
	}
	inFlight := func() *pb.DrainProgress {
		// Read detached: a cancelled drain must still tell a move in flight.
		if row, err := corrosion.GetVM(context.WithoutCancel(ctx), s.db, vm); err == nil && row != nil && row.State == "migrating" {
			return &pb.DrainProgress{VmName: vm, TargetHost: target, Status: "skipped", Strategy: notMoved,
				Error: s.inFlightMoveAdvice(context.WithoutCancel(ctx), vm)}
		}
		return nil
	}
	if u, ok := s.tryLockVMAs(vm, "drain"); ok {
		return u, nil
	}
	if p := inFlight(); p != nil {
		return nil, p
	}
	deadline := time.NewTimer(drainLockWait)
	defer deadline.Stop()
	tick := time.NewTicker(drainLockPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, cancelled()
		case <-deadline.C:
			holder := "its holder is not recorded"
			if h, ok := s.vmLockHolderOf(vm); ok && h.who != "" {
				holder = fmt.Sprintf("held by %s since %s", h.who, h.since.UTC().Format(time.RFC3339))
			}
			return nil, &pb.DrainProgress{VmName: vm, TargetHost: target, Status: "skipped", Strategy: notMoved,
				Error: fmt.Sprintf("another operation still holds this VM after %s (%s); re-run drain once it ends",
					drainLockWait, holder)}
		case <-tick.C:
		}
		if u, ok := s.tryLockVMAs(vm, "drain"); ok {
			return u, nil
		}
		if p := inFlight(); p != nil {
			return nil, p
		}
	}
}

// undrainJudge is undrain's judgement of host's drain_move_timed_out. On the
// drained host it judges the whole set. Served by another host, it never
// writes a name set (a write from here could restore a name the drained
// host's forgetDrainTimeout just removed): it resolves the condition only
// when no VM it names is still in flight, and otherwise leaves it to the
// drained host, whose forget drops the rest once the host is no longer
// draining.
func (s *Server) undrainJudge(ctx context.Context, host string) {
	if host == s.hostName {
		s.judgeDrainTimeouts(ctx, host, nil, true)
		return
	}
	if s.db == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	for _, v := range s.drainTimeoutsNamed(ctx, host) {
		if row, err := corrosion.GetVM(ctx, s.db, v); err == nil && row != nil && row.HostName == host && row.State == "migrating" {
			return
		}
	}
	s.setHostConditionOf(ctx, drainEvaluator, condDrainMoveTimedOut, host, false, corrosion.SeverityWarning, "")
}

// drainBackgroundMarker is in the Error of such a frame when libvirt did not
// answer the abort and the move was handed to a background owner.
const drainBackgroundMarker = "finish in the background"

// drainEndedBeforeAnyMove records a drain whose client went away before any
// move was started: nothing was moved, and the drain does not end silently.
func (s *Server) drainEndedBeforeAnyMove(ctx context.Context, host string, err error) {
	dctx := context.WithoutCancel(ctx)
	slog.Warn("drain: the client went away before any move started; nothing was moved", "host", host, "error", err)
	s.publish("host.drain.cancelled", host, "the drain's client went away before any move started")
	s.audit(dctx, "host.drain", host, "the drain's client went away before any move started; nothing was moved", "cancelled")
}

// trackDrainMove records cancel as vm's drain move in flight on this host,
// and returns the func that forgets it.
func (s *Server) trackDrainMove(vm string, cancel context.CancelFunc) func() {
	s.drainMovesMu.Lock()
	if s.drainMoves == nil {
		s.drainMoves = map[string]context.CancelFunc{}
	}
	s.drainMoves[vm] = cancel
	s.drainMovesMu.Unlock()
	return func() {
		s.drainMovesMu.Lock()
		delete(s.drainMoves, vm)
		s.drainMovesMu.Unlock()
	}
}

// cancelDrainMove cancels vm's drain move in flight on this host, reporting
// whether there was one.
func (s *Server) cancelDrainMove(vm string) bool {
	s.drainMovesMu.Lock()
	cancel, ok := s.drainMoves[vm]
	s.drainMovesMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// drainOutcome is one VM's drain frame in words, for the record of a drain
// whose client went away.
func drainOutcome(p *pb.DrainProgress) string {
	switch {
	case p.Status == "done" && p.Error == "":
		return p.VmName + " moved to " + p.TargetHost
	case p.Status == "done":
		return p.VmName + " moved to " + p.TargetHost + ", " + p.Error
	case p.Error != "":
		return p.VmName + " " + p.Status + ": " + p.Error
	default:
		return p.VmName + " " + p.Status
	}
}

// drainEventResult is a drain frame's VM event result.
func drainEventResult(p *pb.DrainProgress) string {
	if p.Status == "done" && p.Error == "" {
		return "ok"
	}
	return "error"
}

// isDrainTimedOut reports whether p is the frame of a live move aborted at
// its migration policy's timeout.
func isDrainTimedOut(p *pb.DrainProgress) bool {
	return (p.Status == "failed" || p.Status == "error") && strings.HasPrefix(p.Error, drainTimedOutPrefix)
}

// drainAbortRetry is how often a drain sends again an abort of a live move
// that libvirt refused (drainLiveMigrate).
const drainAbortRetry = time.Second

// defaultDrainAbortGrace bounds how long a drain waits for libvirt to answer
// the abort of a timed-out live move (Server.drainAbortGrace overrides it).
const defaultDrainAbortGrace = 2 * time.Minute

func (s *Server) drainAbortGraceOrDefault() time.Duration {
	if s.drainAbortGrace > 0 {
		return s.drainAbortGrace
	}
	return defaultDrainAbortGrace
}

// liveStop is why a drain's live move was told to stop (drainLiveMigrate).
type liveStop int

const (
	liveNotStopped liveStop = iota // libvirt ended the move on its own
	liveTimedOut                   // it reached the VM's migration policy timeout
	liveAborted                    // `lv operation abort <vm> --force` cancelled it
	liveUnanswered                 // libvirt's call ended without an answer (errLibvirtCallUnanswered)
)

// drainLiveMigrate runs a drain's live move under the VM's migration policy
// timeout (timeoutSec, none when 0), as `lv migrate` does, and under ctx,
// which `lv operation abort <vm> --force` cancels (cancelDrainMove).
// MigrateToTarget takes no context, so a move past its timeout, or whose ctx
// ends, is aborted in libvirt (AbortMigration) and its outcome is waited for,
// for up to the abort grace: libvirt returns an error once the abort has
// taken, and the guest is still on this host; it returns nil when the
// cut-over completed before the abort could, and the guest runs on the target
// only. Either way the drain acts on what libvirt did, never on the timeout
// or the abort alone. stopped reports why the abort was sent when the guest
// stayed (or may still move, with pending); liveUnanswered when libvirt's
// call ended without an answer (errLibvirtCallUnanswered); liveNotStopped
// otherwise.
//
// When libvirt does not answer within the grace, pending is the channel its
// outcome will arrive on, and the caller hands it to a background owner: the
// move may still complete, so nothing else may act on it.
func (s *Server) drainLiveMigrate(ctx context.Context, name, dconnuri string, mp libvirt.MigrateParams, timeoutSec int32) (err error, stopped liveStop, pending <-chan error) {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("the move was aborted before libvirt started it: %w", cerr), liveAborted, nil
	}
	// The drain, or the background owner of pending, always gets an answer
	// (answerLibvirtCall).
	done := answerLibvirtCall(func() error { return s.virt.MigrateToTarget(name, dconnuri, mp) })
	var timeout <-chan time.Time
	if timeoutSec > 0 {
		timer := time.NewTimer(time.Duration(timeoutSec) * time.Second)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case err := <-done:
		if errors.Is(err, errLibvirtCallUnanswered) {
			// What libvirt did with the move is not known: no cold move
			// follows, and the guest is taken as still here.
			return err, liveUnanswered, nil
		}
		return err, liveNotStopped, nil
	case <-timeout:
		stopped = liveTimedOut
		slog.Warn("drain: live move reached its migration policy timeout; aborting the libvirt migration job",
			"vm", name, "timeout_sec", timeoutSec)
	case <-ctx.Done():
		stopped = liveAborted
		slog.Warn("drain: live move cancelled by admin; aborting the libvirt migration job", "vm", name)
	}
	aerr := s.virt.AbortMigration(name)
	if aerr != nil {
		slog.Error("drain: could not abort the live move; trying again while waiting for libvirt to end it",
			"vm", name, "error", aerr)
	}
	grace := time.NewTimer(s.drainAbortGraceOrDefault())
	defer grace.Stop()
	// An abort that reached libvirt before its migration job existed failed
	// ("no job is active"): it is sent again until one is taken.
	retry := time.NewTicker(drainAbortRetry)
	defer retry.Stop()
wait:
	for {
		select {
		case err = <-done:
			break wait
		case <-retry.C:
			if aerr != nil {
				aerr = s.virt.AbortMigration(name)
			}
		case <-grace.C:
			slog.Warn("drain: libvirt did not answer the abort of a live move; finishing it in the background",
				"vm", name, "grace", s.drainAbortGraceOrDefault(), "abort_error", aerr)
			return nil, stopped, done
		}
	}
	if err == nil {
		slog.Warn("drain: the live move completed before its abort took", "vm", name)
		return nil, liveNotStopped, nil
	}
	return err, stopped, nil
}

// condDrainMoveTimedOut names the VMs whose live move this host's last drain
// aborted at their migration policy's timeout. Raised by the drain, resolved
// by a drain that has none and by undrain.
const (
	condDrainMoveTimedOut = "drain_move_timed_out"
	drainEvaluator        = corrosion.DrainEvaluator
)

// drainTimeoutEvidence is drain_move_timed_out's evidence: the VMs it names,
// and what to do.
type drainTimeoutEvidence struct {
	VMs    []string `json:"vms"`
	Detail string   `json:"detail"`
}

// drainTimeoutsNamed is the VMs host's drain_move_timed_out names now.
func (s *Server) drainTimeoutsNamed(ctx context.Context, host string) []string {
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condDrainMoveTimedOut, "host", host)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return nil
	}
	var ev drainTimeoutEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) != nil {
		return nil
	}
	return ev.VMs
}

// judgeDrainTimeouts raises or resolves host's drain_move_timed_out after a
// drain of it (or an undrain). seen are the VMs this drain's live move timed
// out; full says the drain saw every move it started. A VM is named while its
// row is still on host. One already named whose move is still finishing in the
// background (its row migrating on host) stays named; a partial judgement
// never removes a name.
func (s *Server) judgeDrainTimeouts(ctx context.Context, host string, seen []string, full bool) {
	if s.db == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	s.drainCondMu.Lock()
	defer s.drainCondMu.Unlock()
	set := map[string]bool{}
	for _, v := range s.drainTimeoutsNamed(ctx, host) {
		if !full {
			set[v] = true
			continue
		}
		if row, err := corrosion.GetVM(ctx, s.db, v); err == nil && row != nil && row.HostName == host && row.State == "migrating" {
			set[v] = true
		}
	}
	for _, v := range seen {
		if row, err := corrosion.GetVM(ctx, s.db, v); err == nil && row != nil && row.HostName == host {
			set[v] = true
		}
	}
	s.writeDrainTimeouts(ctx, host, set)
}

// forgetDrainTimeout takes vm out of host's drain_move_timed_out: its move
// finished in the background and the guest left host.
func (s *Server) forgetDrainTimeout(ctx context.Context, host, vm string) {
	if s.db == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	s.drainCondMu.Lock()
	defer s.drainCondMu.Unlock()
	named := s.drainTimeoutsNamed(ctx, host)
	if !slices.Contains(named, vm) {
		return
	}
	// A host no longer draining (undrained meanwhile) owes no aborted move:
	// only VMs still in flight there stay named. Read from this replica: one
	// that has not yet seen the undrain keeps the aborted names, and an
	// undrain served elsewhere that still sees a stale migrating row writes
	// nothing, so under replication lag they can stay named until the next
	// drain or undrain of the host. Cosmetic: no VM is moved by the condition.
	draining := true
	if h, err := corrosion.GetHost(ctx, s.db, host); err == nil && h != nil && h.State != "draining" {
		draining = false
	}
	set := map[string]bool{}
	for _, v := range named {
		if v == vm {
			continue
		}
		if !draining {
			row, err := corrosion.GetVM(ctx, s.db, v)
			if err != nil || row == nil || row.HostName != host || row.State != "migrating" {
				continue
			}
		}
		set[v] = true
	}
	s.writeDrainTimeouts(ctx, host, set)
}

// writeDrainTimeouts writes host's drain_move_timed_out naming set (resolved
// when empty). drainCondMu is held.
func (s *Server) writeDrainTimeouts(ctx context.Context, host string, set map[string]bool) {
	vms := make([]string, 0, len(set))
	for v := range set {
		vms = append(vms, v)
	}
	sort.Strings(vms)
	evidence := ""
	if len(vms) > 0 {
		b, _ := json.Marshal(drainTimeoutEvidence{VMs: vms, Detail: fmt.Sprintf(
			"the live move of %s off %s did not finish within its migration policy's timeout_sec and was aborted; "+
				"each keeps running on %s, unless libvirt did not answer its abort and the move is finishing in the background "+
				"(see its drain result and `lv events <vm>`). Raise the timeout, move each with `lv migrate <vm> <target-host>`, or stop it and drain again",
			strings.Join(vms, ", "), host, host)})
		evidence = string(b)
	}
	s.setHostConditionOf(ctx, drainEvaluator, condDrainMoveTimedOut, host, len(vms) > 0, corrosion.SeverityWarning, evidence)
}

// runDrainPostMigrate runs the post_migrate hook of a drain whose live attempt
// ran pre_migrate but did not end in a live cut-over (finishMigrationOnTarget
// runs it for that one), so every pre_migrate is followed by exactly one
// post_migrate naming the VM's final host and state. Detached: the drain's
// request going away must not skip it.
func (s *Server) runDrainPostMigrate(ctx context.Context, pbVM *pb.VM, hspec *pb.HooksSpec, host string, state pb.VMState) {
	pbVM.HostName, pbVM.State = host, state
	hooks.Run(context.WithoutCancel(ctx), hooks.PostMigrate, pbVM, hspec)
}

// drainVMStateHere is the state of a VM a drain left on this host, from its
// row (running when it cannot be read: the drain found it running).
func (s *Server) drainVMStateHere(ctx context.Context, name string) pb.VMState {
	if cur, err := corrosion.GetVM(context.WithoutCancel(ctx), s.db, name); err == nil && cur != nil {
		return vmStateToPB(cur.State)
	}
	return pb.VMState_VM_RUNNING
}

// UndrainHost returns a host from draining/maintenance to active.
func (s *Server) UndrainHost(ctx context.Context, req *pb.UndrainHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	if err := s.hostOperatorWriteAllowed(ctx, "undrain", req.Name); err != nil {
		return nil, err
	}

	if err := s.undrainFrom(ctx, req.Name, h.State); err != nil {
		return nil, err
	}
	// The host is no longer being drained: a move its drain timed out is no
	// longer owed (one still finishing in the background stays named).
	s.undrainJudge(ctx, req.Name)
	s.publish("host.undrained", req.Name, "")
	s.audit(ctx, "host.undrain", req.Name, "", "ok")
	reply, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}
	// Moves back, in the background, the VMs a drain moved away that opted in
	// to returning (failback.go), and says so in the reply.
	s.autoFailback(ctx, req.Name, reply)
	return reply, nil
}

// undrainPingTimeout bounds the Ping undrain sends a host recorded
// 'upgrading'.
const undrainPingTimeout = 5 * time.Second

// undrainRestarting records active a host recorded 'upgrading', only if its
// daemon answers a Ping. A host that answers serves but did not record itself
// active (upgrading_unconfirmed), and recording it active is the remedy. One
// that does not answer is still restarting: recording it active would end its
// restart allowance, and the failover coordinator would fence it on the
// failing run left from its stop (lab 1, 2026-10-17). It turns active by
// itself once it serves (hostboot.ConfirmServing). The write is made only
// while the host is still recorded 'upgrading'.
func (s *Server) undrainRestarting(ctx context.Context, host string) error {
	if host != s.hostName {
		if err := s.pingHost(ctx, host); err != nil {
			age := ""
			if since, ok, serr := corrosion.HostStateSince(ctx, s.db, host); serr == nil && ok {
				age = fmt.Sprintf(" (recorded upgrading %s ago)", time.Since(since).Round(time.Second))
			}
			return status.Errorf(codes.FailedPrecondition,
				"%s is restarting%s and its daemon does not answer yet (%v); it turns active by itself once its daemon serves",
				host, age, err)
		}
	}
	applied, err := corrosion.UpdateHostStateFrom(ctx, s.db, host, "upgrading", "active")
	if err != nil {
		return status.Errorf(codes.Internal, "update host state: %v", err)
	}
	if applied {
		return nil
	}
	h, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil || h == nil {
		return status.Errorf(codes.NotFound, "host %q not found", host)
	}
	if h.State == "active" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s is now recorded %s; run 'lv host undrain %s' again if it should be active", host, h.State, host)
}

// pingHost reports whether host's daemon answers a Ping as host. An answer
// in another host's name (a misaddressed peer, or a node that dials itself
// behind NAT) is not one.
func (s *Server) pingHost(ctx context.Context, host string) error {
	pctx, cancel := context.WithTimeout(ctx, undrainPingTimeout)
	defer cancel()
	c, closeConn, err := s.dialPeer(pctx, host)
	if err != nil {
		return err
	}
	defer closeConn()
	resp, err := c.Ping(pctx, &pb.PingRequest{})
	if err != nil {
		return err
	}
	if got := resp.GetHostName(); got != host {
		return fmt.Errorf("the daemon at its address answered as %q", got)
	}
	return nil
}

// undrainAttempts bounds how often undrainFrom re-reads a state that changed
// under its write.
const undrainAttempts = 3

// undrainStateWrite is undrainFrom's conditional write; a var so a test can
// make the state change under every write.
var undrainStateWrite = corrosion.UpdateHostStateFrom

// undrainFrom records host active, read as `from`. The write is made only
// while the host is still recorded so, and on a miss the state is read again:
// a SIGTERM's 'upgrading' write landing after the read is not overwritten,
// and goes through undrainRestarting instead.
func (s *Server) undrainFrom(ctx context.Context, host, from string) error {
	for i := 0; i < undrainAttempts; i++ {
		if from == "upgrading" {
			return s.undrainRestarting(ctx, host)
		}
		applied, err := undrainStateWrite(ctx, s.db, host, from, "active")
		if err != nil {
			return status.Errorf(codes.Internal, "update host state: %v", err)
		}
		if applied {
			return nil
		}
		h, err := corrosion.GetHost(ctx, s.db, host)
		if err != nil || h == nil {
			return status.Errorf(codes.NotFound, "host %q not found", host)
		}
		from = h.State
	}
	return status.Errorf(codes.Aborted, "%s's state kept changing while undrain wrote it; run 'lv host undrain %s' again", host, host)
}

// SetHostLabels sets or removes labels on a host.
func (s *Server) SetHostLabels(ctx context.Context, req *pb.SetHostLabelsRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	if err := s.hostOperatorWriteAllowed(ctx, "label", req.Name); err != nil {
		return nil, err
	}

	// Load existing labels from DB, merge, then remove requested keys.
	labels := map[string]string{}
	rows, err := s.db.Query(ctx, `SELECT labels FROM hosts WHERE name = ?`, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load host labels: %v", err)
	}
	if len(rows) > 0 {
		if raw := rows[0].String("labels"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &labels)
		}
	}
	for k, v := range req.Labels {
		labels[k] = v
	}
	for _, k := range req.Remove {
		delete(labels, k)
	}

	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal labels: %v", err)
	}

	if err := s.db.Execute(ctx,
		`UPDATE hosts SET labels = ?, updated_at = ? WHERE name = ?`,
		string(labelsJSON), s.db.NowTS(), req.Name,
	); err != nil {
		return nil, status.Errorf(codes.Internal, "update labels: %v", err)
	}

	slog.Info("host labels updated", "host", req.Name, "labels", labels)
	s.publish("host.labels", req.Name, string(labelsJSON))
	s.audit(ctx, "host.labels", req.Name, string(labelsJSON), "ok")

	return s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
}

// recordFence writes a fence row and the host state it records as one
// replicated entry. If the combined write fails it falls back to the two
// writes separately, as the coordinator does: the state is required (its
// failure is the RPC's error), the row is best effort.
func (s *Server) recordFence(ctx context.Context, rec corrosion.FenceLogRecord, state string) error {
	if err := corrosion.RecordFenceWithState(ctx, s.db, rec, state); err == nil {
		return nil
	} else {
		slog.Warn("fence: write fence_log and host state together", "host", rec.HostName, "state", state, "error", err)
	}
	if err := corrosion.UpdateHostState(ctx, s.db, rec.HostName, state); err != nil {
		return status.Errorf(codes.Internal, "update host state: %v", err)
	}
	if err := corrosion.InsertFenceLog(ctx, s.db, rec); err != nil {
		slog.Warn("fence log insert failed", "error", err)
	}
	return nil
}

// fenceExecutorFunc is the shape of fence.Execute.
type fenceExecutorFunc = func(context.Context, fence.HostConfig) fence.Result

// fenceExecutor is the fence an operator's FenceHost runs: fence.Execute,
// unless a test injected another (SetFenceExecutor).
func (s *Server) fenceExecutor() func(context.Context, fence.HostConfig) fence.Result {
	if s.fenceExec != nil {
		return s.fenceExec
	}
	return fence.Execute
}

// SetFenceSSH wires this host's managed fence SSH agent (internal/fencessh).
func (s *Server) SetFenceSSH(a *fencessh.Agent) { s.fenceSSH = a }

// fenceSSHPath is how an SSH fence from this node reaches target: decided
// by the agent from target's verified host_fence_ssh row, or the legacy path
// when no agent is wired.
func (s *Server) fenceSSHPath(ctx context.Context, target string) fence.SSHFence {
	if s.fenceSSH == nil {
		return fence.SSHFence{}
	}
	return s.fenceSSH.FenceConfig(ctx, target)
}

// SetFenceExecutor replaces the fence FenceHost runs. For tests: the fleet
// harness has no machines to power off.
func (s *Server) SetFenceExecutor(fn func(context.Context, fence.HostConfig) fence.Result) {
	s.fenceExec = fn
}

// FenceHost forcibly powers off a host via SSH poweroff, then marks it offline.
// If the host has IPMI configured, ipmitool is preferred over SSH.
//
// A fence that succeeds is authority for automatic recovery: if a quorum also
// sees the host down and the fence still stands, the failover coordinator
// resumes recovery of its workloads from this record, as it would from its
// own fence (failover recordedFence / resumeActionFor), and the host is not put
// back in service automatically afterwards — `lv host undrain`, or its own
// reboot, brings it back.
func (s *Server) FenceHost(ctx context.Context, req *pb.FenceHostRequest) (*pb.FenceResult, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if !req.Confirmed {
		return nil, status.Error(codes.InvalidArgument, "pass --confirmed to fence a host")
	}

	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	if h == nil || h.State == "removed" {
		// A removed host can still be running: `lv host rm --force` asks for
		// no fence, and a host whose daemon died may still run its qemu on a
		// shared disk. Its confirmation is what lets a promotion reattach that
		// disk (sharedReattachVerdict, review R3-I2), so it is accepted here.
		// Nothing else is: there is nothing left to fence it by.
		return s.confirmRemovedHostFence(ctx, req, h)
	}

	// confirm_manual_only path: operator has already powered the host off
	// (or otherwise ensured it's not running workloads) and is now telling
	// the cluster to clear the manual-fence-pending state so the failover
	// coordinator can reschedule its VMs. We do NOT execute a fence here.
	if req.ConfirmManualOnly {
		if err := s.refuseFenceConfirmOfLiveHost(ctx, req.Name); err != nil {
			return nil, err
		}
		// The 'fenced' state and the confirmation row are one replicated entry
		// (RecordFenceWithState), so no peer holds a 'fenced' state whose proof
		// has not arrived — corrosion.HostProvedOff reads them together.
		if err := s.recordFence(ctx, corrosion.FenceLogRecord{
			ID:       randid.New(),
			HostName: req.Name,
			Method:   "manual",
			Result:   "manual-confirmed",
			Detail:   "operator confirmation via FenceHost(confirm_manual_only)",
		}, "fenced"); err != nil {
			return nil, err
		}
		slog.Warn("manual fence confirmed by operator", "host", req.Name)
		s.publish("host.fence-confirmed", req.Name, "manual")
		s.audit(ctx, "host.fence-confirm", req.Name,
			"operator confirmed manual fence", "manual-confirmed")
		// Deliberately narrow wording. This unblocks the flow where the COORDINATOR
		// fenced (manual / best-effort strategy) and is waiting on confirmation
		// before it reschedules (resumeFromConfirmation needs a fence attempt the
		// cluster itself made). A confirmation with no attempt behind it moves
		// nothing by itself — FenceHost never enumerates workloads — so
		// promising a reschedule here would be false in exactly the case an
		// operator is most likely to be in.
		//
		// A genuinely failed host does not need this: peers observe it by health
		// quorum and the coordinator runs the whole fence-and-relocate sequence
		// itself. For PLANNED removal, `lv host drain` is the tool — it migrates
		// workloads off before the host goes away.
		return &pb.FenceResult{
			HostName: req.Name,
			Method:   "manual",
			Result:   "manual-confirmed",
			Detail: "operator confirmation recorded; a coordinator waiting on this confirmation may now reschedule. " +
				"This does not itself move workloads — for planned removal use `lv host drain " + req.Name + "` first",
		}, nil
	}

	fr := s.fenceExecutor()(ctx, fence.HostConfig{
		Name:          h.Name,
		Address:       h.Address,
		SSHUser:       h.SSHUser,
		SSHPort:       h.SSHPort,
		FenceStrategy: h.FenceStrategy,
		IPMIAddress:   h.IPMIAddress,
		IPMIUser:      h.IPMIUser,
		IPMIPass:      h.IPMIPass,
		Redfish:       h.Redfish,
		WatchdogDev:   h.WatchdogDev,
		// A retired credential is reported, never sent as an empty password.
		IPMICredentialRetired: h.IPMIPassRetired,
		// Only a fence aimed at THIS node may use the watchdog strategy; it arms
		// the caller's own device. Everything else is unaffected.
		IsSelf: h.Name == s.hostName,
		SSH:    s.fenceSSHPath(ctx, h.Name),
	})

	method := fr.Method
	detail := fr.Detail
	result := fr.LogResult()
	if !fr.Success {
		detail = fmt.Sprintf("fence failed (%s); host marked offline in state", fr.Detail)
	}
	// The physical fence went through THIS node's row, which may lag a
	// re-admission: say which incarnation it aimed at, so an operator can
	// re-run it on a caught-up node (host_incarnation.go).
	detail += fenceTargetNote(ctx, s.db, h)

	// Mark it offline regardless of fence success, and record the fence, in
	// ONE replicated entry (RecordFenceWithState). A successful operator fence
	// of a host a quorum also sees down is authority the failover coordinator
	// resumes a recovery from (recordedFence: 'offline' with a successful
	// newest attempt), and two separate entries made that a race: a leader
	// cycle between them saw 'offline' with no successful row, cached the
	// host as handled, and never looked again. Together, every peer holds
	// both or neither (colonelpanik/litevirt#253).
	if err := s.recordFence(ctx, corrosion.FenceLogRecord{
		ID:       randid.New(),
		HostName: req.Name,
		Method:   method,
		Result:   result,
		Detail:   detail,
	}, "offline"); err != nil {
		return nil, err
	}

	slog.Warn("host fenced", "host", req.Name, "method", method, "result", result)
	s.publish("host.fenced", req.Name, fmt.Sprintf("method=%s result=%s", method, result))
	s.audit(ctx, "host.fence", req.Name, detail, result)

	return &pb.FenceResult{
		HostName: req.Name,
		Method:   method,
		Result:   result,
		Detail:   detail,
	}, nil
}

// confirmRemovedHostFence is FenceHost for a host that has been removed from
// the cluster (h is nil for a tombstoned row). Only an operator's
// confirmation is accepted, and it writes the manual-confirmed fencing_log
// row alone — no membership state: the host is no longer a member, and a
// state write would bring its row back. fencing_log rows outlive the
// tombstone, so corrosion.FenceRecordProvesOff reads it like any other
// confirmation. A name this replica holds no row for at all is unknown, not
// removed, and stays NotFound: a typo must not mint a proof.
func (s *Server) confirmRemovedHostFence(ctx context.Context, req *pb.FenceHostRequest, h *corrosion.HostRecord) (*pb.FenceResult, error) {
	if h == nil {
		removed, err := corrosion.HostRemoved(ctx, s.db, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read host %q: %v", req.Name, err)
		}
		if !removed {
			return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
		}
	}
	if !req.ConfirmManualOnly {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has been removed, so there is nothing left to fence it by; once it is powered off, "+
				"`lv host fence-confirm %s` records that", req.Name, req.Name)
	}
	if err := corrosion.InsertFenceLog(ctx, s.db, corrosion.FenceLogRecord{
		ID:       randid.New(),
		HostName: req.Name,
		Method:   "manual",
		Result:   "manual-confirmed",
		Detail:   "operator confirmation via FenceHost(confirm_manual_only) of a removed host",
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "record the confirmation: %v", err)
	}
	slog.Warn("manual fence of a removed host confirmed by operator", "host", req.Name)
	s.publish("host.fence-confirmed", req.Name, "manual")
	s.audit(ctx, "host.fence-confirm", req.Name,
		"operator confirmed manual fence of a removed host", "manual-confirmed")
	return &pb.FenceResult{
		HostName: req.Name,
		Method:   "manual",
		Result:   "manual-confirmed",
		// Review R4-m1: the confirmation is also the proof-grade fence that
		// lets the failover coordinator recover, under recovery claims, every
		// workload still recorded on the removed host (recoverRemovedHosts),
		// and that can come before the operator's own promotion.
		Detail: "operator confirmation of a removed host recorded; a promotion made from now on may reattach " +
			"a shared disk it owned. With recovery claims enforced, the failover coordinator may now also recover " +
			"every workload still recorded on " + req.Name + " under its failure policy, possibly before a promotion you run",
	}, nil
}

// ConfigureHost updates host fencing and IPMI configuration.
func (s *Server) ConfigureHost(ctx context.Context, req *pb.ConfigureHostRequest) (*pb.Host, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil || h == nil {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	if err := s.hostOperatorWriteAllowed(ctx, "configure", req.Name); err != nil {
		return nil, err
	}

	// Validate fence strategy if provided.
	//
	// The set must match what internal/fence actually implements. It did not:
	// "manual" and "best-effort" are both real strategies (fence.Execute
	// dispatches them, and the failover coordinator has explicit handling for
	// each), but ConfigureHost rejected them — so the ONE strategy whose whole
	// purpose is operator-confirmed rescheduling could not be configured through
	// the CLI at all, and "best-effort" (the default for hosts created before this
	// field existed) could not be restored once changed away from.
	if req.FenceStrategy != "" {
		switch req.FenceStrategy {
		case "ssh", "ipmi", "redfish", "watchdog", "manual", "best-effort":
		default:
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid fence strategy %q (valid: ssh, ipmi, redfish, watchdog, manual, best-effort)", req.FenceStrategy)
		}
	}

	// The Redfish settings: what this request does to them, decided and
	// validated before anything is written or any release gate is taken.
	redfish, err := planRedfishChange(h, req)
	if err != nil {
		return nil, err
	}

	// clear_ipmi removes the IPMI address, user and password, which an empty
	// field cannot: empty means "leave alone". It is refused with any ipmi_*
	// value beside it (set or clear, not both), and when it would leave the
	// host fencing by "ipmi" with nothing to authenticate with — every fence
	// would fail. And it needs this node's credentials_split_v1 gate open:
	// readers take the live credential row whenever one exists, a closed gate
	// cannot write it, and an empty old column is never absorbed into one
	// (credentials_absorb.go), so a latched peer would go on serving the
	// password this was meant to remove.
	if req.ClearIpmi {
		if req.IpmiAddress != "" || req.IpmiUser != "" || req.IpmiPass != "" {
			return nil, status.Error(codes.InvalidArgument,
				"clear_ipmi cannot be combined with ipmi_address, ipmi_user or ipmi_pass")
		}
		strategy := h.FenceStrategy
		if req.FenceStrategy != "" {
			strategy = req.FenceStrategy
		}
		if strategy == "ipmi" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"host %q fences by ipmi; clearing its IPMI settings would fail every fence. "+
					"Set another fence strategy in the same request", req.Name)
		}
		if !s.db.MayWriteCredentialTables() {
			return nil, status.Error(codes.FailedPrecondition,
				"IPMI settings cannot be cleared until credentials_split_v1 has latched on this node "+
					"(a peer's credential row would keep the password); retry once the upgrade completes")
		}
	}

	// Validate role if provided (side-effecting: refuse witness promotion with VMs).
	if req.Role != "" {
		switch req.Role {
		case "worker", "witness":
		default:
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid host role %q (valid: worker, witness)", req.Role)
		}
		if req.Role == "witness" {
			vms, err := corrosion.ListVMs(ctx, s.db, "", req.Name)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list vms on %s: %v", req.Name, err)
			}
			if len(vms) > 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"host %q still has %d VM(s); drain before promoting to witness",
					req.Name, len(vms))
			}
		}
	}

	// Under region-scoped failover a host's region decides whose votes may fence
	// it, so relabelling one is a change to two regions' voter sets. Made from
	// one side of a partition, it would let that side count hosts on the other
	// as its own and fence them. Same precondition as changing the policy: every
	// voter reachable. A policy that cannot be read refuses.
	if req.Region != "" && req.Region != h.Region {
		scope, err := corrosion.GetFailoverScope(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot read the failover scope, so a region change cannot be shown safe: %v", err)
		}
		if scope.Region() {
			missing, err := s.unreachableVoters(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "check voters are reachable: %v", err)
			}
			if len(missing) > 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"failover is region-scoped, so a host's region decides who may fence it, and a region "+
						"can only be changed while every voter is reachable; %s cannot reach %s",
					s.hostName, strings.Join(missing, ", "))
			}
		}
	}

	// One CONSTANT statement (compile-time visible to the ledger / replication apply path)
	// instead of a dynamically-assembled SET list: each field is COALESCE(?, col), so an
	// unspecified field (NULL param) keeps its current value and is never clobbered, while a
	// specified field is set. Order must match configureHostSQL. hosts is replicated, so
	// updated_at is the monotonic LWW key.
	fields := []string{
		req.FenceStrategy, req.IpmiAddress, req.IpmiUser, req.IpmiPass,
		req.WatchdogDev, req.Role, req.Region,
	}
	args := make([]interface{}, 0, len(fields)+2)
	provided := 0
	for i, f := range fields {
		// A clear binds '' to the three IPMI columns, which COALESCE keeps:
		// the statement's shape is unchanged, and every reader treats an
		// empty value as "not configured".
		if req.ClearIpmi && i >= 1 && i <= 3 {
			args = append(args, "")
			provided++
			continue
		}
		if f == "" {
			args = append(args, nil)
			continue
		}
		args = append(args, f)
		provided++
	}
	// Capacity overrides are numeric, so "" cannot mean unset — they are proto
	// `optional` and a nil pointer is what leaves the column alone. A ratio of 0
	// and a NEGATIVE reserve both mean "clear back to the cluster default"; a
	// reserve of exactly 0 is a real setting (hand guests everything), which is
	// why it could not double as the unset sentinel.
	if v := req.CpuOvercommit; v != nil {
		args, provided = append(args, *v), provided+1
	} else {
		args = append(args, nil)
	}
	if v := req.MemOvercommit; v != nil {
		args, provided = append(args, *v), provided+1
	} else {
		args = append(args, nil)
	}
	if v := req.CpuReserve; v != nil {
		args, provided = append(args, int(*v)), provided+1
	} else {
		args = append(args, nil)
	}
	if v := req.MemReserveMib; v != nil {
		args, provided = append(args, int(*v)), provided+1
	} else {
		args = append(args, nil)
	}

	hostsProvided := provided
	if redfish.touched {
		provided++
	}
	if provided == 0 {
		return nil, status.Error(codes.InvalidArgument, "no fields to update")
	}
	now := s.db.NowTS()
	args = append(args, now, req.Name)

	// Once credentials_split_v1 has latched, a supplied IPMI password is ALSO
	// written to the host's sensitive-lane credential row, in the same batch
	// and under the same updated_at. hosts.ipmi_pass keeps it too until
	// credentials_clear_v1 latches: a host on a build before credentials_split_v1
	// reads that column and nothing else (docs/design/credentials-clear.md). Before
	// the latch no node may write the credential table (a previous-release
	// peer cannot decode it), so the password goes to hosts.ipmi_pass alone.
	// err is reused from the host lookup above.
	// A clear writes an empty password to the credential row the same way
	// (checked above that the gate is open): a live row with no secret, which
	// readers serve as "none".
	//
	// Once credentials_clear_v1 has latched as well, the old column gets ''
	// instead of the password, in the same statement shape: nothing reads it
	// any more, and the operator-safe dump must not carry it.
	ipmiCredential := (req.IpmiPass != "" || req.ClearIpmi) && s.db.MayWriteCredentialTables()
	if ipmiCredential && req.IpmiPass != "" && s.db.MayClearCredentialColumns() {
		args[3] = ""
	}
	switch {
	case redfish.gated:
		// A 'redfish' strategy and the Redfish row are the release feature
		// redfish_fence's data: a previous-release peer cannot decode the row
		// and would fence a 'redfish' host as best-effort SSH. Written through
		// the gate on this node, which refuses (FailedPrecondition) until
		// release_2026_11_v1 has latched and records the use first. The hosts
		// write, the IPMI credential and the Redfish row are one batch under
		// one updated_at.
		err = s.WithReleaseFeature(ctx, capabilities.FeatureRedfishFence,
			func(ctx context.Context, g capabilities.FeatureGrant) error {
				if gerr := g.Check(capabilities.FeatureRedfishFence); gerr != nil {
					return gerr
				}
				batch := []corrosion.Statement{}
				if hostsProvided > 0 {
					batch = append(batch, corrosion.Statement{SQL: configureHostSQL, Params: args})
				}
				if ipmiCredential {
					batch = append(batch, corrosion.Statement{
						SQL: corrosion.HostFenceCredentialUpsertSQL, Params: []interface{}{req.Name, req.IpmiPass, now}})
				}
				if redfish.write {
					st, serr := hostFenceRedfishStatement(g, req.Name, redfish.cfg, now)
					if serr != nil {
						return serr
					}
					batch = append(batch, st)
				}
				return s.db.ExecuteBatch(ctx, batch)
			})
		if err != nil {
			if _, ok := status.FromError(err); ok {
				return nil, err
			}
			return nil, configureHostError(err)
		}
	case hostsProvided == 0:
		// Only a --clear-redfish of a host with no Redfish settings: there is
		// nothing to clear, and nothing to record.
	case ipmiCredential:
		err = s.db.ExecuteBatch(ctx, []corrosion.Statement{
			{SQL: configureHostSQL, Params: args},
			{SQL: corrosion.HostFenceCredentialUpsertSQL, Params: []interface{}{req.Name, req.IpmiPass, now}},
		})
	default:
		err = s.db.Execute(ctx, configureHostSQL, args...)
	}
	if err != nil {
		return nil, configureHostError(err)
	}

	slog.Info("host configured", "host", req.Name)
	s.audit(ctx, "host.configure", req.Name, fmt.Sprintf("fields=%d", provided), "ok")

	return s.InspectHost(ctx, &pb.InspectHostRequest{Name: req.Name})
}

// configureHostError is the status of a failed ConfigureHost write. A
// password this node's replica cannot set (its hosts row predates the host's
// current admission) is the operator's to retry elsewhere or later.
func configureHostError(err error) error {
	if errors.Is(err, corrosion.ErrHostRowBehindAdmission) {
		return status.Errorf(codes.FailedPrecondition, "update host config: %v", err)
	}
	return status.Errorf(codes.Internal, "update host config: %v", err)
}

// redfishChange is what one ConfigureHost does to a host's Redfish settings.
type redfishChange struct {
	// touched: the request named a redfish_* field or clear_redfish.
	touched bool
	// gated: the write goes through the redfish_fence release gate — it
	// writes the Redfish row, or sets fence_strategy to "redfish".
	gated bool
	// write: the Redfish row is written, to set (cfg non-nil) or clear (nil).
	write bool
	cfg   *fence.RedfishConfig
}

// planRedfishChange decides and validates what req does to h's Redfish
// settings. A request that names some of them keeps the rest (an empty field
// means "leave alone", as for ipmi_*). A host left fencing by "redfish" must
// have an endpoint, a user and a password to fence with: refused here, at
// configuration time, rather than discovered by the first fence of an outage.
func planRedfishChange(h *corrosion.HostRecord, req *pb.ConfigureHostRequest) (redfishChange, error) {
	named := req.RedfishEndpoint != "" || req.RedfishUser != "" || req.RedfishPass != "" ||
		req.RedfishSystemId != "" || req.RedfishAuth != "" || req.RedfishCaPem != "" ||
		req.ClearRedfishSystemId || req.ClearRedfishCa
	if req.ClearRedfishSystemId && req.RedfishSystemId != "" {
		return redfishChange{}, status.Error(codes.InvalidArgument,
			"clear_redfish_system_id cannot be combined with redfish_system_id")
	}
	if req.ClearRedfishCa && req.RedfishCaPem != "" {
		return redfishChange{}, status.Error(codes.InvalidArgument,
			"clear_redfish_ca cannot be combined with redfish_ca_pem")
	}
	strategy := h.FenceStrategy
	if req.FenceStrategy != "" {
		strategy = req.FenceStrategy
	}
	var ch redfishChange
	ch.touched = named || req.ClearRedfish
	cur := h.Redfish
	switch {
	case req.ClearRedfish:
		if named {
			return ch, status.Error(codes.InvalidArgument,
				"clear_redfish cannot be combined with a redfish_* field")
		}
		if strategy == "redfish" {
			return ch, status.Errorf(codes.FailedPrecondition,
				"host %q fences by redfish; clearing its Redfish settings would fail every fence. "+
					"Set another fence strategy in the same request", req.Name)
		}
		// Nothing to clear is not a write: a cluster that never used the
		// feature is not made to record a use for it.
		if cur.Configured() {
			ch.write, ch.gated = true, true
		}
		return ch, nil
	case named:
		if req.RedfishEndpoint != "" {
			cur.Endpoint = req.RedfishEndpoint
		}
		if req.RedfishUser != "" {
			cur.User = req.RedfishUser
		}
		if req.RedfishPass != "" {
			cur.Pass = req.RedfishPass
		}
		if req.RedfishSystemId != "" {
			cur.SystemID = req.RedfishSystemId
		}
		if req.ClearRedfishSystemId {
			cur.SystemID = ""
		}
		if req.RedfishAuth != "" {
			cur.Auth = req.RedfishAuth
		}
		if req.RedfishCaPem != "" {
			cur.CACert = req.RedfishCaPem
		}
		if req.ClearRedfishCa {
			cur.CACert = ""
		}
		if err := fence.ValidateRedfishConfig(cur); err != nil {
			return ch, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if !cur.Configured() {
			return ch, status.Error(codes.InvalidArgument,
				"Redfish settings need redfish_endpoint (https://host[:port])")
		}
		c := cur
		ch.write, ch.gated, ch.cfg = true, true, &c
	}
	if strategy == "redfish" && (req.FenceStrategy == "redfish" || named) {
		if !cur.Configured() || cur.User == "" || cur.Pass == "" {
			return ch, status.Errorf(codes.FailedPrecondition,
				"host %q cannot fence by redfish without a Redfish endpoint, user and password; "+
					"set redfish_endpoint, redfish_user and redfish_pass in the same request", req.Name)
		}
	}
	if req.FenceStrategy == "redfish" {
		ch.gated = true
	}
	return ch, nil
}

// hostFenceRedfishStatement is the statement that sets host's Redfish settings
// to cfg or, for cfg nil, clears them (a tombstone with every field empty). It
// is redfish_fence's data, so it takes the feature's grant. updatedAt is the
// batch's clock, shared with the hosts write beside it.
func hostFenceRedfishStatement(g capabilities.FeatureGrant, host string, cfg *fence.RedfishConfig, updatedAt string) (corrosion.Statement, error) {
	if err := g.Check(capabilities.FeatureRedfishFence); err != nil {
		return corrosion.Statement{}, err
	}
	if cfg == nil {
		return corrosion.Statement{SQL: corrosion.HostFenceRedfishClearSQL,
			Params: []interface{}{updatedAt, updatedAt, host}}, nil
	}
	return corrosion.Statement{SQL: corrosion.HostFenceRedfishUpsertSQL, Params: []interface{}{
		host, cfg.Endpoint, cfg.User, cfg.Pass, cfg.SystemID, cfg.Auth, cfg.CACert, updatedAt,
	}}, nil
}

// configureHostSQL is the single fixed shape ConfigureHost emits. COALESCE(?, col) keeps a
// field's current value when its param is NULL (field not supplied), so a partial update
// touches only the supplied fields without a dynamic SET list.
const configureHostSQL = `UPDATE hosts SET ` +
	`fence_strategy = COALESCE(?, fence_strategy), ` +
	`ipmi_address = COALESCE(?, ipmi_address), ` +
	`ipmi_user = COALESCE(?, ipmi_user), ` +
	`ipmi_pass = COALESCE(?, ipmi_pass), ` +
	`watchdog_dev = COALESCE(?, watchdog_dev), ` +
	`role = COALESCE(?, role), ` +
	`region = COALESCE(?, region), ` +
	`cpu_overcommit = COALESCE(?, cpu_overcommit), ` +
	`mem_overcommit = COALESCE(?, mem_overcommit), ` +
	`cpu_reserve = COALESCE(?, cpu_reserve), ` +
	`mem_reserve_mib = COALESCE(?, mem_reserve_mib), ` +
	`updated_at = ? ` +
	`WHERE name = ?`

// RemoveHost removes a host from the cluster. If force is false and the host
// has running VMs, the request is rejected. CRL revocation is handled here.
func (s *Server) RemoveHost(ctx context.Context, req *pb.RemoveHostRequest) (*pb.RemoveHostResponse, error) {
	h, key, err := s.removeHostRefusal(ctx, req)
	if err != nil {
		return nil, err
	}
	incarnation := key.N

	if hook := s.removeHostBeforeDeleteHook; hook != nil {
		hook(req.Name)
	}
	// Soft-delete the host and clean up related records, only while its row
	// is still the admission the checks above passed: a removal and a
	// re-admission of the name, or a certificate renewal, may have landed
	// since, and the new machine is not this removal's to delete.
	//
	// Once the release token has latched, every host this one replicates to
	// knows the removal that names the certificate serial it ends, so a
	// receiver that holds a later admission of the name never ends it
	// (corrosion.DeleteHostAdmissionIf). Before, the previous shape, which
	// every receiver applies as it always has. A row that records no serial
	// (the schema allows '') has none to name, and is removed in the previous
	// shape too.
	var applied bool
	if s.ReleaseTokenLatched() && h.CertSerial != "" {
		applied, err = corrosion.DeleteHostAdmissionIf(ctx, s.db, req.Name, h.CertSerial, key)
	} else {
		applied, err = corrosion.DeleteHostIf(ctx, s.db, req.Name, h.CertSerial, key)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete host: %v", err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s's row changed while it was being removed (it was serial %s at incarnation %d, admitted %s); nothing was removed. "+
				"Check `lv host inspect %s`, and run `lv host rm` again if it is still to go",
			req.Name, h.CertSerial, incarnation, key.At, req.Name)
	}

	slog.Warn("host removed from cluster", "host", req.Name, "cert_serial", h.CertSerial, "incarnation", incarnation)
	s.publish("host.removed", req.Name, "cert_serial="+h.CertSerial)
	// Only the raising host resolves its held-line conditions, and a removed
	// one never will.
	if err := corrosion.ResolveSpecEditHeldOfHost(ctx, s.db, req.Name); err != nil {
		slog.Warn("could not resolve a removed host's held-spec-edit conditions", "host", req.Name, "error", err)
	}

	return &pb.RemoveHostResponse{CertSerial: h.CertSerial, Incarnation: incarnation}, nil
}

// PreflightRemoveHost runs every refusal RemoveHost would give req and
// removes nothing. `lv host rm` asks it before it revokes the host's
// certificate: the revocation is not undone by a refusal that follows it.
//
// For a request naming an expected certificate serial that the row of the
// name does not hold here (no row, or another admission's), it runs a
// removal's gates anyway (admin, caught up, voter majority, a pull of the
// hosts table) and answers on the pulled table: the ordinary refusals when
// the row now holds the serial, and otherwise, when no live row holds it, a
// refusal marked apimeta.AdmissionAbsentReason (NotFound with no row of the
// name, FailedPrecondition with another admission's). That mark is what
// `lv host rm <host> --serial <serial>` needs before it revokes a serial no
// row holds.
func (s *Server) PreflightRemoveHost(ctx context.Context, req *pb.RemoveHostRequest) (*emptypb.Empty, error) {
	if want := req.GetExpectedCertSerial(); want != "" {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
		h, err := corrosion.GetHost(ctx, s.db, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read host %q: %v", req.Name, err)
		}
		if h == nil || !sameSerial(h.CertSerial, want) {
			if err := s.absentAdmissionRefusal(ctx, req); err != nil {
				return nil, err
			}
			return &emptypb.Empty{}, nil
		}
	}
	if _, _, err := s.removeHostRefusal(ctx, req); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// sameSerial reports whether a and b spell one certificate serial.
func sameSerial(a, b string) bool {
	ca, err := pki.CanonicalSerial(a)
	if err != nil {
		return false
	}
	cb, err := pki.CanonicalSerial(b)
	return err == nil && ca == cb
}

// absentAdmissionRefusal is PreflightRemoveHost for an expected serial the
// row of the name does not hold here.
func (s *Server) absentAdmissionRefusal(ctx context.Context, req *pb.RemoveHostRequest) error {
	want, err := pki.CanonicalSerial(req.GetExpectedCertSerial())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.hostOperatorWriteAllowed(ctx, "remove", req.Name); err != nil {
		return err
	}
	if err := s.requireVoterMajority(ctx, "remove", req.Name); err != nil {
		return err
	}
	if err := s.pullHostsNow(ctx, "remove", req.Name); err != nil {
		return err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read host %q: %v", req.Name, err)
	}
	if h != nil && sameSerial(h.CertSerial, want) {
		// Its row has arrived: the ordinary removal's checks decide.
		_, _, err := s.removeHostRefusal(ctx, req)
		return err
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Unavailable, "list hosts: %v", err)
	}
	for _, o := range hosts {
		if sameSerial(o.CertSerial, want) {
			return status.Errorf(codes.FailedPrecondition, "certificate %s is %s's, not %s's", want, o.Name, req.Name)
		}
	}
	code, msg := codes.NotFound, fmt.Sprintf("no row of %s and no live row holding certificate %s, after a pull of the hosts table", req.Name, want)
	if h != nil {
		code = codes.FailedPrecondition
		msg = fmt.Sprintf("%s's row holds certificate %s, not %s, and no live row holds %s, after a pull of the hosts table",
			req.Name, h.CertSerial, want, want)
	}
	st := status.New(code, msg)
	if d, derr := st.WithDetails(&errdetails.ErrorInfo{Reason: apimeta.AdmissionAbsentReason, Domain: apimeta.AdmissionAbsentDomain}); derr == nil {
		st = d
	}
	return st.Err()
}

// removeHostRefusal is RemoveHost's checks: the host's row and the key of the
// admission they were made on (incarnation and admission stamp) when it may
// be removed.
func (s *Server) removeHostRefusal(ctx context.Context, req *pb.RemoveHostRequest) (*corrosion.HostRecord, corrosion.HostIncarnation, error) {
	var none corrosion.HostIncarnation
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, none, err
	}
	h, err := corrosion.GetHost(ctx, s.db, req.Name)
	if err != nil {
		// Not NotFound: `lv host rm` reads that on a retry as its own removal.
		return nil, none, status.Errorf(codes.Unavailable, "read host %q: %v", req.Name, err)
	}
	if h == nil {
		return nil, none, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	// `--dead`'s refusals that do not depend on the vote come first: `lv host
	// rm --dead` asks this preflight before it removes a voter's vote, and a
	// refused removal must change nothing (D2 re-review I-4).
	if req.Dead {
		if err := s.deadRemovalRefusal(ctx, h); err != nil {
			return nil, none, err
		}
		if !req.Force {
			if err := s.deadRemovalFirmwareRefusal(ctx, req.Name); err != nil {
				return nil, none, err
			}
		}
	}
	// A removal decides the row a later re-admission counts from, so it is
	// made on a caught-up node, by the voter majority, on the row a peer
	// confirms, and only of the certificate the operator revoked
	// (host_incarnation.go).
	if err := s.hostOperatorWriteAllowed(ctx, "remove", req.Name); err != nil {
		return nil, none, err
	}
	if err := s.requireVoterMajority(ctx, "remove", req.Name); err != nil {
		return nil, none, err
	}
	if err := s.pullHostsNow(ctx, "remove", req.Name); err != nil {
		return nil, none, err
	}
	if h, err = corrosion.GetHost(ctx, s.db, req.Name); err != nil {
		return nil, none, status.Errorf(codes.Unavailable, "read host %q: %v", req.Name, err)
	} else if h == nil {
		return nil, none, status.Errorf(codes.NotFound, "host %q not found", req.Name)
	}
	if want := req.GetExpectedCertSerial(); want != "" && !strings.EqualFold(want, h.CertSerial) {
		return nil, none, status.Errorf(codes.FailedPrecondition,
			"%s's row changed since its certificate was revoked (it now names %s, not %s); run `lv host rm` again",
			req.Name, h.CertSerial, want)
	}
	if hook := s.removeHostBetweenReadsHook; hook != nil {
		hook(req.Name)
	}
	incarnation, at, keySerial, deleted, found, err := corrosion.HostIncarnationOf(ctx, s.db, req.Name)
	if err != nil {
		return nil, none, status.Errorf(codes.Unavailable, "read %s's incarnation: %v", req.Name, err)
	}
	// The key and the row checked are one admission: one that changed
	// between the two reads (another certificate, or a later admission of
	// the same one) is not the row checked.
	if !found || deleted || !strings.EqualFold(keySerial, h.CertSerial) || at != h.CreatedAt {
		return nil, none, status.Errorf(codes.FailedPrecondition,
			"%s's row changed while its removal was checked; run `lv host rm` again", req.Name)
	}
	key := corrosion.HostIncarnation{N: incarnation, At: at}

	// `lv host rm --dead` (recovery-claims.md §3.12): a host fenced proof-grade
	// and gone for good. Its workloads are not drained first — they are the
	// stranded ones, and their rows stay in place for the recovery claims to
	// supersede once this removal and the CRL have replicated.
	if req.Dead {
		// Again on the row the peers confirmed.
		if err := s.deadRemovalRefusal(ctx, h); err != nil {
			return nil, none, err
		}
	} else {
		// Check for VMs on this host.
		vms, _ := corrosion.ListVMs(ctx, s.db, "", req.Name)
		if len(vms) > 0 && !req.Force {
			return nil, none, status.Errorf(codes.FailedPrecondition,
				"host %q has %d VMs — drain first or use --force", req.Name, len(vms))
		}
	}
	// A current voter keeps its vote whatever its hosts row says, so deleting
	// the row must not look like removing the voter (recovery-claims.md §4.3).
	// Asked last: `lv host rm --dead` preflights a voter's host before it
	// removes the vote and goes on only on this refusal, so every other
	// refusal must come first, or a refused removal would have removed the
	// vote. None of them depends on the vote: the majority above is counted
	// without the host already, as the cluster counts it once the vote is
	// gone, and the pull never asks the host itself.
	if err := s.voterRemovalRefusal(ctx, req.Name); err != nil {
		return nil, none, err
	}
	return h, key, nil
}

// checkAdmitName applies the new-name rule (pki.ValidateHostName) to a name
// no live host holds. A live row is an add being resumed under a name an
// older build admitted, which keeps it if `lv host add` can keep its pair
// (pki.ValidateExistingHostName). A removed name is admitted as a new one.
func (s *Server) checkAdmitName(ctx context.Context, name string) error {
	rows, err := s.db.Query(ctx, `SELECT name FROM hosts WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the host row for %s: %v", name, err)
	}
	check := pki.ValidateHostName
	if len(rows) > 0 {
		check = pki.ValidateExistingHostName
	}
	if err := check(name); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// admitGRPCPort is the gRPC port AdmitHost records for an admitted host.
const admitGRPCPort = 7443

// addressLostRefusal refuses an admission of name that is written but loses
// address to winner, admitted there first on another replica.
func addressLostRefusal(address, name, winner string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s:%d is %s's address (active there, or admitted there before %s on another replica): "+
			"%s stays admitted (joining) but is never activated, and nothing was installed for it. Remove it "+
			"(`lv host rm %s`), or remove %s (`lv host rm %s`, or `lv host rm --dead %s` if it is fenced and gone "+
			"for good) and run the add again",
		address, admitGRPCPort, winner, name, name, name, winner, winner, winner)
}

// addressHeldRefusal refuses to admit name at address, which other holds.
func addressHeldRefusal(address, name, other string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s:%d is %s's address: a machine is admitted under one name. Remove %s first (`lv host rm %s`, or "+
			"`lv host rm --dead %s` if it is fenced and gone for good) to add the machine as %s",
		address, admitGRPCPort, other, other, other, other, name)
}

// AdmitHost records the CA-authorized identity produced by `lv host add`.
// Running it on an existing member breaks the tombstone/authentication deadlock
// when a removed machine is deliberately re-added with a fresh certificate.
//
// The host is admitted 'joining', not 'active': `lv host add` admits it before
// its setup runs, and its daemon records it 'active' when it first boots. An
// 'active' row for a machine with no daemon yet was a fence candidate as soon
// as the observers' probes found nothing listening, and the coordinator
// powered the machine off part-way through its setup (kvm003 drill 6).
//
// The response carries the name's audit chain position on this node (the last
// seq and its hash), which `lv host add` signs and hands to the new machine so
// it does not append to its own chain before that history has reached it
// (corrosion/audit_hold.go). It is read from THIS replica, which therefore has
// to be able to vouch for it (auditAdmissionPosition), or the admission is
// refused.
func (s *Server) AdmitHost(ctx context.Context, req *pb.AdmitHostRequest) (*pb.AdmitHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Address == "" || req.CertSerial == "" {
		return nil, status.Error(codes.InvalidArgument, "name, address, and certificate serial are required")
	}
	if err := s.checkAdmitName(ctx, req.Name); err != nil {
		return nil, err
	}
	// One machine, one name: an address another live or joining host is
	// dialled at belongs to that host. Checked here, not only by `lv host
	// add`, and again by the admission write itself, in its transaction
	// (corrosion.AdmitHost), so two adds of one machine under two names on
	// this replica cannot both pass. This read only refuses early.
	other, err := corrosion.HostAddressHolder(ctx, s.db, req.Address, req.Name, admitGRPCPort)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the hosts at %s: %v", req.Address, err)
	}
	if other != "" {
		return nil, addressHeldRefusal(req.Address, req.Name, other)
	}
	// A name whose removed machine still has workloads recorded on it is not
	// given to a new machine: those rows are the old machine's, recovered by
	// the claim path only while the name stays removed, and the new machine
	// would take them over (corrosion.WorkloadsOnRemovedHost). Stopped ones,
	// and restart-same VMs failover holds for their host, do not block:
	// failover leaves them on their machine, and they come back with it
	// (corrosion.WorkloadsBlockingReadmission).
	left, err := corrosion.WorkloadsBlockingReadmission(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the workloads recorded on %s: %v", req.Name, err)
	}
	if len(left) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q was removed with %d workload(s) still recorded on it (%s). They belong to the machine "+
				"removed under that name, and a new machine admitted under it would take them over. The "+
				"failover coordinator recovers them by claim onto a live host once the removal and the CRL "+
				"have replicated (`lv health` shows ha.claim.stranded for any it cannot). One that no live "+
				"host can take, such as a container when no other host runs containers, moves as soon as "+
				"a host that can take it is up: add one (this machine under another name will do), or "+
				"remove the workload (`lv rm <vm>`, `lv ct rm <name>`). Then add the host again",
			req.Name, len(left), strings.Join(left, ", "))
	}
	tailSeq, tailHash, err := s.auditAdmissionPosition(ctx, req.Name, req.CertSerial)
	if err != nil {
		return nil, err
	}
	notIssued, err := s.admitHostRow(ctx, corrosion.HostRecord{
		Name:       req.Name,
		Address:    req.Address,
		SSHUser:    "root",
		SSHPort:    22,
		GRPCPort:   admitGRPCPort,
		State:      corrosion.HostStateJoining,
		CertSerial: req.CertSerial,
	})
	if err != nil {
		return nil, err
	}
	// The write's guard sees only this replica. Pulled again now that it is
	// written, the address is decided by the rule activation follows
	// (corrosion.AddressLostTo): a host active at this address, or an
	// admission another replica made there first, keeps it, and this one is
	// refused before anything is installed for it. Its row stays, and is never
	// activated. `lv host add` asks again, under its lock on the machine,
	// right before it installs.
	if err := s.pullHostsNow(ctx, "admit", req.Name); err != nil {
		return nil, err
	}
	if lostTo, err := corrosion.AddressLostTo(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the hosts at %s: %v", req.Address, err)
	} else if lostTo != "" {
		return nil, addressLostRefusal(req.Address, req.Name, lostTo)
	}
	s.publish("host.admitted", req.Name, "cert_serial="+req.CertSerial)
	return &pb.AdmitHostResponse{AuditTailSeq: tailSeq, AuditTailHash: tailHash, AuditPositionProven: true,
		IncarnationNotIssued: notIssued}, nil
}

// hostAllocatedResources returns running-VM CPU and memory, and the DECLARED
// disk size of every VM on the host (stopped VMs included). The disk figure is
// allocation, not usage — hostDiskFromPools is the usage pb.Host reports.
func (s *Server) hostAllocatedResources(ctx context.Context, hostName string) (cpuUsed, memUsed int32, diskAllocatedGiB int64) {
	vms, _ := corrosion.ListVMs(ctx, s.db, "", hostName)
	for _, vm := range vms {
		if vm.State == "running" {
			cpuUsed += int32(vm.CPUActual)
			memUsed += int32(vm.MemActual)
		}
	}
	// Sum disk allocations (all VMs, not just running — disk is allocated regardless of state).
	rows, err := s.db.Query(ctx,
		`SELECT COALESCE(SUM(size_bytes),0) as disk_bytes FROM vm_disks WHERE host_name = ? AND deleted_at IS NULL`,
		hostName)
	if err == nil && len(rows) > 0 {
		diskAllocatedGiB = int64(rows[0].Int("disk_bytes")) / (1024 * 1024 * 1024)
	}
	return
}

// hostStateToPB maps a stored hosts.state string to the wire enum for display.
// Each state maps to the value named after it, since `lv host ls` prints that
// name. Critically it must never report a non-active host as HOST_ACTIVE: a
// fenced (forcibly isolated after failover) or upgrading host shown as ACTIVE
// would hide a dead/transitioning node from operators. The default fails safe
// to OFFLINE so an unknown/future state can't masquerade as healthy.
func hostStateToPB(s string) pb.HostState {
	switch s {
	case "active":
		return pb.HostState_HOST_ACTIVE
	case "draining":
		return pb.HostState_HOST_DRAINING
	case "upgrading":
		return pb.HostState_HOST_UPGRADING
	case "maintenance":
		return pb.HostState_HOST_MAINTENANCE
	case "suspect":
		return pb.HostState_HOST_SUSPECT
	case "offline":
		return pb.HostState_HOST_OFFLINE
	case "fenced":
		return pb.HostState_HOST_FENCED
	case corrosion.HostStateJoining:
		// Admitted by `lv host add`, its daemon not yet started. Not OFFLINE:
		// nothing has failed, and the coordinator never fences it.
		return pb.HostState_HOST_JOINING
	default:
		return pb.HostState_HOST_OFFLINE
	}
}

func parseTimestamp(s string) *timestamppb.Timestamp {
	if s == "" {
		return nil
	}
	// Both-format: updated_at is the LWW key (RFC3339 or HLC once hlc_lww is enabled);
	// last_seen/created_at are wall RFC3339. ParseUpdatedAt handles either.
	t, ok := corrosion.ParseUpdatedAt(s)
	if !ok {
		return nil
	}
	return timestamppb.New(t)
}

// admitHostRow writes an admission. The re-admission of a counted tombstone,
// and of any tombstone once the host_incarnation release feature is available
// here, issues the next incarnation (corrosion.AdmitHostV2): on a node that
// sees a voter majority, on the row a peer confirms, through the feature's
// grant. Everything else — a first admission, a re-admission before the
// feature, an idempotent retry — is corrosion.AdmitHost, as before.
//
// Over a tombstone at incarnation 1 or higher a failure to issue refuses: the
// legacy statement is never written there. Over a tombstone at 0, where the
// legacy statement is exactly the previous release's re-admission, it falls
// back to it when the feature is not available here (not every host runs the
// release yet) or the gate cannot grant it right now (a host has not
// acknowledged the feature's first use), and notIssued says why.
func (s *Server) admitHostRow(ctx context.Context, h corrosion.HostRecord) (notIssued string, err error) {
	if err := s.pullHostsNow(ctx, "re-add", h.Name); err != nil {
		return "", err
	}
	n, _, _, deleted, found, err := corrosion.HostIncarnationOf(ctx, s.db, h.Name)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "read %s's incarnation: %v", h.Name, err)
	}
	legacy := func() error {
		if err := corrosion.AdmitHost(ctx, s.db, h); err != nil {
			if other, ok := corrosion.AsAddressHeld(err); ok {
				// A retry of a standing admission: its row is written.
				if cur, _ := corrosion.GetHost(ctx, s.db, h.Name); cur != nil && strings.EqualFold(cur.CertSerial, h.CertSerial) {
					return addressLostRefusal(h.Address, h.Name, other)
				}
				return addressHeldRefusal(h.Address, h.Name, other)
			}
			if errors.Is(err, corrosion.ErrReadmitNeedsCounter) {
				return status.Errorf(codes.FailedPrecondition, "admit host: %v", err)
			}
			return status.Errorf(codes.FailedPrecondition, "admit host: %v", err)
		}
		return nil
	}
	if !found || !deleted {
		return "", legacy()
	}
	if n == 0 && !s.ReleaseFeatureAvailable(capabilities.FeatureHostIncarnation) {
		why := "the host_incarnation release feature is not available yet"
		if rerr := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureHostIncarnation); rerr != nil {
			why = status.Convert(rerr).Message()
		}
		slog.Warn("re-admitting a host without an incarnation: the host_incarnation feature is not available",
			"host", h.Name, "why", why)
		if err := legacy(); err != nil {
			return "", err
		}
		return why, nil
	}
	if err := admitInstallsIncarnationBuild(ctx, h.Name, n+1); err != nil {
		return "", err
	}
	if err := s.requireVoterMajority(ctx, "re-add", h.Name); err != nil {
		return "", err
	}
	heldBy := ""
	err = s.WithReleaseFeature(ctx, capabilities.FeatureHostIncarnation, func(ctx context.Context, g capabilities.FeatureGrant) error {
		_, _, aerr := corrosion.AdmitHostV2(ctx, s.db, h, g)
		heldBy, _ = corrosion.AsAddressHeld(aerr)
		return aerr
	})
	if err == nil {
		return "", nil
	}
	if heldBy != "" {
		return "", addressHeldRefusal(h.Address, h.Name, heldBy)
	}
	st, isStatus := status.FromError(err)
	gateRefusal := isStatus && (st.Code() == codes.Unavailable || st.Code() == codes.FailedPrecondition) &&
		!strings.HasPrefix(st.Message(), "admit host")
	if n == 0 && gateRefusal {
		why := st.Message()
		slog.Warn("re-admitting a host without an incarnation: the host_incarnation feature could not be used now",
			"host", h.Name, "why", why)
		if lerr := legacy(); lerr != nil {
			return "", lerr
		}
		return why, nil
	}
	if isStatus && st.Code() != codes.Unknown {
		return "", status.Errorf(st.Code(), "re-adding %s at incarnation %d: %s", h.Name, n+1, st.Message())
	}
	return "", status.Errorf(codes.FailedPrecondition, "admit host: %v", err)
}

// admitInstallsIncarnationBuild refuses an admission that would issue
// incarnation next when the `lv host add` making it is from a previous
// release (it names no release it installs): the build it installs cannot
// keep an incarnation, and the host would stay joining, refused by every peer.
func admitInstallsIncarnationBuild(ctx context.Context, name string, next int64) error {
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get(apimeta.AdmitInstallsReleaseHeader)) > 0 {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"re-adding %s issues host incarnation %d, and the client that ran this is from a previous release: "+
			"its `lv host add` installs a build that cannot keep one, so the host would stay joining, refused by "+
			"every peer. Re-run `lv host add` with this release's CLI, which installs its own build. A host "+
			"already admitted on an older build joins after `lv host upgrade %s`", name, next, name)
}

// fenceTargetNote is the incarnation, serial, strategy and BMC a fence of h
// went through, as this node's row records them.
func fenceTargetNote(ctx context.Context, db *corrosion.Client, h *corrosion.HostRecord) string {
	if h == nil {
		return ""
	}
	n, _, _, _, _, err := corrosion.HostIncarnationOf(ctx, db, h.Name)
	if err != nil {
		return ""
	}
	bmc := h.IPMIAddress
	if h.Redfish.Endpoint != "" {
		bmc = h.Redfish.Endpoint
	}
	if bmc == "" {
		bmc = "-"
	}
	return fmt.Sprintf(" [fenced %s as incarnation %d, serial %s, strategy %s at %s]", h.Name, n, h.CertSerial, h.FenceStrategy, bmc)
}

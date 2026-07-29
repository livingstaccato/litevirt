package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

const admissionLockRegistryLimit = 1024

type admissionLockEntry struct {
	sem  chan struct{}
	refs int
}

// admissionLockRegistry is a cancellation-aware keyed mutex registry. Entries
// include holders and waiters in refs and are removed only after the last
// unlock/cancel, preventing an old holder from unlocking a replacement entry.
type admissionLockRegistry struct {
	mu      sync.Mutex
	entries map[string]*admissionLockEntry
	limit   int
}

func newAdmissionLockRegistry(limit int) *admissionLockRegistry {
	return &admissionLockRegistry{entries: make(map[string]*admissionLockEntry), limit: limit}
}

func (r *admissionLockRegistry) lock(ctx context.Context, key string) (func(), error) {
	r.mu.Lock()
	entry := r.entries[key]
	if entry == nil {
		if r.limit > 0 && len(r.entries) >= r.limit {
			r.mu.Unlock()
			return nil, status.Error(codes.ResourceExhausted, "admission lock registry is full")
		}
		entry = &admissionLockEntry{sem: make(chan struct{}, 1)}
		entry.sem <- struct{}{}
		r.entries[key] = entry
	}
	entry.refs++
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		r.dropRef(key, entry)
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-entry.sem:
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			entry.sem <- struct{}{}
			r.dropRef(key, entry)
		})
	}, nil
}

func (r *admissionLockRegistry) dropRef(key string, entry *admissionLockEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.entries[key]
	if current != entry {
		return
	}
	entry.refs--
	if entry.refs == 0 {
		delete(r.entries, key)
	}
}

func (r *admissionLockRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// ReservationRequest is the normalized, internal capacity claim shared by VM
// and container create/start paths. Positive vectors require durable host and
// project reservations after capacity_admission_v1 latches.
type ReservationRequest struct {
	OperationID  string
	RequestHash  string
	Host         string
	Project      string
	CPU          int
	MemMiB       int
	ExecutorHost string
	Header       *corrosion.OperationRecord
}

type ReservationClaim struct {
	Operation corrosion.OperationRecord
	Authority corrosion.ProjectAuthority
	Durable   bool
}

type admissionCoordinator struct {
	server       *Server
	hostLocks    *admissionLockRegistry
	projectLocks *admissionLockRegistry
	latched      func() bool

	// beforeProjectPersist is a test seam for an authority transfer racing the
	// final guarded write. Production leaves it nil.
	beforeProjectPersist func()
}

func newAdmissionCoordinator(s *Server, latched func() bool) *admissionCoordinator {
	if latched == nil {
		latched = s.capacityAdmissionLatched
	}
	return &admissionCoordinator{
		server:       s,
		hostLocks:    newAdmissionLockRegistry(admissionLockRegistryLimit),
		projectLocks: newAdmissionLockRegistry(admissionLockRegistryLimit),
		latched:      latched,
	}
}

func (s *Server) admissionCoordinator() *admissionCoordinator {
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if s.admission == nil {
		s.admission = newAdmissionCoordinator(s, nil)
	}
	return s.admission
}

func normalizeReservationRequest(req ReservationRequest) (ReservationRequest, error) {
	req.OperationID = strings.TrimSpace(req.OperationID)
	req.RequestHash = strings.TrimSpace(req.RequestHash)
	req.Host = strings.TrimSpace(req.Host)
	req.Project = tenancy.NormalizeProject(strings.TrimSpace(req.Project))
	req.ExecutorHost = strings.TrimSpace(req.ExecutorHost)
	if req.OperationID == "" || req.RequestHash == "" || req.Host == "" || req.ExecutorHost == "" {
		return ReservationRequest{}, status.Error(codes.InvalidArgument,
			"operation_id, request_hash, host, and executor_host are required")
	}
	if req.Host != req.ExecutorHost {
		return ReservationRequest{}, status.Error(codes.InvalidArgument,
			"host must match executor_host")
	}
	if req.CPU < 0 || req.MemMiB < 0 {
		return ReservationRequest{}, status.Error(codes.InvalidArgument, "capacity claims must be non-negative")
	}
	if req.CPU > math.MaxInt32 || req.MemMiB > math.MaxInt32 {
		return ReservationRequest{}, status.Error(codes.InvalidArgument, "capacity claim exceeds wire range")
	}
	if req.Header != nil {
		header := *req.Header
		header.Project = tenancy.NormalizeProject(strings.TrimSpace(header.Project))
		if header.ID != req.OperationID || header.RequestHash != req.RequestHash ||
			header.Project != req.Project || header.Method == "" ||
			header.ResourceKind == "" || header.ResourceID == "" ||
			header.OperationKind == "" {
			return ReservationRequest{}, status.Error(codes.InvalidArgument,
				"operation_header does not match the reservation identity")
		}
		req.Header = &header
		if _, _, err := capacityOperation(req, corrosion.ProjectAuthority{}); err != nil {
			return ReservationRequest{}, status.Errorf(codes.InvalidArgument,
				"invalid operation_header reservation: %v", err)
		}
	}
	return req, nil
}

func (c *admissionCoordinator) Claim(ctx context.Context, raw ReservationRequest) (*ReservationClaim, error) {
	req, err := normalizeReservationRequest(raw)
	if err != nil {
		return nil, err
	}
	if req.CPU == 0 && req.MemMiB == 0 {
		return &ReservationClaim{}, nil
	}
	unlock, err := c.hostLocks.lock(ctx, req.Host)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if !c.latched() {
		if err := validateReservationExecutor(ctx, c.server, req.ExecutorHost); err != nil {
			return nil, err
		}
		if err := c.server.checkResourceAdmission(ctx, req.Host, req.Project, req.CPU, req.MemMiB); err != nil {
			return nil, err
		}
		return &ReservationClaim{}, nil
	}
	if replay, err := c.replay(ctx, req); replay != nil || err != nil {
		return replay, err
	}
	if err := validateReservationExecutor(ctx, c.server, req.ExecutorHost); err != nil {
		return nil, err
	}
	if err := c.server.checkHostCapacity(ctx, req.Host, req.CPU, req.MemMiB); err != nil {
		return nil, err
	}
	return c.claimProject(ctx, req)
}

func validateReservationExecutor(ctx context.Context, s *Server, host string) error {
	executor, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil {
		return status.Errorf(codes.Internal, "read executor host: %v", err)
	}
	if executor == nil || executor.State != "active" || executor.IsWitness() {
		return status.Errorf(codes.FailedPrecondition,
			"executor host %q is not an active worker", host)
	}
	return nil
}

func (c *admissionCoordinator) replay(ctx context.Context, req ReservationRequest) (*ReservationClaim, error) {
	existing, err := corrosion.GetOperation(ctx, c.server.db, req.OperationID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read capacity reservation: %v", err)
	}
	if existing == nil {
		return nil, nil
	}
	want, _, err := capacityOperation(req, corrosion.ProjectAuthority{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode capacity reservation: %v", err)
	}
	if existing.RequestHash != want.RequestHash {
		return nil, status.Error(codes.AlreadyExists, corrosion.ErrOperationHashConflict.Error())
	}
	if !sameCapacityOperation(*existing, want) {
		return nil, status.Error(codes.AlreadyExists, corrosion.ErrOperationIdentityConflict.Error())
	}
	steps, err := corrosion.ListOperationSteps(ctx, c.server.db, existing.ID, existing.VMOwnerEpoch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read capacity reservation facts: %v", err)
	}
	var facts corrosion.ReservationFacts
	found := false
	for _, step := range steps {
		if step.StepName != corrosion.OpStepReserved {
			continue
		}
		if err := json.Unmarshal([]byte(step.Facts), &facts); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "malformed capacity reservation facts: %v", err)
		}
		found = true
		break
	}
	if !found {
		return nil, status.Error(codes.FailedPrecondition, "durable capacity reservation facts are missing")
	}
	current, ok, err := corrosion.CurrentProjectAuthority(ctx, c.server.db, req.Project)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
	}
	if facts.Project != req.Project || facts.AuthorityEpoch <= 0 || facts.AuthorityHost == "" {
		return nil, status.Error(codes.FailedPrecondition, "capacity reservation authority facts are invalid")
	}
	if !ok {
		// Initial authority establishment and its operation header can reach the
		// executor before the authority-epoch row does. The peer-authenticated
		// response was verified before import; replay the exact stored facts
		// until normal replication supplies the epoch row.
		current = corrosion.ProjectAuthority{
			Project: facts.Project, Epoch: facts.AuthorityEpoch, Holder: facts.AuthorityHost,
		}
	} else if facts.AuthorityEpoch != current.Epoch || facts.AuthorityHost != current.Holder {
		return nil, status.Error(codes.Aborted, "capacity reservation authority is no longer current")
	}
	return &ReservationClaim{Operation: *existing, Authority: current, Durable: true}, nil
}

func (c *admissionCoordinator) claimProject(ctx context.Context, req ReservationRequest) (*ReservationClaim, error) {
	authority, err := c.server.ensureProjectAuthority(ctx, req.Project)
	if err != nil {
		return nil, authorityStatusError(err)
	}
	if authority.Holder != c.server.hostName {
		return c.claimProjectRemote(ctx, req, authority.Holder)
	}
	return c.claimProjectLocal(ctx, req, authority)
}

func (c *admissionCoordinator) claimProjectLocal(ctx context.Context, req ReservationRequest, authority corrosion.ProjectAuthority) (*ReservationClaim, error) {
	unlock, err := c.projectLocks.lock(ctx, req.Project)
	if err != nil {
		return nil, err
	}
	defer unlock()

	current, ok, err := corrosion.CurrentProjectAuthority(ctx, c.server.db, req.Project)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
	}
	if !ok || current.Epoch != authority.Epoch || current.Holder != c.server.hostName {
		return nil, status.Error(codes.Aborted, "project authority changed during admission")
	}
	if err := c.server.checkProjectQuota(ctx, req.Project, req.CPU, req.MemMiB); err != nil {
		return nil, err
	}
	op, facts, err := capacityOperation(req, current)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode capacity reservation: %v", err)
	}
	if c.beforeProjectPersist != nil {
		c.beforeProjectPersist()
	}
	stored, _, err := corrosion.ClaimCapacityReservation(ctx, c.server.db, op, facts)
	if err != nil {
		return nil, capacityClaimStatusError(err)
	}
	return &ReservationClaim{Operation: *stored, Authority: current, Durable: true}, nil
}

const projectReservationHopMetadata = "x-litevirt-project-reservation-hop"

func boundedMetadataHop(ctx context.Context, key string) (int, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(key)
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, status.Error(codes.InvalidArgument, "invalid project reservation hop metadata")
	}
	hop, err := strconv.Atoi(values[0])
	if err != nil || hop < 0 || hop > 1 {
		return 0, status.Error(codes.FailedPrecondition, "project reservation forward hop limit exceeded")
	}
	return hop, nil
}

func outgoingMetadataHop(ctx context.Context, key string, hop int) context.Context {
	return metadata.AppendToOutgoingContext(ctx, key, strconv.Itoa(hop))
}

func (c *admissionCoordinator) claimProjectRemote(ctx context.Context, req ReservationRequest, authorityHost string) (*ReservationClaim, error) {
	hop, err := boundedMetadataHop(ctx, projectReservationHopMetadata)
	if err != nil {
		return nil, err
	}
	if hop >= 1 {
		return nil, status.Error(codes.FailedPrecondition, "project reservation forward hop limit exceeded")
	}
	client, closePeer, err := c.server.dialPeer(ctx, authorityHost)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot reach project authority %s: %v", authorityHost, err)
	}
	defer closePeer()
	outCtx := outgoingMetadataHop(ctx, projectReservationHopMetadata, hop+1)
	wire, err := client.ClaimProjectReservation(outCtx, &pb.ClaimProjectReservationRequest{
		OperationId: req.OperationID, RequestHash: req.RequestHash,
		Project: req.Project, Cpu: int32(req.CPU), MemoryMib: int32(req.MemMiB),
		ExecutorHost: req.ExecutorHost, OperationHeader: operationRecordToProto(req.Header),
	})
	if status.Code(err) == codes.Unimplemented {
		return nil, status.Errorf(codes.FailedPrecondition,
			"project authority %s does not implement required capacity admission", authorityHost)
	}
	if err != nil {
		return nil, err
	}
	claim, err := reservationClaimFromProto(wire)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "invalid project authority response: %v", err)
	}
	expected, _, err := capacityOperation(req, claim.Authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode expected capacity reservation: %v", err)
	}
	if !sameCapacityOperation(claim.Operation, expected) ||
		claim.Authority.Holder != authorityHost || claim.Authority.Epoch <= 0 {
		if compensateErr := c.compensateRemote(ctx, authorityHost, req,
			"executor rejected mismatched authority response"); compensateErr != nil {
			return nil, status.Errorf(codes.Internal,
				"project authority returned a mismatched reservation and compensation failed: %v", compensateErr)
		}
		return nil, status.Error(codes.FailedPrecondition, "project authority returned a mismatched immutable reservation")
	}
	stored, _, err := corrosion.ImportCapacityReservation(ctx, c.server.db, claim.Operation, corrosion.ReservationFacts{
		Project: req.Project, AuthorityEpoch: claim.Authority.Epoch, AuthorityHost: claim.Authority.Holder,
	})
	if err != nil {
		if compensateErr := c.compensateRemote(ctx, authorityHost, req, "executor import failed"); compensateErr != nil {
			return nil, status.Errorf(codes.Internal,
				"executor import failed (%v) and authority compensation failed: %v", err, compensateErr)
		}
		return nil, capacityClaimStatusError(err)
	}
	claim.Operation = *stored
	claim.Durable = true
	return claim, nil
}

func (c *admissionCoordinator) compensateRemote(ctx context.Context, authorityHost string, req ReservationRequest, detail string) error {
	compensationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	ownerEpoch := int64(0)
	if req.Header != nil {
		ownerEpoch = req.Header.VMOwnerEpoch
	}
	if authorityHost == c.server.hostName {
		return corrosion.ReleaseCapacityReservation(compensationCtx, c.server.db, req.OperationID, ownerEpoch, detail)
	}
	client, closePeer, err := c.server.dialPeer(compensationCtx, authorityHost)
	if err != nil {
		return err
	}
	defer closePeer()
	_, err = client.ClaimProjectReservation(compensationCtx, &pb.ClaimProjectReservationRequest{
		OperationId: req.OperationID, RequestHash: req.RequestHash,
		Project: req.Project, Cpu: int32(req.CPU), MemoryMib: int32(req.MemMiB),
		ExecutorHost: req.ExecutorHost, Compensate: true,
		CompensationDetail: detail, OperationHeader: operationRecordToProto(req.Header),
	})
	return err
}

func sameCapacityOperation(a, b corrosion.OperationRecord) bool {
	return a.ID == b.ID && a.Method == b.Method && a.Project == b.Project &&
		a.Principal == b.Principal &&
		a.ResourceKind == b.ResourceKind && a.ResourceID == b.ResourceID &&
		a.OperationKind == b.OperationKind && a.RequestHash == b.RequestHash &&
		a.IdempotencyKey == b.IdempotencyKey && a.ReservationJSON == b.ReservationJSON &&
		a.DesiredRef == b.DesiredRef && a.VMOwnerEpoch == b.VMOwnerEpoch
}

func reservationClaimToProto(claim *ReservationClaim) *pb.Operation {
	op := claim.Operation
	return &pb.Operation{
		Id: op.ID, Method: op.Method, Project: op.Project,
		ResourceKind: op.ResourceKind, ResourceId: op.ResourceID,
		OperationKind: op.OperationKind, RequestHash: op.RequestHash,
		IdempotencyKey: op.IdempotencyKey, ReservationJson: op.ReservationJSON,
		DesiredRef: op.DesiredRef, OwnerEpoch: op.VMOwnerEpoch,
		AuthorityEpoch: claim.Authority.Epoch, AuthorityHost: claim.Authority.Holder,
		Principal: op.Principal,
	}
}

func operationRecordToProto(op *corrosion.OperationRecord) *pb.Operation {
	if op == nil {
		return nil
	}
	return &pb.Operation{
		Id: op.ID, Method: op.Method, Project: op.Project,
		ResourceKind: op.ResourceKind, ResourceId: op.ResourceID,
		OperationKind: op.OperationKind, RequestHash: op.RequestHash,
		IdempotencyKey: op.IdempotencyKey, ReservationJson: op.ReservationJSON,
		DesiredRef: op.DesiredRef, OwnerEpoch: op.VMOwnerEpoch,
		Principal: op.Principal,
	}
}

func operationRecordFromProto(op *pb.Operation) *corrosion.OperationRecord {
	if op == nil {
		return nil
	}
	return &corrosion.OperationRecord{
		ID: op.GetId(), Method: op.GetMethod(), Project: op.GetProject(),
		ResourceKind: op.GetResourceKind(), ResourceID: op.GetResourceId(),
		OperationKind: op.GetOperationKind(), RequestHash: op.GetRequestHash(),
		IdempotencyKey: op.GetIdempotencyKey(), ReservationJSON: op.GetReservationJson(),
		DesiredRef: op.GetDesiredRef(), VMOwnerEpoch: op.GetOwnerEpoch(),
		Principal: op.GetPrincipal(),
	}
}

func reservationClaimFromProto(op *pb.Operation) (*ReservationClaim, error) {
	if op == nil || op.GetId() == "" || op.GetRequestHash() == "" ||
		op.GetAuthorityEpoch() <= 0 || op.GetAuthorityHost() == "" {
		return nil, fmt.Errorf("operation identity and authority facts are required")
	}
	return &ReservationClaim{
		Operation: corrosion.OperationRecord{
			ID: op.GetId(), Method: op.GetMethod(), Project: tenancy.NormalizeProject(op.GetProject()),
			ResourceKind: op.GetResourceKind(), ResourceID: op.GetResourceId(),
			OperationKind: op.GetOperationKind(), RequestHash: op.GetRequestHash(),
			IdempotencyKey: op.GetIdempotencyKey(), ReservationJSON: op.GetReservationJson(),
			DesiredRef: op.GetDesiredRef(), VMOwnerEpoch: op.GetOwnerEpoch(),
			Principal: op.GetPrincipal(),
		},
		Authority: corrosion.ProjectAuthority{
			Project: tenancy.NormalizeProject(op.GetProject()),
			Epoch:   op.GetAuthorityEpoch(), Holder: op.GetAuthorityHost(),
		},
		Durable: true,
	}, nil
}

// ClaimProjectReservation is peer-only. The selected/current authority alone
// serializes the normalized project, rechecks quota and epoch, and returns the
// exact immutable reservation it persisted.
func (s *Server) ClaimProjectReservation(ctx context.Context, wire *pb.ClaimProjectReservationRequest) (*pb.Operation, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if wire == nil {
		return nil, status.Error(codes.InvalidArgument, "project reservation request is required")
	}
	req, err := normalizeReservationRequest(ReservationRequest{
		OperationID: wire.GetOperationId(), RequestHash: wire.GetRequestHash(),
		Host: wire.GetExecutorHost(), Project: wire.GetProject(),
		CPU: int(wire.GetCpu()), MemMiB: int(wire.GetMemoryMib()),
		ExecutorHost: wire.GetExecutorHost(),
		Header:       operationRecordFromProto(wire.GetOperationHeader()),
	})
	if err != nil {
		return nil, err
	}
	if req.CPU == 0 && req.MemMiB == 0 {
		return nil, status.Error(codes.InvalidArgument, "zero-resource project reservation is not durable")
	}
	authority, err := s.ensureProjectAuthority(ctx, req.Project)
	if err != nil {
		return nil, authorityStatusError(err)
	}
	if wire.GetCompensate() {
		if authority.Holder != s.hostName || authority.Epoch <= 0 {
			return nil, status.Error(codes.Aborted, "only the current project authority may compensate a reservation")
		}
		unlock, lockErr := s.admissionCoordinator().projectLocks.lock(ctx, req.Project)
		if lockErr != nil {
			return nil, lockErr
		}
		defer unlock()
		current, ok, currentErr := corrosion.CurrentProjectAuthority(ctx, s.db, req.Project)
		if currentErr != nil {
			return nil, status.Errorf(codes.Internal, "read project authority: %v", currentErr)
		}
		if !ok || current.Epoch != authority.Epoch || current.Holder != s.hostName {
			return nil, status.Error(codes.Aborted, "project authority changed during compensation")
		}
		existing, readErr := corrosion.GetOperation(ctx, s.db, req.OperationID)
		if readErr != nil {
			return nil, status.Errorf(codes.Internal, "read capacity reservation: %v", readErr)
		}
		expected, _, encodeErr := capacityOperation(req, current)
		if encodeErr != nil {
			return nil, status.Errorf(codes.Internal, "encode capacity reservation: %v", encodeErr)
		}
		if existing == nil || !sameCapacityOperation(*existing, expected) {
			return nil, status.Error(codes.AlreadyExists, "compensation does not match immutable reservation")
		}
		if releaseErr := corrosion.ReleaseCapacityReservation(ctx, s.db, existing.ID, existing.VMOwnerEpoch,
			strings.TrimSpace(wire.GetCompensationDetail())); releaseErr != nil {
			return nil, status.Errorf(codes.Internal, "compensate capacity reservation: %v", releaseErr)
		}
		return reservationClaimToProto(&ReservationClaim{
			Operation: *existing, Authority: current, Durable: true,
		}), nil
	}
	if err := validateReservationExecutor(ctx, s, req.ExecutorHost); err != nil {
		return nil, err
	}
	var claim *ReservationClaim
	if authority.Holder != s.hostName {
		claim, err = s.admissionCoordinator().claimProjectRemote(ctx, req, authority.Holder)
	} else {
		claim, err = s.admissionCoordinator().claimProjectLocal(ctx, req, authority)
	}
	if err != nil {
		return nil, err
	}
	return reservationClaimToProto(claim), nil
}

func capacityOperation(req ReservationRequest, authority corrosion.ProjectAuthority) (corrosion.OperationRecord, corrosion.ReservationFacts, error) {
	reservation, err := (corrosion.ReservationVector{
		Project:       req.Project,
		ProjectCPU:    req.CPU,
		ProjectMemMiB: req.MemMiB,
		TargetHost:    req.Host,
		TargetCPU:     req.CPU,
		TargetMemMiB:  req.MemMiB,
	}).Encode()
	if err != nil {
		return corrosion.OperationRecord{}, corrosion.ReservationFacts{}, err
	}
	op := corrosion.OperationRecord{
		ID: req.OperationID, Method: "CapacityReservation", Project: req.Project,
		ResourceKind: "capacity", ResourceID: req.ExecutorHost,
		OperationKind: string(corrosion.OpWorkloadCreate),
		RequestHash:   req.RequestHash, IdempotencyKey: req.OperationID,
	}
	if req.Header != nil {
		op = *req.Header
		if op.ReservationJSON != "" && op.ReservationJSON != reservation {
			return corrosion.OperationRecord{}, corrosion.ReservationFacts{},
				fmt.Errorf("operation header reservation does not match requested capacity")
		}
	}
	op.ReservationJSON = reservation
	return op, corrosion.ReservationFacts{
		Project: req.Project, AuthorityEpoch: authority.Epoch, AuthorityHost: authority.Holder,
	}, nil
}

func capacityClaimStatusError(err error) error {
	switch {
	case errors.Is(err, corrosion.ErrOperationHashConflict),
		errors.Is(err, corrosion.ErrOperationIdentityConflict),
		errors.Is(err, corrosion.ErrOperationStepConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, corrosion.ErrProjectAuthorityConflict):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return status.Errorf(codes.Internal, "persist capacity reservation: %v", err)
	}
}

func authorityStatusError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return status.Errorf(codes.Unavailable, "resolve project authority: %v", err)
}

func deterministicProjectAuthority(project string, hosts []corrosion.HostRecord) (string, error) {
	return corrosion.DeterministicInitialProjectAuthority(project, hosts)
}

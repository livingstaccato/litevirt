package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func automationOwnerError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, corrosion.ErrAutomationOwnerPermission) {
		return automationPublicError(status.Error(codes.PermissionDenied, ""))
	}
	code, application := codes.Unavailable, automationv1.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE
	switch contract.Code(err) {
	case contract.CodeValidation:
		code, application = codes.InvalidArgument, automationv1.ErrorCode_ERROR_CODE_VALIDATION
	case contract.CodeIdempotencyConflict:
		code, application = codes.AlreadyExists, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT
	case contract.CodeOwnershipConflict:
		code, application = codes.FailedPrecondition, automationv1.ErrorCode_ERROR_CODE_OWNERSHIP_CONFLICT
	default:
		return automationPublicError(err)
	}
	detail := &automationv1.ErrorDetail{Code: application, Message: "automation owner request refused", Retry: &automationv1.RetryAdvice{Action: automationv1.RetryAction_RETRY_ACTION_DO_NOT_RETRY, SafeNextAction: "Resolve the request conflict before submitting a new request."}}
	st, e := status.New(code, detail.Message).WithDetails(detail)
	if e != nil {
		return automationPublicError(e)
	}
	return &automationPublicStatus{value: st}
}

func automationOwnerValidation() error {
	st, err := status.New(codes.InvalidArgument, "invalid automation owner request").WithDetails(&automationv1.ErrorDetail{Code: automationv1.ErrorCode_ERROR_CODE_VALIDATION, Message: "invalid automation owner request", Retry: &automationv1.RetryAdvice{Action: automationv1.RetryAction_RETRY_ACTION_DO_NOT_RETRY}})
	if err != nil {
		return automationPublicError(err)
	}
	return &automationPublicStatus{value: st}
}

func (s *Server) submitAutomationOwner(ctx context.Context, kind string, owner *automationv1.OwnerRef, request, target string, current *automationv1.OwnerSession) (contract.Receipt, contract.Decision, error) {
	if err := requireAutomationPublicPrincipal(ctx); err != nil {
		return contract.Receipt{}, contract.Decision{}, err
	}
	principal, _ := callerAutomationPrincipal(ctx)
	if principal.session == nil {
		return contract.Receipt{}, contract.Decision{}, automationPublicRefusal(ctx)
	}
	if owner == nil {
		return contract.Receipt{}, contract.Decision{}, automationOwnerValidation()
	}
	command := contract.Command{Kind: kind, ClusterUID: principal.clusterUID, PrincipalID: principal.principalUID, ProjectUID: owner.GetProjectUid(), OwnerID: owner.GetOwnerId(), RequestID: request, Body: []byte(`{"version":1}`)}
	if kind == "handoff_session" {
		if current == nil {
			return contract.Receipt{}, contract.Decision{}, automationOwnerValidation()
		}
		command.Session, command.SessionID = current.GetActivationGeneration(), current.GetSessionId()
		command.Body, _ = json.Marshal(contract.OwnerBody{Version: 1, NextPrincipalUID: principal.principalUID})
	}
	submission, err := corrosion.NewAutomationOwnerSubmission(ctx, principal.session, command, target)
	if err != nil {
		return contract.Receipt{}, contract.Decision{}, automationOwnerError(err)
	}
	engine, err := s.AutomationEngine()
	if err != nil {
		return contract.Receipt{}, contract.Decision{}, automationOwnerError(err)
	}
	receipt, err := engine.SubmitOwner(ctx, submission)
	if err != nil {
		return receipt, contract.Decision{}, automationOwnerError(err)
	}
	original, err := submission.Original(ctx, receipt)
	if err != nil {
		return receipt, contract.Decision{}, automationOwnerError(err)
	}
	s.audit(ctx, "automation."+kind, original.Command.PrincipalID, fmt.Sprintf("project_uid=%q owner_id=%q operation_id=%q sequence=%d", original.Command.ProjectUID, original.Command.OwnerID, receipt.OperationID, receipt.Sequence), "ok")
	return receipt, original, nil
}

func ownerCursor(receipt contract.Receipt) *automationv1.ReadCursor {
	return &automationv1.ReadCursor{AppliedSequence: receipt.Sequence, Operation: &automationv1.OperationRef{OperationId: receipt.OperationID, MinimumSequence: receipt.Sequence}}
}

func originalOwnerSession(receipt contract.Receipt, original contract.Decision) (*automationv1.OwnerSession, error) {
	a, err := contract.DecodeAssignment(original)
	if err != nil || a.Owner == nil {
		return nil, automationPublicError(status.Error(codes.Unavailable, ""))
	}
	return &automationv1.OwnerSession{Owner: &automationv1.OwnerRef{ProjectUid: original.Command.ProjectUID, OwnerId: original.Command.OwnerID}, SessionId: a.Owner.SessionID, ActivationGeneration: receipt.Generation}, nil
}

func (s *Server) EnsureOwner(ctx context.Context, req *automationv1.EnsureOwnerRequest) (*automationv1.EnsureOwnerResponse, error) {
	receipt, original, err := s.submitAutomationOwner(ctx, "ensure_owner", req.GetOwner(), req.GetRequestId(), "", nil)
	if err != nil {
		return nil, err
	}
	envelope, err := contract.EncodeDecision(original)
	if err != nil {
		return nil, automationPublicError(err)
	}
	revision := (corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}).MustDigest()
	return &automationv1.EnsureOwnerResponse{Owner: &automationv1.Owner{Ref: &automationv1.OwnerRef{ProjectUid: original.Command.ProjectUID, OwnerId: original.Command.OwnerID}, Revision: revision, ActivationGeneration: receipt.Generation}, Cursor: ownerCursor(receipt)}, nil
}

func (s *Server) AcquireOwnerSession(ctx context.Context, req *automationv1.AcquireOwnerSessionRequest) (*automationv1.AcquireOwnerSessionResponse, error) {
	if err := requireAutomationPublicPrincipal(ctx); err != nil {
		return nil, err
	}
	if req.GetExpectedActivationGeneration() != 0 {
		return nil, automationOwnerValidation()
	}
	receipt, original, err := s.submitAutomationOwner(ctx, "acquire_session", req.GetOwner(), req.GetRequestId(), req.GetSessionId(), nil)
	if err != nil {
		return nil, err
	}
	session, err := originalOwnerSession(receipt, original)
	if err != nil {
		return nil, err
	}
	return &automationv1.AcquireOwnerSessionResponse{Session: session, Cursor: ownerCursor(receipt)}, nil
}

func (s *Server) HandoffOwnerSession(ctx context.Context, req *automationv1.HandoffOwnerSessionRequest) (*automationv1.HandoffOwnerSessionResponse, error) {
	receipt, original, err := s.submitAutomationOwner(ctx, "handoff_session", req.GetCurrent().GetOwner(), req.GetRequestId(), req.GetSuccessorSessionId(), req.GetCurrent())
	if err != nil {
		return nil, err
	}
	session, err := originalOwnerSession(receipt, original)
	if err != nil {
		return nil, err
	}
	return &automationv1.HandoffOwnerSessionResponse{Session: session, Cursor: ownerCursor(receipt)}, nil
}

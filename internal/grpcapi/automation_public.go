package grpcapi

import (
	"context"
	"errors"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ automationv1.AutomationServer = (*Server)(nil)

// Only locally constructed public statuses survive the interceptor's final
// sanitization. Remote/underlying statuses cannot smuggle messages or details.
type automationPublicStatus struct{ value *status.Status }

func (e *automationPublicStatus) Error() string              { return e.value.Err().Error() }
func (e *automationPublicStatus) GRPCStatus() *status.Status { return e.value }

// RegisterServices keeps both services on the same authenticated transport and
// Server lifetime. Registration does not enable automation authority/readiness.
func (s *Server) RegisterServices(registrar grpc.ServiceRegistrar) {
	pb.RegisterLiteVirtServer(registrar, s)
	automationv1.RegisterAutomationServer(registrar, s)
}

func automationPublicMethod(method string) bool {
	switch method {
	case automationv1.Automation_GetAutomationCapabilities_FullMethodName,
		automationv1.Automation_EnsureOwner_FullMethodName,
		automationv1.Automation_AcquireOwnerSession_FullMethodName,
		automationv1.Automation_HandoffOwnerSession_FullMethodName,
		automationv1.Automation_ResolveBinding_FullMethodName,
		automationv1.Automation_ObserveResource_FullMethodName,
		automationv1.Automation_SubmitCreateVM_FullMethodName,
		automationv1.Automation_SubmitUpdateVM_FullMethodName,
		automationv1.Automation_SubmitDeleteVM_FullMethodName,
		automationv1.Automation_GetOperation_FullMethodName,
		automationv1.Automation_ListByOwner_FullMethodName,
		automationv1.Automation_AdoptResource_FullMethodName,
		automationv1.Automation_TransferOwner_FullMethodName:
		return true
	default:
		return false
	}
}

func automationPublicReadOnly(method string) bool {
	switch method {
	case automationv1.Automation_GetAutomationCapabilities_FullMethodName,
		automationv1.Automation_GetOperation_FullMethodName,
		automationv1.Automation_ListByOwner_FullMethodName,
		automationv1.Automation_ResolveBinding_FullMethodName,
		automationv1.Automation_ObserveResource_FullMethodName:
		return true
	default:
		return false
	}
}

// automationPublicError maps by structural status, never diagnostic text. In
// particular an unreadable legacy session/account lookup can surface Internal;
// that is unavailable authentication evidence, not proven invalid identity.
// No underlying text, credential, scope or provisional reference is disclosed.
func automationPublicError(err error) error {
	if err == nil {
		return nil
	}
	var public *automationPublicStatus
	if errors.As(err, &public) {
		return public
	}
	code := status.Code(err)
	application := automationv1.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE
	message := "automation authority unavailable"
	action := automationv1.RetryAction_RETRY_ACTION_SAME_REQUEST
	next := "Retry the same request when automation authority is available."
	switch {
	case code == codes.Unauthenticated:
		application = automationv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED
		message = "current enrolled account authentication required"
		action = automationv1.RetryAction_RETRY_ACTION_OPERATOR_ACTION
		next = "Authenticate with a current enrolled account before retrying."
	case code == codes.PermissionDenied:
		application = automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
		message = "automation access denied"
		action = automationv1.RetryAction_RETRY_ACTION_DO_NOT_RETRY
		next = "Resolve account policy or permission requirements before retrying."
	case errors.Is(err, context.Canceled) || code == codes.Canceled:
		code = codes.Canceled
		message = "automation request canceled"
	case errors.Is(err, context.DeadlineExceeded) || code == codes.DeadlineExceeded:
		code = codes.DeadlineExceeded
		message = "automation request deadline exceeded"
	default:
		code = codes.Unavailable
	}
	detail := &automationv1.ErrorDetail{Code: application, Message: message,
		Retry: &automationv1.RetryAdvice{Action: action, SafeNextAction: next}}
	st, detailErr := status.New(code, message).WithDetails(detail)
	if detailErr != nil {
		return status.Error(codes.Unavailable, "automation authority unavailable")
	}
	return &automationPublicStatus{value: st}
}

// Current Login credential/lifetime validation installs this proof; legacy
// mTLS admin and unstamped sessions cannot supply it. Actual business/read
// providers remain unavailable. Refuse before private lookup, barrier or Submit.
func requireAutomationPublicPrincipal(ctx context.Context) error {
	if _, ok := callerAutomationPrincipal(ctx); !ok {
		return automationPublicError(status.Error(codes.Unauthenticated, ""))
	}
	return nil
}

func automationPublicRefusal(ctx context.Context) error {
	if err := requireAutomationPublicPrincipal(ctx); err != nil {
		return err
	}
	return automationPublicError(status.Error(codes.Unavailable, ""))
}

func (s *Server) GetAutomationCapabilities(ctx context.Context, _ *automationv1.GetAutomationCapabilitiesRequest) (*automationv1.GetAutomationCapabilitiesResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) ResolveBinding(ctx context.Context, _ *automationv1.ResolveBindingRequest) (*automationv1.ResolveBindingResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) ObserveResource(ctx context.Context, _ *automationv1.ObserveResourceRequest) (*automationv1.ObserveResourceResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) SubmitCreateVM(ctx context.Context, _ *automationv1.SubmitCreateVMRequest) (*automationv1.SubmitCreateVMResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) SubmitUpdateVM(ctx context.Context, _ *automationv1.SubmitUpdateVMRequest) (*automationv1.SubmitUpdateVMResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) SubmitDeleteVM(ctx context.Context, _ *automationv1.SubmitDeleteVMRequest) (*automationv1.SubmitDeleteVMResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) GetOperation(ctx context.Context, _ *automationv1.GetOperationRequest) (*automationv1.GetOperationResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) ListByOwner(ctx context.Context, _ *automationv1.ListByOwnerRequest) (*automationv1.ListByOwnerResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) AdoptResource(ctx context.Context, _ *automationv1.AdoptResourceRequest) (*automationv1.AdoptResourceResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

func (s *Server) TransferOwner(ctx context.Context, _ *automationv1.TransferOwnerRequest) (*automationv1.TransferOwnerResponse, error) {
	return nil, automationPublicRefusal(ctx)
}

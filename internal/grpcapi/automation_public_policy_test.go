package grpcapi

import (
	"context"
	"testing"

	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Treating ResolveBinding/ObserveResource as audited writes would block safe
// public reads while the host catches up its audit history.
func TestAutomationPublicReadClassification(t *testing.T) {
	for _, tc := range []struct {
		method string
		read   bool
	}{
		{automationv1.Automation_GetAutomationCapabilities_FullMethodName, true},
		{automationv1.Automation_EnsureOwner_FullMethodName, false},
		{automationv1.Automation_AcquireOwnerSession_FullMethodName, false},
		{automationv1.Automation_HandoffOwnerSession_FullMethodName, false},
		{automationv1.Automation_ResolveBinding_FullMethodName, true},
		{automationv1.Automation_ObserveResource_FullMethodName, true},
		{automationv1.Automation_SubmitCreateVM_FullMethodName, false},
		{automationv1.Automation_SubmitUpdateVM_FullMethodName, false},
		{automationv1.Automation_SubmitDeleteVM_FullMethodName, false},
		{automationv1.Automation_GetOperation_FullMethodName, true},
		{automationv1.Automation_ListByOwner_FullMethodName, true},
		{automationv1.Automation_AdoptResource_FullMethodName, false},
		{automationv1.Automation_TransferOwner_FullMethodName, false},
	} {
		t.Run(methodShortName(tc.method), func(t *testing.T) {
			if got := auditHoldReadOnly(tc.method); got != tc.read {
				t.Errorf("RED_PUBLIC_READ_POLICY: %s read=%v want=%v", tc.method, got, tc.read)
			}
		})
	}
}

// Dropping the public interceptor mapper must lose safe typed authentication
// details; a legacy method keeps its existing authentication error contract.
func TestAutomationPublicInterceptorAuthenticationDetail(t *testing.T) {
	s := testServer(t)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer lvs_missing-session"))
	for _, tc := range []struct {
		name   string
		method string
		public bool
	}{
		{"public", automationv1.Automation_EnsureOwner_FullMethodName, true},
		{"legacy", "/litevirt.v1.LiteVirt/Whoami", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.UnaryAuthInterceptor(ctx, &automationv1.EnsureOwnerRequest{}, &grpc.UnaryServerInfo{FullMethod: tc.method},
				func(context.Context, interface{}) (interface{}, error) {
					t.Fatal("invalid session reached the handler")
					return nil, nil
				})
			st := status.Convert(err)
			if st.Code() != codes.Unauthenticated {
				t.Fatalf("invalid session status=%v want Unauthenticated", st.Code())
			}
			if !tc.public {
				if len(st.Details()) != 0 || st.Message() != "invalid session" {
					t.Fatalf("legacy authentication behavior changed: %v", err)
				}
				return
			}
			if len(st.Details()) != 1 {
				t.Fatalf("RED_PUBLIC_AUTH_DETAIL: public authentication error has %d details, want one typed safe detail", len(st.Details()))
			}
			detail, ok := st.Details()[0].(*automationv1.ErrorDetail)
			if !ok || detail.GetCode() != automationv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED || detail.GetRetry().GetAction() == automationv1.RetryAction_RETRY_ACTION_UNSPECIFIED || detail.GetRetry().GetSafeNextAction() == "" {
				t.Fatalf("public authentication detail is missing its stable code/advice: %v", err)
			}
			if detail.GetOperation() != nil || detail.GetResource() != nil || detail.GetBinding() != nil {
				t.Fatal("pre-admission authentication failure disclosed private references")
			}
		})
	}
}

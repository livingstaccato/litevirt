package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Every generated public route must reject credentials that lack an enrolled
// principal before inspecting caller-supplied scope or touching authority state.
func TestFleet_AutomationPublicMethodsRequireEnrolledPrincipal(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := c.Nodes[0]
	legacy := c.SelfClient(n)
	if _, err := legacy.CreateUser(ctx, &pb.CreateUserRequest{Username: "ordinary", Password: "ordinary-password-0123456789", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	login, err := legacy.Login(ctx, &pb.LoginRequest{Username: "ordinary", Password: "ordinary-password-0123456789", Realm: "local"})
	if err != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("real local Login: %v", err)
	}
	ordinary := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetToken())
	if who, err := legacy.Whoami(ordinary, &emptypb.Empty{}); err != nil || who.GetUsername() != "ordinary" {
		t.Fatalf("real bearer control: %v", err)
	}
	client := automationv1.NewAutomationClient(n.selfConn)
	for _, credential := range []struct {
		name string
		ctx  context.Context
	}{
		{"ordinary-login", ordinary},
		{"invalid-session", metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer lvs_missing-session")},
		{"bearerless-local-root", ctx},
	} {
		t.Run(credential.name, func(t *testing.T) {
			for _, call := range []struct {
				name   string
				invoke func(context.Context) error
			}{
				{"GetAutomationCapabilities", func(ctx context.Context) error {
					_, err := client.GetAutomationCapabilities(ctx, &automationv1.GetAutomationCapabilitiesRequest{})
					return err
				}},
				{"EnsureOwner", func(ctx context.Context) error {
					_, err := client.EnsureOwner(ctx, &automationv1.EnsureOwnerRequest{})
					return err
				}},
				{"AcquireOwnerSession", func(ctx context.Context) error {
					_, err := client.AcquireOwnerSession(ctx, &automationv1.AcquireOwnerSessionRequest{})
					return err
				}},
				{"HandoffOwnerSession", func(ctx context.Context) error {
					_, err := client.HandoffOwnerSession(ctx, &automationv1.HandoffOwnerSessionRequest{})
					return err
				}},
				{"ResolveBinding", func(ctx context.Context) error {
					_, err := client.ResolveBinding(ctx, &automationv1.ResolveBindingRequest{})
					return err
				}},
				{"ObserveResource", func(ctx context.Context) error {
					_, err := client.ObserveResource(ctx, &automationv1.ObserveResourceRequest{})
					return err
				}},
				{"SubmitCreateVM", func(ctx context.Context) error {
					_, err := client.SubmitCreateVM(ctx, &automationv1.SubmitCreateVMRequest{})
					return err
				}},
				{"SubmitUpdateVM", func(ctx context.Context) error {
					_, err := client.SubmitUpdateVM(ctx, &automationv1.SubmitUpdateVMRequest{})
					return err
				}},
				{"SubmitDeleteVM", func(ctx context.Context) error {
					_, err := client.SubmitDeleteVM(ctx, &automationv1.SubmitDeleteVMRequest{})
					return err
				}},
				{"GetOperation", func(ctx context.Context) error {
					_, err := client.GetOperation(ctx, &automationv1.GetOperationRequest{})
					return err
				}},
				{"ListByOwner", func(ctx context.Context) error {
					_, err := client.ListByOwner(ctx, &automationv1.ListByOwnerRequest{})
					return err
				}},
				{"AdoptResource", func(ctx context.Context) error {
					_, err := client.AdoptResource(ctx, &automationv1.AdoptResourceRequest{})
					return err
				}},
				{"TransferOwner", func(ctx context.Context) error {
					_, err := client.TransferOwner(ctx, &automationv1.TransferOwnerRequest{})
					return err
				}},
			} {
				t.Run(call.name, func(t *testing.T) {
					err := call.invoke(credential.ctx)
					st := status.Convert(err)
					if st.Code() != codes.Unauthenticated {
						t.Fatalf("public route status=%s want Unauthenticated: %v", st.Code(), err)
					}
					if len(st.Details()) != 1 {
						t.Fatalf("public route has %d details, want one", len(st.Details()))
					}
					detail, ok := st.Details()[0].(*automationv1.ErrorDetail)
					if !ok || detail.GetCode() != automationv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED || detail.GetRetry().GetAction() == automationv1.RetryAction_RETRY_ACTION_UNSPECIFIED || detail.GetRetry().GetSafeNextAction() == "" {
						t.Fatalf("public refusal lost its typed code/retry advice: %v", err)
					}
					if detail.GetOperation() != nil || detail.GetResource() != nil || detail.GetBinding() != nil || len(detail.GetFieldViolations()) != 0 {
						t.Fatal("authentication refusal disclosed pre-admission scope")
					}
					for _, secret := range []string{login.GetToken(), "ordinary", "lvs_missing-session", "local_automation", "SELECT", "unassigned-project"} {
						if strings.Contains(st.Message(), secret) || strings.Contains(detail.String(), secret) {
							t.Fatal("public authentication refusal disclosed credential/storage/scope text")
						}
					}
				})
			}
		})
	}
	for _, table := range []string{"local_automation_authority", "local_automation_identities", "local_automation_owners", "local_automation_prefix"} {
		rows, err := n.DB.Query(ctx, "SELECT COUNT(*) AS n FROM "+table)
		if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
			t.Fatalf("public refusal created authority/identity/owner/history in %s: %v", table, err)
		}
	}
}

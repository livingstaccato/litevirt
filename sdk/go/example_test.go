package litevirt_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"net/http/httptest"
	"time"

	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	lv "github.com/livingstaccato/litevirt/sdk/go"
)

func ExampleEnroll() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, cleanup := exampleConfig()
	defer cleanup()
	config.ExpectedClusterUID = ""
	config.CredentialSource = func(context.Context) (string, error) { return "existing-automation-token", nil }
	discovered, err := lv.Enroll(ctx, config)
	if err != nil {
		return
	}
	// The caller accepts and persists this UID through its explicit enrollment
	// workflow. Normal clients require it and never learn a new UID on reconnect.
	config.ExpectedClusterUID = discovered.ClusterUid
	client, err := lv.NewClient(config)
	if err != nil {
		return
	}
	defer client.Close()
	fmt.Println(discovered.ClusterUid)
	// Output: cluster-A
}
func ExampleClient_EnsureOwner() {
	config, cleanup := exampleConfig()
	defer cleanup()
	client, err := lv.NewClient(config)
	if err != nil {
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner := &av.OwnerRef{ProjectUid: "project-uid", OwnerId: "controller-deployment"}
	_, err = client.EnsureOwner(ctx, &av.EnsureOwnerRequest{Owner: owner, RequestId: "persisted-ensure-request"})
	if err != nil {
		return
	}
	acquired, err := client.AcquireOwnerSession(ctx, &av.AcquireOwnerSessionRequest{Owner: owner, ExpectedActivationGeneration: 0, SessionId: "persisted-session-id", RequestId: "persisted-acquire-request"})
	if err != nil {
		return
	}
	fmt.Println(acquired.Session.ActivationGeneration)
	// Output: 1
}
func ExampleClient_SubmitCreateVM() {
	config, cleanup := exampleConfig()
	defer cleanup()
	client, err := lv.NewClient(config)
	if err != nil {
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session := &av.OwnerSession{Owner: &av.OwnerRef{ProjectUid: "project-uid", OwnerId: "controller-deployment"}, ActivationGeneration: 1, SessionId: "persisted-session-id"}
	// Persist the request ID, binding key and immutable desired input before
	// submission. Retrying this decision must reuse them byte for byte.
	submitted, err := client.SubmitCreateVM(ctx, &av.SubmitCreateVMRequest{Identity: &av.MutationIdentity{RequestId: "persisted-create-request", Session: session}, Binding: &av.BindingKey{ProjectUid: "project-uid", OwnerId: "controller-deployment", ManagementKey: "machine-123"}, Desired: &av.VMDesired{Name: "machine-123", Cpu: 2, MemoryMib: 2048}})
	if err != nil {
		return
	}
	// Persist the operation reference independently.
	fmt.Println(submitted.Operation.OperationId)
	// Output: op-1
}
func ExampleClient_GetOperation() {
	config, cleanup := exampleConfig()
	defer cleanup()
	client, err := lv.NewClient(config)
	if err != nil {
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Recover after a lost first reply without knowing any resource/operation UID.
	recovered, err := client.GetOperation(ctx, &av.GetOperationRequest{Lookup: &av.GetOperationRequest_Request{Request: &av.OperationRequestLookup{Binding: &av.BindingKey{ProjectUid: "project-uid", OwnerId: "controller-deployment", ManagementKey: "machine-123"}, RequestId: "persisted-create-request"}}})
	if err != nil {
		return
	}
	fmt.Println(recovered.Operation.Ref.OperationId)
	// Output: op-1
}
func ExampleClient_WaitOperation() {
	config, cleanup := exampleConfig()
	defer cleanup()
	// The effective deadline is the earlier caller/configured cap. Raise the
	// default 30-second cap to permit this caller's one-minute wait budget.
	config.DefaultDeadline = time.Minute
	client, err := lv.NewClient(config)
	if err != nil {
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	completed, err := client.WaitOperation(ctx, &av.OperationRef{OperationId: "persisted-operation-id", MinimumSequence: 41})
	var interrupted *lv.WaitError
	if errors.As(err, &interrupted) {
		_ = interrupted.Operation // Save and wait later; admitted work continues.
	}
	if err != nil {
		return
	}
	fmt.Println(completed.Operation.State)
	// Output: OPERATION_STATE_SUCCEEDED

}

// The examples run against an ephemeral implementation of the public generated
// service over real TLS. Production callers supply their configured endpoint,
// trust roots and credential source; this fixture establishes no daemon/VM claim.
func exampleConfig() (lv.Config, func()) {
	https := httptest.NewTLSServer(nil)
	serverTLS := https.TLS.Clone()
	pool := x509.NewCertPool()
	pool.AddCert(https.Certificate())
	https.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	av.RegisterAutomationServer(server, &service{operation: func(_ context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		ref := r.GetOperation()
		if ref == nil {
			ref = &av.OperationRef{OperationId: "op-1", MinimumSequence: 41}
		}
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: ref, State: av.OperationState_OPERATION_STATE_SUCCEEDED}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
	}})
	go func() { _ = server.Serve(listener) }()
	return lv.Config{Endpoints: []string{listener.Addr().String()}, TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, ExpectedClusterUID: "cluster-A"}, server.Stop
}

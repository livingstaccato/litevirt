package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// This transport uses the production service registrar and authentication chain.
// Fleet separately exercises its complete production-like server factory.
func automationPublicTLSClient(t *testing.T, s *Server) *grpc.ClientConn {
	t.Helper()
	dir := t.TempDir()
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(ca, key); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(ca, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), s.hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.pkiDir = dir
	serverTLS, err := pki.ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := pki.PeerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.ChainUnaryInterceptor(s.UnaryAuthInterceptor),
		grpc.ChainStreamInterceptor(s.StreamAuthInterceptor))
	s.RegisterServices(server)
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-done })
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// The accepted historical fixture supplies ONLY an enrolled-principal consumer.
// Its generic authority seed is removed before Login or any public call: it is
// never a current business issuer. Registration cannot enable public readiness.
func TestAutomationPublicEnrolledPrincipalRefusesUnavailableAuthority(t *testing.T) {
	s := automationLoginServer(t)
	if err := s.db.ExecuteLocal(context.Background(), func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(context.Background(), "DELETE FROM local_automation_authority")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	connection := automationPublicTLSClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	legacy := pb.NewLiteVirtClient(connection)
	login, err := legacy.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password", Realm: "local"})
	if err != nil || !strings.HasPrefix(login.GetToken(), SessionTokenPrefix) {
		t.Fatalf("actual enrolled Login: %v", err)
	}
	principal, err := corrosion.AutomationSessionPrincipal(ctx, s.db, strings.TrimPrefix(login.GetToken(), SessionTokenPrefix))
	if err != nil || principal == nil || principal.UID != "principal-uid" || principal.ClusterUID != "established-cluster" {
		t.Fatalf("actual Login did not carry the certified principal: %v", err)
	}
	bearer := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetToken())
	if who, err := legacy.Whoami(bearer, &emptypb.Empty{}); err != nil || who.GetUsername() != "alice" || who.GetRole() != "viewer" {
		t.Fatalf("actual enrolled TLS bearer: %v", err)
	}
	before, err := s.db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := automationv1.NewAutomationClient(connection)
	// Real owner methods validate intent before checking current authorization.
	// Supply valid request fields without inventing a certified project or owner:
	// this principal-only fixture must still refuse unavailable authority.
	owner := &automationv1.OwnerRef{ProjectUid: "unavailable-project", OwnerId: "public-owner"}
	ensureOwner := &automationv1.EnsureOwnerRequest{Owner: owner, RequestId: "public-ensure-owner"}
	acquireSession := &automationv1.AcquireOwnerSessionRequest{
		Owner: owner, ExpectedActivationGeneration: 0,
		SessionId: "public-session", RequestId: "public-acquire-session",
	}
	handoffSession := &automationv1.HandoffOwnerSessionRequest{
		Current:            &automationv1.OwnerSession{Owner: owner, ActivationGeneration: 1, SessionId: "public-session"},
		SuccessorSessionId: "public-successor-session", RequestId: "public-handoff-session",
	}
	for _, call := range []struct {
		name   string
		invoke func() error
	}{
		{"GetAutomationCapabilities", func() error {
			_, err := client.GetAutomationCapabilities(bearer, &automationv1.GetAutomationCapabilitiesRequest{})
			return err
		}},
		{"EnsureOwner", func() error { _, err := client.EnsureOwner(bearer, ensureOwner); return err }},
		{"AcquireOwnerSession", func() error {
			_, err := client.AcquireOwnerSession(bearer, acquireSession)
			return err
		}},
		{"HandoffOwnerSession", func() error {
			_, err := client.HandoffOwnerSession(bearer, handoffSession)
			return err
		}},
		{"ResolveBinding", func() error {
			_, err := client.ResolveBinding(bearer, &automationv1.ResolveBindingRequest{})
			return err
		}},
		{"ObserveResource", func() error {
			_, err := client.ObserveResource(bearer, &automationv1.ObserveResourceRequest{})
			return err
		}},
		{"SubmitCreateVM", func() error {
			_, err := client.SubmitCreateVM(bearer, &automationv1.SubmitCreateVMRequest{})
			return err
		}},
		{"SubmitUpdateVM", func() error {
			_, err := client.SubmitUpdateVM(bearer, &automationv1.SubmitUpdateVMRequest{})
			return err
		}},
		{"SubmitDeleteVM", func() error {
			_, err := client.SubmitDeleteVM(bearer, &automationv1.SubmitDeleteVMRequest{})
			return err
		}},
		{"GetOperation", func() error { _, err := client.GetOperation(bearer, &automationv1.GetOperationRequest{}); return err }},
		{"ListByOwner", func() error { _, err := client.ListByOwner(bearer, &automationv1.ListByOwnerRequest{}); return err }},
		{"AdoptResource", func() error { _, err := client.AdoptResource(bearer, &automationv1.AdoptResourceRequest{}); return err }},
		{"TransferOwner", func() error { _, err := client.TransferOwner(bearer, &automationv1.TransferOwnerRequest{}); return err }},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.invoke()
			st := status.Convert(err)
			if st.Code() != codes.Unavailable || len(st.Details()) != 1 {
				t.Fatalf("enrolled caller must receive typed unavailable, never success/absence: %v", err)
			}
			detail, ok := st.Details()[0].(*automationv1.ErrorDetail)
			if !ok || detail.GetCode() != automationv1.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE || detail.GetRetry().GetAction() != automationv1.RetryAction_RETRY_ACTION_SAME_REQUEST || detail.GetRetry().GetSafeNextAction() == "" {
				t.Fatalf("unavailable authority lost its stable retry contract: %v", err)
			}
			if detail.GetResource() != nil || detail.GetBinding() != nil || detail.GetOperation() != nil || len(detail.GetFieldViolations()) != 0 {
				t.Fatal("unavailable authority disclosed private references")
			}
			for _, secret := range []string{login.GetToken(), "alice", "principal-uid", "established-cluster", "local_automation", "SELECT", "correct-password"} {
				if strings.Contains(st.Message(), secret) || strings.Contains(detail.String(), secret) {
					t.Fatal("unavailable response disclosed credential/storage/principal data")
				}
			}
		})
	}
	if after, err := s.db.AutomationHead(ctx); err != nil || after != before {
		t.Fatalf("public refusal changed retained history: %v", err)
	}
	for _, table := range []string{"local_automation_authority", "local_automation_owners", "local_automation_bindings", "local_automation_resources"} {
		rows, err := s.db.Query(ctx, "SELECT COUNT(*) AS n FROM "+table)
		if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
			t.Fatalf("public registration/refusal created authority or business state in %s: %v", table, err)
		}
	}
	// Credential revocation is still evaluated on this established TLS channel.
	if err := corrosion.RevokeSession(ctx, s.db, strings.TrimPrefix(login.GetToken(), SessionTokenPrefix)); err != nil {
		t.Fatal(err)
	}
	_, err = client.EnsureOwner(bearer, ensureOwner)
	if st := status.Convert(err); st.Code() != codes.Unauthenticated || len(st.Details()) != 1 {
		t.Fatalf("revoked enrolled session bypassed the actual authentication interceptor: %v", err)
	}
	// A fresh actual session still cannot bypass a revoked TLS credential on
	// this already-established connection (no new handshake hides the gate).
	fresh, err := legacy.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password", Realm: "local"})
	if err != nil {
		t.Fatal(err)
	}
	freshBearer := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+fresh.GetToken())
	if _, err := client.EnsureOwner(freshBearer, ensureOwner); status.Code(err) != codes.Unavailable {
		t.Fatalf("fresh enrolled session did not reach unavailable authority: %v", err)
	}
	serial, err := pki.CertSerial(filepath.Join(s.pkiDir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCRL(filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "ca.key"), filepath.Join(s.pkiDir, "crl.pem"), []string{serial}); err != nil {
		t.Fatal(err)
	}
	_, err = client.EnsureOwner(freshBearer, ensureOwner)
	if st := status.Convert(err); st.Code() != codes.Unauthenticated || len(st.Details()) != 1 {
		t.Fatalf("revoked certificate on established TLS bypassed the connection gate: %v", err)
	}
}

func TestAutomationPublicAuthenticationStorageUnavailable(t *testing.T) {
	s := testServer(t)
	connection := automationPublicTLSClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	legacy := pb.NewLiteVirtClient(connection)
	if _, err := legacy.CreateUser(ctx, &pb.CreateUserRequest{Username: "ordinary", Password: "ordinary-password", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	login, err := legacy.Login(ctx, &pb.LoginRequest{Username: "ordinary", Password: "ordinary-password"})
	if err != nil {
		t.Fatal(err)
	}
	bearer := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetToken())
	if _, err := legacy.Whoami(bearer, &emptypb.Empty{}); err != nil {
		t.Fatalf("actual session control: %v", err)
	}
	if _, err := s.db.DB().ExecContext(ctx, "DROP TABLE sessions"); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Whoami(bearer, &emptypb.Empty{}); status.Code(err) != codes.Internal {
		t.Fatalf("legacy session-storage error behavior changed: %v", err)
	}
	_, err = automationv1.NewAutomationClient(connection).EnsureOwner(bearer, &automationv1.EnsureOwnerRequest{})
	st := status.Convert(err)
	if st.Code() != codes.Unavailable || len(st.Details()) != 1 {
		t.Fatalf("unreadable authentication storage became invalid identity/absence: %v", err)
	}
	detail, ok := st.Details()[0].(*automationv1.ErrorDetail)
	if !ok || detail.GetCode() != automationv1.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE || detail.GetRetry().GetAction() != automationv1.RetryAction_RETRY_ACTION_SAME_REQUEST {
		t.Fatalf("authentication uncertainty lost structural unavailable/retry advice: %v", err)
	}
	if strings.Contains(st.Message(), "sessions") || strings.Contains(detail.String(), "SELECT") || strings.Contains(detail.String(), login.GetToken()) {
		t.Fatal("public storage refusal leaked underlying authentication diagnostics")
	}
}

func TestAutomationPublicEnrollmentOnlySessionRemainsDenied(t *testing.T) {
	// Reuse only the existing Login-policy fixture; it supplies no automation
	// identity or business authority. The actual Login mints the restricted
	// session, and the real TLS interceptor enforces its enrollment policy.
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "admin", "bob-password")
	setPolicy(t, s, "all")
	connection := automationPublicTLSClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	legacy := pb.NewLiteVirtClient(connection)
	login, err := legacy.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bob-password"})
	if err != nil || login.GetToken() == "" || !login.GetRequires_2FaEnrollment() {
		t.Fatalf("actual Login did not issue enrollment-only session: %v", err)
	}
	bearer := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetToken())
	if who, err := legacy.Whoami(bearer, &emptypb.Empty{}); err != nil || !who.GetRequires_2FaEnrollment() || who.GetRole() != "" {
		t.Fatalf("actual enrollment-only session control: %v", err)
	}
	_, err = automationv1.NewAutomationClient(connection).EnsureOwner(bearer, &automationv1.EnsureOwnerRequest{})
	st := status.Convert(err)
	if st.Code() != codes.PermissionDenied || len(st.Details()) != 1 {
		t.Fatalf("public service bypassed enrollment-only gate: %v", err)
	}
	detail, ok := st.Details()[0].(*automationv1.ErrorDetail)
	if !ok || detail.GetCode() != automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED || detail.GetRetry().GetAction() != automationv1.RetryAction_RETRY_ACTION_DO_NOT_RETRY {
		t.Fatalf("enrollment-only denial lost its typed permission detail: %v", err)
	}
}

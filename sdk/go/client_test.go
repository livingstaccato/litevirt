package litevirt_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	lv "github.com/livingstaccato/litevirt/sdk/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// These servers implement the published contract over real TLS/HTTP2, without
// daemon/internal imports. They are evidence about client behavior only.
type service struct {
	av.UnimplementedAutomationServer
	caps      func(context.Context, *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error)
	create    func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error)
	owner     func(context.Context, *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error)
	observe   func(context.Context, *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error)
	operation func(context.Context, *av.GetOperationRequest) (*av.GetOperationResponse, error)
}

func capabilities() *av.GetAutomationCapabilitiesResponse {
	return &av.GetAutomationCapabilitiesResponse{ClusterUid: "cluster-A", ContractVersion: "server-defined-value", DurabilityMode: av.DurabilityMode_DURABILITY_MODE_HA_THREE_DURABLE_VOTERS, EnforcedFeatures: []av.EnforcedFeature{av.EnforcedFeature_ENFORCED_FEATURE_DURABLE_IDEMPOTENCY}, Limits: &av.Limits{RequiredDurableVoters: 3}}
}
func (s *service) GetAutomationCapabilities(ctx context.Context, r *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
	if s.caps != nil {
		return s.caps(ctx, r)
	}
	return capabilities(), nil
}
func (s *service) SubmitCreateVM(ctx context.Context, r *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
	if s.create != nil {
		return s.create(ctx, r)
	}
	return &av.SubmitCreateVMResponse{Operation: &av.OperationRef{OperationId: "op-1", MinimumSequence: 41}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) EnsureOwner(ctx context.Context, r *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
	if s.owner != nil {
		return s.owner(ctx, r)
	}
	return &av.EnsureOwnerResponse{Owner: &av.Owner{Ref: r.Owner}, Cursor: &av.ReadCursor{AppliedSequence: 1}}, nil
}
func (s *service) ObserveResource(ctx context.Context, r *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
	if s.observe != nil {
		return s.observe(ctx, r)
	}
	return &av.ObserveResourceResponse{Observation: &av.VMObservation{Presence: av.Presence_PRESENCE_PRESENT}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) GetOperation(ctx context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
	if s.operation != nil {
		return s.operation(ctx, r)
	}
	return &av.GetOperationResponse{Operation: &av.Operation{Ref: r.GetOperation(), State: av.OperationState_OPERATION_STATE_SUCCEEDED}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}

func transport(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SDK transport test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}
func serveAt(t *testing.T, address string, serverTLS *tls.Config, srv *service, options ...grpc.ServerOption) (string, *grpc.Server) {
	t.Helper()
	l, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer(append(options, grpc.Creds(credentials.NewTLS(serverTLS)))...)
	av.RegisterAutomationServer(g, srv)
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	return l.Addr().String(), g
}
func setup(t *testing.T, srv *service) (lv.Config, *grpc.Server) {
	t.Helper()
	st, ct := transport(t)
	address, g := serveAt(t, "127.0.0.1:0", st, srv)
	return lv.Config{Endpoints: []string{address}, TLSConfig: ct, ExpectedClusterUID: "cluster-A", RequiredCapabilities: []av.EnforcedFeature{av.EnforcedFeature_ENFORCED_FEATURE_DURABLE_IDEMPOTENCY}, DefaultDeadline: 2 * time.Second, MaxAttempts: 3, MinBackoff: time.Millisecond, MaxBackoff: 3 * time.Millisecond}, g
}
func client(t *testing.T, c lv.Config) *lv.Client {
	t.Helper()
	v, err := lv.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}
func createRequest() *av.SubmitCreateVMRequest {
	return &av.SubmitCreateVMRequest{Identity: &av.MutationIdentity{RequestId: "retry-this-exact-id", Session: &av.OwnerSession{Owner: &av.OwnerRef{ProjectUid: "project", OwnerId: "owner"}, ActivationGeneration: 1, SessionId: "session"}}, Binding: &av.BindingKey{ProjectUid: "project", OwnerId: "owner", ManagementKey: "machine"}, Desired: &av.VMDesired{Name: "vm", Bootstrap: &av.BootstrapInput{UserData: []byte("#cloud-config\nsecret: $value\n"), NetworkConfig: []byte{}}}}
}

func TestEnrollmentRequiresExplicitDiscovery(t *testing.T) {
	cfg, _ := setup(t, &service{})
	cfg.ExpectedClusterUID = ""
	if _, err := lv.NewClient(cfg); !errors.Is(err, lv.ErrEnrollmentRequired) {
		t.Fatalf("empty UID accepted or wrong error: %v", err)
	}
	caps, err := lv.Enroll(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if caps.ClusterUid != "cluster-A" || caps.ContractVersion != "server-defined-value" {
		t.Fatalf("discovery lost server identity/version: %v", caps)
	}
	cfg.ExpectedClusterUID = caps.ClusterUid
	c := client(t, cfg)
	if _, err = c.EnsureOwner(context.Background(), &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"}); err != nil {
		t.Fatal(err)
	}
}
func TestLostReplyRetainsRequestAndBootstrap(t *testing.T) {
	var n atomic.Int32
	var mu sync.Mutex
	var first *av.SubmitCreateVMRequest
	var firstServer *grpc.Server
	srv := &service{}
	srv.create = func(_ context.Context, r *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
		attempt := n.Add(1)
		if attempt == 1 {
			mu.Lock()
			first = proto.Clone(r).(*av.SubmitCreateVMRequest)
			mu.Unlock()
			// The command is accepted, but the transport is physically terminated
			// before its response can reach the client. A second entry recovers it.
			firstServer.Stop()
		} else {
			mu.Lock()
			same := proto.Equal(first, r)
			mu.Unlock()
			if !same {
				t.Error("retry changed immutable request")
			}
		}
		if r.Desired.Bootstrap.NetworkConfig == nil || !bytes.Equal(r.Desired.Bootstrap.UserData, []byte("#cloud-config\nsecret: $value\n")) {
			t.Error("bootstrap presence/bytes changed")
		}
		return &av.SubmitCreateVMResponse{Operation: &av.OperationRef{OperationId: "same-op", MinimumSequence: 17}, Cursor: &av.ReadCursor{AppliedSequence: 17}}, nil
	}
	st, ct := transport(t)
	var a string
	a, firstServer = serveAt(t, "127.0.0.1:0", st, srv)
	b, _ := serveAt(t, "127.0.0.1:0", st, srv)
	cfg := lv.Config{Endpoints: []string{a, b}, TLSConfig: ct, ExpectedClusterUID: "cluster-A", DefaultDeadline: 2 * time.Second, MinBackoff: time.Millisecond}
	input := createRequest()
	before := proto.Clone(input)
	out, err := client(t, cfg).SubmitCreateVM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 || out.Operation.OperationId != "same-op" {
		t.Fatalf("lost reply not recovered: calls=%d out=%v", n.Load(), out)
	}
	if !proto.Equal(before, input) {
		t.Fatal("caller request mutated")
	}
}
func TestFailoverVerifiesSameCluster(t *testing.T) {
	first := &service{owner: func(context.Context, *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		return nil, status.Error(codes.Unavailable, "entry unavailable")
	}}
	cfg := lv.Config{ExpectedClusterUID: "cluster-A", DefaultDeadline: 2 * time.Second, MinBackoff: time.Millisecond}
	// Both nodes use the same TLS trust; identity is additionally checked by RPC.
	st, ct := transport(t)
	a, _ := serveAt(t, "127.0.0.1:0", st, first)
	var second atomic.Int32
	b, _ := serveAt(t, "127.0.0.1:0", st, &service{owner: func(_ context.Context, r *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		second.Add(1)
		return &av.EnsureOwnerResponse{Owner: &av.Owner{Ref: r.Owner}}, nil
	}})
	cfg.Endpoints = []string{a, b}
	cfg.TLSConfig = ct
	_, err := client(t, cfg).EnsureOwner(context.Background(), &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"})
	if err != nil || second.Load() != 1 {
		t.Fatalf("same cluster failover failed: %v second=%d", err, second.Load())
	}
}
func TestHandshakeRejectsForeignMissingCapabilitiesAndDevelopment(t *testing.T) {
	for _, name := range []string{"foreign", "capability", "development"} {
		t.Run(name, func(t *testing.T) {
			var writes atomic.Int32
			s := &service{caps: func(context.Context, *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
				c := capabilities()
				switch name {
				case "foreign":
					c.ClusterUid = "foreign"
				case "capability":
					c.EnforcedFeatures = nil
				case "development":
					c.DurabilityMode = av.DurabilityMode_DURABILITY_MODE_DEVELOPMENT
				}
				return c, nil
			}, create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
				writes.Add(1)
				return &av.SubmitCreateVMResponse{}, nil
			}}
			cfg, _ := setup(t, s)
			_, err := client(t, cfg).SubmitCreateVM(context.Background(), createRequest())
			if err == nil || writes.Load() != 0 {
				t.Fatalf("unverified write: error=%v calls=%d", err, writes.Load())
			}
			if name == "foreign" && !errors.Is(err, lv.ErrClusterMismatch) {
				t.Fatalf("foreign mismatch not structural: %v", err)
			}
			if name == "development" {
				cfg.AllowDevelopment = true
				if _, err = client(t, cfg).SubmitCreateVM(context.Background(), createRequest()); err != nil {
					t.Fatalf("explicit development denied: %v", err)
				}
			}
		})
	}
}
func TestReplacementTransportCannotReceiveUnverifiedWrite(t *testing.T) {
	st, ct := transport(t)
	var replacementWrites atomic.Int32
	var oldCaps atomic.Int32
	old := &service{caps: func(context.Context, *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
		oldCaps.Add(1)
		return capabilities(), nil
	}}
	address, g := serveAt(t, "127.0.0.1:0", st, old)
	cfg := lv.Config{Endpoints: []string{address}, TLSConfig: ct, ExpectedClusterUID: "cluster-A", DefaultDeadline: 2 * time.Second, MinBackoff: time.Millisecond}
	var credentialsCalls atomic.Int32
	cfg.CredentialSource = func(context.Context) (string, error) {
		if credentialsCalls.Add(1) == 2 {
			g.Stop()
			serveAt(t, address, st, &service{caps: func(context.Context, *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
				v := capabilities()
				v.EnforcedFeatures = nil
				return v, nil
			}, create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
				replacementWrites.Add(1)
				return &av.SubmitCreateVMResponse{}, nil
			}})
		}
		return "token", nil
	}
	cfg.RequiredCapabilities = []av.EnforcedFeature{av.EnforcedFeature_ENFORCED_FEATURE_DURABLE_IDEMPOTENCY}
	_, err := client(t, cfg).SubmitCreateVM(context.Background(), createRequest())
	if err == nil || oldCaps.Load() != 1 || credentialsCalls.Load() < 3 || replacementWrites.Load() != 0 {
		t.Fatalf("replacement bypassed verification: err=%v oldcaps=%d credentials=%d writes=%d", err, oldCaps.Load(), credentialsCalls.Load(), replacementWrites.Load())
	}
}
func TestConcurrentClientsKeepCredentialsSeparate(t *testing.T) {
	s := &service{owner: func(ctx context.Context, r *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if got := md.Get("authorization"); len(got) != 1 || got[0] != "Bearer "+r.Owner.OwnerId {
			return nil, status.Error(codes.PermissionDenied, "credential crossed clients")
		}
		return &av.EnsureOwnerResponse{Owner: &av.Owner{Ref: r.Owner}}, nil
	}}
	cfg, _ := setup(t, s)
	var wg sync.WaitGroup
	for _, token := range []string{"alice", "bob"} {
		c := cfg
		c.CredentialSource = func(context.Context) (string, error) { return token, nil }
		v := client(t, c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if _, err := v.EnsureOwner(context.Background(), &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: token}, RequestId: token}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
func TestWaitDeadlineRetainsClonedReference(t *testing.T) {
	s := &service{operation: func(ctx context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: r.GetOperation(), State: av.OperationState_OPERATION_STATE_BLOCKED, Retry: &av.RetryAdvice{RetryAfter: durationpb.New(time.Millisecond)}}, Cursor: &av.ReadCursor{AppliedSequence: 51}}, nil
	}}
	cfg, _ := setup(t, s)
	c := client(t, cfg)
	ref := &av.OperationRef{OperationId: "known", MinimumSequence: 41}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := c.WaitOperation(ctx, ref)
	var interrupted *lv.WaitError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &interrupted) || interrupted.Operation.OperationId != "known" || interrupted.Operation.MinimumSequence < 41 {
		t.Fatalf("deadline lost ref: %v", err)
	}
	ref.OperationId = "changed"
	if interrupted.Operation.OperationId != "known" {
		t.Fatal("wait error aliases caller ref")
	}
}
func TestObservationCarriesAcceptedMinimum(t *testing.T) {
	var sequence atomic.Uint64
	s := &service{observe: func(_ context.Context, r *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
		sequence.Store(r.GetMinimum().GetAppliedSequence())
		if r.GetMinimum().GetResourceRevision() != "opaque-z" {
			t.Error("opaque revision changed")
		}
		return &av.ObserveResourceResponse{Observation: &av.VMObservation{Presence: av.Presence_PRESENCE_PRESENT}, Cursor: &av.ReadCursor{AppliedSequence: 42}}, nil
	}}
	cfg, _ := setup(t, s)
	c := client(t, cfg)
	if _, err := c.SubmitCreateVM(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	r := &av.ObserveResourceRequest{Resource: &av.ResourceRef{ClusterUid: "cluster-A", ProjectUid: "p", Kind: "vm", ResourceUid: "r"}, Minimum: &av.ReadCursor{AppliedSequence: 2, ResourceRevision: "opaque-z"}}
	if _, err := c.ObserveResource(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if sequence.Load() != 41 || r.Minimum.AppliedSequence != 2 {
		t.Fatalf("accepted floor lost or caller mutated: sent=%d caller=%d", sequence.Load(), r.Minimum.AppliedSequence)
	}
}
func TestTypedErrorsDoNotBecomeAbsenceOrRetry(t *testing.T) {
	var calls atomic.Int32
	detail := &av.ErrorDetail{Code: av.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Operation: &av.OperationRef{OperationId: "admitted"}, Retry: &av.RetryAdvice{Action: av.RetryAction_RETRY_ACTION_DO_NOT_RETRY}}
	st, err := status.New(codes.PermissionDenied, "opaque diagnostic").WithDetails(detail)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := setup(t, &service{create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
		calls.Add(1)
		return nil, st.Err()
	}})
	_, err = client(t, cfg).SubmitCreateVM(context.Background(), createRequest())
	var typed *lv.Error
	if !errors.As(err, &typed) || typed.Code != av.ErrorCode_ERROR_CODE_PERMISSION_DENIED || typed.Detail.Operation.OperationId != "admitted" || status.Code(err) != codes.PermissionDenied || calls.Load() != 1 {
		t.Fatalf("typed error/retry contract lost: err=%v calls=%d", err, calls.Load())
	}
}
func TestUnsafeIdentityIsRejectedBeforeTransport(t *testing.T) {
	var n atomic.Int32
	cfg, _ := setup(t, &service{create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
		n.Add(1)
		return nil, status.Error(codes.Unavailable, "lost")
	}})
	r := createRequest()
	r.Identity.RequestId = ""
	_, err := client(t, cfg).SubmitCreateVM(context.Background(), r)
	if err == nil || n.Load() != 0 {
		t.Fatalf("unbound submission reached transport: %v calls=%d", err, n.Load())
	}
}
func TestCloseCancelsCallsAndRejectsNewWork(t *testing.T) {
	entered := make(chan struct{})
	cfg, _ := setup(t, &service{owner: func(ctx context.Context, _ *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	c := client(t, cfg)
	done := make(chan error, 1)
	go func() {
		_, err := c.EnsureOwner(context.Background(), &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("RPC never started")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, lv.ErrClosed) {
			t.Fatalf("closed call wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel in-flight call")
	}
	if _, err := c.EnsureOwner(context.Background(), &av.EnsureOwnerRequest{}); !errors.Is(err, lv.ErrClosed) {
		t.Fatalf("closed client accepted work: %v", err)
	}
}

func TestStaleObservationCannotEstablishAbsence(t *testing.T) {
	cfg, _ := setup(t, &service{observe: func(context.Context, *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
		return &av.ObserveResourceResponse{Observation: &av.VMObservation{Presence: av.Presence_PRESENCE_ABSENT}, Cursor: &av.ReadCursor{AppliedSequence: 40}}, nil
	}})
	c := client(t, cfg)
	if _, err := c.SubmitCreateVM(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	out, err := c.ObserveResource(context.Background(), &av.ObserveResourceRequest{Resource: &av.ResourceRef{ClusterUid: "cluster-A", ProjectUid: "p", Kind: "vm", ResourceUid: "r"}})
	var typed *lv.Error
	if out != nil || !errors.As(err, &typed) || typed.Code != av.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE {
		t.Fatalf("stale replica established absence below accepted floor41: out=%v err=%v", out, err)
	}
}
func TestAcceptedReferenceSuppliesFloorWithoutCursor(t *testing.T) {
	var sent atomic.Uint64
	s := &service{create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
		return &av.SubmitCreateVMResponse{Operation: &av.OperationRef{OperationId: "accepted", MinimumSequence: 71}}, nil
	}, observe: func(_ context.Context, r *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
		sent.Store(r.GetMinimum().GetAppliedSequence())
		return &av.ObserveResourceResponse{Observation: &av.VMObservation{Presence: av.Presence_PRESENCE_PRESENT}, Cursor: &av.ReadCursor{AppliedSequence: 71}}, nil
	}}
	cfg, _ := setup(t, s)
	c := client(t, cfg)
	if _, err := c.SubmitCreateVM(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ObserveResource(context.Background(), &av.ObserveResourceRequest{Resource: &av.ResourceRef{ClusterUid: "cluster-A", ProjectUid: "p", Kind: "vm", ResourceUid: "r"}}); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 71 {
		t.Fatalf("accepted operation minimum ignored: sent=%d want71", sent.Load())
	}
}
func TestStructuredRetryAdviceBoundsIdentityBoundRetries(t *testing.T) {
	for _, action := range []av.RetryAction{av.RetryAction_RETRY_ACTION_SAME_REQUEST, av.RetryAction_RETRY_ACTION_REFRESH_STATE, av.RetryAction_RETRY_ACTION_DO_NOT_RETRY} {
		t.Run(action.String(), func(t *testing.T) {
			var n atomic.Int32
			detail := &av.ErrorDetail{Code: av.ErrorCode_ERROR_CODE_QUOTA, Retry: &av.RetryAdvice{Action: action, RetryAfter: durationpb.New(2 * time.Millisecond)}}
			st, err := status.New(codes.ResourceExhausted, "quota").WithDetails(detail)
			if err != nil {
				t.Fatal(err)
			}
			cfg, _ := setup(t, &service{create: func(context.Context, *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
				n.Add(1)
				return nil, st.Err()
			}})
			start := time.Now()
			_, err = client(t, cfg).SubmitCreateVM(context.Background(), createRequest())
			var typed *lv.Error
			if !errors.As(err, &typed) || typed.Code != av.ErrorCode_ERROR_CODE_QUOTA {
				t.Fatal(err)
			}
			want := int32(1)
			if action == av.RetryAction_RETRY_ACTION_SAME_REQUEST {
				want = 3
				if time.Since(start) < 4*time.Millisecond {
					t.Fatal("retry advice delay ignored")
				}
			}
			if n.Load() != want {
				t.Fatalf("retry advice ignored: got%d want%d", n.Load(), want)
			}
		})
	}
}
func TestDefaultDeadlineIncludesServerWait(t *testing.T) {
	cfg, _ := setup(t, &service{owner: func(ctx context.Context, _ *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	cfg.DefaultDeadline = 25 * time.Millisecond
	start := time.Now()
	_, err := client(t, cfg).EnsureOwner(context.Background(), &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("default deadline not enforced: %v", err)
	}
}
func TestWaitReturnsTerminalFailureWithResponse(t *testing.T) {
	cfg, _ := setup(t, &service{operation: func(_ context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: r.GetOperation(), State: av.OperationState_OPERATION_STATE_FAILED, Outcome: av.OperationOutcome_OPERATION_OUTCOME_PARTIALLY_APPLIED}, Cursor: &av.ReadCursor{AppliedSequence: 51}}, nil
	}})
	out, err := client(t, cfg).WaitOperation(context.Background(), &av.OperationRef{OperationId: "op", MinimumSequence: 41})
	var typed *lv.Error
	if !errors.As(err, &typed) || typed.Code != av.ErrorCode_ERROR_CODE_OPERATION_FAILED || typed.Detail.GetOperation().GetOperationId() != "op" || out.GetOperation().GetOutcome() != av.OperationOutcome_OPERATION_OUTCOME_PARTIALLY_APPLIED {
		t.Fatalf("terminal failure lost result/ref: out=%v err=%v", out, err)
	}
}
func TestCanceledContextSendsNothing(t *testing.T) {
	var credentialsCalls atomic.Int32
	cfg, _ := setup(t, &service{})
	cfg.CredentialSource = func(context.Context) (string, error) { credentialsCalls.Add(1); return "token", nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client(t, cfg).EnsureOwner(ctx, &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"})
	if !errors.Is(err, context.Canceled) || credentialsCalls.Load() != 0 {
		t.Fatalf("canceled caller triggered transport: err=%v credential calls=%d", err, credentialsCalls.Load())
	}
}

func (s *service) AcquireOwnerSession(_ context.Context, r *av.AcquireOwnerSessionRequest) (*av.AcquireOwnerSessionResponse, error) {
	return &av.AcquireOwnerSessionResponse{Session: &av.OwnerSession{Owner: r.Owner, ActivationGeneration: 1, SessionId: r.SessionId}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) HandoffOwnerSession(_ context.Context, r *av.HandoffOwnerSessionRequest) (*av.HandoffOwnerSessionResponse, error) {
	return &av.HandoffOwnerSessionResponse{Session: &av.OwnerSession{Owner: r.Current.Owner, ActivationGeneration: 2, SessionId: r.SuccessorSessionId}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) ResolveBinding(_ context.Context, r *av.ResolveBindingRequest) (*av.ResolveBindingResponse, error) {
	return &av.ResolveBindingResponse{Binding: &av.Binding{Ref: &av.BindingRef{ProjectUid: r.Key.ProjectUid, OwnerId: r.Key.OwnerId, ManagementKey: r.Key.ManagementKey, CreationGeneration: 1}, Presence: av.Presence_PRESENCE_PRESENT, Operations: []*av.OperationRef{{OperationId: "op-1", MinimumSequence: 41}}}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) SubmitUpdateVM(_ context.Context, r *av.SubmitUpdateVMRequest) (*av.SubmitUpdateVMResponse, error) {
	return &av.SubmitUpdateVMResponse{Resource: r.Resource, Binding: r.Binding, Operation: &av.OperationRef{OperationId: "update", MinimumSequence: 41}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) SubmitDeleteVM(_ context.Context, r *av.SubmitDeleteVMRequest) (*av.SubmitDeleteVMResponse, error) {
	return &av.SubmitDeleteVMResponse{Resource: r.Resource, Binding: r.Binding, Operation: &av.OperationRef{OperationId: "delete", MinimumSequence: 41}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) ListByOwner(_ context.Context, r *av.ListByOwnerRequest) (*av.ListByOwnerResponse, error) {
	return &av.ListByOwnerResponse{Bindings: []*av.Binding{{Ref: &av.BindingRef{ProjectUid: r.Owner.ProjectUid, OwnerId: r.Owner.OwnerId, ManagementKey: "machine", CreationGeneration: 1}, Presence: av.Presence_PRESENCE_RETIRED}}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) AdoptResource(_ context.Context, r *av.AdoptResourceRequest) (*av.AdoptResourceResponse, error) {
	return &av.AdoptResourceResponse{Resource: r.Resource, Operation: &av.OperationRef{OperationId: "adopt", MinimumSequence: 41}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}
func (s *service) TransferOwner(_ context.Context, r *av.TransferOwnerRequest) (*av.TransferOwnerResponse, error) {
	return &av.TransferOwnerResponse{Resource: r.Resource, Operation: &av.OperationRef{OperationId: "transfer", MinimumSequence: 41}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
}

func TestEveryPublicMethodAndBindingRecoveryUsesTypedTransport(t *testing.T) {
	st, ct := transport(t)
	var mu sync.Mutex
	seen := map[string]int{}
	address, _ := serveAt(t, "127.0.0.1:0", st, &service{operation: func(_ context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		lookup := r.GetRequest()
		if lookup == nil || lookup.RequestId != "lost-first-reply" || lookup.Binding.ManagementKey != "machine" || lookup.CreationGeneration != nil {
			t.Error("recovery needs only binding/request, without saved IDs/generation")
		}
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: &av.OperationRef{OperationId: "recovered", MinimumSequence: 41}, RequestId: lookup.RequestId, State: av.OperationState_OPERATION_STATE_SUCCEEDED}, Cursor: &av.ReadCursor{AppliedSequence: 41}}, nil
	}}, grpc.UnaryInterceptor(func(ctx context.Context, r any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		mu.Lock()
		seen[info.FullMethod]++
		mu.Unlock()
		return handler(ctx, r)
	}))
	c := client(t, lv.Config{Endpoints: []string{address}, TLSConfig: ct, ExpectedClusterUID: "cluster-A"})
	ctx := context.Background()
	owner := &av.OwnerRef{ProjectUid: "project", OwnerId: "owner"}
	session := &av.OwnerSession{Owner: owner, SessionId: "session", ActivationGeneration: 1}
	identity := &av.MutationIdentity{Session: session, RequestId: "request"}
	key := &av.BindingKey{ProjectUid: "project", OwnerId: "owner", ManagementKey: "machine"}
	binding := &av.BindingRef{ProjectUid: "project", OwnerId: "owner", ManagementKey: "machine", CreationGeneration: 1}
	resource := &av.ResourceRef{ClusterUid: "cluster-A", ProjectUid: "project", Kind: "vm", ResourceUid: "resource"}
	checks := []func() error{
		func() error {
			_, e := c.GetAutomationCapabilities(ctx, &av.GetAutomationCapabilitiesRequest{})
			return e
		},
		func() error {
			_, e := c.EnsureOwner(ctx, &av.EnsureOwnerRequest{Owner: owner, RequestId: "ensure"})
			return e
		},
		func() error {
			_, e := c.AcquireOwnerSession(ctx, &av.AcquireOwnerSessionRequest{Owner: owner, SessionId: "session", RequestId: "acquire"})
			return e
		},
		func() error {
			_, e := c.HandoffOwnerSession(ctx, &av.HandoffOwnerSessionRequest{Current: session, SuccessorSessionId: "next", RequestId: "handoff"})
			return e
		},
		func() error { _, e := c.ResolveBinding(ctx, &av.ResolveBindingRequest{Key: key}); return e },
		func() error { _, e := c.ObserveResource(ctx, &av.ObserveResourceRequest{Resource: resource}); return e },
		func() error { _, e := c.SubmitCreateVM(ctx, createRequest()); return e },
		func() error {
			_, e := c.SubmitUpdateVM(ctx, &av.SubmitUpdateVMRequest{Identity: identity, Resource: resource, Binding: binding, ExpectedRevision: "opaque", Patch: &av.VMPatch{Cpu: proto.Uint32(2)}, PermittedDisruption: av.DisruptionClass_DISRUPTION_CLASS_LIVE})
			return e
		},
		func() error {
			_, e := c.SubmitDeleteVM(ctx, &av.SubmitDeleteVMRequest{Identity: identity, Resource: resource, Binding: binding, ExpectedRevision: "opaque", DiskPolicy: av.DiskPolicy_DISK_POLICY_RETAIN})
			return e
		},
		func() error {
			out, e := c.GetOperation(ctx, &av.GetOperationRequest{Lookup: &av.GetOperationRequest_Request{Request: &av.OperationRequestLookup{Binding: key, RequestId: "lost-first-reply"}}})
			if e == nil && out.Operation.Ref.OperationId != "recovered" {
				t.Error("request lookup did not recover operation")
			}
			return e
		},
		func() error {
			_, e := c.ListByOwner(ctx, &av.ListByOwnerRequest{Owner: owner, IncludeRetired: proto.Bool(true)})
			return e
		},
		func() error {
			_, e := c.AdoptResource(ctx, &av.AdoptResourceRequest{Identity: identity, Resource: resource, Target: key, ExpectedRevision: "opaque"})
			return e
		},
		func() error {
			_, e := c.TransferOwner(ctx, &av.TransferOwnerRequest{Identity: identity, Resource: resource, Source: binding, Target: key, TargetSession: session, ExpectedRevision: "opaque"})
			return e
		},
	}
	for i, check := range checks {
		if err := check(); err != nil {
			t.Fatalf("method%d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 13 {
		t.Fatalf("not all13 public RPCs reached actual transport: %v", seen)
	}
}

func TestWaitPollsBlockedToSuccessAtIncreasingFloor(t *testing.T) {
	var n atomic.Int32
	cfg, _ := setup(t, &service{operation: func(_ context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		attempt := n.Add(1)
		want := []uint64{41, 45, 46}
		if attempt > 3 {
			t.Error("terminal success polled again")
			return nil, status.Error(codes.Internal, "extra poll")
		}
		if r.GetOperation().MinimumSequence != want[attempt-1] {
			t.Errorf("poll%d minimum=%d want%d", attempt, r.GetOperation().MinimumSequence, want[attempt-1])
		}
		state := []av.OperationState{av.OperationState_OPERATION_STATE_BLOCKED, av.OperationState_OPERATION_STATE_RUNNING, av.OperationState_OPERATION_STATE_SUCCEEDED}[attempt-1]
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: r.GetOperation(), State: state}, Cursor: &av.ReadCursor{AppliedSequence: uint64(44 + attempt)}}, nil
	}})
	ref := &av.OperationRef{OperationId: "progress", MinimumSequence: 41}
	out, err := client(t, cfg).WaitOperation(context.Background(), ref)
	if err != nil || out.GetOperation().GetState() != av.OperationState_OPERATION_STATE_SUCCEEDED || n.Load() != 3 || ref.MinimumSequence != 41 {
		t.Fatalf("wait progression/ref contract failed: out=%v err=%v polls=%d ref=%v", out, err, n.Load(), ref)
	}
}

func TestOversizedWaitAdviceReturnsRecoverableStructuredDeferral(t *testing.T) {
	var calls atomic.Int32
	cfg, _ := setup(t, &service{operation: func(_ context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		calls.Add(1)
		return &av.GetOperationResponse{Operation: &av.Operation{Ref: r.GetOperation(), State: av.OperationState_OPERATION_STATE_RUNNING, Retry: &av.RetryAdvice{Action: av.RetryAction_RETRY_ACTION_SAME_REQUEST, RetryAfter: durationpb.New(time.Hour), SafeNextAction: "observe after advised delay"}}, Cursor: &av.ReadCursor{AppliedSequence: 51}}, nil
	}})
	cfg.DefaultDeadline = 100 * time.Millisecond
	c := client(t, cfg)
	ref := &av.OperationRef{OperationId: "known", MinimumSequence: 41}
	start := time.Now()
	out, err := c.WaitOperation(context.Background(), ref)
	var deferred *lv.WaitError
	if !errors.Is(err, lv.ErrWaitBackoffExceeded) || !errors.As(err, &deferred) {
		t.Fatalf("oversized advice slept past configured bound instead of structured deferral: elapsed=%v err=%v", time.Since(start), err)
	}
	if calls.Load() != 1 {
		t.Fatalf("overbound sleep or polling: elapsed=%v calls=%d", time.Since(start), calls.Load())
	}
	if out.GetOperation().GetState() != av.OperationState_OPERATION_STATE_RUNNING || deferred.Operation.OperationId != "known" || deferred.Operation.MinimumSequence != 51 || deferred.Retry.GetRetryAfter().AsDuration() != time.Hour || deferred.Retry.SafeNextAction != "observe after advised delay" {
		t.Fatalf("deferral discarded running result/ref/advice: out=%v err=%v", out, deferred)
	}
	ref.OperationId = "mutated-input"
	out.Operation.Retry.RetryAfter.Seconds = 1
	if deferred.Operation.OperationId != "known" || deferred.Retry.RetryAfter.AsDuration() != time.Hour {
		t.Fatal("deferred reference/advice aliases input or response")
	}
}
func TestLocalRPCInputValidationIsTyped(t *testing.T) {
	cfg, _ := setup(t, &service{})
	var credentialsCalls atomic.Int32
	cfg.CredentialSource = func(context.Context) (string, error) { credentialsCalls.Add(1); return "token", nil }
	c := client(t, cfg)
	cases := []struct {
		name string
		call func() error
	}{
		{"nil request", func() error { _, err := c.SubmitCreateVM(context.Background(), nil); return err }},
		{"missing mutation identity", func() error {
			r := createRequest()
			r.Identity = nil
			_, err := c.SubmitCreateVM(context.Background(), r)
			return err
		}},
		{"empty mutation request ID", func() error {
			r := createRequest()
			r.Identity.RequestId = ""
			_, err := c.SubmitCreateVM(context.Background(), r)
			return err
		}},
		{"nil wait reference", func() error { _, err := c.WaitOperation(context.Background(), nil); return err }},
		{"empty wait operation ID", func() error { _, err := c.WaitOperation(context.Background(), &av.OperationRef{}); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			var typed *lv.Error
			if !errors.As(err, &typed) || typed.Code != av.ErrorCode_ERROR_CODE_VALIDATION || status.Code(err) != codes.InvalidArgument {
				t.Fatalf("local validation has inconsistent public error interface: %T %v", err, err)
			}
		})
	}
	if credentialsCalls.Load() != 0 {
		t.Fatal("local validation reached transport")
	}
}
func TestDefaultDeadlineCapsLongerCallerDeadline(t *testing.T) {
	cfg, _ := setup(t, &service{owner: func(ctx context.Context, _ *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	cfg.DefaultDeadline = 25 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := client(t, cfg).EnsureOwner(ctx, &av.EnsureOwnerRequest{Owner: &av.OwnerRef{ProjectUid: "p", OwnerId: "o"}, RequestId: "ensure"})
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("configured maximum failed to cap longer caller deadline: err=%v caller=%v elapsed=%v", err, ctx.Err(), time.Since(start))
	}
}

// Package litevirt provides explicit, recovery-aware Automation clients.
// Each RPC attempt uses a fresh TLS connection, verifies cluster capabilities,
// and closes that connection. A connection can never transparently reconnect
// between verification and an application RPC. This favors safety over pooling.
package litevirt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	ErrEnrollmentRequired = errors.New("litevirt: explicit cluster enrollment required")
	ErrClusterMismatch    = errors.New("litevirt: cluster identity mismatch")
	ErrClosed             = errors.New("litevirt: client closed")
)

// Config is copied by NewClient. Endpoints are static host:port addresses.
// TLSConfig must verify server identity. CredentialSource returns an existing
// bearer token, is called for each wire RPC, and must support concurrent calls.
// No login, token persistence, or account enrollment is performed by this SDK.
// MaxAttempts bounds safe retries; zero selects 3. Deadlines bound the entire
// logical call including dialing, capability checks and retries. DefaultDeadline
// is a maximum even when the caller supplies a longer deadline; zero selects
// 30 seconds. The earlier caller/configured deadline always wins.
type Config struct {
	Endpoints              []string
	TLSConfig              *tls.Config
	CredentialSource       func(context.Context) (string, error)
	ExpectedClusterUID     string
	RequiredCapabilities   []av.EnforcedFeature
	DefaultDeadline        time.Duration
	AllowDevelopment       bool
	MaxAttempts            int
	MinBackoff, MaxBackoff time.Duration
}

type Client struct {
	cfg         Config
	life        context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[*grpc.ClientConn]struct{}
	next        atomic.Uint64
	floor       atomic.Uint64
}

func validateConfig(cfg Config, enrollment bool) (Config, error) {
	if !enrollment && cfg.ExpectedClusterUID == "" {
		return cfg, ErrEnrollmentRequired
	}
	if len(cfg.Endpoints) == 0 {
		return cfg, errors.New("litevirt: endpoints required")
	}
	cfg.Endpoints = append([]string(nil), cfg.Endpoints...)
	for _, endpoint := range cfg.Endpoints {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" || port == "" {
			return cfg, errors.New("litevirt: endpoint must be host:port")
		}
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		return cfg, errors.New("litevirt: verified TLS configuration required")
	}
	cfg.TLSConfig = cfg.TLSConfig.Clone()
	if cfg.TLSConfig.RootCAs != nil {
		cfg.TLSConfig.RootCAs = cfg.TLSConfig.RootCAs.Clone()
	}
	if cfg.TLSConfig.MinVersion < tls.VersionTLS12 {
		cfg.TLSConfig.MinVersion = tls.VersionTLS12
	}
	cfg.RequiredCapabilities = append([]av.EnforcedFeature(nil), cfg.RequiredCapabilities...)
	for _, f := range cfg.RequiredCapabilities {
		if f == av.EnforcedFeature_ENFORCED_FEATURE_UNSPECIFIED {
			return cfg, errors.New("litevirt: unspecified required capability")
		}
	}
	if cfg.DefaultDeadline == 0 {
		cfg.DefaultDeadline = 30 * time.Second
	}
	if cfg.DefaultDeadline < 0 {
		return cfg, errors.New("litevirt: negative default deadline")
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 100 {
		return cfg, errors.New("litevirt: max attempts must be between 1 and 100")
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = 25 * time.Millisecond
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = time.Second
	}
	if cfg.MinBackoff < 0 || cfg.MaxBackoff < cfg.MinBackoff || cfg.MaxBackoff > time.Minute {
		return cfg, errors.New("litevirt: invalid backoff bounds")
	}
	return cfg, nil
}

// NewClient validates configuration without performing network calls. Obtain
// an expected UID through explicit Enroll, then accept and persist it yourself.
func NewClient(cfg Config) (*Client, error) {
	cfg, err := validateConfig(cfg, false)
	if err != nil {
		return nil, err
	}
	return newClient(cfg), nil
}
func newClient(cfg Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{cfg: cfg, life: ctx, cancel: cancel, connections: make(map[*grpc.ClientConn]struct{})}
}

// Close cancels active calls and closes their transports. It is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	connections := make([]*grpc.ClientConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}
func (c *Client) isClosed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
func (c *Client) begin(ctx context.Context) (context.Context, func(), error) {
	if c.isClosed() {
		return nil, nil, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.DefaultDeadline)
	stop := context.AfterFunc(c.life, cancel)
	return ctx, func() { stop(); cancel() }, nil
}
func (c *Client) normalize(ctx context.Context, err error) error {
	if c.isClosed() {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return decodeError(err)
}

// Enroll explicitly discovers a TLS-authenticated cluster UID using the existing
// capability RPC. Returning it does not persist or automatically accept trust.
// Pass the accepted UID to NewClient for all subsequent ordinary operations.
func Enroll(ctx context.Context, cfg Config) (*av.GetAutomationCapabilitiesResponse, error) {
	cfg, err := validateConfig(cfg, true)
	if err != nil {
		return nil, err
	}
	c := newClient(cfg)
	defer c.Close()
	return c.GetAutomationCapabilities(ctx, &av.GetAutomationCapabilitiesRequest{})
}

func (c *Client) authContext(ctx context.Context) (context.Context, error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Delete("authorization")
	if c.cfg.CredentialSource != nil {
		token, err := c.cfg.CredentialSource(ctx)
		if err != nil {
			return nil, fmt.Errorf("litevirt credential source: %w", err)
		}
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty credential")
		}
		md.Set("authorization", "Bearer "+token)
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

// connect permits exactly one physical TCP connection. gRPC may retry dialing
// internally, but can never receive a second socket for this verified attempt.
func (c *Client) connect(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "endpoint unavailable")
	}
	var used atomic.Bool
	conn, err := grpc.DialContext(ctx, "passthrough:///"+endpoint, grpc.WithTransportCredentials(credentials.NewTLS(c.cfg.TLSConfig.Clone())), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		if !used.CompareAndSwap(false, true) {
			return nil, errors.New("litevirt: verified transport cannot reconnect")
		}
		return raw, nil
	}), grpc.WithBlock(), grpc.WithDisableRetry())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, ErrClosed
	}
	c.connections[conn] = struct{}{}
	c.mu.Unlock()
	return conn, nil
}
func (c *Client) release(conn *grpc.ClientConn) {
	_ = conn.Close()
	c.mu.Lock()
	delete(c.connections, conn)
	c.mu.Unlock()
}
func (c *Client) verify(ctx context.Context, svc av.AutomationClient, mutation bool) (*av.GetAutomationCapabilitiesResponse, error) {
	auth, err := c.authContext(ctx)
	if err != nil {
		return nil, err
	}
	req := &av.GetAutomationCapabilitiesRequest{}
	if c.cfg.ExpectedClusterUID != "" {
		req.ExpectedClusterUid = proto.String(c.cfg.ExpectedClusterUID)
	}
	caps, err := svc.GetAutomationCapabilities(auth, req)
	if err != nil {
		return nil, err
	}
	if caps.GetClusterUid() == "" {
		return nil, ErrEnrollmentRequired
	}
	if c.cfg.ExpectedClusterUID != "" && caps.ClusterUid != c.cfg.ExpectedClusterUID {
		return nil, ErrClusterMismatch
	}
	unsupported := func() error {
		return &Error{Code: av.ErrorCode_ERROR_CODE_UNSUPPORTED, Detail: &av.ErrorDetail{Code: av.ErrorCode_ERROR_CODE_UNSUPPORTED}, Cause: status.Error(codes.FailedPrecondition, "required capability or durability unavailable")}
	}
	if caps.DurabilityMode != av.DurabilityMode_DURABILITY_MODE_HA_THREE_DURABLE_VOTERS && !(caps.DurabilityMode == av.DurabilityMode_DURABILITY_MODE_DEVELOPMENT && c.cfg.AllowDevelopment) {
		return nil, unsupported()
	}
	if caps.DurabilityMode == av.DurabilityMode_DURABILITY_MODE_HA_THREE_DURABLE_VOTERS && caps.GetLimits().GetRequiredDurableVoters() < 3 {
		return nil, unsupported()
	}
	have := make(map[av.EnforcedFeature]bool)
	for _, f := range caps.EnforcedFeatures {
		have[f] = true
	}
	for _, f := range c.cfg.RequiredCapabilities {
		if !have[f] {
			return nil, unsupported()
		}
	}
	if mutation && !have[av.EnforcedFeature_ENFORCED_FEATURE_DURABLE_IDEMPOTENCY] {
		return nil, unsupported()
	}
	return caps, nil
}
func (c *Client) remember(response proto.Message) {
	var n uint64
	if r, ok := response.(interface{ GetCursor() *av.ReadCursor }); ok {
		n = r.GetCursor().GetAppliedSequence()
	}
	if r, ok := response.(interface{ GetOperation() *av.OperationRef }); ok {
		n = max(n, r.GetOperation().GetMinimumSequence())
	}
	for old := c.floor.Load(); n > old; old = c.floor.Load() {
		if c.floor.CompareAndSwap(old, n) {
			break
		}
	}
}

// Do not expose even an apparently successful absence below the requested
// authoritative prefix. Snapshot pagination has its own fixed prefix and is
// deliberately excluded from this check.
func validateReadResponse(request, response proto.Message) error {
	var minimum uint64
	switch r := request.(type) {
	case interface{ GetMinimum() *av.ReadCursor }:
		minimum = max(r.GetMinimum().GetAppliedSequence(), r.GetMinimum().GetOperation().GetMinimumSequence())
	case *av.GetOperationRequest:
		minimum = r.GetOperation().GetMinimumSequence()
	default:
		return nil
	}
	r, ok := response.(interface{ GetCursor() *av.ReadCursor })
	if !ok || r.GetCursor().GetAppliedSequence() < minimum {
		return status.Error(codes.Unavailable, "response below required observation prefix")
	}
	return nil
}
func (c *Client) minimum(r *av.ReadCursor) *av.ReadCursor {
	if r == nil {
		r = &av.ReadCursor{}
	} else {
		r = proto.Clone(r).(*av.ReadCursor)
	}
	r.AppliedSequence = max(r.AppliedSequence, c.floor.Load())
	return r
}
func (c *Client) prepare(request proto.Message) error {
	switch r := request.(type) {
	case *av.ObserveResourceRequest:
		r.Minimum = c.minimum(r.Minimum)
		if r.GetResource().GetClusterUid() != c.cfg.ExpectedClusterUID {
			return ErrClusterMismatch
		}
	case *av.ResolveBindingRequest:
		r.Minimum = c.minimum(r.Minimum)
	case *av.GetOperationRequest:
		if op := r.GetOperation(); op != nil {
			op.MinimumSequence = max(op.MinimumSequence, c.floor.Load())
		}
	case *av.GetAutomationCapabilitiesRequest:
		if r.ExpectedClusterUid != nil && r.GetExpectedClusterUid() != c.cfg.ExpectedClusterUID && c.cfg.ExpectedClusterUID != "" {
			return ErrClusterMismatch
		}
	}
	switch r := request.(type) {
	case interface{ GetResource() *av.ResourceRef }:
		if r.GetResource() != nil && r.GetResource().GetClusterUid() != c.cfg.ExpectedClusterUID {
			return ErrClusterMismatch
		}
	}
	return nil
}
func validOwner(r *av.OwnerRef) bool { return r.GetProjectUid() != "" && r.GetOwnerId() != "" }
func validSession(s *av.OwnerSession) bool {
	return validOwner(s.GetOwner()) && s.GetActivationGeneration() > 0 && s.GetSessionId() != ""
}
func identityBound(request proto.Message) bool {
	switch r := request.(type) {
	case *av.EnsureOwnerRequest:
		return r.RequestId != "" && validOwner(r.Owner)
	case *av.AcquireOwnerSessionRequest:
		return r.RequestId != "" && r.SessionId != "" && validOwner(r.Owner)
	case *av.HandoffOwnerSessionRequest:
		return r.RequestId != "" && r.SuccessorSessionId != "" && validSession(r.Current)
	case interface{ GetIdentity() *av.MutationIdentity }:
		return r.GetIdentity().GetRequestId() != "" && validSession(r.GetIdentity().GetSession())
	}
	return false
}

func rpc[Req proto.Message, Resp proto.Message](c *Client, parent context.Context, request Req, mutation bool, invoke func(av.AutomationClient, context.Context, Req) (Resp, error)) (Resp, error) {
	var zero Resp
	ctx, done, err := c.begin(parent)
	if err != nil {
		return zero, err
	}
	defer done()
	if reflect.ValueOf(request).IsNil() {
		return zero, decodeError(status.Error(codes.InvalidArgument, "request required"))
	}
	request = proto.Clone(request).(Req)
	if err = c.prepare(request); err != nil {
		return zero, err
	}
	if mutation && !identityBound(request) {
		return zero, decodeError(status.Error(codes.InvalidArgument, "identity-bound request required"))
	}
	start := int(c.next.Add(1)-1) % len(c.cfg.Endpoints)
	for attempt := 0; attempt < c.cfg.MaxAttempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return zero, c.normalize(ctx, err)
		}
		conn, connectErr := c.connect(ctx, c.cfg.Endpoints[(start+attempt)%len(c.cfg.Endpoints)])
		err = connectErr
		if err == nil {
			svc := av.NewAutomationClient(conn)
			var caps *av.GetAutomationCapabilitiesResponse
			caps, err = c.verify(ctx, svc, mutation)
			if err == nil {
				if _, ok := any(request).(*av.GetAutomationCapabilitiesRequest); ok {
					c.release(conn)
					return any(caps).(Resp), nil
				}
				var auth context.Context
				auth, err = c.authContext(ctx)
				if err == nil {
					var response Resp
					response, err = invoke(svc, auth, request)
					if err == nil {
						err = validateReadResponse(request, response)
					}
					if err == nil {
						c.remember(response)
						c.release(conn)
						return response, nil
					}
				}
			}
			c.release(conn)
		}
		err = c.normalize(ctx, err)
		if attempt+1 == c.cfg.MaxAttempts || !retryable(err) {
			return zero, err
		}
		delay := c.backoff(attempt)
		if advice := retryAdvice(err); advice != nil && advice.RetryAfter != nil && advice.RetryAfter.IsValid() {
			delay = max(delay, advice.RetryAfter.AsDuration())
			if delay > c.cfg.MaxBackoff {
				return zero, err
			}
		}
		if waitErr := sleep(ctx, delay); waitErr != nil {
			return zero, c.normalize(ctx, waitErr)
		}
	}
	return zero, err
}
func (c *Client) backoff(attempt int) time.Duration {
	d := c.cfg.MinBackoff
	for range attempt {
		if d >= c.cfg.MaxBackoff/2 {
			d = c.cfg.MaxBackoff
			break
		}
		d *= 2
	}
	d = min(d, c.cfg.MaxBackoff)
	return d/2 + time.Duration(rand.Int64N(int64(d-d/2)+1))
}
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
)

// BeginOIDCLogin starts an authorization-code + PKCE login through an OIDC
// realm on THIS node. It is pre-session (skipAuth): it authenticates nothing
// and mints nothing, it only records a flow (state, PKCE verifier, nonce,
// redirect) in the realm's node-local store and returns the IdP URL. Login,
// called on the same node with the code and state, completes it.
//
// The redirect is the realm's configured one for the client ("web": the node's
// UI callback, redirect_url; "cli": the loopback listener, cli_redirect_url).
// A caller cannot name a redirect, so the allow-list is the configuration.
func (s *Server) BeginOIDCLogin(ctx context.Context, req *pb.BeginOIDCLoginRequest) (*pb.BeginOIDCLoginResponse, error) {
	name := req.GetRealm()
	if !strings.HasPrefix(name, "oidc:") {
		return nil, status.Errorf(codes.InvalidArgument, "realm %q is not an OIDC realm (want oidc:<name>)", name)
	}
	// A node in WAL quarantine accepts no user login (I8); say so before the
	// user is sent through the IdP for nothing.
	if err := s.refuseUserBearersInQuarantine(); err != nil {
		return nil, err
	}
	realm := s.realmRegistry.Get(name)
	if realm == nil {
		return nil, status.Errorf(codes.Unimplemented, "realm %q not configured on this node", name)
	}
	starter, ok := realm.(auth.OIDCFlowStarter)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "realm %q cannot begin an OIDC login", name)
	}
	start, err := starter.BeginFlow(req.GetClient())
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrOIDCTooManyFlows):
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, auth.ErrOIDCClientNotConfigured):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	default:
		return nil, status.Errorf(codes.Internal, "begin OIDC login: %v", err)
	}
	return &pb.BeginOIDCLoginResponse{
		AuthUrl:     start.AuthURL,
		State:       start.State,
		RedirectUri: start.RedirectURI,
		ExpiresAt:   start.ExpiresAt.UTC().Format(time.RFC3339),
	}, nil
}

// oidcPendingTTL and oidcPendingMaxAttempts bound an OIDC login waiting for
// litevirt's second factor. The IdP step is done and its code spent; what is
// held is the principal it proved, so the handle is short-lived and a wrong
// code is allowed only a few times before the login must start over.
const (
	oidcPendingTTL         = 5 * time.Minute
	oidcPendingMaxAttempts = 5
	oidcPendingMax         = 4096
)

// oidcPendingLogin is an OIDC login that verified at the IdP and stopped for
// litevirt's own second factor. It is node-local and never replicated.
type oidcPendingLogin struct {
	realm     string
	principal auth.Principal
	expiry    time.Time
	attempts  int
}

// oidcPendingStore holds pending OIDC logins by an unguessable handle.
type oidcPendingStore struct {
	mu sync.Mutex
	m  map[string]*oidcPendingLogin
}

func (st *oidcPendingStore) pruneLocked(now time.Time) {
	for h, p := range st.m {
		if now.After(p.expiry) {
			delete(st.m, h)
		}
	}
}

// put stores p and returns its handle (256 random bits).
func (st *oidcPendingStore) put(realm string, p *auth.Principal) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(b)
	cp := *p
	cp.Groups = append([]string(nil), p.Groups...)
	cp.ExternalIDs = append([]string(nil), p.ExternalIDs...)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	st.pruneLocked(now)
	if st.m == nil {
		st.m = map[string]*oidcPendingLogin{}
	}
	if len(st.m) >= oidcPendingMax {
		return "", errors.New("too many OIDC logins waiting for a second factor on this node; retry shortly")
	}
	st.m[h] = &oidcPendingLogin{realm: realm, principal: cp, expiry: now.Add(oidcPendingTTL)}
	return h, nil
}

// get returns a copy of the principal a live handle holds for realm.
func (st *oidcPendingStore) get(handle, realm string) (*auth.Principal, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneLocked(time.Now())
	p, ok := st.m[handle]
	if !ok || p.realm != realm {
		return nil, false
	}
	cp := p.principal
	cp.Groups = append([]string(nil), p.principal.Groups...)
	cp.ExternalIDs = append([]string(nil), p.principal.ExternalIDs...)
	return &cp, true
}

// failed counts a wrong second factor against handle; the handle is dropped
// at the bound.
func (st *oidcPendingStore) failed(handle string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if p, ok := st.m[handle]; ok {
		p.attempts++
		if p.attempts >= oidcPendingMaxAttempts {
			delete(st.m, handle)
		}
	}
}

// drop removes handle (used once the login completed or was refused for good).
func (st *oidcPendingStore) drop(handle string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, handle)
}

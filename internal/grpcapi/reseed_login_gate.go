package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// preSessionAuthMethods are the skipAuth entries that AUTHENTICATE a caller —
// the ones that take a credential and hand back a session. They bypass the
// interceptor because the caller has no bearer yet, which is correct and also
// means they are the only RPCs that can be reached on a node whose secret
// state is incomplete.
//
// Ping and ListRealms are deliberately NOT here. Ping is how an operator and
// every peer diagnose this node, and the reseed path itself calls it; gating it
// would hide the very condition the marker records and break the recovery it
// points at.
var preSessionAuthMethods = map[string]bool{
	"/litevirt.v1.LiteVirt/Login":               true,
	"/litevirt.v1.LiteVirt/BeginWebAuthnLogin":  true,
	"/litevirt.v1.LiteVirt/FinishWebAuthnLogin": true,
}

// refuseLoginWhileReseedIncomplete refuses a pre-session credential exchange
// while a reseed has deleted this node's state and not finished restoring it.
//
// The window is real and fails OPEN without this: a reseed discards the
// sensitive tables and restores them in a LATER step than users and their
// password hashes, so a process that dies in between leaves every enrolled
// account reachable with a password alone — LocalRealm.Authenticate derives
// Requires2FA from len(factors) > 0, and an empty user_2fa is indistinguishable
// there from nobody having enrolled.
//
// Refusing only these methods is what keeps recovery possible. Everything else
// goes through the interceptor, which accepts this node's mTLS client
// certificate as admin, so `lv host reseed` can still be run to repeat the
// reseed. Gating the whole surface would strand the node.
//
// A marker that cannot be READ also refuses. The caller is a credential gate,
// and an unreadable marker must not read as permission to serve — the same
// fail-closed rule the 2FA enrollment lookup already follows.
func (s *Server) refuseLoginWhileReseedIncomplete(ctx context.Context, method string) error {
	if !preSessionAuthMethods[method] {
		return nil
	}
	if s.db == nil {
		return nil
	}
	incomplete, source, err := s.db.ReseedIncomplete(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot confirm this node finished its last reseed, so it will not authenticate: %v", err)
	}
	if !incomplete {
		return nil
	}
	return status.Errorf(codes.Unavailable,
		"this node is mid-reseed from %s and its secret-bearing state is incomplete, so it "+
			"will not authenticate; repeat the reseed from %s (mTLS admin access still works)",
		source, source)
}

// reseedFenceKeyType keys the fence reading taken when a pre-session credential
// exchange was admitted, so the mint at the far end can tell whether a reseed
// ran while the credentials were being checked.
type reseedFenceKeyType struct{}

var reseedFenceKey reseedFenceKeyType

// stampReseedFence records the fence reading for a pre-session credential
// exchange, before the handler reads any credential state.
//
// A read failure is not fatal here: the mint re-reads and fails closed on its
// own, so a transient error costs a retry rather than a lockout.
func (s *Server) stampReseedFence(ctx context.Context, method string) context.Context {
	if !preSessionAuthMethods[method] || s.db == nil {
		return ctx
	}
	_, _, generation, err := s.db.ReseedFence(ctx)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, reseedFenceKey, generation)
}

// refuseIfReseedMovedSinceEntry refuses to issue a session when a reseed has
// begun — or begun AND finished — since this request was admitted.
//
// This is the other half of the gate, and without it the gate is a TOCTOU. The
// interceptor checks the marker once, before the handler runs; the handler then
// reads the user row, spends a deliberately-slow bcrypt on the password, and
// only THEN reads user_2fa. A request admitted just before a reseed starts
// therefore finishes its bcrypt on the far side of the discard, and
// LocalRealm.Authenticate reads an empty user_2fa as "nobody enrolled" — minting
// a session with no second factor for an enrolled account. The marker stops new
// requests; it cannot drain the ones already inside.
//
// The generation rather than a second read of the marker: an entire reseed can
// start and finish inside one bcrypt, and the boolean would be clear again.
//
// Called from mintSession rather than from Login, so every path that issues a
// session is covered — password login, WebAuthn, and whatever is added next —
// instead of only the one that was audited.
func (s *Server) refuseIfReseedMovedSinceEntry(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	incomplete, source, generation, err := s.db.ReseedFence(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot confirm this node finished its last reseed, so it will not issue a session: %v", err)
	}
	if incomplete {
		return status.Errorf(codes.Unavailable,
			"this node is mid-reseed from %s and its secret-bearing state is incomplete, so it "+
				"will not issue a session; repeat the reseed from %s", source, source)
	}
	entry, ok := ctx.Value(reseedFenceKey).(int64)
	if !ok {
		// No entry reading: this mint did not come through the pre-session gate,
		// so there is nothing to compare. The incomplete check above still holds.
		return nil
	}
	if generation != entry {
		return status.Errorf(codes.Unavailable,
			"a reseed ran while these credentials were being checked, so the second-factor "+
				"state they were checked against may already be gone; retry the login")
	}
	return nil
}

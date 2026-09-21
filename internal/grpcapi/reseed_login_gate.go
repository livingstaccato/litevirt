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

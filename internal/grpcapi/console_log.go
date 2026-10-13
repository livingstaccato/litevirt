package grpcapi

import (
	"context"
	"log/slog"
)

// consoleCallerAttrs names who a console session (ProxyVNC, ProxySpice) is
// for, for its log lines.
//
// A call relayed by a peer daemon on its host certificate, with no forwarded
// user identity, carries the peer's "admin" principal: logging that as the
// user would misattribute every console opened through another host. Such a
// call is named by the relaying peer (via_peer=<its certificate CN>) and no
// user; the entry host, the only one that authenticated the user, logs the
// session under the user (logForwardedConsole). A forwarded identity this
// host verified itself (authenticateForwardedBearer) is a real user and is
// logged as one. Nothing here authorizes anything.
func consoleCallerAttrs(ctx context.Context) []any {
	if callerAuthMethod(ctx) == authMethodMTLS && callerPrincipalKind(ctx) == principalKindPeer {
		return []any{"via_peer", callerMTLSCommonName(ctx)}
	}
	return []any{"user", callerUsername(ctx)}
}

// logForwardedConsole logs, on the entry host, a console session it relays
// to the VM's owner — under the caller it authenticated — and returns the
// matching end-of-session logger.
func logForwardedConsole(ctx context.Context, kind, vmName, owner string) func() {
	attrs := append([]any{"vm", vmName, "owner", owner}, consoleCallerAttrs(ctx)...)
	slog.Info(kind+" proxy session started", attrs...)
	return func() { slog.Info(kind+" proxy session ended", attrs...) }
}

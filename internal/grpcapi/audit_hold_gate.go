package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A host re-added under an old name holds its own audit rows until its history
// has arrived (corrosion/audit_hold.go), and never drops one. Past the hold's
// limit, an audited action taken here would have nowhere for its row to go — so
// the actions this node can refuse are refused, retryably, instead of running
// unaudited: every client RPC except reads, and the logins (a successful login
// is an audited action too; denied ones are coalesced while held and cannot
// fill the hold by themselves).
//
// Calls on a cluster host certificate with no user identity are never refused:
// a peer host acting as the system (replication and anti-entropy are how the
// history arrives and the hold drains), and root on this node itself, the
// operator's way in when nothing else can act. A user's call a peer relays
// under forwarded identity is a client call and is refused.

// auditHoldReadPrefixes are method-name prefixes of RPCs that only read. Anything
// else is treated as able to write an audit row. Erring that way refuses a read
// on a node in this state, which is a cost; the other way runs an action whose
// row is lost.
var auditHoldReadPrefixes = []string{
	"Get", "List", "Watch", "Verify", "Export", "Describe", "Plan", "Diff", "Dump", "Stream",
	"Ping", "Ready",
}

// auditHoldWriteRPCs are read-prefixed RPCs that write audit rows anyway.
// VerifyBackupRepo audits the check it runs (and a refusal to open the repo).
var auditHoldWriteRPCs = map[string]bool{
	"VerifyBackupRepo": true,
}

func auditHoldReadOnly(fullMethod string) bool {
	name := methodShortName(fullMethod)
	if auditHoldWriteRPCs[name] {
		return false
	}
	for _, p := range auditHoldReadPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// gateAuditHold refuses fullMethod with Unavailable while this host's audit hold
// is full, unless it only reads or the caller is a peer host or on-node root
// with no user identity. Called by the auth interceptors after authentication, and for the
// pre-session logins.
func (s *Server) gateAuditHold(ctx context.Context, fullMethod string, preSession bool) error {
	if s.db == nil || auditHoldReadOnly(fullMethod) || !s.db.AuditHoldFull(s.hostName) {
		return nil
	}
	if !preSession && s.requirePeerCert(ctx) == nil && callerAuthMethod(ctx) == authMethodMTLS {
		return nil
	}
	slog.Warn("refusing an audited action: this host's audit hold is full, and the action's audit row "+
		"would have nowhere to go", "rpc", methodShortName(fullMethod))
	return status.Errorf(codes.Unavailable,
		"%s refused on %s: this host was re-added under a name whose audit history has not reached it yet, "+
			"and it is holding the maximum number of its own audit rows until it does. Actions here would "+
			"go unaudited, so they are refused; retry once the history has arrived (`lv health` shows "+
			"audit_chain_held), or run the command against another node", methodShortName(fullMethod), s.hostName)
}

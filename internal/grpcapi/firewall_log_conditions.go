package grpcapi

import (
	"context"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// CondFirewallLogListener is raised while this host's firewall log listener
// cannot bind its NFLOG group (docs/diagnostics.md).
const CondFirewallLogListener = "firewall.log.listener"

// RecordFirewallLogListener raises firewall.log.listener while the listener
// cannot bind its group (err), and resolves it once bound (nil). The listener
// calls it once per transition.
func (s *Server) RecordFirewallLogListener(ctx context.Context, err error) {
	detail := ""
	if err != nil {
		detail = "the firewall log listener cannot read its NFLOG group, so logged packets are discarded by the kernel " +
			"(another program may hold the group: set firewall.log_group to a free one): " + err.Error()
	}
	s.setFirewallCondition(ctx, CondFirewallLogListener, err != nil, corrosion.SeverityWarning, detail)
}

// CondFirewallLogUnavailable is raised while this host's kernel refuses the
// logging forms (ProbeLogging): it renders no log line.
const CondFirewallLogUnavailable = "firewall.log.unavailable"

// CondFirewallPolicyUnreadable is raised while a firewall policy row cannot
// be read here; it is read as its documented fallback.
const CondFirewallPolicyUnreadable = "firewall.policy.unreadable"

// RecordFirewallLogAvailability raises firewall.log.unavailable when the
// logging probe was refused (err), and resolves it when it passed.
func (s *Server) RecordFirewallLogAvailability(ctx context.Context, err error) {
	detail := ""
	if err != nil {
		detail = "this host's kernel or nft refuses the firewall logging forms (nft_log, nfnetlink_log, nft_limit), " +
			"so no packet is logged here; the per-NIC rules are unaffected: " + err.Error()
	}
	s.setFirewallCondition(ctx, CondFirewallLogUnavailable, err != nil, corrosion.SeverityWarning, detail)
}

// unreadablePoliciesText names each unreadable policy row.
func unreadablePoliciesText(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return "firewall policy rows this build cannot read, each read as its documented fallback " +
		"(the log policy as off at the default budget); set the policy again to replace the row: " + strings.Join(rows, "; ")
}

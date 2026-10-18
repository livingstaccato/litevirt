package grpcapi

import (
	"context"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// SYN-flood condition codes (firewall extras spec §1.3, §1.5), one row per host.
const (
	// The kernel refused the SYN-flood probe: no SYN-flood protection is
	// rendered on this host.
	CondFirewallSynfloodUnavailable = "firewall.synflood.unavailable"
	// A firewall policy row cannot be read here.
	CondFirewallPolicyUnreadable = "firewall.policy.unreadable"
)

// recordSynFloodState raises or resolves this host's SYN-flood conditions
// from one pass's state.
func (s *Server) recordSynFloodState(ctx context.Context, st firewall.AppliedState) {
	s.setFirewallCondition(ctx, CondFirewallSynfloodUnavailable, st.SynFloodUnavailable != "", corrosion.SeverityWarning,
		"the kernel refused the SYN-flood probe at daemon start: guest NICs on this host are not SYN-flood protected "+
			"(the module nft_limit is needed; restart the daemon once it loads): "+st.SynFloodUnavailable)
	s.setFirewallCondition(ctx, CondFirewallPolicyUnreadable, len(st.UnreadablePolicies) > 0, corrosion.SeverityWarning,
		"firewall policy rows this host cannot read: "+strings.Join(st.UnreadablePolicies, "; "))
}

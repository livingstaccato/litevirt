package grpcapi

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// SYN-flood condition codes (firewall extras spec §1.3, §1.5), one row per host.
const (
	// The kernel refused the SYN-flood probe: no SYN-flood protection is
	// rendered on this host.
	CondFirewallSynfloodUnavailable = "firewall.synflood.unavailable"
)

// recordSynFloodState raises or resolves this host's SYN-flood condition
// from one pass's state. An unreadable SYN-flood row is in
// st.UnreadablePolicies, which firewall.policy.unreadable's one raiser (the
// log policy's recorder) reports with every other unreadable policy.
func (s *Server) recordSynFloodState(ctx context.Context, st firewall.AppliedState) {
	which := "IPv4 and IPv6"
	switch {
	case st.SynFlood.On && st.SynFlood.NoV4:
		which = "IPv4"
	case st.SynFlood.On && st.SynFlood.NoV6:
		which = "IPv6"
	}
	s.setFirewallCondition(ctx, CondFirewallSynfloodUnavailable, st.SynFloodUnavailable != "", corrosion.SeverityWarning,
		"the kernel refused SYN-flood rules at daemon start: "+which+" SYNs to guest NICs on this host are not limited "+
			"(nft_limit is needed, and for IPv6 an nft that keys a set by prefix; restart the daemon once it can): "+st.SynFloodUnavailable)
}

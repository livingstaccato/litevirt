package grpcapi

import (
	"context"

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

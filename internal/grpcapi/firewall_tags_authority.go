package grpcapi

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// mintFWTagAuthority is the only minter of a corrosion.FWTagAuthority, the
// proof corrosion.SetFirewallTags takes that its caller holds sg.write. It is
// claimed here, once (a second claim panics), and only fwTagAuthority calls
// it (corrosion's authority guard).
var mintFWTagAuthority = corrosion.ClaimFWTagAuthorityMinter()

// fwTagAuthority checks sg.write at the cluster root, as every firewall
// write does (requireSGWrite: Admin and NetworkAdmin; Operator holds sg.read
// only), and only then mints the authority a firewall-tags write needs.
func (s *Server) fwTagAuthority(ctx context.Context) (corrosion.FWTagAuthority, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return corrosion.FWTagAuthority{}, err
	}
	return mintFWTagAuthority(), nil
}

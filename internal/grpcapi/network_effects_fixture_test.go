package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
	"net/netip"
)

type isolatedNetworkEffects struct{}

func (isolatedNetworkEffects) AddFDBEntry(int, string, string) error            { return nil }
func (isolatedNetworkEffects) DeleteFDBEntry(int, string, string) error         { return nil }
func (isolatedNetworkEffects) SendGARP(string, string) error                    { return nil }
func (isolatedNetworkEffects) AnnounceGateway(string, netip.Addr) (bool, error) { return false, nil }
func (isolatedNetworkEffects) SyncPeerVTEP(context.Context, *corrosion.Client, string, string, int, string, string) error {
	return nil
}

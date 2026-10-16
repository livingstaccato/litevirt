package grpcapi

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// NetworkEffects is the host-local FDB and gratuitous-ARP boundary. Fleet
// nodes supply their own network model before serving RPCs; production uses
// the existing host implementations when no override is installed.
type NetworkEffects interface {
	AddFDBEntry(vni int, mac, remoteVTEP string) error
	DeleteFDBEntry(vni int, mac, remoteVTEP string) error
	SendGARP(bridge, ip string) error
	SyncPeerVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int, peer, peerAddr string) error
}

// SetNetworkEffects installs per-server effects before any consumers start.
func (s *Server) SetNetworkEffects(effects NetworkEffects) { s.networkEffects = effects }

type hostNetworkEffects struct{}

func (hostNetworkEffects) AddFDBEntry(vni int, mac, remoteVTEP string) error {
	return network.AddFDBEntry(vni, mac, remoteVTEP)
}
func (hostNetworkEffects) DeleteFDBEntry(vni int, mac, remoteVTEP string) error {
	return network.DeleteFDBEntry(vni, mac, remoteVTEP)
}
func (hostNetworkEffects) SendGARP(bridge, ip string) error {
	return network.SendGARP(bridge, ip)
}

func (hostNetworkEffects) SyncPeerVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int, peer, peerAddr string) error {
	return syncPeerVTEP(ctx, db, networkName, hostName, vni, peer, peerAddr)
}

func (s *Server) hostNetworkEffects() NetworkEffects {
	if s.networkEffects != nil {
		return s.networkEffects
	}
	return hostNetworkEffects{}
}

func (s *Server) sendGARPBestEffort(bridge, ip string) {
	if err := s.hostNetworkEffects().SendGARP(bridge, ip); err != nil {
		slog.Warn("gratuitous ARP failed (non-fatal)", "bridge", bridge, "ip", ip, "error", err)
	}
}

package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/lb"
)

// vrrpUnicastActive reports whether this host renders its LBs' VRRP as
// unicast over the host network: enforcement.vrrp_unicast AND a DURABLE
// vrrp_unicast_v1 latch. Durable, so a restart cannot take a host back to the
// multicast transport its peers have left.
func (s *Server) vrrpUnicastActive() bool {
	if !s.enfVRRPUnicast.Load() {
		return false
	}
	g := s.gateV()
	return g != nil && g.DurablyLatched(capabilities.VRRPUnicastV1)
}

// lbVRRPTransport sets the VRRP transport of cfg, an LB this host runs with
// the other hosts in lbHosts. While vrrpUnicastActive is false it leaves cfg
// on the multicast transport, which is what every peer that has not latched
// renders. Otherwise the adverts go from this host's recorded address to each
// other LB host's, over the device holding this host's own (lb.Config.VRRPUnicast).
//
// It refuses rather than guess: an address it cannot read leaves the apply
// failed, since a host rendering a peer set short of a peer holds the VIP
// beside it, and the multicast transport would not reach a peer that has
// switched.
func (s *Server) lbVRRPTransport(ctx context.Context, cfg *lb.Config, lbHosts []string) error {
	if !s.vrrpUnicastActive() {
		return nil
	}
	local, err := s.hostIPv4(ctx, s.hostName)
	if err != nil {
		return fmt.Errorf("vrrp: %w", err)
	}
	if local == "" {
		return fmt.Errorf("vrrp: host %s has no IPv4 address recorded to send VRRP from", s.hostName)
	}
	seen := map[string]bool{s.hostName: true}
	var peers []string
	for _, h := range lbHosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		ip, err := s.hostIPv4(ctx, h)
		if err != nil {
			return fmt.Errorf("vrrp: %w", err)
		}
		if ip == "" {
			return fmt.Errorf("vrrp: LB host %s has no IPv4 address recorded to send VRRP to", h)
		}
		peers = append(peers, ip)
	}
	cfg.VRRPUnicast = true
	cfg.VRRPInterface = s.lbIfaceForIP(local)
	cfg.UnicastSrc = local
	cfg.UnicastPeers = peers
	return nil
}

func (s *Server) lbIfaceForIP(ip string) string {
	if s.lbIfaceForIPOverride != nil {
		return s.lbIfaceForIPOverride(ip)
	}
	return lb.DetectInterfaceForIP(ip)
}

// lbVRRPStale reports whether an LB's keepalived config on disk renders the
// other VRRP transport from the one this host now renders — the LB was last
// applied before vrrp_unicast_v1 latched here, or before
// enforcement.vrrp_unicast was turned off — so the reconciler re-applies it.
// No readable config is not stale: there is nothing to switch.
func (s *Server) lbVRRPStale(name string) bool {
	var unicast, ok bool
	if s.lbRenderedUnicastOverride != nil {
		unicast, ok = s.lbRenderedUnicastOverride(name)
	} else {
		unicast, ok = s.lbManager().KeepalivedUnicast(name)
	}
	return ok && unicast != s.vrrpUnicastActive()
}

package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// applyLBAsPeer runs a forwarded ApplyLB for a two-host LB on a host-isolated
// network's bridge and returns the config handed to the LB manager.
func applyLBAsPeer(t *testing.T, req *pb.ApplyLBRequest) lb.Config {
	t.Helper()
	s := newPeerAuthServer(t)
	isolateLBEffects(t, s)
	s.SetBridgeExists(func(string) bool { return true })
	ctx := context.Background()
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	// peer-1 is recorded at 127.0.0.1 by newPeerAuthServer.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "192.0.2.11", State: "active"}); err != nil {
		t.Fatal(err)
	}
	var applied []lb.Config
	s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }
	req.LbName, req.Vip, req.Hosts = "lbr-lb", "10.202.0.250/24", []string{"peer-1", s.hostName}
	req.Backends = []*pb.LBBackend{{VmName: "lbr1", Address: "10.202.0.72"}}
	if _, err := s.ApplyLB(mtlsCtx("peer-1"), req); err != nil {
		t.Fatalf("ApplyLB: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied %d configs, want 1", len(applied))
	}
	return applied[0]
}

func fullPorts() []*pb.LBPort {
	return []*pb.LBPort{
		{Listen: 80, Target: 8080, Protocol: "http", RedirectHttps: true},
		{Listen: 443, Target: 8080, Protocol: "http", Tls: &pb.LBTlsSpec{Cert: lb.CertDir + "/a.crt", Key: lb.CertDir + "/a.key"}},
	}
}

// TestApplyLB_ServesTheWholeStackLB (C1): a forwarded apply of a stack LB
// with snat is built by the same conversion as the coordinator's own apply
// (health, sticky, TLS, redirect) and gets the same conntrackd sync, so the
// peer renders the same keepalived whichever path applies it.
//
// Mutations (each red): ApplyLB ignores req.Health / req.StickySessions;
// skips lbSNATSync.
func TestApplyLB_ServesTheWholeStackLB(t *testing.T) {
	c := applyLBAsPeer(t, &pb.ApplyLBRequest{
		Ports: fullPorts(), Health: &pb.LBHealthSpec{Type: "http", Path: "/healthz", Interval: "1500ms"},
		StickySessions: true, Snat: proto.Bool(true), StackName: "lbr",
	})
	if !c.Sticky || c.Health == nil || c.Health.Path != "/healthz" || c.Health.IntervalMS != 1500 {
		t.Errorf("sticky=%v health=%+v, want sticky and the http check", c.Sticky, c.Health)
	}
	if len(c.Ports) != 2 || !c.Ports[0].RedirectHTTPS || c.Ports[1].TLS == nil {
		t.Errorf("ports %+v, want the redirect and the TLS listener", c.Ports)
	}
	if !c.SNATEnabled || c.LocalIP != "192.0.2.11" || c.PeerIP != "127.0.0.1" || c.KeepSNAT {
		t.Errorf("SNAT sync enabled=%v local=%q peer=%q keep=%v, want synced with peer-1", c.SNATEnabled, c.LocalIP, c.PeerIP, c.KeepSNAT)
	}
}

// TestApplyLB_OlderPeerLeavesSNATAlone (C1): an apply from a coordinator on
// an earlier build carries no snat; it asks the manager to keep the LB's
// SNAT side as it is (KeepSNAT), rather than render it off and tear down
// conntrackd. An explicit LB (no stack) gets no conntrackd.
//
// Mutation: drop the req.Snat == nil case — red.
func TestApplyLB_OlderPeerLeavesSNATAlone(t *testing.T) {
	if c := applyLBAsPeer(t, &pb.ApplyLBRequest{Ports: fullPorts()}); !c.KeepSNAT || c.SNATEnabled {
		t.Errorf("snat absent: keep=%v enabled=%v, want keep", c.KeepSNAT, c.SNATEnabled)
	}
	if c := applyLBAsPeer(t, &pb.ApplyLBRequest{Ports: fullPorts(), Snat: proto.Bool(true)}); c.KeepSNAT || c.SNATEnabled {
		t.Errorf("explicit LB: keep=%v enabled=%v, want neither", c.KeepSNAT, c.SNATEnabled)
	}
	if c := applyLBAsPeer(t, &pb.ApplyLBRequest{Ports: fullPorts(), Snat: proto.Bool(false), StackName: "lbr"}); c.KeepSNAT || c.SNATEnabled {
		t.Errorf("snat false: keep=%v enabled=%v, want neither", c.KeepSNAT, c.SNATEnabled)
	}
}

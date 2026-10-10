package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Recovery-claim posture in the readiness report (colonelpanik/litevirt#250).
// recovery_claim_v1 is WITHHELD while a host's flag is off, so a host that
// advertises other tokens but not this one is not enforcing — the shape of a
// host rolled back to a build that reads a missing key as false. Reading its
// silence as unknown, as the fence posture does for an unconditional token,
// would hide exactly the host the diagnostic exists to name.
//
// Mutation: report the "advertises other tokens but not recovery_claim_v1"
// case as unknown — both not-advertising rows go red (a latched host with its
// flag off withholds the token too, so not_enforcing only sharpens the detail).
//
// A host that withholds voter_config_v1 as well cannot vote durably, which
// withholds recovery_claim_v1 whatever its flag says: it is unknown, never
// accused (partials-p1 review R1-1). Mutation: drop that case — the
// cannot-vote row reads NOT enforcing and goes red.
func TestClaimPostureFromPing(t *testing.T) {
	claims := []string{capabilities.SplitBrainGateV1, capabilities.RecoveryClaimV1}
	for _, tc := range []struct {
		name                     string
		resp                     *pb.PingResponse
		wantKnown, wantEnforcing bool
	}{
		{"old binary or withheld posture", &pb.PingResponse{Capabilities: claims}, false, false},
		{"WAL-quarantined", &pb.PingResponse{PostureReported: true, WalQuarantined: true}, false, false},
		{"self-fenced, advertising nothing", &pb.PingResponse{PostureReported: true}, false, false},
		{"advertises it", &pb.PingResponse{PostureReported: true, Capabilities: claims}, true, true},
		{"latched and withheld: flag off", &pb.PingResponse{PostureReported: true,
			Capabilities: []string{capabilities.SplitBrainGateV1},
			NotEnforcing: []string{capabilities.RecoveryClaimV1}}, true, false},
		{"does not advertise it (rolled back, no key)", &pb.PingResponse{PostureReported: true,
			Capabilities: []string{capabilities.SplitBrainGateV1, capabilities.VoterConfigV1}}, true, false},
		{"cannot vote durably: withholds voter_config_v1 too", &pb.PingResponse{PostureReported: true,
			Capabilities: []string{capabilities.SplitBrainGateV1}}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := claimPostureFromPing("peer", tc.resp)
			if !p.GetReachable() {
				t.Error("a host that answered Ping is reported unreachable")
			}
			if p.GetPostureKnown() != tc.wantKnown || p.GetEnforcing() != tc.wantEnforcing {
				t.Errorf("posture_known=%v enforcing=%v (detail %q), want %v/%v",
					p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail(), tc.wantKnown, tc.wantEnforcing)
			}
		})
	}
}

// The report carries the responding node's recovery_claim_v1 latch (read with
// Latched, never Enforced) and a recovery-claim posture for EVERY host,
// witnesses included: a witness runs a failover coordinator, so unlike the
// fence posture it is part of the answer.
//
// Mutation: leave recovery_claim_latched unset, or skip witnesses in
// recovery_claim_hosts — the test goes red.
func TestGetFenceReadiness_ReportsRecoveryClaimPosture(t *testing.T) {
	s := claimPostureServer(t, capabilities.SharedStorageFenceV1, capabilities.RecoveryClaimV1, capabilities.SplitBrainGateV1)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "arbiter", Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", Role: "witness",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	for _, on := range []bool{true, false} {
		s.SetRecoveryClaimEnforce(on)
		r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("GetFenceReadiness: %v", err)
		}
		if !r.GetRecoveryClaimLatched() {
			t.Error("recovery_claim_latched is false though the gate reports recovery_claim_v1 latched")
		}
		got := map[string]*pb.FenceHostPosture{}
		for _, p := range r.GetRecoveryClaimHosts() {
			got[p.GetHost()] = p
		}
		if _, ok := got["arbiter"]; !ok {
			t.Errorf("the witness is missing from recovery_claim_hosts: %v", r.GetRecoveryClaimHosts())
		}
		self, ok := got[s.hostName]
		if !ok {
			t.Fatalf("the responding host is missing from recovery_claim_hosts: %v", r.GetRecoveryClaimHosts())
		}
		if !self.GetPostureKnown() || self.GetEnforcing() != on {
			t.Errorf("flag %v: local posture known=%v enforcing=%v (detail %q)",
				on, self.GetPostureKnown(), self.GetEnforcing(), self.GetDetail())
		}
		for _, p := range r.GetHosts() {
			if p.GetHost() == "arbiter" {
				t.Error("the witness leaked into the fence posture")
			}
		}
	}
}

// claimPostureServer is a voter-ready server (namedVoterServer) with its own
// hosts row and the given tokens latched.
func claimPostureServer(t *testing.T, latched ...string) *Server {
	t.Helper()
	s := recoveryClaimServer(t, true, latched...)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return s
}

// The queried node's own row is read by the predicate its peers read it by —
// whether it advertises recovery_claim_v1 — not by its flag alone, so one
// state reads alike from whichever node is queried (partials-p1 review R1-2).
// A flag-on node whose split_brain_gate_v1 has not latched does not advertise
// the token: NOT enforcing, with the reason. One that cannot vote durably is
// unknown, as a peer reports it.
//
// Mutation: read the self row from the flag alone again — both rows read
// enforcing and go red.
func TestGetFenceReadiness_SelfClaimPostureIsItsAdvertisement(t *testing.T) {
	selfRow := func(t *testing.T, s *Server) *pb.FenceHostPosture {
		t.Helper()
		r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("GetFenceReadiness: %v", err)
		}
		for _, p := range r.GetRecoveryClaimHosts() {
			if p.GetHost() == s.hostName {
				return p
			}
		}
		t.Fatalf("the responding host is missing from recovery_claim_hosts: %v", r.GetRecoveryClaimHosts())
		return nil
	}

	t.Run("split_brain_gate_v1 not latched", func(t *testing.T) {
		s := claimPostureServer(t)
		p := selfRow(t, s)
		if !p.GetPostureKnown() || p.GetEnforcing() || !strings.Contains(p.GetDetail(), capabilities.SplitBrainGateV1) {
			t.Errorf("posture known=%v enforcing=%v detail %q; want known, NOT enforcing, naming %s",
				p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail(), capabilities.SplitBrainGateV1)
		}
	})
	t.Run("cannot vote durably", func(t *testing.T) {
		s := fenceTestServer(t, true, true) // no host signing key
		s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.SplitBrainGateV1: true}})
		s.SetRecoveryClaimEnforce(true)
		p := selfRow(t, s)
		if p.GetPostureKnown() || p.GetEnforcing() {
			t.Errorf("posture known=%v enforcing=%v detail %q; a node that cannot vote durably is unknown",
				p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail())
		}
	})
}

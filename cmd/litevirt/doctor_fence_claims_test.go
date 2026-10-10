package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv doctor fence` warns when recovery_claim_v1 has latched and a reachable
// host does not enforce recovery claims, and names the explicit config line
// that fixes it. That host is what a rollback to an older build produces: it
// reads a missing enforcement.recovery_claim as false and is not
// WAL-quarantined for it (colonelpanik/litevirt#250). Diagnostic only: the
// exit code stays the shared-disk fence verdict.
//
// Mutation: drop the warning — the first case goes red; warn without the latch
// — the unlatched case goes red; count an unreachable host as not enforcing —
// the unreachable case goes red.
func TestDoctorFence_WarnsOnALatchedClusterWithANonEnforcingHost(t *testing.T) {
	notEnforcing := &pb.FenceHostPosture{Host: "kvm002", Reachable: true, PostureKnown: true,
		Detail: "host does not advertise recovery_claim_v1"}
	unreachable := &pb.FenceHostPosture{Host: "kvm003", Detail: "dial: refused"}
	covered := func(claimLatched bool, claimHosts ...*pb.FenceHostPosture) *pb.FenceReadiness {
		return &pb.FenceReadiness{
			CapabilityLatched: true, EnforcedEverywhere: true,
			Hosts:                []*pb.FenceHostPosture{enforcingHost("kvm001")},
			RecoveryClaimLatched: claimLatched,
			RecoveryClaimHosts:   claimHosts,
		}
	}
	for _, tc := range []struct {
		name     string
		resp     *pb.FenceReadiness
		wantWarn bool
	}{
		{"latched, one host not enforcing", covered(true, enforcingHost("kvm001"), notEnforcing), true},
		{"latched, every host enforcing", covered(true, enforcingHost("kvm001"), enforcingHost("kvm002")), false},
		{"not latched yet", covered(false, enforcingHost("kvm001"), notEnforcing), false},
		{"latched, one host unreachable", covered(true, enforcingHost("kvm001"), unreachable), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runDoctorFence(t, tc.resp)
			if code != 0 {
				t.Errorf("exit code = %d; the recovery-claim posture must not change it", code)
			}
			warned := strings.Contains(out, "WARNING: recovery_claim_v1 has latched")
			if warned != tc.wantWarn {
				t.Fatalf("warned = %v, want %v; got:\n%s", warned, tc.wantWarn, out)
			}
			if tc.wantWarn && !strings.Contains(out, "add `enforcement.recovery_claim: true` explicitly to kvm002's config") {
				t.Errorf("the warning does not name the host and the fix; got:\n%s", out)
			}
			// The flag is not the only cause, and the warning says so (R1-1).
			if tc.wantWarn && !strings.Contains(out, "split_brain_gate_v1 has not latched") {
				t.Errorf("the warning names only the flag fix; a flag-on host that is not ready gets it too; got:\n%s", out)
			}
			if !strings.Contains(out, "recovery_claim_v1 latched:") {
				t.Errorf("the report does not show the recovery_claim_v1 latch; got:\n%s", out)
			}
		})
	}
}

// A server that predates the field sends no recovery-claim rows; the report
// says so rather than printing an empty table or a false all-clear.
func TestDoctorFence_OlderServerHasNoRecoveryClaimPosture(t *testing.T) {
	out, _ := runDoctorFence(t, &pb.FenceReadiness{
		CapabilityLatched: true, EnforcedEverywhere: true,
		Hosts: []*pb.FenceHostPosture{enforcingHost("kvm001")},
	})
	if !strings.Contains(out, "does not report recovery-claim posture") {
		t.Errorf("an older server's silence is not called out; got:\n%s", out)
	}
}

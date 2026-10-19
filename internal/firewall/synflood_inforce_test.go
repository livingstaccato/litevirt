package firewall

import (
	"context"
	"fmt"
	"testing"
)

// A pass records what SYN-flood protection it put in force (Track B review
// I-2): on only when the per-NIC table enforces it; observe counts, never
// drops; guards-only renders nothing; unavailable when the kernel refused
// the rules; off when the policy is off.
//
// A host with no guest NIC renders no per-NIC table, so nothing is limited
// there: it says so rather than on (Track B round-1 re-review n-1).
//
// Mutations: report on in observe mode — red; report on in guards-only — red;
// report off for a refused probe — red; report on with no guest NIC — red;
// report on with one family refused — red (round-2 re-review R2-m1).
func TestRecordState_SynFloodInForce(t *testing.T) {
	on := SynFlood{On: true, Rate: 200, Burst: 1000}
	nics := []NICBinding{{NICDev: "tap0", VMName: "vm1"}}
	for _, tc := range []struct {
		name string
		plan Plan
		want string
	}{
		{"enforce", Plan{NICMode: NICModeEnforce, SynFlood: on, NICs: nics}, SynFloodInForceOn},
		{"enforce, no guest NIC", Plan{NICMode: NICModeEnforce, SynFlood: on}, SynFloodInForceNoGuestNICs},
		{"observe", Plan{NICMode: NICModeObserve, SynFlood: on, NICs: nics}, SynFloodInForceObserve},
		{"observe, no guest NIC", Plan{NICMode: NICModeObserve, SynFlood: on}, SynFloodInForceNoGuestNICs},
		{"off, no guest NIC", Plan{NICMode: NICModeEnforce}, SynFloodInForceOff},
		{"guards-only", Plan{NICMode: NICModeGuardsOnly, SynFlood: on, NICs: nics}, SynFloodInForceGuardsOnly},
		{"refused probe", Plan{NICMode: NICModeEnforce, SynFloodUnavailable: "no nft_limit", NICs: nics}, SynFloodInForceUnavailable},
		{"policy off", Plan{NICMode: NICModeEnforce, NICs: nics}, SynFloodInForceOff},
		{"IPv6 refused", Plan{NICMode: NICModeEnforce, NICs: nics, SynFloodUnavailable: "IPv6: x",
			SynFlood: SynFlood{On: true, Rate: 200, Burst: 1000, NoV6: true}}, SynFloodInForceIPv4Only},
		{"IPv4 refused", Plan{NICMode: NICModeEnforce, NICs: nics, SynFloodUnavailable: "IPv4: x",
			SynFlood: SynFlood{On: true, Rate: 200, Burst: 1000, NoV4: true}}, SynFloodInForceIPv6Only},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Reconciler{}
			r.recordState(context.Background(), tc.plan, nil)
			if got := r.AppliedState().SynFloodInForce; got != tc.want {
				t.Errorf("SynFloodInForce = %q, want %q", got, tc.want)
			}
		})
	}
}

// When the kernel refuses the per-NIC table, the previous one stays: IN FORCE
// keeps what the previous pass put in force, not what the refused plan asked
// for; with no previous pass (a fresh boot) nothing is in force, which reads
// unavailable (Track B round-1 re-review N-I1).
//
// Mutation: take IN FORCE from the plan whatever applyErr says — red.
func TestRecordState_SynFloodInForceKeepsWhatTheKernelHolds(t *testing.T) {
	ctx := context.Background()
	nics := []NICBinding{{NICDev: "tap0", VMName: "vm1"}}
	refused := fmt.Errorf("%w: nft said no", ErrNICTableRefused)

	r := &Reconciler{}
	r.recordState(ctx, Plan{NICMode: NICModeEnforce, NICs: nics}, nil) // off, applied
	r.recordState(ctx, Plan{NICMode: NICModeEnforce, NICs: nics, SynFlood: SynFlood{On: true, Rate: 200, Burst: 1000}}, refused)
	if got := r.AppliedState().SynFloodInForce; got != SynFloodInForceOff {
		t.Errorf("on refused after off: %q, want off (the kernel kept the previous table)", got)
	}

	fresh := &Reconciler{}
	fresh.recordState(ctx, Plan{NICMode: NICModeEnforce, NICs: nics, SynFlood: SynFlood{On: true, Rate: 200, Burst: 1000}}, refused)
	if got := fresh.AppliedState().SynFloodInForce; got != SynFloodInForceUnavailable {
		t.Errorf("first table refused: %q, want unavailable (nothing in force)", got)
	}
}

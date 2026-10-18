package firewall

import (
	"context"
	"testing"
)

// A pass records what SYN-flood protection it put in force (Track B review
// I-2): on only when the per-NIC table enforces it; observe counts, never
// drops; guards-only renders nothing; unavailable when the kernel refused
// the rules; off when the policy is off.
//
// Mutations: report on in observe mode — red; report on in guards-only — red;
// report off for a refused probe — red.
func TestRecordState_SynFloodInForce(t *testing.T) {
	on := SynFlood{On: true, Rate: 200, Burst: 1000}
	nics := []NICBinding{{NICDev: "tap0", VMName: "vm1"}}
	for _, tc := range []struct {
		name string
		plan Plan
		want string
	}{
		{"enforce", Plan{NICMode: NICModeEnforce, SynFlood: on, NICs: nics}, SynFloodInForceOn},
		{"enforce, no guest NIC", Plan{NICMode: NICModeEnforce, SynFlood: on}, SynFloodInForceOn},
		{"observe", Plan{NICMode: NICModeObserve, SynFlood: on, NICs: nics}, SynFloodInForceObserve},
		{"observe, no guest NIC", Plan{NICMode: NICModeObserve, SynFlood: on}, SynFloodInForceObserve},
		{"guards-only", Plan{NICMode: NICModeGuardsOnly, SynFlood: on, NICs: nics}, SynFloodInForceGuardsOnly},
		{"refused probe", Plan{NICMode: NICModeEnforce, SynFloodUnavailable: "no nft_limit", NICs: nics}, SynFloodInForceUnavailable},
		{"policy off", Plan{NICMode: NICModeEnforce, NICs: nics}, SynFloodInForceOff},
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

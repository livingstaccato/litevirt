package failover

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Failover placement must run under the cluster's configured capacity policy —
// not the built-in defaults — or the coordinator picks a target that the
// target-side admission check (which uses the configured policy) then refuses,
// and the VM never restarts.
func TestBuildFailoverPlacementRequest_CarriesCapacityPolicy(t *testing.T) {
	pol := corrosion.CapacityPolicy{
		CPUOvercommit: 2.0, MemOvercommit: 1.0,
		CPUReserve: 2, MemReserveMiB: 8192, MemReservePct: 10, VMMemOverheadMiB: 256,
	}
	vm := corrosion.VMRecord{Name: "vm1", CPUActual: 2, MemActual: 2048}

	req := buildFailoverPlacementRequest(vm, "failed-host", pol, noneDown)

	if req.Capacity != pol {
		t.Errorf("req.Capacity = %+v, want configured policy %+v", req.Capacity, pol)
	}
	if req.VMName != "vm1" || req.CPUNeeded != 2 || req.MemMiBNeeded != 2048 {
		t.Errorf("basic fields wrong: %+v", req)
	}
}

// A spec pin to the failed host must be dropped; a pin elsewhere survives.
func TestBuildFailoverPlacementRequest_DropsPinToFailedHost(t *testing.T) {
	for _, tc := range []struct {
		spec, wantPin string
	}{
		{`{"placement":{"host":"failed-host"}}`, ""},
		{`{"placement":{"host":"healthy-host"}}`, "healthy-host"},
	} {
		vm := corrosion.VMRecord{Name: "vm1", CPUActual: 1, MemActual: 512, Spec: tc.spec}
		req := buildFailoverPlacementRequest(vm, "failed-host", corrosion.CapacityPolicy{}, noneDown)
		if req.PinHost != tc.wantPin {
			t.Errorf("spec %s: PinHost = %q, want %q", tc.spec, req.PinHost, tc.wantPin)
		}
	}

	vm := corrosion.VMRecord{
		Name: "vm1", CPUActual: 1, MemActual: 512,
		Spec: `{"placement":{"host":"failed-host","anti_affinity":["other"]}}`,
	}
	req := buildFailoverPlacementRequest(vm, "failed-host", corrosion.CapacityPolicy{}, noneDown)
	if len(req.AntiAffinity) != 1 || req.AntiAffinity[0] != "other" {
		t.Errorf("AntiAffinity = %v, want [other] (constraints survive the pin drop)", req.AntiAffinity)
	}
}

// noneDown is a cluster in which every pinned host is up.
func noneDown(string) bool { return false }

// A pin to a host that is down is ignored for the recovery, as a pin to the
// failed host is: the VM cannot run there either way. A pin to a host that is
// up still holds.
func TestBuildFailoverPlacementRequest_IgnoresPinToADownHost(t *testing.T) {
	down := func(h string) bool { return h == "down-host" }
	for _, tc := range []struct {
		spec, wantPin string
	}{
		{`{"placement":{"host":"down-host"}}`, ""},
		{`{"placement":{"host":"healthy-host"}}`, "healthy-host"},
	} {
		vm := corrosion.VMRecord{Name: "vm1", CPUActual: 1, MemActual: 512, Spec: tc.spec}
		if req := buildFailoverPlacementRequest(vm, "failed-host", corrosion.CapacityPolicy{}, down); req.PinHost != tc.wantPin {
			t.Errorf("spec %s: PinHost = %q, want %q", tc.spec, req.PinHost, tc.wantPin)
		}
	}
}

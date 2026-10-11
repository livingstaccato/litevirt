package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Drain target selection must run under the cluster's configured capacity
// policy — not the built-in defaults — or drain picks a target that admission
// on the migration path then refuses.
func TestBuildDrainPlacementRequest_CarriesCapacityPolicy(t *testing.T) {
	pol := corrosion.CapacityPolicy{
		CPUOvercommit: 2.0, MemOvercommit: 1.0,
		CPUReserve: 2, MemReserveMiB: 8192, MemReservePct: 10, VMMemOverheadMiB: 256,
	}
	vm := corrosion.VMRecord{Name: "vm1", CPUActual: 2, MemActual: 2048}

	req := buildDrainPlacementRequest(vm, "draining-host", pol)

	if req.Capacity != pol {
		t.Errorf("req.Capacity = %+v, want configured policy %+v", req.Capacity, pol)
	}
	if req.VMName != "vm1" || req.CPUNeeded != 2 || req.MemMiBNeeded != 2048 {
		t.Errorf("basic fields wrong: %+v", req)
	}
}

// A spec pin to the draining host must be dropped — the VM has to leave.
func TestBuildDrainPlacementRequest_DropsPinToDrainingHost(t *testing.T) {
	for _, tc := range []struct {
		spec, wantPin string
	}{
		{`{"placement":{"host":"draining-host"}}`, ""},
		{`{"placement":{"host":"healthy-host"}}`, "healthy-host"},
	} {
		vm := corrosion.VMRecord{Name: "vm1", CPUActual: 1, MemActual: 512, Spec: tc.spec}
		req := buildDrainPlacementRequest(vm, "draining-host", corrosion.CapacityPolicy{})
		if req.PinHost != tc.wantPin {
			t.Errorf("spec %s: PinHost = %q, want %q", tc.spec, req.PinHost, tc.wantPin)
		}
	}

	vm := corrosion.VMRecord{
		Name: "vm1", CPUActual: 1, MemActual: 512,
		Spec: `{"placement":{"host":"draining-host","anti_affinity":["other"]}}`,
	}
	req := buildDrainPlacementRequest(vm, "draining-host", corrosion.CapacityPolicy{})
	if len(req.AntiAffinity) != 1 || req.AntiAffinity[0] != "other" {
		t.Errorf("AntiAffinity = %v, want [other] (constraints survive the pin drop)", req.AntiAffinity)
	}
}

// A raw USB device binds a VM to the host being drained, so no target
// qualifies; a mapped one limits it to the mapping's hosts.
func TestBuildDrainPlacementRequest_CarriesUSBConstraints(t *testing.T) {
	raw := corrosion.VMRecord{Name: "vm1", HostName: "draining-host", Spec: `{"usb_devices":[{"vendor":"046d","product":"c52b"}]}`}
	if req := buildDrainPlacementRequest(raw, "draining-host", corrosion.CapacityPolicy{}); req.USBHost != "draining-host" {
		t.Errorf("raw USB: USBHost = %q; want the draining host", req.USBHost)
	}
	mapped := corrosion.VMRecord{Name: "vm1", HostName: "draining-host", Spec: `{"usb_devices":[{"mapping":"dongle"}]}`}
	if req := buildDrainPlacementRequest(mapped, "draining-host", corrosion.CapacityPolicy{}); len(req.USBMappings) != 1 || req.USBHost != "" {
		t.Errorf("mapped USB: USBMappings %v USBHost %q; want [dongle] and no host", req.USBMappings, req.USBHost)
	}
}

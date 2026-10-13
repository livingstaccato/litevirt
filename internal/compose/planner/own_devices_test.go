package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// An update of a VM is placed with the PCI devices it already holds counted as
// its own, not as taken. A type+mapping GPU VM on a host whose only GPU it
// holds itself could otherwise plan no update at all: the mapping (and before
// the mapping was carried, the type) asked for a FREE device, and there was
// none. Main planned such an update only when the host had a spare GPU.

const ownGPU = "0000:41:00.0"

// ownDeviceState is h1 with one GPU, held by hwv of stack pclhw, which runs
// there; mapping accel names that GPU.
func ownDeviceState(holder string) *ClusterState {
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 16, 32768)},
		[]corrosion.VMRecord{{
			Name: "hwv", StackName: "pclhw", HostName: "h1",
			Spec: `{"name":"hwv","image":"ubuntu","cpu":1,"memory_mib":512,` +
				`"devices":[{"type":"gpu","mapping":"accel","count":1,"address":"` + ownGPU + `"}],` +
				`"placement":{"host":"h1"}}`,
			State: "running", CPUActual: 1, MemActual: 512,
		}},
		nil,
	)
	state.HeldDevices = map[string][]corrosion.PCIDeviceRecord{
		"h1": {{HostName: "h1", Address: ownGPU, Type: "gpu", IOMMUGroup: 3, VMName: holder}},
	}
	state.Mappings = map[string]map[string][]string{"accel": {"h1": {ownGPU}}}
	return state
}

func ownDeviceFile() *compose.File {
	return makeFile("pclhw", map[string]compose.VMDef{
		"hwv": {Image: "ubuntu", CPU: 1, Memory: 512,
			Labels:    map[string]string{"tier": "gpu"},
			Placement: &compose.PlacementDef{Host: "h1"},
			Devices:   []compose.DeviceDef{{Type: "gpu", Mapping: "accel"}}},
	})
}

func TestResolve_UpdateOfATypeAndMappingVMReusesItsOwnDevice(t *testing.T) {
	plan, err := Resolve(context.Background(), ownDeviceFile(), ownDeviceState("hwv"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := findAction(t, plan, "hwv")
	if a.Kind != OpUpdate || a.TargetHost != "h1" {
		t.Fatalf("hwv = %s on %q, want an update on h1", a.Kind, a.TargetHost)
	}
}

// The same holds for a type-only device: main refused this update too.
func TestResolve_UpdateOfATypeVMReusesItsOwnDevice(t *testing.T) {
	state := ownDeviceState("hwv")
	state.VMs[0].Spec = strings.Replace(state.VMs[0].Spec, `"mapping":"accel",`, "", 1)
	f := ownDeviceFile()
	def := f.VMs["hwv"]
	def.Devices = []compose.DeviceDef{{Type: "gpu"}}
	f.VMs["hwv"] = def
	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if a := findAction(t, plan, "hwv"); a.Kind != OpUpdate || a.TargetHost != "h1" {
		t.Fatalf("hwv = %s on %q, want an update on h1", a.Kind, a.TargetHost)
	}
}

// Only the VM's OWN device is freed: a GPU another VM holds stays taken.
func TestResolve_UpdateDoesNotReuseAnotherVMsDevice(t *testing.T) {
	_, err := Resolve(context.Background(), ownDeviceFile(), ownDeviceState("other"))
	if err == nil || !strings.Contains(err.Error(), "no eligible host") {
		t.Fatalf("Resolve err = %v, want no eligible host (the GPU is another VM's)", err)
	}
}

// And a new VM in the same batch cannot be planned onto the updated VM's
// device: it is freed for hwv's own evaluation only.
func TestResolve_AnUpdatedVMsDeviceStaysTakenForTheRestOfTheBatch(t *testing.T) {
	f := ownDeviceFile()
	f.VMs["zz"] = compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512,
		Devices: []compose.DeviceDef{{Address: ownGPU}}}
	_, err := Resolve(context.Background(), f, ownDeviceState("hwv"))
	if err == nil || !strings.Contains(err.Error(), `"zz"`) {
		t.Fatalf("Resolve err = %v, want no eligible host for zz (hwv keeps its GPU)", err)
	}
}

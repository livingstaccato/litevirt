package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A VM update and the PCI devices the VM already holds:
//   - applied to the same VM (live, or reconfigure and restart), it keeps
//     them and acquires nothing, so its devices are not placed again;
//   - a recreate takes them again after the delete, so the ones it holds
//     count as free to it (placement.Request.ReuseDevicesOf);
//   - a recreate that runs beside the old VM (blue-green,
//     snapshot-and-replace) does not get them: the old VM keeps them.
// Main counted the VM's own device as taken, so a VM holding the only
// matching device on its host could plan no update unless a spare existed.

const (
	ownGPU   = "0000:41:00.0"
	otherGPU = "0000:40:00.0"
)

// ownDeviceState is h1 with GPU 41:00.0 held by hwv of stack pclhw (image
// ubuntu), which runs there; mapping accel names that GPU.
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

// ownDeviceFile is hwv with a label added (a live change), on image.
func ownDeviceFile(image, strategy string) *compose.File {
	def := compose.VMDef{Image: image, CPU: 1, Memory: 512,
		Labels:    map[string]string{"tier": "gpu"},
		Placement: &compose.PlacementDef{Host: "h1"},
		Devices:   []compose.DeviceDef{{Type: "gpu", Mapping: "accel"}}}
	if strategy != "" {
		def.Update = &compose.UpdateDef{Strategy: strategy}
	}
	return makeFile("pclhw", map[string]compose.VMDef{"hwv": def})
}

func wantUpdateOnH1(t *testing.T, plan *ResolvedPlan, err error, want compose.Action) {
	t.Helper()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := findAction(t, plan, "hwv")
	if a.Kind != OpUpdate || a.TargetHost != "h1" || a.Apply != want {
		t.Fatalf("hwv = %s/%s on %q, want an update (%s) on h1", a.Kind, a.Apply, a.TargetHost, want)
	}
}

// A label edit is applied to the running VM, which keeps its GPU. Its mapping
// has since been given a lower address on h1, held by another VM: re-judging
// the mapping would refuse an update that acquires nothing.
func TestResolve_ALiveUpdateKeepsTheDevicesItHolds(t *testing.T) {
	state := ownDeviceState("hwv")
	state.Mappings["accel"]["h1"] = []string{otherGPU, ownGPU}
	state.HeldDevices["h1"] = append(state.HeldDevices["h1"],
		corrosion.PCIDeviceRecord{HostName: "h1", Address: otherGPU, Type: "gpu", IOMMUGroup: 2, VMName: "other"})
	plan, err := Resolve(context.Background(), ownDeviceFile("ubuntu", ""), state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if a := findAction(t, plan, "hwv"); a.Kind != OpUpdate || a.TargetHost != "h1" || a.Apply == compose.ActionRecreate {
		t.Fatalf("hwv = %s/%s on %q, want an update of the same VM on h1", a.Kind, a.Apply, a.TargetHost)
	}
}

// An image change recreates hwv; the GPU it holds is the only one on h1, and
// is free to its own recreate.
func TestResolve_ARecreateReusesItsOwnDevice(t *testing.T) {
	plan, err := Resolve(context.Background(), ownDeviceFile("debian", ""), ownDeviceState("hwv"))
	wantUpdateOnH1(t, plan, err, compose.ActionRecreate)
}

// The same for a type-only device.
func TestResolve_ARecreateOfATypeVMReusesItsOwnDevice(t *testing.T) {
	state := ownDeviceState("hwv")
	state.VMs[0].Spec = strings.Replace(state.VMs[0].Spec, `"mapping":"accel",`, "", 1)
	f := ownDeviceFile("debian", "")
	def := f.VMs["hwv"]
	def.Devices = []compose.DeviceDef{{Type: "gpu"}}
	f.VMs["hwv"] = def
	plan, err := Resolve(context.Background(), f, state)
	wantUpdateOnH1(t, plan, err, compose.ActionRecreate)
}

// Only the VM's OWN device is freed: a GPU another VM holds stays taken.
func TestResolve_ARecreateDoesNotReuseAnotherVMsDevice(t *testing.T) {
	_, err := Resolve(context.Background(), ownDeviceFile("debian", ""), ownDeviceState("other"))
	if err == nil || !strings.Contains(err.Error(), "no eligible host") {
		t.Fatalf("Resolve err = %v, want no eligible host (the GPU is another VM's)", err)
	}
}

// blue-green and snapshot-and-replace create the new VM beside the old one,
// which keeps its GPU until the cutover: on a one-GPU host there is none for
// the new VM. Under the strategies that delete first the same change plans.
func TestResolve_ARecreateBesideTheOldVMDoesNotGetItsDevice(t *testing.T) {
	for _, c := range []struct {
		strategy string
		fits     bool
	}{
		{"blue-green", false},
		{"snapshot-and-replace", false},
		{"recreate", true},
		{"rolling", true},
	} {
		plan, err := Resolve(context.Background(), ownDeviceFile("debian", c.strategy), ownDeviceState("hwv"))
		if c.fits {
			if err != nil {
				t.Errorf("%s: Resolve: %v", c.strategy, err)
			} else if a := findAction(t, plan, "hwv"); a.TargetHost != "h1" {
				t.Errorf("%s: hwv on %q, want h1", c.strategy, a.TargetHost)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "h1: devices") {
			t.Errorf("%s: Resolve err = %v, want h1 refused for devices (the old VM keeps the GPU)", c.strategy, err)
		}
	}
}

// A new VM in the same batch cannot be planned onto the recreated VM's
// device: it is freed for hwv's own evaluation only.
func TestResolve_ARecreatedVMsDeviceStaysTakenForTheRestOfTheBatch(t *testing.T) {
	f := ownDeviceFile("debian", "")
	f.VMs["zz"] = compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512,
		Devices: []compose.DeviceDef{{Address: ownGPU}}}
	_, err := Resolve(context.Background(), f, ownDeviceState("hwv"))
	if err == nil || !strings.Contains(err.Error(), `"zz"`) {
		t.Fatalf("Resolve err = %v, want no eligible host for zz (hwv keeps its GPU)", err)
	}
}

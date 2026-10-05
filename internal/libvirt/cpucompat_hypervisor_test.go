package libvirt

import (
	"errors"
	"os"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// fakeCPUCompareAPI answers the two libvirt CPU compare calls independently, so
// a test can tell which one a verdict came from.
type fakeCPUCompareAPI struct {
	legacyResult int32
	legacyCalls  int

	hypervisorResult int32
	hypervisorErr    error
	hypervisorXML    []string
	hypervisorArgs   [][]golibvirt.OptString
}

func (f *fakeCPUCompareAPI) ConnectCompareCPU(xml string, _ golibvirt.ConnectCompareCPUFlags) (int32, error) {
	f.legacyCalls++
	return f.legacyResult, nil
}

func (f *fakeCPUCompareAPI) ConnectCompareHypervisorCPU(emulator, arch, machine, virttype golibvirt.OptString, xml string, _ uint32) (int32, error) {
	f.hypervisorXML = append(f.hypervisorXML, xml)
	f.hypervisorArgs = append(f.hypervisorArgs, []golibvirt.OptString{emulator, arch, machine, virttype})
	return f.hypervisorResult, f.hypervisorErr
}

// labHostModelCPU is the live <cpu> of a running host-model guest on the lab
// (EPYC-Milan, libvirt 10.0.0, QEMU 8.2.2), read with `virsh dumpxml`.
func labHostModelCPU(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/cpu_live_host_model_epyc_milan.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// The lab guest above is reported incompatible by the legacy
// virConnectCompareCPU even on the host it is running on: that call compares
// against the host's raw capabilities CPU, which lacks features (spec-ctrl,
// arch-capabilities, topoext …) that QEMU provides to guests. The compare must
// therefore ask the hypervisor-aware API, which compares against what this
// host's QEMU can actually give a guest.
func TestCompareCPUAsksTheHypervisorNotTheRawHostCPU(t *testing.T) {
	cpu := labHostModelCPU(t)
	api := &fakeCPUCompareAPI{
		legacyResult:     int32(golibvirt.CPUCompareIncompatible),
		hypervisorResult: int32(golibvirt.CPUCompareIdentical),
	}
	got, err := compareCPU(api, cpu)
	if err != nil {
		t.Fatalf("compareCPU: %v", err)
	}
	if got != CPUCompareIdentical {
		t.Fatalf("verdict = %v, want identical (the hypervisor's answer)", got)
	}
	if api.legacyCalls != 0 {
		t.Errorf("legacy ConnectCompareCPU was called %d times; it misjudges host-model guests", api.legacyCalls)
	}
	if len(api.hypervisorXML) != 1 || api.hypervisorXML[0] != cpu {
		t.Fatalf("hypervisor compare was not asked about the guest CPU verbatim: %q", api.hypervisorXML)
	}
	// Defaults for emulator/arch/machine/virttype: libvirt picks this host's
	// default emulator and KVM, i.e. the hypervisor a migrated guest lands on.
	for i, a := range api.hypervisorArgs[0] {
		if len(a) != 0 {
			t.Errorf("hypervisor compare arg %d = %q, want libvirt's default", i, a)
		}
	}
}

// A genuine "cannot run" from the hypervisor must still come through: the fix
// is about asking the right question, not about softening the answer.
func TestCompareCPUPassesThroughAHypervisorIncompatible(t *testing.T) {
	api := &fakeCPUCompareAPI{
		legacyResult:     int32(golibvirt.CPUCompareSuperset),
		hypervisorResult: int32(golibvirt.CPUCompareIncompatible),
	}
	got, err := compareCPU(api, labHostModelCPU(t))
	if err != nil {
		t.Fatalf("compareCPU: %v", err)
	}
	if got != CPUCompareIncompatible || got.Runnable() {
		t.Fatalf("verdict = %v, want incompatible", got)
	}
}

func TestCompareCPUHypervisorErrors(t *testing.T) {
	cpu := labHostModelCPU(t)

	api := &fakeCPUCompareAPI{hypervisorErr: errors.New("boom")}
	if _, err := compareCPU(api, cpu); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("transport error not surfaced: %v", err)
	}

	api = &fakeCPUCompareAPI{hypervisorResult: int32(golibvirt.CPUCompareError)}
	if _, err := compareCPU(api, cpu); err == nil {
		t.Error("an error RESULT (-1) must be an error, not a verdict")
	}

	api = &fakeCPUCompareAPI{}
	if _, err := compareCPU(api, "  "); err == nil {
		t.Error("empty cpu xml must be refused")
	}
	if len(api.hypervisorXML) != 0 || api.legacyCalls != 0 {
		t.Error("empty cpu xml reached libvirt")
	}
}

// The real lab live XML is a comparable requirement as-is.
func TestDomainCPURequirementLabHostModel(t *testing.T) {
	cpu := labHostModelCPU(t)
	got, ok := DomainCPURequirement("<domain type='kvm'><name>app</name>" + cpu + "</domain>")
	if !ok || got != cpu {
		t.Fatalf("DomainCPURequirement = %q, %v; want the live element verbatim", got, ok)
	}
}

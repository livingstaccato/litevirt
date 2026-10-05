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

	domCaps     string
	domCapsArgs [][]golibvirt.OptString
}

func (f *fakeCPUCompareAPI) ConnectGetDomainCapabilities(emulator, arch, machine, virttype golibvirt.OptString, _ golibvirt.ConnectGetDomainCapabilitiesFlags) (string, error) {
	f.domCapsArgs = append(f.domCapsArgs, []golibvirt.OptString{emulator, arch, machine, virttype})
	return f.domCaps, nil
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
	got, err := compareCPU(api, cpu, "pc-q35-8.2")
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
	// The guest's machine type is passed; emulator/arch/virttype are libvirt's
	// defaults: this host's default emulator and KVM, i.e. the hypervisor a
	// migrated guest lands on.
	args := api.hypervisorArgs[0]
	if len(args[2]) != 1 || args[2][0] != "pc-q35-8.2" {
		t.Errorf("hypervisor compare machine = %q, want the guest's pc-q35-8.2", args[2])
	}
	for _, i := range []int{0, 1, 3} {
		if len(args[i]) != 0 {
			t.Errorf("hypervisor compare arg %d = %q, want libvirt's default", i, args[i])
		}
	}
	// No machine type: libvirt's default, not an empty string.
	if _, err := compareCPU(api, cpu, ""); err != nil {
		t.Fatalf("compareCPU: %v", err)
	}
	if m := api.hypervisorArgs[1][2]; len(m) != 0 {
		t.Errorf("empty machine was sent as %q, want absent", m)
	}
}

// A genuine "cannot run" from the hypervisor must still come through: the fix
// is about asking the right question, not about softening the answer.
func TestCompareCPUPassesThroughAHypervisorIncompatible(t *testing.T) {
	api := &fakeCPUCompareAPI{
		legacyResult:     int32(golibvirt.CPUCompareSuperset),
		hypervisorResult: int32(golibvirt.CPUCompareIncompatible),
	}
	got, err := compareCPU(api, labHostModelCPU(t), "")
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
	if _, err := compareCPU(api, cpu, ""); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("transport error not surfaced: %v", err)
	}

	api = &fakeCPUCompareAPI{hypervisorResult: int32(golibvirt.CPUCompareError)}
	if _, err := compareCPU(api, cpu, ""); err == nil {
		t.Error("an error RESULT (-1) must be an error, not a verdict")
	}

	api = &fakeCPUCompareAPI{}
	if _, err := compareCPU(api, "  ", ""); err == nil {
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

func labDomCaps(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/domcaps_epyc_milan.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// The lab host's domcapabilities host-model list, read through the API with the
// guest's machine type.
func TestHostModelCPUFeaturesLab(t *testing.T) {
	api := &fakeCPUCompareAPI{domCaps: labDomCaps(t)}
	got, err := hostModelCPUFeatures(api, "pc-q35-8.2")
	if err != nil {
		t.Fatalf("hostModelCPUFeatures: %v", err)
	}
	if len(got) != 30 {
		t.Errorf("host-model lists %d features, want the lab's 30: %v", len(got), got)
	}
	for _, f := range []string{"vaes", "spec-ctrl", "arch-capabilities", "gds-no"} {
		if !got[f] {
			t.Errorf("host-model does not credit %s", f)
		}
	}
	if got["topoext"] {
		t.Error("lab host-model credits topoext; the fixture says it does not")
	}
	if m := api.domCapsArgs[0][2]; len(m) != 1 || m[0] != "pc-q35-8.2" {
		t.Errorf("domain capabilities machine = %q, want pc-q35-8.2", m)
	}
}

func TestHostModelFeaturesFromDomCapsPolicies(t *testing.T) {
	caps := `<domainCapabilities><cpu>
	  <mode name='host-passthrough' supported='yes'/>
	  <mode name='host-model' supported='yes'>
	    <model fallback='forbid'>X</model>
	    <feature policy='require' name='a'/>
	    <feature policy='disable' name='b'/>
	  </mode>
	  <mode name='custom' supported='yes'><model usable='yes'>c</model></mode>
	</cpu></domainCapabilities>`
	got, err := hostModelFeaturesFromDomCaps(caps)
	if err != nil {
		t.Fatalf("hostModelFeaturesFromDomCaps: %v", err)
	}
	if !got["a"] || got["b"] || got["c"] {
		t.Errorf("credited = %v; want a only (b is disabled, c is a custom model)", got)
	}
	for _, bad := range []string{
		`<domainCapabilities><cpu><mode name='host-model' supported='no'/></cpu></domainCapabilities>`,
		`<domainCapabilities><cpu><mode name='custom' supported='yes'/></cpu></domainCapabilities>`,
		`not xml`,
	} {
		if _, err := hostModelFeaturesFromDomCaps(bad); err == nil {
			t.Errorf("want an error for %q", bad)
		}
	}
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// On the lab the only live feature the source's host-model does not credit is
// topoext, so exactly that goes, and everything else is byte for byte intact.
func TestCreditCPURequirementLab(t *testing.T) {
	cpu := labHostModelCPU(t)
	hm, err := hostModelFeaturesFromDomCaps(labDomCaps(t))
	if err != nil {
		t.Fatal(err)
	}
	got, dropped := CreditCPURequirement(cpu, hm)
	if len(dropped) != 1 || dropped[0] != "topoext" {
		t.Fatalf("dropped = %v, want exactly [topoext]", dropped)
	}
	want := strings.Replace(cpu, "\n  <feature policy='require' name='topoext'/>", "", 1)
	if got != want {
		t.Fatalf("credited requirement is not the live element minus topoext:\n%s", got)
	}
	if _, ok := DomainCPURequirement("<domain>" + got + "</domain>"); !ok {
		t.Error("credited requirement is no longer a comparable <cpu>")
	}
}

func TestCreditCPURequirementPolicies(t *testing.T) {
	cpu := `<cpu mode='custom' match='exact'><model fallback='forbid'>M</model>` +
		`<feature policy='require' name='kept'/>` +
		`<feature policy='require' name='gone'/>` +
		`<feature policy='disable' name='off'/>` +
		`<feature policy='require' name='disabled-on-host'/></cpu>`
	hm := map[string]bool{"kept": true, "disabled-on-host": false}
	got, dropped := CreditCPURequirement(cpu, hm)
	want := `<cpu mode='custom' match='exact'><model fallback='forbid'>M</model>` +
		`<feature policy='require' name='kept'/>` +
		`<feature policy='disable' name='off'/></cpu>`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if strings.Join(dropped, ",") != "gone,disabled-on-host" {
		t.Errorf("dropped = %v", dropped)
	}
	// Nothing to strip: the input comes back unchanged.
	if got, dropped := CreditCPURequirement(want, set("kept")); got != want || len(dropped) != 0 {
		t.Errorf("a fully credited cpu changed: %s %v", got, dropped)
	}
}

func TestDomainMachineType(t *testing.T) {
	dom := `<domain type='kvm'><name>v</name><metadata><os><type machine='decoy'/></os></metadata>` +
		`<os><type arch='x86_64' machine='pc-q35-8.2'>hvm</type></os></domain>`
	if got := DomainMachineType(dom); got != "pc-q35-8.2" {
		t.Errorf("DomainMachineType = %q, want pc-q35-8.2", got)
	}
	if got := DomainMachineType(`<domain><name>v</name></domain>`); got != "" {
		t.Errorf("no <os>: got %q", got)
	}
}

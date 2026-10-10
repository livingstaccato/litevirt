package libvirt

import (
	"strings"
	"testing"
)

func TestCPUTuneQuota_IsPerVCPU(t *testing.T) {
	cases := []struct {
		limit float64
		vcpus int
		want  int64
	}{
		{2, 4, 50000},    // 2 cores over 4 vCPUs: half a period each
		{1, 1, 100000},   // a single vCPU capped at one core is uncapped
		{0.5, 1, 50000},  // fractional
		{4, 4, 100000},   // at the vCPU count: full period each
		{0.01, 1, 1000},  // libvirt floor
		{1.5, 3, 50000},  // 1.5 over 3
		{2.5, 2, 100000}, // clamped to a period (validation refuses it earlier)
	}
	for _, c := range cases {
		period, quota := CPUTuneQuota(c.limit, c.vcpus)
		if period != CPUPeriodUS || quota != c.want {
			t.Errorf("CPUTuneQuota(%v,%d) = %d/%d, want %d/%d", c.limit, c.vcpus, period, quota, CPUPeriodUS, c.want)
		}
	}
}

func TestValidateCPULimit(t *testing.T) {
	for _, ok := range []struct {
		l float64
		v int
	}{{0, 2}, {2, 2}, {0.5, 2}, {0.02, 2}} {
		if err := ValidateCPULimit(ok.l, ok.v); err != nil {
			t.Errorf("ValidateCPULimit(%v,%d) = %v, want nil", ok.l, ok.v, err)
		}
	}
	for _, bad := range []struct {
		l float64
		v int
	}{{-1, 2}, {2.5, 2}, {0.001, 2}} {
		if err := ValidateCPULimit(bad.l, bad.v); err == nil {
			t.Errorf("ValidateCPULimit(%v,%d) = nil, want error", bad.l, bad.v)
		}
	}
}

func TestValidateCPUSharesAndRate(t *testing.T) {
	if ValidateCPUShares(0) != nil || ValidateCPUShares(1024) != nil || ValidateCPUShares(262144) != nil {
		t.Error("valid shares refused")
	}
	if ValidateCPUShares(1) == nil || ValidateCPUShares(262145) == nil || ValidateCPUShares(-5) == nil {
		t.Error("invalid shares accepted")
	}
	if ValidateNICRate(0) != nil || ValidateNICRate(12.5) != nil {
		t.Error("valid rate refused")
	}
	if ValidateNICRate(-1) == nil || ValidateNICRate(0.0000001) == nil {
		t.Error("invalid rate accepted")
	}
}

func TestGenerateDomainXML_CPUTuneLimitAndShares(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{Name: "lim", CPU: 4, MemoryMiB: 1024, CPULimit: 2, CPUShares: 2048})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<cputune>", "<shares>2048</shares>", "<period>100000</period>", "<quota>50000</quota>"} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q in:\n%s", want, x)
		}
	}
	// Pinning and limits share one <cputune>.
	x, _ = GenerateDomainXML(VMConfig{Name: "pin", CPU: 2, MemoryMiB: 1024, CPUPinning: []int{0, 1}, CPULimit: 1})
	if strings.Count(x, "<cputune>") != 1 || !strings.Contains(x, "<vcpupin") || !strings.Contains(x, "<quota>50000</quota>") {
		t.Errorf("pinning + limit not merged into one cputune:\n%s", x)
	}
	// Unset renders nothing.
	x, _ = GenerateDomainXML(VMConfig{Name: "none", CPU: 2, MemoryMiB: 1024})
	if strings.Contains(x, "cputune") {
		t.Errorf("unlimited VM rendered cputune:\n%s", x)
	}
}

func TestGenerateDomainXML_NICBandwidth(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{Name: "bw", CPU: 1, MemoryMiB: 512, Networks: []NetworkConfig{
		{Bridge: "br0", MAC: "52:54:00:00:00:01", Model: "virtio", RateMBps: 10},
		{Bridge: "br0", MAC: "52:54:00:00:00:02", Model: "virtio"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// 10 MB/s = 10e6/1024 KiB/s = 9766.
	if strings.Count(x, "<bandwidth>") != 1 ||
		!strings.Contains(x, `<inbound average="9766">`) ||
		!strings.Contains(x, `<outbound average="9766">`) {
		t.Errorf("bandwidth wrong (want exactly one, 9766 KiB/s each way):\n%s", x)
	}
}

const tuneBase = `<domain type='kvm'>
  <name>t</name>
  <vcpu placement='static'>4</vcpu>
  <cputune>
    <vcpupin vcpu='0' cpuset='1'/>
    <shares>512</shares>
    <period>100000</period>
    <quota>10000</quota>
  </cputune>
  <os/>
</domain>`

func TestPatchInactiveCPUTune_ReplacesAndKeepsPinning(t *testing.T) {
	out, err := PatchInactiveCPUTune(tuneBase, 2, 2048, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<vcpupin vcpu='0' cpuset='1'/>", "<shares>2048</shares>", "<quota>50000</quota>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"<shares>512</shares>", "<quota>10000</quota>"} {
		if strings.Contains(out, gone) {
			t.Errorf("stale %q survived:\n%s", gone, out)
		}
	}
	if strings.Count(out, "<period>") != 1 || strings.Count(out, "<cputune>") != 1 {
		t.Errorf("duplicated elements:\n%s", out)
	}
}

func TestPatchInactiveCPUTune_InsertAndRemove(t *testing.T) {
	bare := "<domain>\n  <vcpu>2</vcpu>\n  <os/>\n</domain>"
	out, err := PatchInactiveCPUTune(bare, 1, 0, 2)
	if err != nil || !strings.Contains(out, "<quota>50000</quota>") || strings.Contains(out, "<shares>") {
		t.Fatalf("insert: %v\n%s", err, out)
	}
	// Clearing everything on a block that only had limits drops the block.
	only := "<domain>\n  <vcpu>2</vcpu>\n  <cputune>\n    <quota>50000</quota>\n    <period>100000</period>\n  </cputune>\n  <os/>\n</domain>"
	out, err = PatchInactiveCPUTune(only, 0, 0, 2)
	if err != nil || strings.Contains(out, "cputune") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	// ...but keeps pinning when clearing limits.
	out, _ = PatchInactiveCPUTune(tuneBase, 0, 0, 4)
	if !strings.Contains(out, "vcpupin") || strings.Contains(out, "quota") || strings.Contains(out, "shares") {
		t.Errorf("clear kept wrong set:\n%s", out)
	}
	// A vCPU count change moves the per-vCPU quota.
	a, _ := PatchInactiveCPUTune(bare, 2, 0, 4)
	b, _ := PatchInactiveCPUTune(bare, 2, 0, 8)
	if !strings.Contains(a, "<quota>50000</quota>") || !strings.Contains(b, "<quota>25000</quota>") {
		t.Errorf("quota did not follow vcpus:\n%s\n%s", a, b)
	}
}

const ifaceBase = `<domain>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:01'/>
      <source bridge='br0'/>
      <model type='virtio'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:02'/>
      <source bridge='br0'/>
      <bandwidth>
        <inbound average='5'/>
      </bandwidth>
    </interface>
  </devices>
</domain>`

func TestPatchInterfaceBandwidth(t *testing.T) {
	out, ok := PatchInterfaceBandwidth(ifaceBase, "52:54:00:AA:BB:01", 1)
	if !ok || strings.Count(out, "<bandwidth>") != 2 || !strings.Contains(out, "average='977'") {
		t.Fatalf("set: ok=%v\n%s", ok, out)
	}
	// Only the addressed NIC changed: the other keeps its own cap.
	if !strings.Contains(out, "average='5'") {
		t.Errorf("neighbour NIC's bandwidth was touched:\n%s", out)
	}
	out, ok = PatchInterfaceBandwidth(ifaceBase, "52:54:00:aa:bb:02", 0)
	if !ok || strings.Count(out, "<bandwidth>") != 0 {
		t.Fatalf("clear: ok=%v\n%s", ok, out)
	}
	if _, ok := PatchInterfaceBandwidth(ifaceBase, "52:54:00:00:00:99", 1); ok {
		t.Error("unknown MAC reported as found")
	}
}

package libvirt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cpulimit is a cap on the whole domain (libvirt global_period/global_quota,
// the cgroup's cpu.max), not a per-vCPU quota: a guest running one busy thread
// can use a full core of a 2.5-core cap.
func TestGlobalQuota_IsTheTotalNotPerVCPU(t *testing.T) {
	for _, c := range []struct {
		limit float64
		want  int64
	}{
		{2.5, 250000}, // 2.5 cores: 250ms of CPU per 100ms period, across all vCPUs
		{1, 100000},
		{0.5, 50000},
		{0.01, 1000},  // libvirt's floor
		{0.004, 1000}, // clamped to it
		{8, 800000},
	} {
		period, quota := GlobalQuota(c.limit)
		if period != CPUPeriodUS || quota != c.want {
			t.Errorf("GlobalQuota(%v) = %d/%d, want %d/%d", c.limit, period, quota, CPUPeriodUS, c.want)
		}
	}
}

func TestValidateCPULimit(t *testing.T) {
	for _, ok := range []struct {
		l float64
		v int
	}{{0, 2}, {2, 2}, {0.5, 2}, {0.01, 2}, {0.05, 8}} {
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

// cpu-shares is Proxmox's cpuunits: the cgroup v2 cpu.weight, 1..10000.
func TestValidateCPUShares_IsTheCgroupV2WeightRange(t *testing.T) {
	for _, ok := range []int{0, 1, 100, 1024, 10000} {
		if err := ValidateCPUShares(ok); err != nil {
			t.Errorf("ValidateCPUShares(%d) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []int{-1, 10001, 20000, 262144} {
		if err := ValidateCPUShares(bad); err == nil {
			t.Errorf("ValidateCPUShares(%d) = nil, want error (the kernel rejects cpu.weight outside 1..10000)", bad)
		}
	}
}

func TestDefaultCPUWeight_FollowsTheHostsCgroupVersion(t *testing.T) {
	dir := t.TempDir()
	v2 := filepath.Join(dir, "cgroup.controllers")
	if err := os.WriteFile(v2, []byte("cpu io memory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := cgroupControllersFile
	defer func() { cgroupControllersFile = old }()
	cgroupControllersFile = v2
	if got := DefaultCPUWeight(); got != 100 {
		t.Errorf("cgroup v2 host default = %d, want 100 (cpu.weight's default)", got)
	}
	cgroupControllersFile = filepath.Join(dir, "absent")
	if got := DefaultCPUWeight(); got != 1024 {
		t.Errorf("cgroup v1 host default = %d, want 1024 (cpu.shares' default)", got)
	}
}

func TestValidateNICRate(t *testing.T) {
	if ValidateNICRate(0) != nil || ValidateNICRate(12.5) != nil {
		t.Error("valid rate refused")
	}
	if ValidateNICRate(-1) == nil || ValidateNICRate(0.0000001) == nil {
		t.Error("invalid rate accepted")
	}
}

func TestGenerateDomainXML_CPUTuneLimitAndShares(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{Name: "lim", CPU: 4, MemoryMiB: 1024, CPULimit: 2, CPUShares: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<cputune>", "<shares>200</shares>", "<global_period>100000</global_period>", "<global_quota>200000</global_quota>"} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q in:\n%s", want, x)
		}
	}
	// The cap is the whole domain's: no per-vCPU quota is set.
	if strings.Contains(x, "<quota>") || strings.Contains(x, "<period>") {
		t.Errorf("a per-vCPU quota was rendered:\n%s", x)
	}
	// Pinning and limits share one <cputune>.
	x, _ = GenerateDomainXML(VMConfig{Name: "pin", CPU: 2, MemoryMiB: 1024, CPUPinning: []int{0, 1}, CPULimit: 1})
	if strings.Count(x, "<cputune>") != 1 || !strings.Contains(x, "<vcpupin") || !strings.Contains(x, "<global_quota>100000</global_quota>") {
		t.Errorf("pinning + limit not merged into one cputune:\n%s", x)
	}
	// Unset renders nothing.
	x, _ = GenerateDomainXML(VMConfig{Name: "none", CPU: 2, MemoryMiB: 1024})
	if strings.Contains(x, "cputune") {
		t.Errorf("unlimited VM rendered cputune:\n%s", x)
	}
}

// The unit is pinned, not just the plumbing: Proxmox's rate is MB/s (10^6
// bytes) and libvirt's average is kilobytes/s, which libvirt hands to tc as
// "<n>kbps" — 1000 bytes/s in iproute2 — so 10 MB/s is exactly 10000.
func TestNICRateConversion_PinsTheExactNumbers(t *testing.T) {
	for _, c := range []struct {
		mbps float64
		want uint64
	}{{10, 10000}, {1, 1000}, {12.5, 12500}, {0.5, 500}, {100, 100000}, {0.001, 1}} {
		if got := rateKBps(c.mbps); got != c.want {
			t.Errorf("rateKBps(%v) = %d, want %d", c.mbps, got, c.want)
		}
	}
	x, err := GenerateDomainXML(VMConfig{Name: "bw", CPU: 1, MemoryMiB: 512, Networks: []NetworkConfig{
		{Bridge: "br0", MAC: "52:54:00:00:00:01", Model: "virtio", RateMBps: 10},
		{Bridge: "br0", MAC: "52:54:00:00:00:02", Model: "virtio"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(x, "<bandwidth>") != 1 ||
		!strings.Contains(x, `<inbound average="10000">`) ||
		!strings.Contains(x, `<outbound average="10000">`) {
		t.Errorf("bandwidth wrong (want exactly one, 10000 KB/s each way):\n%s", x)
	}
}

const tuneBase = `<domain type='kvm'>
  <name>t</name>
  <vcpu placement='static'>4</vcpu>
  <cputune>
    <vcpupin vcpu='0' cpuset='1'/>
    <shares>50</shares>
    <global_period>100000</global_period>
    <global_quota>10000</global_quota>
    <period>100000</period>
    <quota>10000</quota>
  </cputune>
  <os/>
</domain>`

func TestPatchInactiveCPUTune_ReplacesAndKeepsPinning(t *testing.T) {
	out, err := PatchInactiveCPUTune(tuneBase, 2, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<vcpupin vcpu='0' cpuset='1'/>", "<shares>200</shares>", "<global_quota>200000</global_quota>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"<shares>50</shares>", "<global_quota>10000</global_quota>", "<quota>10000</quota>"} {
		if strings.Contains(out, gone) {
			t.Errorf("stale %q survived:\n%s", gone, out)
		}
	}
	if strings.Count(out, "<global_period>") != 1 || strings.Count(out, "<cputune>") != 1 {
		t.Errorf("duplicated elements:\n%s", out)
	}
}

func TestPatchInactiveCPUTune_InsertAndRemove(t *testing.T) {
	bare := "<domain>\n  <vcpu>2</vcpu>\n  <os/>\n</domain>"
	out, err := PatchInactiveCPUTune(bare, 1, 0)
	if err != nil || !strings.Contains(out, "<global_quota>100000</global_quota>") || strings.Contains(out, "<shares>") {
		t.Fatalf("insert: %v\n%s", err, out)
	}
	only := "<domain>\n  <vcpu>2</vcpu>\n  <cputune>\n    <global_quota>50000</global_quota>\n    <global_period>100000</global_period>\n  </cputune>\n  <os/>\n</domain>"
	out, err = PatchInactiveCPUTune(only, 0, 0)
	if err != nil || strings.Contains(out, "cputune") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	out, _ = PatchInactiveCPUTune(tuneBase, 0, 0)
	if !strings.Contains(out, "vcpupin") || strings.Contains(out, "quota") || strings.Contains(out, "shares") {
		t.Errorf("clear kept wrong set:\n%s", out)
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
	if !ok || strings.Count(out, "<bandwidth>") != 2 || !strings.Contains(out, "average='1000'") {
		t.Fatalf("set: ok=%v\n%s", ok, out)
	}
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

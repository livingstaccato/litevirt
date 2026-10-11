package e2e

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The noisy-neighbour controls against a real hypervisor. tests/fleet injects
// internal/libvirtfake, which only models the XML edit; whether libvirt accepts
// the cputune global quota, the scheduler write reaches the cgroup of a running
// guest, the weight lands in cpu.weight, and the <bandwidth> shapes the tap and
// survives a migration is only knowable here. Every assertion reads libvirt
// (virsh), the cgroup or tc, not litevirt's report of what it did.
//
// Runs on a cluster node (virsh is local); skips elsewhere.

var schedKV = regexp.MustCompile(`^\s*([a-z_]+)\s*:\s*(-?\d+)\s*$`)

// virshSched returns `virsh schedinfo` as a map. config selects the persistent
// definition rather than the running domain.
func virshSched(t *testing.T, domain string, config bool) map[string]string {
	t.Helper()
	args := []string{"-c", "qemu:///system", "schedinfo", domain}
	if config {
		args = append(args, "--config")
	}
	out, err := exec.Command("virsh", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh %v: %v\n%s", args, err, out)
	}
	return parseSched(string(out))
}

func parseSched(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if m := schedKV.FindStringSubmatch(line); m != nil {
			got[m[1]] = m[2]
		}
	}
	return got
}

// virshIfaceRate returns the inbound/outbound average libvirt reports for a
// NIC, live or in the persistent config.
func virshIfaceRate(t *testing.T, domain, mac string, config bool) (in, out string) {
	t.Helper()
	args := []string{"-c", "qemu:///system", "domiftune", domain, mac}
	if config {
		args = append(args, "--config")
	}
	b, err := exec.Command("virsh", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh %v: %v\n%s", args, err, b)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[1] == ":" {
			switch f[0] {
			case "inbound.average":
				in = f[2]
			case "outbound.average":
				out = f[2]
			}
		}
	}
	return in, out
}

func wantSched(t *testing.T, when string, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: schedinfo %s = %q, want %q (all: %v)", when, k, got[k], v, got)
		}
	}
}

// domainCgroupFile reads a control file from the domain's cgroup (cgroup v2),
// or "" when the host has no such cgroup layout. The scope name escapes the
// VM name's dashes, so the pattern wildcards them.
// localV2 reports whether this host runs the unified cgroup hierarchy.
func localV2() bool { return fileExists("/sys/fs/cgroup/cgroup.controllers") }

// remoteV2 reports whether target runs the unified cgroup hierarchy.
func remoteV2(t *testing.T, target string) bool {
	t.Helper()
	return exec.Command("timeout", "30", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", target,
		"test -e /sys/fs/cgroup/cgroup.controllers").Run() == nil
}

// hostShares is the <shares> a weight renders as on a host of that cgroup
// version: unchanged on v2, scaled by 1024/100 (floor 2) on v1.
func hostShares(v2 bool, weight int) int {
	if v2 {
		return weight
	}
	v := int(math.Round(float64(weight) * 1024 / 100))
	if v < 2 {
		v = 2
	}
	return v
}

func domainCgroupFile(domain, file string) string {
	pat := "/sys/fs/cgroup/machine.slice/machine-qemu*" + strings.ReplaceAll(domain, "-", "*") + "*.scope/" + file
	m, _ := filepath.Glob(pat)
	if len(m) == 0 {
		return ""
	}
	b, err := os.ReadFile(m[0])
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// tapOf returns the host tap device of a domain's first NIC.
func tapOf(t *testing.T, domain string) string {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "domiflist", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh domiflist: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 5 && strings.Count(f[len(f)-1], ":") == 5 {
			return f[0]
		}
	}
	return ""
}

func TestVM_NoisyNeighbourLimits_AppliedLiveAndPersisted(t *testing.T) {
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node")
	}
	requireImage(t)
	name := uniqueName("limits")
	host := hostWithCapacity(t, 2, 1024)
	if host != localHost {
		t.Skipf("no local capacity (placed on %s); virsh assertions need the local host", host)
	}
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	// A 1-core cap is 100000us of CPU per 100000us period for the WHOLE guest;
	// the weight is cgroup v2's cpu.weight (default 100).
	runWithLimits(t, name, host)
	wantSched(t, "at create", virshSched(t, name, false),
		map[string]string{"cpu_shares": strconv.Itoa(hostShares(localV2(), 200)), "global_period": "100000", "global_quota": "100000"})
	// cgroup v2: the weight is passed through unconverted; cgroup v1 reads
	// cpu.shares instead, scaled by 1024/100.
	if got := domainCgroupFile(name, "cpu.weight"); got != "" && got != "200" {
		t.Errorf("cgroup cpu.weight = %q, want 200 (the weight is passed through unconverted)", got)
	}
	if got := domainCgroupFile(name, "cpu.max"); got != "" && got != "100000 100000" {
		t.Errorf("cgroup cpu.max = %q, want \"100000 100000\" (a whole-domain cap)", got)
	}

	macs := domIfaceMACs(t, name)
	if len(macs) == 0 {
		t.Fatal("VM has no NIC to rate-limit")
	}

	// Change everything on the RUNNING guest: no stop, same qemu process.
	pid := qemuPID(name)
	lv(t, "update", name, "--cpu-limit", "1.5", "--cpu-shares", "400", "--nic-rate", "0=4")
	if got := qemuPID(name); pid == "" || got != pid {
		t.Errorf("qemu pid %q -> %q: a limit change restarted the guest", pid, got)
	}
	live := map[string]string{"cpu_shares": strconv.Itoa(hostShares(localV2(), 400)), "global_period": "100000", "global_quota": "150000"}
	wantSched(t, "live", virshSched(t, name, false), live)
	wantSched(t, "config", virshSched(t, name, true), live) // a reboot keeps it
	if got := domainCgroupFile(name, "cpu.max"); got != "" && got != "150000 100000" {
		t.Errorf("cgroup cpu.max = %q, want \"150000 100000\"", got)
	}
	// 4 MB/s is 4000 KB/s (libvirt's unit), live and persistent.
	for _, config := range []bool{false, true} {
		if in, out := virshIfaceRate(t, name, macs[0], config); in != "4000" || out != "4000" {
			t.Errorf("domiftune (config=%v) = in %s out %s, want 4000/4000", config, in, out)
		}
	}
	// ...and the tap is actually shaped: tc shows the class at 4 MB/s = 32Mbit,
	// which is what pins libvirt's kilobyte as 1000 bytes.
	if tap := tapOf(t, name); tap != "" {
		if out, err := exec.Command("tc", "class", "show", "dev", tap).CombinedOutput(); err == nil &&
			!strings.Contains(string(out), "32Mbit") {
			t.Errorf("tc class show dev %s lacks a 32Mbit class for a 4 MB/s cap:\n%s", tap, out)
		}
	}
	if out := lv(t, "inspect", name); !strings.Contains(out, "cpuLimit") || !strings.Contains(out, "rateMbSec") {
		t.Errorf("lv inspect does not show the limits:\n%s", out)
	}

	// Removal. Clearing the weight writes the host's DEFAULT back, never a
	// leftover or a hard-coded number: 100 on a cgroup v2 host.
	lv(t, "update", name, "--cpu-limit", "0", "--cpu-shares", "0", "--nic-rate", "0=0")
	got := virshSched(t, name, false)
	if q := got["global_quota"]; q != "-1" && q != "0" {
		t.Errorf("cap not removed: global_quota = %q", q)
	}
	if want := strconv.Itoa(hostShares(localV2(), 100)); got["cpu_shares"] != want {
		t.Errorf("clearing cpu-shares left cpu_shares = %q, want this host's default %s", got["cpu_shares"], want)
	}
	if in, out := virshIfaceRate(t, name, macs[0], false); in != "0" && in != "" || out != "0" && out != "" {
		t.Errorf("NIC cap not removed: in %q out %q", in, out)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// A live migration carries the definition, so the destination's guest must run
// under the same cap, weight and rate. Needs a second ACTIVE host reachable by
// ssh from here; skips only when there is none. Once there is one, a failure to
// migrate or to read the destination is a failure, not a skip.
func TestVM_NoisyNeighbourLimits_SurviveMigration(t *testing.T) {
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node")
	}
	requireImage(t)
	var target string
	for _, line := range strings.Split(lv(t, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) > 3 && strings.Contains(line, "ACTIVE") && f[0] != localHost {
			target = f[0]
			break
		}
	}
	if target == "" {
		t.Skip("needs a second active host")
	}
	name := uniqueName("limmig")
	host := hostWithCapacity(t, 2, 1024)
	if host != localHost {
		t.Skipf("no local capacity (placed on %s)", host)
	}
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })
	runWithLimits(t, name, host)
	lv(t, "update", name, "--nic-rate", "0=2")
	if out, err := lvErr(t, "migrate", name, target); err != nil {
		t.Fatalf("migration to %s failed: %v\n%s", target, err, out)
	}
	waitVM(t, name, "RUNNING", 3*time.Minute)

	out, err := exec.Command("timeout", "30", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", target,
		"virsh -c qemu:///system schedinfo "+name+"; virsh -c qemu:///system dumpxml "+name).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot read libvirt on %s: %v\n%s", target, err, out)
	}
	s := string(out)
	// The destination definition carries the TARGET's scale for the weight.
	for _, want := range []string{fmt.Sprintf(`cpu_shares\s*:\s*%d`, hostShares(remoteV2(t, target), 200)), `global_quota\s*:\s*100000`} {
		if !regexp.MustCompile(want).MatchString(s) {
			t.Errorf("destination domain lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "<inbound average='2000'") {
		t.Errorf("destination NIC lost its 2 MB/s cap:\n%s", s)
	}
}

// runWithLimits creates the test VM with a cap and a weight, skipping when the
// cluster refuses limits because the release token has not latched (a node is still
// on an older build) — a rollout state, not a defect.
func runWithLimits(t *testing.T, name, host string) {
	t.Helper()
	out, err := lvErr(t, "run", "--name", name, "--image", testImage,
		"--cpu", "2", "--memory", "1024", "--disk", "5G", "--host", host,
		"--cpu-limit", "1", "--cpu-shares", "200")
	if err != nil {
		if strings.Contains(out+err.Error(), "cluster upgrade") {
			t.Skipf("the release token has not latched (roll every node to this build first): %v", err)
		}
		t.Fatalf("lv run with limits: %v\n%s", err, out)
	}
}

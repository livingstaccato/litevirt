package e2e

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The noisy-neighbour controls against a real hypervisor. tests/fleet injects
// internal/libvirtfake, which only models the XML edit; whether libvirt accepts
// the cputune period/quota, the scheduler write reaches the cgroup of a running
// guest, and the <bandwidth> survives a migration is only knowable here. Every
// assertion reads libvirt (virsh), not litevirt's report of what it did.
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
	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if m := schedKV.FindStringSubmatch(line); m != nil {
			got[m[1]] = m[2]
		}
	}
	return got
}

// virshIfaceRate returns the inbound/outbound average (KiB/s) libvirt reports
// for a NIC, live or in the persistent config.
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

	// 1 core over 2 vCPUs: 50000us per 100000us period per vCPU.
	runWithLimits(t, name, host)
	waitVM(t, name, "RUNNING", 2*time.Minute)
	wantSched(t, "at create", virshSched(t, name, false),
		map[string]string{"cpu_shares": "2048", "vcpu_period": "100000", "vcpu_quota": "50000"})

	macs := domIfaceMACs(t, name)
	if len(macs) == 0 {
		t.Fatal("VM has no NIC to rate-limit")
	}

	// Change everything on the RUNNING guest: no stop, same qemu process.
	pid := qemuPID(name)
	lv(t, "update", name, "--cpu-limit", "1.5", "--cpu-shares", "512", "--nic-rate", "0=4")
	if got := qemuPID(name); pid == "" || got != pid {
		t.Errorf("qemu pid %q -> %q: a limit change restarted the guest", pid, got)
	}
	live := map[string]string{"cpu_shares": "512", "vcpu_period": "100000", "vcpu_quota": "75000"}
	wantSched(t, "live", virshSched(t, name, false), live)
	// ...and in the persistent definition, so a reboot keeps it.
	wantSched(t, "config", virshSched(t, name, true), live)
	// 4 MB/s = 3906 KiB/s, both directions, live and persistent.
	for _, config := range []bool{false, true} {
		if in, out := virshIfaceRate(t, name, macs[0], config); in != "3906" || out != "3906" {
			t.Errorf("domiftune (config=%v) = in %s out %s, want 3906/3906", config, in, out)
		}
	}
	if out := lv(t, "inspect", name); !strings.Contains(out, "cpuLimit") || !strings.Contains(out, "rateMbSec") {
		t.Errorf("lv inspect does not show the limits:\n%s", out)
	}

	// Removal.
	lv(t, "update", name, "--cpu-limit", "0", "--cpu-shares", "0", "--nic-rate", "0=0")
	got := virshSched(t, name, false)
	if q := got["vcpu_quota"]; q != "-1" && q != "0" {
		t.Errorf("cap not removed: vcpu_quota = %q", q)
	}
	if in, out := virshIfaceRate(t, name, macs[0], false); in != "0" && in != "" || out != "0" && out != "" {
		t.Errorf("NIC cap not removed: in %q out %q", in, out)
	}
}

// A live migration carries the definition, so the destination's guest must run
// under the same cap, weight and rate. Needs a second ACTIVE host reachable by
// ssh from here; skips otherwise.
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
	waitVM(t, name, "RUNNING", 2*time.Minute)
	lv(t, "update", name, "--nic-rate", "0=2")
	if out, err := lvErr(t, "migrate", name, target); err != nil {
		t.Skipf("migration to %s not possible here: %v\n%s", target, err, out)
	}
	waitVM(t, name, "RUNNING", 3*time.Minute)

	out, err := exec.Command("timeout", "30", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", target,
		"virsh -c qemu:///system schedinfo "+name+"; virsh -c qemu:///system dumpxml "+name).CombinedOutput()
	if err != nil {
		t.Skipf("cannot ssh to %s to read its libvirt: %v", target, err)
	}
	s := string(out)
	for _, want := range []string{`cpu_shares\s*:\s*2048`, `vcpu_quota\s*:\s*50000`} {
		if !regexp.MustCompile(want).MatchString(s) {
			t.Errorf("destination domain lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "<inbound average='1953'") {
		t.Errorf("destination NIC lost its 2 MB/s cap:\n%s", s)
	}
}

// runWithLimits creates the test VM with a cap and a weight, skipping when the
// cluster refuses limits because vm_limits_v1 has not latched (a node is still
// on an older build) — a rollout state, not a defect.
func runWithLimits(t *testing.T, name, host string) {
	t.Helper()
	out, err := lvErr(t, "run", "--name", name, "--image", testImage,
		"--cpu", "2", "--memory", "1024", "--disk", "5G", "--host", host,
		"--cpu-limit", "1", "--cpu-shares", "2048")
	if err != nil {
		if strings.Contains(out+err.Error(), "cluster upgrade") {
			t.Skipf("vm_limits_v1 has not latched (roll every node to this build first): %v", err)
		}
		t.Fatalf("lv run with limits: %v\n%s", err, out)
	}
}

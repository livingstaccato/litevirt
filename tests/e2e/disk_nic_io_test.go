package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Disk discard, per-disk I/O limits and virtio-net multiqueue, asserted against
// the real hypervisor. tests/fleet injects internal/libvirtfake, whose
// SetDiskIOTune only edits an XML string, so it cannot say whether qemu is
// really throttling the disk or whether libvirt accepted the queue count; this
// reads both back through virsh. It needs the suite to run on a cluster node
// (localMode) for those reads; from elsewhere the CLI assertions carry it.

func virshBlkIOTune(t *testing.T, domain, dev string) map[string]string {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "blkdeviotune", domain, dev).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh blkdeviotune %s %s: %v\n%s", domain, dev, err, out)
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return vals
}

func virshXML(t *testing.T, domain string, inactive bool) string {
	t.Helper()
	args := []string{"-c", "qemu:///system", "dumpxml"}
	if inactive {
		args = append(args, "--inactive")
	}
	out, err := exec.Command("virsh", append(args, domain)...).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh dumpxml %s: %v\n%s", domain, err, out)
	}
	return string(out)
}

func tuneComposeFile(t *testing.T, stack, vm, host, netName string, readIops int) string {
	t.Helper()
	y := fmt.Sprintf(`name: %s
networks:
  %s:
    external: true
vms:
  %s:
    image: %s
    cpu: 2
    memory: 1024
    disks:
      root:
        size: 5G
        discard: unmap
        detect_zeroes: unmap
        iotune:
          read_iops_sec: %d
    network:
      - name: %s
        queues: auto
    placement:
      host: %s
`, stack, netName, vm, testImage, readIops, netName, host)
	f := fmt.Sprintf("/tmp/e2e-tune-%d.yaml", os.Getpid())
	if err := os.WriteFile(f, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f) })
	return f
}

func TestVM_DiskDiscardIOLimitsAndNICQueues(t *testing.T) {
	requireImage(t)
	// The feature is refused until the shared release token has latched
	// (vm_disk_nic_io under release_2026_11_v1). Until then this skips rather
	// than reporting a product defect.

	stack, vm := uniqueName("tune"), uniqueName("tv")
	host := hostWithCapacity(t, 2, 1024)
	netName := uniqueName("tn")
	cleanup(t, func() {
		lvErr(t, "compose", "down", "--name", stack, "-y")
		lvErr(t, "network", "rm", netName, "--force")
		// `network rm` leaves a user-managed bridge behind; remove the one this
		// test created on every host the VM touched.
		removeTestBridge(t, netName)
	})
	lv(t, "network", "create", netName, "--type", "bridge", "--subnet", "172.31.7.0/24", "--dhcp")

	file := tuneComposeFile(t, stack, vm, host, netName, 300)
	if out, err := lvErr(t, "compose", "up", "-f", file, "-y"); err != nil {
		if strings.Contains(out, "cluster upgrade must finish") {
			t.Skipf("disk/NIC tuning is not open on this cluster yet (the release token has not latched): %s", out)
		}
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	waitVM(t, vm, "RUNNING", 2*time.Minute)

	if virshAvailable() {
		x := virshXML(t, vm, false)
		if !strings.Contains(x, "discard='unmap'") {
			t.Errorf("a new VM's root disk on the local store has no discard=unmap:\n%s", x)
		}
		if !strings.Contains(x, "detect_zeroes='unmap'") {
			t.Errorf("detect_zeroes=unmap is not on the root disk:\n%s", x)
		}
		if !strings.Contains(x, "queues='2'") {
			t.Errorf("the NIC has no multiqueue driver:\n%s", x)
		}
		if got := virshBlkIOTune(t, vm, "vda")["read_iops_sec"]; got != "300" {
			t.Errorf("libvirt reports read_iops_sec=%q on vda at create, want 300", got)
		}
	}
	pid := qemuPID(vm)

	// `lv disk-io` throttles the RUNNING disk in place.
	lv(t, "disk-io", vm, "--disk", "root", "--read-iops", "600", "--write-bps", "20M")
	if virshAvailable() {
		got := virshBlkIOTune(t, vm, "vda")
		if got["read_iops_sec"] != "600" || got["write_bytes_sec"] != "20971520" {
			t.Errorf("after lv disk-io the live throttle is %v, want read_iops_sec=600 write_bytes_sec=20971520", got)
		}
		if !strings.Contains(virshXML(t, vm, true), "<read_iops_sec>600</read_iops_sec>") {
			t.Error("the persistent definition did not take the new limit: a restart would drop it")
		}
		if now := qemuPID(vm); pid != "" && now != pid {
			t.Errorf("qemu pid %s → %s: the VM was restarted, so the limit was not applied live", pid, now)
		}
	}

	// Changing the file does the same, in place.
	lv(t, "compose", "up", "-f", tuneComposeFile(t, stack, vm, host, netName, 900), "-y")
	if virshAvailable() {
		if got := virshBlkIOTune(t, vm, "vda")["read_iops_sec"]; got != "900" {
			t.Errorf("after the compose change libvirt reports read_iops_sec=%q, want 900", got)
		}
		if now := qemuPID(vm); pid != "" && now != pid {
			t.Errorf("qemu pid %s → %s: a compose iotune change restarted the VM", pid, now)
		}
	}

	// A restart keeps it, because it is rendered from the spec.
	lv(t, "stop", vm)
	waitVM(t, vm, "STOPPED", time.Minute)
	lv(t, "start", vm)
	waitVM(t, vm, "RUNNING", 2*time.Minute)
	if virshAvailable() {
		if got := virshBlkIOTune(t, vm, "vda")["read_iops_sec"]; got != "900" {
			t.Errorf("after a restart libvirt reports read_iops_sec=%q, want 900", got)
		}
	}

	// A burst: the ceiling and its length reach the live domain.
	lv(t, "disk-io", vm, "--disk", "root", "--write-bps", "10M", "--write-bps-max", "40M", "--burst-seconds", "5")
	if virshAvailable() {
		got := virshBlkIOTune(t, vm, "vda")
		if got["write_bytes_sec"] != "10485760" || got["write_bytes_sec_max"] != "41943040" || got["write_bytes_sec_max_length"] != "5" {
			t.Errorf("burst not applied live: %v", got)
		}
	}

	// A discard really reclaims space: write, delete, fstrim in the guest, and the
	// image's allocation drops. Needs the guest agent and a local-store disk.
	if virshAvailable() {
		path := strings.TrimSpace(virshDiskPath(t, vm, "vda"))
		before := allocatedBytes(t, path)
		if _, err := lvErr(t, "exec", vm, "--", "sh", "-c", "dd if=/dev/urandom of=/var/tmp/fill bs=1M count=64 && sync && rm /var/tmp/fill && fstrim -av"); err != nil {
			t.Logf("guest fstrim step unavailable (no agent?): %v", err)
		} else if after := allocatedBytes(t, path); after > before+(8<<20) {
			t.Errorf("the image still holds %d bytes after the guest freed and trimmed 64 MiB (was %d): discard did not reclaim", after, before)
		}
	}

	lv(t, "disk-io", vm, "--disk", "root", "--clear")
	if virshAvailable() {
		if got := virshBlkIOTune(t, vm, "vda")["read_iops_sec"]; got != "0" {
			t.Errorf("after --clear libvirt reports read_iops_sec=%q, want 0", got)
		}
	}

	// Live migration carries the throttle (libvirt copies the running
	// definition). Skipped on a single-host lab. Runs last because the VM then
	// lives on another host, out of reach of the local virsh reads above.
	if len(hostNames) > 1 {
		target := hostNames[1]
		if target == host {
			target = hostNames[0]
		}
		lv(t, "disk-io", vm, "--disk", "root", "--read-iops", "700")
		// A local-disk VM needs --with-storage. A failure here fails the test: a
		// silent skip would stop checking that migration carries the throttle.
		if out, err := lvErr(t, "migrate", vm, target, "--with-storage"); err != nil {
			t.Fatalf("live migration to %s failed: %v\n%s", target, err, out)
		}
		waitVM(t, vm, "RUNNING", 2*time.Minute)
		if got := lv(t, "inspect", vm); !strings.Contains(got, target) {
			t.Errorf("VM did not land on %s:\n%s", target, got)
		}
		// Read the throttle from libvirt on the destination, not through litevirt.
		out, err := exec.Command("timeout", "30", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", target,
			"virsh -c qemu:///system blkdeviotune "+vm+" vda").CombinedOutput()
		if err != nil {
			t.Fatalf("cannot read libvirt on %s: %v\n%s", target, err, out)
		}
		if !regexp.MustCompile(`(?m)^read_iops_sec\s*:\s*700\s*$`).Match(out) {
			t.Errorf("destination %s lost the read_iops_sec=700 throttle after migration:\n%s", target, out)
		}
	}
}

func virshDiskPath(t *testing.T, domain, dev string) string {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "domblklist", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh domblklist: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == dev {
			return f[1]
		}
	}
	t.Fatalf("no %s in domblklist:\n%s", dev, out)
	return ""
}

// allocatedBytes is what the image file really occupies (du), not its size.
func allocatedBytes(t *testing.T, path string) int64 {
	t.Helper()
	out, err := exec.Command("du", "-B1", "--apparent-size=false", path).CombinedOutput()
	if err != nil {
		out, err = exec.Command("du", "-B1", path).CombinedOutput()
		if err != nil {
			t.Fatalf("du %s: %v\n%s", path, err, out)
		}
	}
	var n int64
	fmt.Sscan(strings.Fields(string(out))[0], &n)
	return n
}

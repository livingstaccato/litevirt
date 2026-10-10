package e2e

import (
	"fmt"
	"os"
	"os/exec"
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
	stack, vm := uniqueName("tune"), uniqueName("tv")
	host := hostWithCapacity(t, 2, 1024)
	netName := uniqueName("tn")
	cleanup(t, func() {
		lvErr(t, "compose", "down", "--name", stack, "-y")
		lvErr(t, "network", "rm", netName, "--force")
	})
	lv(t, "network", "create", netName, "--type", "bridge", "--subnet", "172.31.7.0/24", "--dhcp")

	file := tuneComposeFile(t, stack, vm, host, netName, 300)
	lv(t, "compose", "up", "-f", file, "-y")
	waitVM(t, vm, "RUNNING", 2*time.Minute)

	if virshAvailable() {
		x := virshXML(t, vm, false)
		if !strings.Contains(x, "discard='unmap'") {
			t.Errorf("a new VM's root disk on the local store has no discard=unmap:\n%s", x)
		}
		if !strings.Contains(x, "name='vhost'") || !strings.Contains(x, "queues='2'") {
			t.Errorf("the NIC has no vhost multiqueue driver:\n%s", x)
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

	lv(t, "disk-io", vm, "--disk", "root", "--clear")
	if virshAvailable() {
		if got := virshBlkIOTune(t, vm, "vda")["read_iops_sec"]; got != "0" {
			t.Errorf("after --clear libvirt reports read_iops_sec=%q, want 0", got)
		}
	}
}

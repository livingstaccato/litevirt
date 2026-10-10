package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// USB passthrough, virtio-mem memory hot-add and container host mounts against
// a REAL hypervisor and REAL LXC. tests/fleet runs these paths over
// internal/libvirtfake and a container fake, which record calls; only libvirt
// and the kernel can say whether the guest got the memory, the domain names
// the device, or the container sees the host path read-only.
//
// Every assertion reads virsh, /proc or the container's own view, never
// litevirt's report of what it did. Run on a cluster node (local mode) with:
//
//   - enforcement.usb_mounts_memory: true on EVERY node (else the tests skip
//     with the gate's refusal, rather than fail);
//   - for the container test, LV_E2E_MOUNT_DIR naming a directory under this
//     host's containers.bind_mount_paths.

const gateRefusal = "usb_mounts_memory_v1"

func skipIfGated(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil && strings.Contains(out+err.Error(), gateRefusal) {
		t.Skipf("enforcement.usb_mounts_memory is not on and latched cluster-wide: %s", strings.TrimSpace(out))
	}
}

func virshXML(t *testing.T, domain string, inactive bool) string {
	t.Helper()
	args := []string{"-c", "qemu:///system", "dumpxml", domain}
	if inactive {
		args = append(args, "--inactive")
	}
	out, err := exec.Command("virsh", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh dumpxml %s: %v\n%s", domain, err, out)
	}
	return string(out)
}

var reRequested = regexp.MustCompile(`<requested unit='KiB'>(\d+)</requested>`)

// TestVM_MemoryHotplug_LivePlug: a running VM with a virtio-mem region gains
// memory in place — same qemu process, and libvirt's live AND persistent
// definitions both carry the new plugged size.
func TestVM_MemoryHotplug_LivePlug(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node (local mode)")
	}
	name := uniqueName("memhp")
	host := hostWithCapacity(t, 1, 2048)
	if host != localHost {
		t.Skipf("no capacity on the local host %s", localHost)
	}
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	out, err := lvErr(t, "run", "--name", name, "--image", testImage, "--cpu", "1",
		"--memory", "1024", "--memory-hotplug-max", "2048", "--disk", "5G", "--host", host)
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	waitVM(t, name, "RUNNING", 2*time.Minute)

	x := virshXML(t, name, false)
	if !strings.Contains(x, "model='virtio-mem'") || !strings.Contains(x, "<maxMemory slots=") {
		t.Fatalf("the running domain has no virtio-mem region:\n%s", x)
	}
	pid := qemuPID(name)

	lv(t, "set-memory", name, "1536")
	for _, inactive := range []bool{false, true} {
		m := reRequested.FindStringSubmatch(virshXML(t, name, inactive))
		if m == nil || m[1] != strconv.Itoa(512*1024) {
			t.Fatalf("virtio-mem requested (inactive=%v) = %v; want 524288 KiB plugged", inactive, m)
		}
	}
	if now := qemuPID(name); now == "" || now != pid {
		t.Fatalf("qemu pid %q -> %q: the hot-add restarted the guest", pid, now)
	}
	// Beyond the region is refused, not silently clamped.
	if out, err := lvErr(t, "set-memory", name, "4096"); err == nil {
		t.Fatalf("set-memory above the hot-add maximum succeeded:\n%s", out)
	}
}

// firstHostUSBDevice returns a vendor:product on this host that is not a root
// hub, or "" when there is none.
func firstHostUSBDevice() string {
	matches, _ := filepath.Glob("/sys/bus/usb/devices/*/idVendor")
	for _, v := range matches {
		vendor, err1 := os.ReadFile(v)
		product, err2 := os.ReadFile(filepath.Join(filepath.Dir(v), "idProduct"))
		if err1 != nil || err2 != nil {
			continue
		}
		vs, ps := strings.TrimSpace(string(vendor)), strings.TrimSpace(string(product))
		if vs == "1d6b" { // Linux Foundation root hubs
			continue
		}
		return vs + ":" + ps
	}
	return ""
}

// TestVM_USBPassthrough_Definition: a USB device set on a stopped VM lands in
// libvirt's persistent definition as a usb hostdev, live migration is refused,
// and --clear-usb removes it. The VM is not started with the device, so no
// host device is taken from the host.
func TestVM_USBPassthrough_Definition(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node (local mode)")
	}
	dev := firstHostUSBDevice()
	if dev == "" {
		t.Skip("this host has no USB device other than root hubs")
	}
	name := uniqueName("usb")
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })
	lv(t, "run", "--name", name, "--image", testImage, "--cpu", "1", "--memory", "512", "--disk", "5G", "--host", localHost)
	waitVM(t, name, "RUNNING", 2*time.Minute)
	lv(t, "stop", name)
	waitVM(t, name, "STOPPED", 2*time.Minute)

	out, err := lvErr(t, "update", name, "--usb", dev)
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("update --usb: %v\n%s", err, out)
	}
	vendor, product, _ := strings.Cut(dev, ":")
	x := virshXML(t, name, true)
	if !strings.Contains(x, "type='usb'") || !strings.Contains(x, "<vendor id='0x"+vendor+"'/>") || !strings.Contains(x, "<product id='0x"+product+"'/>") {
		t.Fatalf("the persistent definition has no usb hostdev for %s:\n%s", dev, x)
	}
	if len(hostNames) > 1 {
		other := hostNames[0]
		if other == localHost {
			other = hostNames[1]
		}
		if out, err := lvErr(t, "migrate", name, other, "--cold"); err == nil {
			t.Fatalf("a cold migration of a raw-USB VM succeeded:\n%s", out)
		}
	}
	lv(t, "update", name, "--clear-usb")
	if x := virshXML(t, name, true); strings.Contains(x, "type='usb'") {
		t.Fatalf("--clear-usb left a usb hostdev:\n%s", x)
	}
}

// TestContainer_HostMount_ReadOnlyAndConfined: an admin's bind mount of an
// allowed directory is visible in the container, read-only by default; a
// symlink inside the allowed tree that points out of it is refused at create.
func TestContainer_HostMount_ReadOnlyAndConfined(t *testing.T) {
	dir := os.Getenv("LV_E2E_MOUNT_DIR")
	if dir == "" {
		t.Skip("set LV_E2E_MOUNT_DIR to a directory under this host's containers.bind_mount_paths")
	}
	requireLXC(t)
	marker := filepath.Join(dir, "lv-e2e-marker")
	if err := os.WriteFile(marker, []byte("from-the-host\n"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	defer os.Remove(marker)

	name := uniqueName("ctm")
	cleanup(t, func() { lvErr(t, "ct", "rm", name, "--host", localHost, "--force") })
	out, err := lvErr(t, "ct", "create", name, "--host", localHost, "--mount", dir+":/mnt/host")
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("ct create --mount: %v\n%s", err, out)
	}
	startCT(t, name)
	got := lv(t, "ct", "exec", name, "--host", localHost, "--", "cat", "/mnt/host/lv-e2e-marker")
	if !strings.Contains(got, "from-the-host") {
		t.Fatalf("the container does not see the host file: %q", got)
	}
	if out, err := lvErr(t, "ct", "exec", name, "--host", localHost, "--", "touch", "/mnt/host/written"); err == nil &&
		!strings.Contains(out, "Read-only") {
		if _, serr := os.Stat(filepath.Join(dir, "written")); serr == nil {
			os.Remove(filepath.Join(dir, "written"))
			t.Fatal("a default (read-only) mount was writable from the container")
		}
	}

	link := filepath.Join(dir, "lv-e2e-escape")
	_ = os.Remove(link)
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	defer os.Remove(link)
	esc := uniqueName("ctx")
	cleanup(t, func() { lvErr(t, "ct", "rm", esc, "--host", localHost, "--force") })
	if out, err := lvErr(t, "ct", "create", esc, "--host", localHost, "--mount", link+":/mnt/etc"); err == nil {
		t.Fatalf("a symlink out of the allowed tree was mounted:\n%s", out)
	}
}

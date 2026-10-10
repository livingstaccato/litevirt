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
//   - every host on this release (else the tests skip with the release
//     gate's refusal, rather than fail);
//   - for the container test, LV_E2E_MOUNT_DIR naming a directory under this
//     host's containers.bind_mount_paths.

const gateRefusal = "the cluster upgrade must finish first"

func skipIfGated(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil && strings.Contains(out+err.Error(), gateRefusal) {
		t.Skipf("the cluster is mid-upgrade: %s", strings.TrimSpace(out))
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
	// Unplug back down: libvirt reports what the guest actually gave back
	// (<current>), which litevirt counts until it matches the request.
	lv(t, "set-memory", name, "1024")
	time.Sleep(5 * time.Second)
	if live := virshXML(t, name, false); !strings.Contains(live, "<current unit='KiB'>") {
		t.Errorf("the live virtio-mem device reports no <current> size:\n%s", live)
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
// allowed directory is visible in the container and provably read-only —
// the kernel's mount flags say ro,nosuid,nodev, a write fails with EROFS on a
// directory the container's root could otherwise write, and container root
// cannot remount it read-write. A symlink swapped in while the container is
// stopped refuses the start, and one swapped in while it runs is not followed
// by a reboot from inside it (the LXC start hook mounts from an fd).
func TestContainer_HostMount_ReadOnlyAndConfined(t *testing.T) {
	dir := os.Getenv("LV_E2E_MOUNT_DIR")
	if dir == "" {
		t.Skip("set LV_E2E_MOUNT_DIR to a directory under this host's containers.bind_mount_paths")
	}
	requireLXC(t)
	sub := filepath.Join(dir, "lv-e2e")
	_ = os.RemoveAll(sub)
	if err := os.MkdirAll(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sub)
	// World-writable, so only the read-only mount can refuse a write.
	_ = os.Chmod(sub, 0o777)
	if err := os.WriteFile(filepath.Join(sub, "marker"), []byte("from-the-host\n"), 0o666); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	name := uniqueName("ctm")
	cleanup(t, func() { lvErr(t, "ct", "rm", name, "--host", localHost, "--force") })
	out, err := lvErr(t, "ct", "create", name, "--host", localHost, "--mount", sub+":/mnt/host")
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("ct create --mount: %v\n%s", err, out)
	}
	startCT(t, name)
	if got := lv(t, "ct", "exec", name, "--host", localHost, "--", "cat", "/mnt/host/marker"); !strings.Contains(got, "from-the-host") {
		t.Fatalf("the container does not see the host file: %q", got)
	}
	mi := lv(t, "ct", "exec", name, "--host", localHost, "--", "cat", "/proc/self/mountinfo")
	var line string
	for _, l := range strings.Split(mi, "\n") {
		if f := strings.Fields(l); len(f) > 5 && f[4] == "/mnt/host" {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("/mnt/host is not a mount in the container:\n%s", mi)
	}
	opts := strings.Fields(line)[5]
	for _, want := range []string{"ro", "nosuid", "nodev"} {
		if !strings.Contains(","+opts+",", ","+want+",") {
			t.Errorf("/mnt/host mount options %q lack %s", opts, want)
		}
	}
	out, err = lvErr(t, "ct", "exec", name, "--host", localHost, "--", "touch", "/mnt/host/written")
	if err == nil || !strings.Contains(out, "Read-only file system") {
		t.Errorf("a write to the read-only mount = %v %q; want EROFS", err, out)
	}
	if _, serr := os.Stat(filepath.Join(sub, "written")); serr == nil {
		t.Fatal("a read-only mount was written through")
	}
	if out, err := lvErr(t, "ct", "exec", name, "--host", localHost, "--", "mount", "-o", "remount,rw", "/mnt/host"); err == nil {
		t.Fatalf("container root remounted the host mount read-write:\n%s", out)
	}

	// While it runs, swap the mounted directory for a symlink to /etc, then
	// reboot from inside: the start hook must not follow it.
	_ = os.Rename(sub, sub+".old")
	defer os.RemoveAll(sub + ".old")
	if err := os.Symlink("/etc", sub); err != nil {
		t.Fatal(err)
	}
	_, _ = lvErr(t, "ct", "exec", name, "--host", localHost, "--", "reboot")
	time.Sleep(10 * time.Second)
	if got, err := lvErr(t, "ct", "exec", name, "--host", localHost, "--", "ls", "/mnt/host"); err == nil && strings.Contains(got, "passwd") {
		t.Fatalf("an in-container reboot followed a swapped-in symlink to /etc:\n%s", got)
	}

	// Stopped, the swapped tree refuses the start outright.
	_, _ = lvErr(t, "ct", "stop", name, "--host", localHost)
	waitCT(t, name, "stopped", 90*time.Second)
	if out, err := lvErr(t, "ct", "start", name, "--host", localHost); err == nil {
		t.Fatalf("a container whose mount source became a symlink started:\n%s", out)
	}
	_ = os.Remove(sub)

	// A symlink out of the allowed tree is refused at create.
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

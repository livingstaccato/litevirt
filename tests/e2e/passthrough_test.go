package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
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
//   - for the device test, LV_E2E_BLOCK_DEVICE naming a spare block device
//     listed in this host's containers.device_paths, holding nothing the
//     host uses (a scratch virtio disk on a lab node).

const gateRefusal = "the cluster upgrade must finish first"

func skipIfGated(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil && strings.Contains(out+err.Error(), gateRefusal) {
		t.Skipf("the cluster is mid-upgrade: %s", strings.TrimSpace(out))
	}
}

// virshXML is in disk_nic_io_test.go (same helper; both branches defined it).

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

// usbHostdev matches a USB passthrough device, `<hostdev mode='subsystem'
// type='usb' ...>`, and nothing else: a bare "type='usb'" also matches the xhci
// `<controller type='usb'>` every domain with a USB bus carries, so it cannot
// tell a device that is there from one that was cleared.
var usbHostdev = regexp.MustCompile(`<hostdev\b[^>]*\btype='usb'`)

// TestUsbHostdevPattern pins usbHostdev against the two elements libvirt
// emits. Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestUsbHostdevPattern(t *testing.T) {
	const ctrl = "<controller type='usb' index='0' model='qemu-xhci'/>\n"
	const dev = "<hostdev mode='subsystem' type='usb' managed='yes'>\n<source><vendor id='0x1234'/></source>\n</hostdev>\n"
	if usbHostdev.MatchString(ctrl) {
		t.Error("the xhci controller was taken for a hostdev")
	}
	if !usbHostdev.MatchString(ctrl + dev) {
		t.Error("a usb hostdev was not found")
	}
	if usbHostdev.MatchString("<hostdev mode='subsystem' type='pci' managed='yes'><source/></hostdev>" + ctrl) {
		t.Error("a pci hostdev was taken for a usb one")
	}
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
	if !usbHostdev.MatchString(x) || !strings.Contains(x, "<vendor id='0x"+vendor+"'/>") || !strings.Contains(x, "<product id='0x"+product+"'/>") {
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
	if x := virshXML(t, name, true); usbHostdev.MatchString(x) {
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
	// Refused, not merely unmounted: the hook failed the reboot's start, so
	// LXC left the container stopped, and the refusal is in the system log.
	if st, err := exec.Command("lxc-info", "-n", name, "-sH").CombinedOutput(); err != nil || strings.TrimSpace(string(st)) != "STOPPED" {
		t.Errorf("after the refused in-container reboot the container is %q (%v); want STOPPED", strings.TrimSpace(string(st)), err)
	}
	if jl, err := exec.Command("journalctl", "-t", "litevirt-lxc-hook", "--since", "-5min", "--no-pager", "-o", "cat").CombinedOutput(); err != nil ||
		!strings.Contains(string(jl), name+": refusing to start") {
		t.Errorf("the system log holds no refusal for %s (%v):\n%s", name, err, jl)
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

// rdevOf is a device node's device number.
func rdevOf(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode()&os.ModeDevice == 0 {
		t.Fatalf("%s is not a device node", p)
	}
	return uint64(st.Rdev)
}

// deviceHolders lists the pids, on this host, with an fd open on the device
// whose number is rdev (fds are stat'ed, so a node at any path counts).
func deviceHolders(rdev uint64) []string {
	var out []string
	pids, _ := os.ReadDir("/proc")
	for _, p := range pids {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		for _, fd := range fds {
			fi, err := os.Stat(filepath.Join("/proc", p.Name(), "fd", fd.Name()))
			if err != nil || fi.Mode()&os.ModeDevice == 0 {
				continue
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Rdev) == rdev {
				out = append(out, p.Name())
				break
			}
		}
	}
	return out
}

// containerInitPid is the host pid of name's init, or "" when it has none
// (not running).
func containerInitPid(t *testing.T, name string) string {
	t.Helper()
	b, err := exec.Command("lxc-info", "-n", name, "-pH").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// TestContainer_GrantedBlockDeviceSurvivesInContainerReboot (R3-I2): a
// container whose own process holds its granted block device open keeps the
// grant across the once-a-minute policy refresh, and a reboot from inside it
// more than a minute after its start comes back RUNNING — the refresh judges
// what the device is, never who holds it, and the start hook's pre-start
// judgment runs after the container's old processes are gone.
func TestContainer_GrantedBlockDeviceSurvivesInContainerReboot(t *testing.T) {
	dev := os.Getenv("LV_E2E_BLOCK_DEVICE")
	if dev == "" {
		t.Skip("set LV_E2E_BLOCK_DEVICE to a spare block device listed in this host's containers.device_paths")
	}
	requireLXC(t)
	rdev := rdevOf(t, dev)
	name := uniqueName("ctd")
	cleanup(t, func() { lvErr(t, "ct", "rm", name, "--host", localHost, "--force") })
	// Privileged, so container root may open the node (an unprivileged
	// container's root is "other" to a root:disk 0660 node).
	out, err := lvErr(t, "ct", "create", name, "--host", localHost, "--privileged", "--device", dev)
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("ct create --device: %v\n%s", err, out)
	}
	startCT(t, name)
	if len(deviceHolders(rdev)) != 0 {
		t.Fatalf("%s is held open on the host before the container opened it: %v", dev, deviceHolders(rdev))
	}
	lv(t, "ct", "exec", name, "--host", localHost, "--", "sh", "-c",
		"nohup sh -c 'exec 3<"+dev+"; exec sleep 3600' >/dev/null 2>&1 &")
	deadline := time.Now().Add(15 * time.Second)
	for len(deviceHolders(rdev)) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	if len(deviceHolders(rdev)) == 0 {
		t.Fatalf("no process holds %s after the container opened it", dev)
	}

	// Past at least one policy refresh (once a minute).
	time.Sleep(75 * time.Second)
	pol, err := os.ReadFile("/run/litevirt/lxc-hook-policy/" + name + ".json")
	if err != nil {
		t.Fatalf("read %s's hook policy: %v", name, err)
	}
	if !strings.Contains(string(pol), `"Source":"`+dev+`"`) {
		t.Fatalf("the refresh revoked the device %s its container holds open; policy:\n%s", dev, pol)
	}

	// The container's boot: the host pid of its init. A container shares the
	// host's kernel, so /proc/sys/kernel/random/boot_id is the host's and does
	// not change; a new init does, and only a reboot starts one.
	boot := containerInitPid(t, name)
	if boot == "" {
		t.Fatalf("%s has no init pid before the reboot", name)
	}
	since := time.Now().Add(-time.Second).Format("2006-01-02 15:04:05")
	if out, err := lvErr(t, "ct", "exec", name, "--host", localHost, "--", "reboot"); err != nil {
		t.Logf("reboot from inside %s returned %v (the exec may lose its session as init goes): %s", name, err, out)
	}
	var st, after string
	deadline = time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		b, _ := exec.Command("lxc-info", "-n", name, "-sH").CombinedOutput()
		st = strings.TrimSpace(string(b))
		if after = containerInitPid(t, name); st == "RUNNING" && after != "" && after != boot {
			break
		}
	}
	jl, _ := exec.Command("journalctl", "-t", "litevirt-lxc-hook", "--since", since, "--no-pager", "-o", "cat").CombinedOutput()
	if after == boot {
		t.Fatalf("the container did not reboot: its init is still pid %s (state %q); the test proves nothing. hook log:\n%s", boot, st, jl)
	}
	if st != "RUNNING" {
		t.Fatalf("after an in-container reboot the container is %q; want RUNNING. hook log:\n%s", st, jl)
	}
	if strings.Contains(string(jl), name+": refusing to start") {
		t.Errorf("the hook refused the reboot's start:\n%s", jl)
	}
	if got := lv(t, "ct", "exec", name, "--host", localHost, "--", "sh", "-c", "test -b "+dev+" && echo present"); !strings.Contains(got, "present") {
		t.Errorf("after the reboot the container has no %s: %q", dev, got)
	}
}

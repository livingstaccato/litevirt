package vfio

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// kernelFS models how the PCI core answers the sysfs writes Bind and Unbind make,
// for one device. memFS only records a write; kernelFS applies it the way the
// kernel does, which is what the lab caught Unbind getting wrong (V1, igb VF on
// kernel 6.8):
//
//   - driver_override: a ZERO-LENGTH write is a no-op (sysfs_kf_write returns
//     before the store runs when count is 0). Otherwise the value up to the first
//     newline is the override, and an empty one clears it. A cleared override
//     reads back as "(null)".
//   - A driver MATCHES the device when the override names it, or, with no
//     override, when it is the device's native driver or holds a dynamic ID for
//     the device's vendor:device (new_id, or the kernel's vfio-pci.ids=).
//   - <dev>/driver/unbind detaches the bound driver.
//   - drivers/<drv>/bind: ENOENT when the driver is not loaded, EBUSY when the
//     device is bound, ENODEV when the driver does not match, EINVAL when the
//     driver's probe refuses the device.
//   - drivers_probe tries the loaded drivers in REGISTRATION order (the bus
//     klist order, __device_attach) and binds the first that matches and does
//     not refuse; it is a no-op on a bound device.
//   - drivers/<drv>/new_id adds a dynamic ID and attaches an unbound device that
//     now matches; drivers/<drv>/remove_id drops one (ENODEV if absent).
type kernelFS struct {
	*memFS
	addr     string
	id       string          // "vvvv dddd", as new_id/remove_id take it
	native   string          // the driver whose own ID table matches ("" = none)
	order    []string        // loaded drivers, in registration order
	override string          // "" = (null)
	dynids   map[string]bool // "drv id" -> a dynamic ID is present
	refuse   map[string]bool // driver whose probe rejects the device
	log      []string        // every write, in order: "path=data"
	onWrite  func(path string)
	// stickyOverride makes every override write a no-op, to model a kernel that
	// does not honour the clear at all.
	stickyOverride bool
	// absent models a device that is gone from sysfs (a VF that did not come back
	// after a reboot, a pulled card): every path under it is ENOENT.
	absent bool
}

func (k *kernelFS) gone(path string) error {
	if k.absent && strings.HasPrefix(path, k.devPath()+"/") {
		return &fs.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
	}
	return nil
}

func (k *kernelFS) Readlink(path string) (string, error) {
	if err := k.gone(path); err != nil {
		return "", err
	}
	return k.memFS.Readlink(path)
}

func newKernelFS(addr, native, bound, override string, loaded ...string) *kernelFS {
	m := newMemFS()
	m.addDevice(addr, "0x8086", "0x10ca", bound)
	return &kernelFS{memFS: m, addr: addr, id: "8086 10ca", native: native, order: loaded,
		override: override, dynids: map[string]bool{}, refuse: map[string]bool{}}
}

func (k *kernelFS) devPath() string { return filepath.Join(sysDevices, k.addr) }

func (k *kernelFS) loaded(drv string) bool {
	for _, d := range k.order {
		if d == drv {
			return true
		}
	}
	return false
}

func (k *kernelFS) matches(drv string) bool {
	if k.override != "" {
		return k.override == drv
	}
	return drv == k.native || k.dynids[drv+" "+k.id]
}

func (k *kernelFS) driver() string {
	d, err := k.memFS.Readlink(k.devPath() + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(d)
}

// wrote reports whether a write to a path ending in suffix happened.
func (k *kernelFS) wrote(suffix string) bool {
	for _, w := range k.log {
		p, _, _ := strings.Cut(w, "=")
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

func (k *kernelFS) ReadFile(path string) ([]byte, error) {
	if err := k.gone(path); err != nil {
		return nil, err
	}
	if path == k.devPath()+"/driver_override" {
		if k.override == "" {
			return []byte("(null)\n"), nil
		}
		return []byte(k.override + "\n"), nil
	}
	return k.memFS.ReadFile(path)
}

func (k *kernelFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	k.log = append(k.log, path+"="+string(data))
	if k.onWrite != nil {
		k.onWrite(path)
	}
	if err := k.gone(path); err != nil {
		return err
	}
	if err := k.memFS.WriteFile(path, data, perm); err != nil {
		return err // injected failure
	}
	const drivers = "/sys/bus/pci/drivers/"
	val := strings.TrimSpace(string(data))
	switch {
	case path == k.devPath()+"/driver_override":
		if len(data) == 0 || k.stickyOverride {
			return nil
		}
		v, _, _ := strings.Cut(string(data), "\n")
		k.override = v
	case path == k.devPath()+"/driver/unbind":
		if k.driver() == "" {
			return syscall.ENODEV
		}
		k.memFS.setDriver(k.addr, "")
	case path == "/sys/bus/pci/drivers_probe":
		if k.driver() != "" {
			return nil
		}
		for _, d := range k.order {
			if k.matches(d) && !k.refuse[d] {
				k.memFS.setDriver(k.addr, d)
				break
			}
		}
	case strings.HasPrefix(path, drivers):
		drv, attr, _ := strings.Cut(strings.TrimPrefix(path, drivers), "/")
		if !k.loaded(drv) {
			return syscall.ENOENT
		}
		switch attr {
		case "bind":
			if k.driver() != "" {
				return syscall.EBUSY
			}
			if !k.matches(drv) {
				return syscall.ENODEV
			}
			if k.refuse[drv] {
				return syscall.EINVAL
			}
			k.memFS.setDriver(k.addr, drv)
		case "new_id":
			k.dynids[drv+" "+val] = true
			if k.driver() == "" && k.matches(drv) && !k.refuse[drv] {
				k.memFS.setDriver(k.addr, drv)
			}
		case "remove_id":
			if !k.dynids[drv+" "+val] {
				return syscall.ENODEV
			}
			delete(k.dynids, drv+" "+val)
		}
	}
	return nil
}

// recordPath returns a fresh per-test host-driver record path.
func recordPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), HostDriversFileName)
}

func readRecord(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]string{}
	}
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("record %s is not an address→driver map: %v (%s)", path, err, b)
	}
	return m
}

func writeRecord(t *testing.T, path string, m map[string]string) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUnbind_ReturnsDeviceToHostDriver is the lab V1 case: an igb VF on vfio-pci
// with driver_override=vfio-pci, released after the VM let go of it. Whatever
// driver the caller names — the original one, the "vfio-pci" an inventory rescan
// records, or none — the device must end on igbvf with the override cleared. With
// a zero-length clear the override survives, the explicit igbvf bind is refused
// (ENODEV), and drivers_probe hands the device straight back to vfio-pci.
func TestUnbind_ReturnsDeviceToHostDriver(t *testing.T) {
	for _, restore := range []string{"igbvf", "vfio-pci", ""} {
		t.Run("restore="+restore, func(t *testing.T) {
			addr := "0000:01:10.0"
			k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
			defer SetFS(k)()

			if err := Unbind(addr, restore); err != nil {
				t.Fatalf("Unbind: %v", err)
			}
			if got := k.driver(); got != "igbvf" {
				t.Fatalf("driver = %q, want igbvf", got)
			}
			if k.override != "" {
				t.Fatalf("driver_override = %q, want cleared", k.override)
			}
		})
	}
}

// TestBindUnbind_RoundTrip binds a VF the way an attach does and releases it the
// way a detach does, with the restore driver the inventory holds by then
// ("vfio-pci"). The device must come back to igbvf with no override, and Bind
// must not have added a vfio-pci dynamic ID, which would let vfio-pci claim every
// sibling VF with the same vendor:device.
func TestBindUnbind_RoundTrip(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf", "vfio-pci")
	defer SetFS(k)()

	prev, err := Bind(addr)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if prev != "igbvf" || k.driver() != "vfio-pci" || k.override != "vfio-pci" {
		t.Fatalf("after Bind: prev=%q driver=%q override=%q, want igbvf/vfio-pci/vfio-pci", prev, k.driver(), k.override)
	}
	if k.wrote("vfio-pci/new_id") {
		t.Fatal("Bind wrote vfio-pci/new_id; driver_override alone must claim the device")
	}

	if err := Unbind(addr, "vfio-pci"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "igbvf" || k.override != "" {
		t.Fatalf("after Unbind: driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}

// TestUnbind_OverrideNotClearedFailsBeforeUnbinding: when the kernel still
// reports the override after the clear, Unbind must stop with a clear error and
// leave the device on vfio-pci, not unbind it into a probe that re-claims it.
func TestUnbind_OverrideNotClearedFailsBeforeUnbinding(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	k.stickyOverride = true
	defer SetFS(k)()

	err := Unbind(addr, "igbvf")
	if err == nil || !strings.Contains(err.Error(), "driver_override") {
		t.Fatalf("Unbind error = %v, want a driver_override error", err)
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci (untouched)", k.driver())
	}
	if k.wrote("/driver/unbind") {
		t.Fatal("Unbind unbound the device although the override was still set")
	}
}

// TestUnbind_LeftWithoutDriver: a named host driver that cannot bind and a
// reprobe that finds nothing leaves the device driverless, which Unbind reports
// as a failure. With no driver named, driverless is the device's normal state on
// that host and is accepted.
func TestUnbind_LeftWithoutDriver(t *testing.T) {
	addr := "0000:01:10.0"

	k := newKernelFS(addr, "", "vfio-pci", "vfio-pci", "vfio-pci") // igbvf not loaded
	restore := SetFS(k)
	err := Unbind(addr, "igbvf")
	restore()
	if err == nil || !strings.Contains(err.Error(), "no driver") {
		t.Fatalf("Unbind(igbvf) error = %v, want a left-with-no-driver failure", err)
	}
	if k.driver() != "" || k.override != "" {
		t.Fatalf("driver=%q override=%q, want released and cleared", k.driver(), k.override)
	}

	k = newKernelFS(addr, "", "vfio-pci", "vfio-pci", "vfio-pci")
	defer SetFS(k)()
	if err := Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind(\"\") with no host driver: %v", err)
	}
}

// TestBind_FailureRestoresPreviousDriver: vfio-pci is not loaded, so the bind
// cannot happen. Bind has already set the override and taken the device off
// igbvf; it must put both back rather than leave a driverless device that the
// next probe gives to vfio-pci.
func TestBind_FailureRestoresPreviousDriver(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf")
	defer SetFS(k)()

	if _, err := Bind(addr); err == nil {
		t.Fatal("Bind succeeded without vfio-pci loaded")
	}
	if k.driver() != "igbvf" || k.override != "" {
		t.Fatalf("after failed Bind: driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}

// ── Round 1: the host-driver record (I1) and the minor findings ──

// TestHost_RecordedDriverBeatsAnOldBuildsDynamicID is review I1 scenario B.
// vfio-pci holds a dynamic ID for the VF's vendor:device (a new_id someone
// wrote), and vfio-pci registered before igbvf. A reprobe hands the VF to
// vfio-pci every time, and the inventory's restore driver is "vfio-pci" (a rescan
// saw it bound). The driver Bind recorded must be bound explicitly, which matches
// on igbvf's own ID table whatever the probe order or dynamic IDs say.
func TestHost_RecordedDriverBeatsAnOldBuildsDynamicID(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true // a new_id someone wrote
	defer SetFS(k)()
	h := HostAt(recordPath(t))

	if _, err := h.Bind(addr); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := h.Unbind(addr, "vfio-pci"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "igbvf" || k.override != "" {
		t.Fatalf("after Unbind: driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}

// TestHost_RecordIsWrittenBeforeTheBindAndDroppedAfterRelease: the record has to
// exist before the device leaves its host driver, or a crash in between loses
// the only copy of it. It is a plain address → driver map, and a verified release
// removes the entry.
func TestHost_RecordIsWrittenBeforeTheBindAndDroppedAfterRelease(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf", "vfio-pci")
	defer SetFS(k)()
	path := recordPath(t)
	h := HostAt(path)

	var atUnbind map[string]string
	k.onWrite = func(p string) {
		if p == k.devPath()+"/driver/unbind" && atUnbind == nil {
			atUnbind = readRecord(t, path)
		}
	}
	if _, err := h.Bind(addr); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if atUnbind[addr] != "igbvf" {
		t.Fatalf("record when the host driver was unbound = %v, want %s → igbvf", atUnbind, addr)
	}
	if got := readRecord(t, path); got[addr] != "igbvf" {
		t.Fatalf("record after Bind = %v, want %s → igbvf", got, addr)
	}
	k.onWrite = nil
	if err := h.Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if got := readRecord(t, path); len(got) != 0 {
		t.Fatalf("record after a verified release = %v, want empty", got)
	}
}

// TestHost_RecordedDriverThatCannotBindFailsWithoutReprobing: with a recorded
// driver, a failed explicit bind is the answer. A reprobe could hand the device
// to whatever matches first, which is exactly what the record exists to avoid.
func TestHost_RecordedDriverThatCannotBindFailsWithoutReprobing(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "vfio-pci") // igbvf not loaded
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})

	err := HostAt(path).Unbind(addr, "")
	if err == nil || !strings.Contains(err.Error(), "igbvf") {
		t.Fatalf("Unbind error = %v, want a failure naming igbvf", err)
	}
	if k.wrote("drivers_probe") {
		t.Fatal("Unbind reprobed although a host driver was recorded")
	}
}

// TestHost_OperatorVfioIDsDeviceIsLeftOnVfio is review I1 scenario A. The
// operator gave vfio-pci the device with vfio-pci.ids= on the kernel command
// line, so it sits on vfio-pci with NO override before litevirt ever touches it.
// Bind records that it was already there; the release leaves it on vfio-pci and
// succeeds, where an unbind and reprobe could only land it on vfio-pci again.
func TestHost_OperatorVfioIDsDeviceIsLeftOnVfio(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true
	k.files["/proc/cmdline"] = []byte("BOOT_IMAGE=/vmlinuz root=/dev/sda1 intel_iommu=on vfio-pci.ids=8086:10ca\n")
	defer SetFS(k)()
	path := recordPath(t)
	h := HostAt(path)

	prev, err := h.Bind(addr)
	if err != nil || prev != "vfio-pci" {
		t.Fatalf("Bind = %q, %v; want vfio-pci, nil", prev, err)
	}
	if got := readRecord(t, path); got[addr] != "vfio-pci" {
		t.Fatalf("record = %v, want %s → vfio-pci (it was there before litevirt)", got, addr)
	}
	if err := h.Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci (the operator's)", k.driver())
	}
	if k.wrote("/driver/unbind") || k.wrote("remove_id") {
		t.Fatal("the release touched an operator's vfio-pci device")
	}
	if got := readRecord(t, path); len(got) != 0 {
		t.Fatalf("record after release = %v, want empty", got)
	}
}

// TestHost_PreBoundWithOverrideIsNotRecordedAsTheOperators: a device already on
// vfio-pci WITH driver_override=vfio-pci was put there by an override-setter,
// not by the operator's ids=, so Bind must not record it
// as "was on vfio-pci" — that would leave it on vfio-pci forever.
func TestHost_PreBoundWithOverrideIsNotRecordedAsTheOperators(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	defer SetFS(k)()
	path := recordPath(t)
	h := HostAt(path)

	if _, err := h.Bind(addr); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got := readRecord(t, path); got[addr] == "vfio-pci" {
		t.Fatalf("record = %v; an override-bound device was recorded as the operator's", got)
	}
	if err := h.Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "igbvf" {
		t.Fatalf("driver = %q, want igbvf", k.driver())
	}
}

// TestHost_MissingRecordNeverRemovesADynamicID: a device on vfio-pci with
// driver_override=vfio-pci and no record (a record lost, or a host with no
// data directory) whose release lands back on vfio-pci by a dynamic ID that
// is in no config file. litevirt never adds a vfio-pci ID, so the ID is
// someone else's choice: the release leaves the device there and never
// writes remove_id.
//
// Mutation: remove the dynamic ID and reprobe when a device with no record
// lands back on vfio-pci — red.
func TestHost_MissingRecordNeverRemovesADynamicID(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true
	k.files["/proc/cmdline"] = []byte("BOOT_IMAGE=/vmlinuz intel_iommu=on\n")
	defer SetFS(k)()

	if err := HostAt(recordPath(t)).Unbind(addr, "vfio-pci"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.wrote("remove_id") || !k.dynids["vfio-pci "+k.id] {
		t.Fatal("the release removed a vfio-pci dynamic ID litevirt never added")
	}
	if k.driver() != "vfio-pci" || k.override != "" {
		t.Fatalf("driver=%q override=%q, want vfio-pci with the override cleared", k.driver(), k.override)
	}
}

// TestHost_MissingRecordNeverRemovesTheOperatorsIDs: the same shape, but the
// operator's modprobe.d gives vfio-pci the ID. The device belongs on vfio-pci on
// this host, so the release succeeds with it there, and the operator's ID stays.
func TestHost_MissingRecordNeverRemovesTheOperatorsIDs(t *testing.T) {
	for _, tc := range []struct{ name, cmdline, conf string }{
		{name: "cmdline", cmdline: "ro quiet vfio_pci.ids=10de:2204,8086:10ca\n"},
		{name: "modprobe.d", cmdline: "ro quiet\n", conf: "# passthrough\noptions vfio-pci disable_vga=1 ids=8086:10ca\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := "0000:01:10.0"
			k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "vfio-pci", "igbvf")
			k.dynids["vfio-pci "+k.id] = true
			k.files["/proc/cmdline"] = []byte(tc.cmdline)
			if tc.conf != "" {
				k.dirs["/etc/modprobe.d"] = []os.DirEntry{fakeEntry{"vfio.conf"}}
				k.files["/etc/modprobe.d/vfio.conf"] = []byte(tc.conf)
			}
			defer SetFS(k)()

			if err := HostAt(recordPath(t)).Unbind(addr, ""); err != nil {
				t.Fatalf("Unbind: %v", err)
			}
			if k.driver() != "vfio-pci" {
				t.Fatalf("driver = %q, want vfio-pci (the operator's ids=)", k.driver())
			}
			if k.wrote("remove_id") || !k.dynids["vfio-pci "+k.id] {
				t.Fatal("the release removed the operator's vfio-pci ID")
			}
		})
	}
}

// TestBind_SetsTheOverrideBeforeUnbindingTheHostDriver (review M1): with the
// override written first, a probe between the two writes can only bind vfio-pci;
// unbinding first leaves a window in which igbvf, or a dynamic ID, takes it back.
func TestBind_SetsTheOverrideBeforeUnbindingTheHostDriver(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf", "vfio-pci")
	defer SetFS(k)()
	if _, err := Bind(addr); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	override, unbind := -1, -1
	for i, w := range k.log {
		switch {
		case strings.HasPrefix(w, k.devPath()+"/driver_override=vfio-pci") && override < 0:
			override = i
		case strings.HasPrefix(w, k.devPath()+"/driver/unbind=") && unbind < 0:
			unbind = i
		}
	}
	if override < 0 || unbind < 0 || override > unbind {
		t.Fatalf("override written at %d, host driver unbound at %d; want the override first (%v)", override, unbind, k.log)
	}
}

// TestBind_RollbackReportsWhereTheDeviceEnded (review M4): when the bind fails
// and the rollback cannot return the device either, the error must say the
// device was left with no driver rather than only report the bind failure.
func TestBind_RollbackReportsWhereTheDeviceEnded(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf", "vfio-pci")
	k.refuse["vfio-pci"] = true
	k.refuse["igbvf"] = true // its rebind fails too
	defer SetFS(k)()

	_, err := Bind(addr)
	if err == nil {
		t.Fatal("Bind succeeded although vfio-pci refused the device")
	}
	if !strings.Contains(err.Error(), "no driver") {
		t.Fatalf("Bind error = %v, want it to say the device was left with no driver", err)
	}
}

// TestHost_ReleaseUnboundClearsAStaleOverride (review M2): an owned device that
// is not bound but still carries driver_override=vfio-pci (a failed Bind) is
// released by the callers without an Unbind. Its override must be
// cleared and the device reprobed, or the next probe gives it to vfio-pci while
// it is unowned.
func TestHost_ReleaseUnboundClearsAStaleOverride(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "", "vfio-pci", "igbvf", "vfio-pci")
	defer SetFS(k)()

	if err := HostAt(recordPath(t)).ReleaseUnbound(addr); err != nil {
		t.Fatalf("ReleaseUnbound: %v", err)
	}
	if k.override != "" || k.driver() != "igbvf" {
		t.Fatalf("driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}

// TestHost_ReleaseUnboundLeavesACleanDeviceAlone: a device with no override and
// no record is not written to at all, so the "never Unbind a not-bound device"
// guards keep their meaning.
func TestHost_ReleaseUnboundLeavesACleanDeviceAlone(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "", "", "igbvf", "vfio-pci")
	defer SetFS(k)()
	if err := HostAt(recordPath(t)).ReleaseUnbound(addr); err != nil {
		t.Fatalf("ReleaseUnbound: %v", err)
	}
	if len(k.log) != 0 {
		t.Fatalf("ReleaseUnbound wrote %v to a clean device", k.log)
	}
}

// ── Round 2 ──

// TestHost_ReleaseUnboundOfAVanishedDeviceReleasesIt (re-review R1-I1): a device
// that is gone from sysfs — a VF that did not come back after a reboot, a pulled
// card — has nothing to clear. Its release must succeed and drop its record
// entry, as it did before ReleaseUnbound existed; an error here blocks `lv rm` on
// every retry.
func TestHost_ReleaseUnboundOfAVanishedDeviceReleasesIt(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "", "", "igbvf", "vfio-pci")
	k.absent = true
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})

	if err := HostAt(path).ReleaseUnbound(addr); err != nil {
		t.Fatalf("ReleaseUnbound of a vanished device: %v", err)
	}
	if got := readRecord(t, path); len(got) != 0 {
		t.Fatalf("record = %v, want the vanished device's entry dropped", got)
	}
}

// TestHost_NoRecordAndNoOverrideIsLeftOnVfio (re-review R1-M1): a device on
// vfio-pci with no record and NO override was bound by ID, not by litevirt (its
// Bind always sets the override). Whoever bound it — the operator's ids=
// in an initramfs, or a hand-written new_id — owns that choice: the release
// leaves it on vfio-pci and never removes the ID.
func TestHost_NoRecordAndNoOverrideIsLeftOnVfio(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true // added by hand; in no config file
	k.files["/proc/cmdline"] = []byte("ro quiet\n")
	defer SetFS(k)()

	if err := HostAt(recordPath(t)).Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci (bound by ID, not by litevirt)", k.driver())
	}
	if k.wrote("remove_id") || k.wrote("/driver/unbind") {
		t.Fatalf("the release touched a device litevirt did not bind: %v", k.log)
	}
}

// TestHost_ARecordedDeviceNeverRemovesADynamicID (re-review R1-M1): this build
// recorded the device (it had no driver before), so it never wrote a new_id for
// it. A reprobe that lands on vfio-pci by a dynamic ID found someone else's
// choice: the device stays on vfio-pci.
func TestHost_ARecordedDeviceNeverRemovesADynamicID(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true
	k.files["/proc/cmdline"] = []byte("ro quiet\n")
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: ""})

	if err := HostAt(path).Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.wrote("remove_id") || !k.dynids["vfio-pci "+k.id] {
		t.Fatal("the release removed a dynamic ID this build never added")
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci", k.driver())
	}
}

// TestHost_DriverctlPinnedDeviceIsLeftOnVfio (re-review R1-M3): driverctl pins a
// device to vfio-pci with an override it re-applies at boot, recorded in
// /etc/driverctl.d/pci-<addr>. That is the operator's choice: Bind records it as
// such, and the release leaves the device on vfio-pci with driverctl's override
// in place — with or without a record.
func TestHost_DriverctlPinnedDeviceIsLeftOnVfio(t *testing.T) {
	for _, viaBind := range []bool{true, false} {
		t.Run(map[bool]string{true: "recorded-at-bind", false: "no-record"}[viaBind], func(t *testing.T) {
			addr := "0000:01:10.0"
			k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
			k.files["/etc/driverctl.d/pci-"+addr] = []byte("vfio-pci\n")
			defer SetFS(k)()
			path := recordPath(t)
			h := HostAt(path)
			if viaBind {
				if _, err := h.Bind(addr); err != nil {
					t.Fatalf("Bind: %v", err)
				}
				if got := readRecord(t, path); got[addr] != "vfio-pci" {
					t.Fatalf("record = %v, want %s → vfio-pci (driverctl's)", got, addr)
				}
			}
			if err := h.Unbind(addr, ""); err != nil {
				t.Fatalf("Unbind: %v", err)
			}
			if k.driver() != "vfio-pci" || k.override != "vfio-pci" {
				t.Fatalf("driver=%q override=%q, want driverctl's vfio-pci binding left as it was", k.driver(), k.override)
			}
		})
	}
}

// TestHost_OperatorIDsBeatARecordedHostDriver (re-review R1-M4): the record says
// igbvf, but since then the operator gave vfio-pci this device's ID (ids= and a
// reboot). The operator's configuration wins: the release leaves the device on
// vfio-pci and drops the stale entry.
func TestHost_OperatorIDsBeatARecordedHostDriver(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "vfio-pci", "igbvf")
	k.dynids["vfio-pci "+k.id] = true
	k.files["/proc/cmdline"] = []byte("ro vfio-pci.ids=8086:10ca\n")
	defer SetFS(k)()
	path := recordPath(t)
	writeRecord(t, path, map[string]string{addr: "igbvf"})

	if err := HostAt(path).Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci (the operator's ids= now names it)", k.driver())
	}
	if got := readRecord(t, path); len(got) != 0 {
		t.Fatalf("record = %v, want the stale entry dropped", got)
	}
}

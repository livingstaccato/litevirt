// Package vfio manages binding and unbinding PCI devices to/from the vfio-pci driver.
package vfio

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/secretfile"
)

const (
	sysDevices     = "/sys/bus/pci/devices"
	vfioDriverPath = "/sys/bus/pci/drivers/vfio-pci"

	// driversProbePath asks the PCI core to probe an unbound device against every
	// driver; a set driver_override restricts that probe to the named driver.
	driversProbePath = "/sys/bus/pci/drivers_probe"

	// clearOverride is the value that clears a device's driver_override: a lone
	// newline, which is what `echo > driver_override` writes. A ZERO-LENGTH write
	// does not clear it: sysfs_kf_write returns before the attribute's store runs
	// when count is 0, so the override stays set and the next probe hands the
	// device straight back to vfio-pci.
	clearOverride = "\n"

	// HostDriversFileName is the per-host record, in the daemon's data
	// directory, of the driver each device was on before Bind took it: a JSON
	// object of PCI address → driver. "" means the device had no driver, and
	// "vfio-pci" that it was already on vfio-pci (the operator's vfio-pci.ids=
	// or driverctl), and legacyBind that an older build bound it.
	// It is host-local hardware state and is never replicated.
	HostDriversFileName = "vfio-host-drivers.json"

	vfioDriver = "vfio-pci"

	// legacyBind is the record entry for a device an OLDER litevirt build bound
	// (found on vfio-pci with driver_override=vfio-pci and no record). It is not a
	// driver name: it marks the one case in which the release may remove a
	// vfio-pci dynamic ID, since that build added one with new_id. It is written
	// before the release clears the override, which erases that evidence.
	legacyBind = "(older-litevirt-bind)"

	// driverctlDir holds driverctl's persistent overrides, one pci-<address>
	// file per device, naming the driver it binds at boot.
	driverctlDir = "/etc/driverctl.d"
)

// SysFS abstracts sysfs filesystem operations for testability.
type SysFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Readlink(path string) (string, error)
	ReadDir(path string) ([]os.DirEntry, error)
}

type realFS struct{}

func (realFS) ReadFile(path string) ([]byte, error)                 { return os.ReadFile(path) }
func (realFS) WriteFile(path string, d []byte, p os.FileMode) error { return os.WriteFile(path, d, p) }
func (realFS) Readlink(path string) (string, error)                 { return os.Readlink(path) }
func (realFS) ReadDir(path string) ([]os.DirEntry, error)           { return os.ReadDir(path) }

var sysfs SysFS = realFS{}

// SetFS replaces the filesystem implementation (for testing). Returns a restore function.
func SetFS(f SysFS) func() {
	old := sysfs
	sysfs = f
	return func() { sysfs = old }
}

// Host binds and releases this host's PCI devices and keeps the record of the
// driver each was on before Bind (HostDriversFileName), so the release can bind
// that driver explicitly. An explicit drivers/<x>/bind matches the device on
// that driver's own ID table, so neither driver registration order nor a
// dynamic vfio-pci ID can steer it, where a reprobe can be steered by both.
//
// The record is written before the device leaves its driver and dropped after a
// verified release. A Host with no path keeps no record and releases by the
// restore driver its caller names, or by reprobing.
type Host struct {
	path string
	mu   sync.Mutex // serialises the record's read-modify-write
}

var hosts sync.Map // record path → *Host

// HostAt returns the Host whose record lives at path, one per path, so every
// caller on a host shares the lock on its record. "" keeps no record.
func HostAt(path string) *Host {
	h, _ := hosts.LoadOrStore(path, &Host{path: path})
	return h.(*Host)
}

// Bind is Host.Bind without a record.
func Bind(address string) (string, error) { return HostAt("").Bind(address) }

// Unbind is Host.Unbind without a record.
func Unbind(address, restoreDriver string) error { return HostAt("").Unbind(address, restoreDriver) }

// Bind unbinds a PCI device from its current driver and binds it to vfio-pci.
// Returns the name of the previous driver.
//
// The previous driver is recorded first. A device already on vfio-pci with no
// override set was put there by the operator (vfio-pci.ids=, or a tool that
// binds by ID), or one driverctl pins there: it is recorded as "vfio-pci", and
// its release leaves it there. One already on vfio-pci WITH
// driver_override=vfio-pci and no driverctl pin was bound by an older litevirt
// build, so nothing is recorded and its release identifies it (legacyBind).
//
// It claims the device through driver_override alone, set BEFORE the host
// driver is unbound so a probe in between can only pick vfio-pci. It never
// writes vfio-pci's new_id: that adds a dynamic vendor:device match, so every
// OTHER device with the same ID (the sibling VFs of an SR-IOV NIC) becomes
// claimable by vfio-pci on its next probe.
//
// If the bind cannot be verified, Bind puts the device back on its previous
// driver with the override cleared, and its error says where the device ended.
func (h *Host) Bind(address string) (previousDriver string, err error) {
	devPath := filepath.Join(sysDevices, address)

	previousDriver, err = currentDriver(devPath)
	if err != nil {
		return "", fmt.Errorf("read the driver of %s: %w", address, err)
	}
	if previousDriver == vfioDriver {
		_, recorded, err := h.recorded(address)
		if err != nil {
			return "", err
		}
		if !recorded && h.path != "" {
			ov, err := readOverride(devPath)
			if err != nil {
				return "", fmt.Errorf("read driver_override of %s: %w", address, err)
			}
			// No override: bound by ID (the operator's vfio-pci.ids=). An override
			// driverctl re-applies at boot: the operator's pin. Either way the
			// device belongs on vfio-pci. (A device carrying litevirt's legacy
			// marker is already recorded and never lands here.)
			if ov == "" || (ov == vfioDriver && driverctlPinsVFIO(address)) {
				if err := h.record(address, vfioDriver); err != nil {
					return "", err
				}
			}
		}
		slog.Debug("device already bound to vfio-pci", "address", address)
		return previousDriver, nil
	}

	// The device must exist before anything is changed.
	vendorID := readTrimmed(filepath.Join(devPath, "vendor"))
	deviceID := readTrimmed(filepath.Join(devPath, "device"))
	if vendorID == "" || deviceID == "" {
		return "", fmt.Errorf("cannot read vendor/device for %s", address)
	}

	// Recorded before anything changes, so a crash from here on still knows
	// where the device belongs.
	if err := h.record(address, previousDriver); err != nil {
		return "", err
	}

	// From here on a failure returns the device to its previous driver.
	fail := func(err error) (string, error) {
		final, rerr := h.restoreAfterFailedBind(devPath, address, previousDriver)
		switch {
		case rerr != nil:
			return "", fmt.Errorf("%w (returning %s to its previous driver also failed: %v)", err, address, rerr)
		case final == previousDriver:
			if ferr := h.forget(address); ferr != nil {
				slog.Warn("vfio: could not drop the host-driver record after a rolled-back bind", "address", address, "error", ferr)
			}
			return "", err
		case final == "":
			return "", fmt.Errorf("%w; %s was left with no driver (%s did not take it back)", err, address, previousDriver)
		default:
			return "", fmt.Errorf("%w; %s is now on %s, not its previous driver %q", err, address, final, previousDriver)
		}
	}

	// driver_override makes vfio-pci, and only vfio-pci, able to claim the
	// device. While the host driver still holds it, the override changes nothing.
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte(vfioDriver), 0200); err != nil {
		return fail(fmt.Errorf("set driver_override for %s: %w", address, err))
	}

	if previousDriver != "" {
		unbindPath := filepath.Join(devPath, "driver", "unbind")
		if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
			return fail(fmt.Errorf("unbind %s from %s: %w", address, previousDriver, err))
		}
		slog.Info("unbound device from driver", "address", address, "driver", previousDriver)
	}

	// Bind to vfio-pci, or reprobe (the override steers the probe to vfio-pci).
	bindPath := filepath.Join(vfioDriverPath, "bind")
	if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
		if err2 := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err2 != nil {
			return fail(fmt.Errorf("bind %s to vfio-pci: %w (probe also failed: %v)", address, err, err2))
		}
	}

	// Verify binding took effect.
	final, verifyErr := currentDriver(devPath)
	if verifyErr != nil || final != vfioDriver {
		if verifyErr != nil || final == "" {
			final = "none"
		}
		return fail(fmt.Errorf("bind %s: verification failed — driver is %q, expected vfio-pci", address, final))
	}

	slog.Info("device bound to vfio-pci", "address", address, "previous", previousDriver)
	return previousDriver, nil
}

// restoreAfterFailedBind undoes a Bind that did not reach vfio-pci: it clears the
// override and returns a driverless device to previousDriver, reprobing when it
// had none or that bind fails. It returns the driver the device ended on.
func (h *Host) restoreAfterFailedBind(devPath, address, previousDriver string) (string, error) {
	if err := clearDriverOverride(devPath, address); err != nil {
		return "", err
	}
	cur, err := currentDriver(devPath)
	if err != nil {
		return "", err
	}
	if cur == "" {
		bound := false
		if previousDriver != "" {
			bindPath := filepath.Join("/sys/bus/pci/drivers", previousDriver, "bind")
			bound = sysfs.WriteFile(bindPath, []byte(address), 0200) == nil
		}
		if !bound {
			if err := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err != nil {
				return "", err
			}
		}
	}
	return currentDriver(devPath)
}

// Unbind removes a device from vfio-pci and returns it to its host driver.
//
//  1. The operator's devices are left on vfio-pci and the release succeeds
//     untouched: one recorded as already on vfio-pci before Bind, one driverctl
//     pins to vfio-pci, and — with no record — one on vfio-pci with NO override
//     (bound by ID; every older litevirt bind set the override). A device with
//     no record and driver_override=vfio-pci is an older litevirt build's: that
//     fingerprint is recorded (legacyBind) before the override is cleared. A
//     recorded host driver yields when the operator's ids= now names the device.
//  2. Clear driver_override (with "\n", see clearOverride) and read it back. If
//     it is still set, stop with the device still on vfio-pci.
//  3. Unbind from vfio-pci.
//  4. With a recorded driver, bind it explicitly, and a failure is the answer:
//     no reprobe. With a record of no driver, reprobe. For an older build's
//     device, bind restoreDriver explicitly with a reprobe as fallback, or
//     reprobe when it names nothing usable ("" or "vfio-pci", which is what the
//     inventory holds once a rescan saw the device bound).
//  5. Read the driver back. Landing on vfio-pci with the override clear means a
//     dynamic vfio-pci ID matched it. Only for an older build's device, whose
//     new_id it may be, is that ID removed (releaseFromDynamicID); otherwise
//     someone else chose vfio-pci and the device stays. NO driver is an error
//     when a driver was named, and accepted when none was: a host with no driver
//     for the device never had one.
func (h *Host) Unbind(address, restoreDriver string) error {
	devPath := filepath.Join(sysDevices, address)

	current, err := currentDriver(devPath)
	if err != nil {
		return fmt.Errorf("read the driver of %s: %w", address, err)
	}
	rec, recorded, err := h.recorded(address)
	if err != nil {
		return err
	}

	// 1. The operator's vfio-pci device stays where the operator put it.
	if recorded && rec == vfioDriver {
		slog.Info("device was on vfio-pci before litevirt bound it; leaving it there", "address", address)
		return h.forget(address)
	}
	if current == vfioDriver && driverctlPinsVFIO(address) {
		slog.Info("device is pinned to vfio-pci by driverctl; leaving it there", "address", address)
		return h.forget(address)
	}

	// With no record, the override says who bound the device. Every older
	// litevirt Bind set driver_override=vfio-pci (with a new_id it never
	// removed); a device on vfio-pci with NO override was bound by ID, by the
	// operator or by hand, and is left there. The older build's fingerprint is
	// persisted before step 2 clears the override, so a release that fails after
	// the clear cannot later be mistaken for the operator's device.
	if !recorded && current == vfioDriver {
		ov, err := readOverride(devPath)
		if err != nil {
			return fmt.Errorf("read driver_override of %s: %w", address, err)
		}
		if ov == "" {
			slog.Warn("device is on vfio-pci with no override and no record: bound by ID, not by litevirt; leaving it there", "address", address)
			return nil
		}
		if ov == vfioDriver {
			if err := h.record(address, legacyBind); err != nil {
				return err
			}
			rec, recorded = legacyBind, true
		}
	}
	legacy := recorded && rec == legacyBind
	hostDriver := ""
	if recorded && !legacy {
		hostDriver = rec
	}

	// A recorded host driver yields to the operator's configuration: a device
	// whose ID the operator has since given vfio-pci (ids= and a reboot) stays.
	if hostDriver != "" && current == vfioDriver && operatorClaims(devPath) {
		if err := clearDriverOverride(devPath, address); err != nil {
			return err
		}
		slog.Info("device's ID is now in the operator's vfio-pci ids=; leaving it on vfio-pci instead of its recorded driver",
			"address", address, "recorded", hostDriver)
		return h.forget(address)
	}

	// 2. Clear the override and prove it cleared, before the binding changes.
	if err := clearDriverOverride(devPath, address); err != nil {
		return err
	}
	if current != "" && current != vfioDriver {
		return h.forget(address) // on a host driver already; nothing to release
	}

	// 3. Unbind from vfio-pci.
	if current == vfioDriver {
		unbindPath := filepath.Join(devPath, "driver", "unbind")
		if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
			return fmt.Errorf("unbind %s from vfio-pci: %w", address, err)
		}
	}

	// 4. Return the device to a host driver.
	want := hostDriver
	switch {
	case hostDriver != "":
		bindPath := filepath.Join("/sys/bus/pci/drivers", hostDriver, "bind")
		if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
			return fmt.Errorf("restore %s to its recorded host driver %s: %w (not reprobing, which could hand it to any matching driver)", address, hostDriver, err)
		}
	case recorded && !legacy:
		if err := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err != nil {
			return fmt.Errorf("reprobe %s: %w", address, err)
		}
	default:
		want = restoreDriver
		if want == vfioDriver {
			want = ""
		}
		if err := bindOrProbe(address, want); err != nil {
			return err
		}
	}

	// 5. Verify where the device ended up.
	final, err := currentDriver(devPath)
	if err != nil {
		return fmt.Errorf("unbind %s: cannot read the driver back: %w", address, err)
	}
	if final == vfioDriver {
		if !legacy {
			// A dynamic ID litevirt did not add (this build never writes new_id):
			// someone chose vfio-pci for this ID, so it stays.
			slog.Warn("a reprobe gave the device to vfio-pci by a dynamic ID litevirt did not add; leaving it there", "address", address)
			return h.forget(address)
		}
		if final, err = h.releaseFromDynamicID(devPath, address, want); err != nil {
			return fmt.Errorf("unbind %s: verification failed — still bound to vfio-pci: %w", address, err)
		}
	}
	switch {
	case final == vfioDriver:
		// releaseFromDynamicID found the operator's ids= for it: its place.
	case final == "" && want != "":
		return fmt.Errorf("unbind %s: verification failed — released from vfio-pci but left with no driver (%s did not bind and a reprobe found none)", address, want)
	case final == "":
		slog.Warn("device released from vfio-pci; no host driver claimed it", "address", address)
	case want != "" && final != want:
		slog.Warn("device released from vfio-pci to a different host driver", "address", address, "driver", final, "wanted", want)
	default:
		slog.Info("device restored to host driver", "address", address, "driver", final)
	}
	return h.forget(address)
}

// bindOrProbe binds an unbound device to want, falling back to a reprobe, or
// just reprobes when want is "".
func bindOrProbe(address, want string) error {
	if want == "" {
		if err := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err != nil {
			return fmt.Errorf("reprobe %s: %w", address, err)
		}
		return nil
	}
	bindPath := filepath.Join("/sys/bus/pci/drivers", want, "bind")
	if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
		if err2 := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err2 != nil {
			return fmt.Errorf("restore %s to driver %s: bind failed: %v, probe also failed: %w",
				address, want, err, err2)
		}
	}
	return nil
}

// releaseFromDynamicID handles a device that a reprobe put back on vfio-pci
// although its override is clear: vfio-pci holds a dynamic ID for its
// vendor:device. That ID is either the operator's (vfio-pci.ids= on the kernel
// command line or in modprobe.d), in which case vfio-pci is where the device
// belongs on this host and it stays, or one an older litevirt build added with
// new_id and never removed. Only the second is removed (remove_id), and the
// device is unbound and returned once more. It returns the driver the device
// ended on.
func (h *Host) releaseFromDynamicID(devPath, address, want string) (string, error) {
	vendor := strings.TrimPrefix(readTrimmed(filepath.Join(devPath, "vendor")), "0x")
	device := strings.TrimPrefix(readTrimmed(filepath.Join(devPath, "device")), "0x")
	if vendor == "" || device == "" {
		return vfioDriver, fmt.Errorf("cannot read vendor/device for %s", address)
	}
	id := strings.ToLower(vendor + " " + device)
	operator, err := operatorVfioIDs()
	if err != nil {
		return vfioDriver, fmt.Errorf("a vfio-pci dynamic ID (%s) matched it, and whether the operator configured that ID cannot be told: %w", id, err)
	}
	if operator[id] {
		slog.Info("device is on vfio-pci by the operator's vfio-pci ids=; leaving it there", "address", address, "id", id)
		return vfioDriver, nil
	}

	remedy := fmt.Sprintf("echo '%s' > %s/remove_id, then echo %s > %s, or reboot", id, vfioDriverPath, address, driversProbePath)
	if err := sysfs.WriteFile(filepath.Join(vfioDriverPath, "remove_id"), []byte(id), 0200); err != nil {
		return vfioDriver, fmt.Errorf("a vfio-pci dynamic ID (%s) that is not the operator's matched it, and removing it failed: %v (%s)", id, err, remedy)
	}
	slog.Warn("removed a vfio-pci dynamic ID an older litevirt build added", "address", address, "id", id)
	if err := sysfs.WriteFile(filepath.Join(devPath, "driver", "unbind"), []byte(address), 0200); err != nil {
		return vfioDriver, fmt.Errorf("unbind after removing vfio-pci's dynamic ID %s: %v (%s)", id, err, remedy)
	}
	if err := bindOrProbe(address, want); err != nil {
		return "", err
	}
	final, err := currentDriver(devPath)
	if err != nil {
		return "", err
	}
	if final == vfioDriver {
		return final, fmt.Errorf("a reprobe still chose vfio-pci after its dynamic ID %s was removed (%s)", id, remedy)
	}
	return final, nil
}

// driverctlPinsVFIO reports whether driverctl pins the device at address to
// vfio-pci: /etc/driverctl.d/pci-<address> names the driver whose override
// driverctl re-applies at every boot. Any read error is "not pinned".
func driverctlPinsVFIO(address string) bool {
	b, err := sysfs.ReadFile(filepath.Join(driverctlDir, "pci-"+address))
	return err == nil && strings.TrimSpace(string(b)) == vfioDriver
}

// operatorClaims reports whether the operator's vfio-pci ids= names the device
// at devPath. A configuration that cannot be read claims nothing.
func operatorClaims(devPath string) bool {
	vendor := strings.TrimPrefix(readTrimmed(filepath.Join(devPath, "vendor")), "0x")
	device := strings.TrimPrefix(readTrimmed(filepath.Join(devPath, "device")), "0x")
	if vendor == "" || device == "" {
		return false
	}
	ids, err := operatorVfioIDs()
	return err == nil && ids[strings.ToLower(vendor+" "+device)]
}

// modprobeDirs are where modprobe reads options from, in its own order.
var modprobeDirs = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}

// operatorVfioIDs returns the vendor:device IDs ("vvvv dddd") the operator gave
// vfio-pci: vfio-pci.ids= (or vfio_pci.ids=) on the kernel command line, and
// `options vfio-pci ... ids=` in modprobe.d. An unreadable command line is an
// error, so a caller never takes "not the operator's" from a read it could not
// make; a missing modprobe.d directory is just none.
func operatorVfioIDs() (map[string]bool, error) {
	ids := map[string]bool{}
	add := func(list string) {
		for _, e := range strings.Split(list, ",") {
			parts := strings.Split(strings.TrimSpace(e), ":")
			if len(parts) >= 2 {
				ids[strings.ToLower(parts[0]+" "+parts[1])] = true
			}
		}
	}
	cmdline, err := sysfs.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, fmt.Errorf("read /proc/cmdline: %w", err)
	}
	for _, f := range strings.Fields(string(cmdline)) {
		for _, p := range []string{"vfio-pci.ids=", "vfio_pci.ids="} {
			if v, ok := strings.CutPrefix(f, p); ok {
				add(v)
			}
		}
	}
	for _, dir := range modprobeDirs {
		entries, err := sysfs.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			data, err := sysfs.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Fields(line)
				if len(f) < 3 || f[0] != "options" || (f[1] != "vfio-pci" && f[1] != "vfio_pci") {
					continue
				}
				for _, opt := range f[2:] {
					if v, ok := strings.CutPrefix(opt, "ids="); ok {
						add(v)
					}
				}
			}
		}
	}
	return ids, nil
}

// ReleaseUnbound finishes the release of a device its caller found NOT bound to
// vfio-pci, which it releases without an Unbind. A device that still carries
// driver_override=vfio-pci (a failed Bind by an older build) has the override
// cleared, or the next probe would give it to vfio-pci while it is unowned. A
// driverless device is then returned to its recorded host driver, or reprobed.
// A device with no override and no record is not written to at all.
func (h *Host) ReleaseUnbound(address string) error {
	devPath := filepath.Join(sysDevices, address)
	cur, err := currentDriver(devPath)
	if err != nil {
		return fmt.Errorf("read the driver of %s: %w", address, err)
	}
	if cur == vfioDriver {
		return nil // bound: Unbind's job
	}
	ov, err := readOverride(devPath)
	if errors.Is(err, fs.ErrNotExist) {
		// The device is gone from sysfs (a VF that did not come back after a
		// reboot, a pulled card): nothing is left to clear, and the release goes
		// ahead as it always did.
		slog.Info("released device is no longer present; nothing to clear", "address", address)
		return h.forget(address)
	}
	if err != nil {
		return fmt.Errorf("read driver_override of %s: %w", address, err)
	}
	rec, recorded, err := h.recorded(address)
	if err != nil {
		return err
	}
	stale := ov == vfioDriver
	hostDriver := ""
	if recorded && rec != vfioDriver && rec != legacyBind {
		hostDriver = rec
	}
	if !stale && hostDriver == "" {
		if recorded {
			return h.forget(address)
		}
		return nil
	}
	if stale {
		if err := clearDriverOverride(devPath, address); err != nil {
			return err
		}
	}
	if cur == "" {
		if err := bindOrProbe(address, hostDriver); err != nil {
			return err
		}
		final, err := currentDriver(devPath)
		if err != nil {
			return err
		}
		if final == vfioDriver {
			return fmt.Errorf("release %s: a reprobe bound it to vfio-pci (a dynamic vfio-pci ID matches it)", address)
		}
		slog.Info("released device's stale vfio state cleared", "address", address, "driver", final)
	}
	if recorded {
		return h.forget(address)
	}
	return nil
}

// ── the host-driver record ──

func (h *Host) load() (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(h.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the host-driver record %s: %w", h.path, err)
	}
	if len(b) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("the host-driver record %s is not an address → driver map: %w", h.path, err)
	}
	return m, nil
}

func (h *Host) store(m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := secretfile.Write(h.path, b, 0o600); err != nil {
		return fmt.Errorf("write the host-driver record: %w", err)
	}
	// The rename is atomic; syncing the directory makes it durable.
	if d, err := os.Open(filepath.Dir(h.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// recorded returns the driver recorded for address, and whether one is.
func (h *Host) recorded(address string) (string, bool, error) {
	if h.path == "" {
		return "", false, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	m, err := h.load()
	if err != nil {
		return "", false, err
	}
	d, ok := m[address]
	return d, ok, nil
}

func (h *Host) record(address, driver string) error {
	if h.path == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	m, err := h.load()
	if err != nil {
		return err
	}
	if d, ok := m[address]; ok && d == driver {
		return nil
	}
	m[address] = driver
	if err := h.store(m); err != nil {
		return fmt.Errorf("record the host driver of %s: %w", address, err)
	}
	return nil
}

func (h *Host) forget(address string) error {
	if h.path == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	m, err := h.load()
	if err != nil {
		return err
	}
	if _, ok := m[address]; !ok {
		return nil
	}
	delete(m, address)
	if err := h.store(m); err != nil {
		return fmt.Errorf("drop the host-driver record of %s: %w", address, err)
	}
	return nil
}

// ── sysfs reads ──

// clearDriverOverride clears devPath's driver_override and reads it back, failing
// while the kernel still reports an override.
func clearDriverOverride(devPath, address string) error {
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte(clearOverride), 0200); err != nil {
		return fmt.Errorf("clear driver_override for %s: %w", address, err)
	}
	v, err := readOverride(devPath)
	if err != nil {
		return fmt.Errorf("clear driver_override for %s: cannot read it back: %w", address, err)
	}
	if v != "" {
		return fmt.Errorf("clear driver_override for %s: still %q after the clear; not unbinding, the next probe would bind %s again", address, v, v)
	}
	return nil
}

// readOverride returns devPath's driver_override, "" when none is set (the
// kernel shows that as "(null)").
func readOverride(devPath string) (string, error) {
	data, err := sysfs.ReadFile(filepath.Join(devPath, "driver_override"))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(data))
	if v == "(null)" {
		v = ""
	}
	return v, nil
}

// currentDriver returns the name of the driver bound to the device at devPath, or
// "" when none is. Only a not-exist error means "no driver"; any other error is
// returned, so a caller fails closed rather than assume the device is unbound.
func currentDriver(devPath string) (string, error) {
	link, err := sysfs.Readlink(filepath.Join(devPath, "driver"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(link), nil
}

// CurrentDriver returns the driver the PCI device at address is bound to now,
// "" when none is.
func CurrentDriver(address string) (string, error) {
	return currentDriver(filepath.Join(sysDevices, address))
}

// IsBoundToVFIO reports whether the PCI device at address is CURRENTLY bound to the
// vfio-pci driver, read from the device's driver symlink. This is the GROUND-TRUTH
// "is this device claimed by vfio right now" signal — as opposed to inferring
// boundness from bookkeeping such as vm_pci_realizations rows, which can lie after a
// crash or a rollback that tombstoned the rows while retaining the binding. It mirrors
// the readlink pattern Bind/Unbind use: bound iff the driver link's basename is
// "vfio-pci". A device with NO driver bound (the link is absent → a not-exist error)
// is reported false, nil; an UNEXPECTED filesystem error (anything other than
// not-exist) is returned so a caller can fail closed rather than assume "unbound".
func IsBoundToVFIO(address string) (bool, error) {
	link, err := sysfs.Readlink(filepath.Join(sysDevices, address, "driver"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return filepath.Base(link) == "vfio-pci", nil
}

// IsVF returns true if the PCI device at the given address is an SR-IOV Virtual Function.
// VFs have a "physfn" symlink pointing to their parent Physical Function.
func IsVF(address string) bool {
	_, err := sysfs.Readlink(filepath.Join(sysDevices, address, "physfn"))
	return err == nil
}

// IsIOMMUEnabled checks if IOMMU is available on the host.
func IsIOMMUEnabled() bool {
	entries, err := sysfs.ReadDir("/sys/kernel/iommu_groups")
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func readTrimmed(path string) string {
	data, err := sysfs.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

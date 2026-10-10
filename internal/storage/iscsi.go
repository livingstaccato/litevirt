package storage

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

// iscsiDriver attaches a pre-provisioned iSCSI LUN. litevirt does not
// allocate LUNs on the SAN — the operator does that out-of-band; we
// only handle iscsiadm discovery / login and surface the resulting
// /dev/disk/by-path device to libvirt.
type iscsiDriver struct {
	target string
	opts   map[string]string
	run    cmdRunner // iscsiadm seam (Teardown); tests inject a fake
}

func (d *iscsiDriver) String() string { return "iscsi" }

// Teardown logs the host out of the iSCSI target on pool delete. Idempotent: a
// "no matching"/"not found" logout is treated as already-gone. The caller is
// responsible for the cross-pool refcount (don't log out a target another pool's
// LUN still uses). Safe to call without a prior Prepare.
func (d *iscsiDriver) Teardown(ctx context.Context) error {
	portal := d.opts["portal"]
	if portal == "" {
		portal = "127.0.0.1"
	}
	run := d.run
	if run == nil {
		run = realCmd
	}
	out, err := run(ctx, "iscsiadm", "-m", "node", "-T", d.target, "-p", portal, "--logout")
	if err != nil && !strings.Contains(string(out), "No matching") && !strings.Contains(string(out), "not found") {
		return fmt.Errorf("iscsi logout %s: %w: %s", d.target, err, out)
	}
	slog.Info("iSCSI logged out", "target", d.target)
	return nil
}

func (d *iscsiDriver) Prepare(ctx context.Context) error {
	portal := d.opts["portal"]
	if portal == "" {
		portal = "127.0.0.1"
	}

	run := d.run
	if run == nil {
		run = realCmd
	}
	out, err := run(ctx, "iscsiadm",
		"-m", "discovery", "-t", "st", "-p", portal)
	if err != nil {
		return fmt.Errorf("iscsi discovery %s: %w: %s", portal, err, out)
	}

	out, err = run(ctx, "iscsiadm",
		"-m", "node", "-T", d.target, "-p", portal, "--login")
	if err != nil && !strings.Contains(string(out), "already") {
		return fmt.Errorf("iscsi login %s: %w: %s", d.target, err, out)
	}
	slog.Info("iSCSI target connected", "target", d.target)
	return nil
}

// CreateDisk allocates nothing: it names the pool's one LUN. Every disk on the
// pool gets the same device, so the caller must not hand it to a second disk
// (FixedDevice; CreateVM refuses a LUN another disk already uses).
func (d *iscsiDriver) CreateDisk(_ context.Context, opts DiskOptions) (string, error) {
	path := iscsiDevicePath(d.target, d.opts)
	slog.Info("iSCSI disk path", "vm", opts.VMName, "disk", opts.DiskName, "path", path)
	return path, nil
}

// iscsiDevicePath is the /dev/disk/by-path name of a pool's LUN, spelled as the
// pool's options spell it — the path every disk on the pool has been recorded
// with, so it must not change.
func iscsiDevicePath(target string, opts map[string]string) string {
	lun := opts["lun"]
	if lun == "" {
		lun = "0"
	}
	return fmt.Sprintf("/dev/disk/by-path/ip-%s-iscsi-%s-lun-%s", opts["portal"], target, lun)
}

// iscsiByPathRe takes a recorded iscsi disk path apart. The target starts with
// iqn./eui./naa. (ValidateSource), which is what finds where a portal — a host
// name may contain "-iscsi-" — ends.
var iscsiByPathRe = regexp.MustCompile(`^/dev/disk/by-path/ip-(.*?)-iscsi-((?i:iqn|eui|naa)\..+)-lun-([^-/]+)$`)

// iscsiLUNKey is the identity of one LUN, whatever a pool spells it as: the
// portal with its port (3260 when none is given; the driver's 127.0.0.1 when no
// portal is), the target lowercased (iSCSI names compare case-insensitively),
// and the LUN number.
func iscsiLUNKey(portal, target, lun string) string {
	if portal == "" {
		portal = "127.0.0.1"
	}
	portal = strings.ToLower(portal)
	host, port := portal, "3260"
	if strings.HasPrefix(portal, "[") {
		if i := strings.Index(portal, "]"); i >= 0 {
			host = portal[:i+1]
			if p, ok := strings.CutPrefix(portal[i+1:], ":"); ok && p != "" {
				port = p
			}
		}
	} else if h, p, ok := strings.Cut(portal, ":"); ok && !strings.Contains(p, ":") {
		host = h
		if p != "" {
			port = p
		}
	}
	if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}
	if lun == "" {
		lun = "0"
	}
	if n, err := strconv.ParseUint(lun, 10, 64); err == nil {
		lun = strconv.FormatUint(n, 10)
	} else {
		lun = strings.ToLower(lun)
	}
	return "iscsi:" + host + ":" + port + "/" + strings.ToLower(target) + "/lun" + lun
}

// FixedDevice reports whether a pool hands every disk on it the same device —
// an iscsi pool is one pre-provisioned LUN, and CreateDisk allocates nothing —
// and if so returns the key that device is compared by and the device path
// CreateDisk returns. Two disks with one key are one block device: two VMs
// writing it corrupt each other. Every other driver allocates a new object per
// disk (a file, zvol, LV, subvolume or RBD image) and refuses one that exists.
func FixedDevice(cfg Config) (key, device string, ok bool) {
	if !strings.EqualFold(cfg.Driver, "iscsi") {
		return "", "", false
	}
	return iscsiLUNKey(cfg.Options["portal"], cfg.Source, cfg.Options["lun"]),
		iscsiDevicePath(cfg.Source, cfg.Options), true
}

// FixedDeviceKeyOfPath is FixedDevice's key for a recorded disk path: a path an
// iscsi pool handed out keys to its LUN, any other path to nothing.
func FixedDeviceKeyOfPath(path string) (string, bool) {
	m := iscsiByPathRe.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	return iscsiLUNKey(m[1], m[2], m[3]), true
}

func (d *iscsiDriver) DeleteDisk(_ context.Context, path string) error {
	slog.Info("iSCSI DeleteDisk: LUN management is external", "path", path)
	return nil
}

// iscsiRun is the iscsiadm runner New gives an iscsi driver.
var iscsiRun cmdRunner = realCmd

// OverrideISCSICommandForTest replaces how every iscsi driver New builds runs
// iscsiadm, for tests in other packages that create disks on an iscsi pool
// without a SAN. It returns the restore.
func OverrideISCSICommandForTest(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := iscsiRun
	iscsiRun = run
	return func() { iscsiRun = prev }
}

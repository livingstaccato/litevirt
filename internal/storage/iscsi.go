package storage

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
// target lowercased (iSCSI names compare case-insensitively) and the LUN
// number. The portal is not part of it: one target is reached through several
// portals (a portal per storage subnet, multipath), and an IQN is globally
// unique, so two pools naming one target and LUN through two portals are one
// LUN. Two arrays answering to one IQN are a misconfiguration worth refusing.
func iscsiLUNKey(target, lun string) string {
	if lun == "" {
		lun = "0"
	}
	if n, err := strconv.ParseUint(lun, 10, 64); err == nil {
		lun = strconv.FormatUint(n, 10)
	} else {
		lun = strings.ToLower(lun)
	}
	return "iscsi:" + strings.ToLower(target) + "/lun" + lun
}

// NormalizeISCSIPortal is the portal a NEW iscsi pool stores: host:port,
// with the iSCSI default port 3260 when none is given — udev names the device
// ip-<host>:<port>-iscsi-..., so a pool without the port names a device that
// never appears — and a host name resolved to its IPv4 address, for the same
// reason. A name that does not resolve is kept, with the port, and a warning:
// refusing it would refuse a pool create main accepted. Existing pools keep
// their spelling: their disks' recorded paths must keep matching.
func NormalizeISCSIPortal(portal string, lookup func(host string) ([]net.IP, error)) (normalized, warning string) {
	if portal == "" {
		return "", ""
	}
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
	bare := strings.Trim(host, "[]")
	if net.ParseIP(bare) == nil && lookup != nil {
		ips, err := lookup(bare)
		var v4 net.IP
		for _, ip := range ips {
			if ip.To4() != nil {
				v4 = ip.To4()
				break
			}
		}
		switch {
		case err != nil || v4 == nil:
			warning = fmt.Sprintf("iscsi portal %q does not resolve to an IPv4 address (%v); kept as %s:%s — the "+
				"disk device path is spelled from it, so it must match how udev names the session", bare, err, host, port)
		default:
			warning = fmt.Sprintf("iscsi portal %q resolved to %s; the pool records the address, as udev names "+
				"the device by it", bare, v4)
			host = v4.String()
		}
	}
	return host + ":" + port, warning
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
	return iscsiLUNKey(cfg.Source, cfg.Options["lun"]), iscsiDevicePath(cfg.Source, cfg.Options), true
}

// FixedDeviceKeyOfPath is FixedDevice's key for a recorded disk path: a path an
// iscsi pool handed out keys to its LUN, any other path to nothing.
func FixedDeviceKeyOfPath(path string) (string, bool) {
	m := iscsiByPathRe.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	return iscsiLUNKey(m[2], m[3]), true
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

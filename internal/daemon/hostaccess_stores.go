package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Every store this host serves is a protected tree for container host
// mounts: a container handed one could read or rewrite another workload's
// disks, backups or images. data_dir and pki_dir come from hostAccess; the
// rest are here. lxc.deniedTree compares the resolved, canonical form of each.

// storeDenyStatic is what the config names: the image and disk stores and restore
// cache under data_dir (named even though data_dir covers them, in case
// either is a symlink to elsewhere) and every configured backup repo.
func (d *Daemon) storeDenyStatic() []string {
	out := []string{
		filepath.Join(d.cfg.DataDir, "images"),
		filepath.Join(d.cfg.DataDir, "disks"),
		filepath.Join(d.cfg.DataDir, "ct-restore"),
	}
	for _, p := range d.cfg.BackupRepos {
		out = append(out, p)
	}
	return out
}

// storeDenyDynamic is what the cluster names, read at every resolve and so
// at every start: this host's storage pools' sources and targets and every
// registered backup repo. A read that fails is an error: a mount is never
// judged against a store list that could not be read (the resolve refuses
// every mount), and the periodic refresh keeps the policy it last wrote.
func (d *Daemon) storeDenyDynamic() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pools, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("container host mounts: this host's storage pools cannot be read; no mount can be judged", "err", err)
		return nil, fmt.Errorf("read this host's storage pools: %w", err)
	}
	var out []string
	for _, p := range pools {
		out = append(out, p.Source, p.Target)
	}
	repos, err := corrosion.ListBackupRepos(ctx, d.db)
	if err != nil {
		slog.Warn("container host mounts: backup repos cannot be read; no mount can be judged", "err", err)
		return nil, fmt.Errorf("read the backup repos: %w", err)
	}
	for _, r := range repos {
		out = append(out, r.Path)
	}
	return out, nil
}

// vmDiskBlockInUse reports a VM disk — any VM's in the cluster, so a shared
// LUN backing a VM on another host counts — that is the block device
// major:minor here, compared by device number (never by path, which a
// symlink or a rename changes). A read that fails is an error, which refuses
// the device (and a refresh keeps the policy it last wrote).
func (d *Daemon) vmDiskBlockInUse(major, minor uint32) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	disks, err := corrosion.VMDiskPaths(ctx, d.db)
	if err != nil {
		return "", fmt.Errorf("this host's VM disks cannot be read: %w", err)
	}
	return diskWithNumber(disks, major, minor, blockNumber), nil
}

// blockNumber reads a block node's number; tests replace it.
var blockNumber = lxc.BlockDeviceNumber

// diskWithNumber names the VM whose disk is the device major:minor, or "".
func diskWithNumber(disks map[string]string, major, minor uint32, number func(string) (uint32, uint32, bool)) string {
	for path, vm := range disks {
		if ma, mi, ok := number(path); ok && ma == major && mi == minor {
			return "it is the disk of VM " + vm + " (" + path + ")"
		}
	}
	return ""
}

// hookPolicyRefreshInterval is how often every container's start-hook policy
// is rewritten from its record and this host's stores.
const hookPolicyRefreshInterval = time.Minute

// refreshHookPolicies keeps every container's start-hook policy current: at
// daemon start, then once a minute, so a pool or repo created, or a prefix
// withdrawn, reaches what an in-container reboot is judged against.
func refreshHookPolicies(ctx context.Context, r interface{ RefreshHookPolicies() error }) {
	t := time.NewTicker(hookPolicyRefreshInterval)
	defer t.Stop()
	for {
		if err := r.RefreshHookPolicies(); err != nil {
			slog.Warn("container host access: refreshing the start hook's policies", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// hostAccessEvaluator raises the conditions about this host's container
// host-access config.
const hostAccessEvaluator = "host-access"

// CondHostAccessPrefixOverlap is raised by a node about itself while one of
// its containers.bind_mount_paths prefixes shares a filesystem with a
// protected tree (lxc.HostAccessOverlaps). Such a config loaded before
// filesystem identity was checked, so it still loads (m-6); mount sources in
// the protected tree are refused when they are resolved.
const CondHostAccessPrefixOverlap = "container_mount_prefix_overlap"

// noteHostAccessOverlaps warns about, and raises or resolves the condition
// for, the prefixes lxc.HostAccessOverlaps reports.
func (d *Daemon) noteHostAccessOverlaps(ctx context.Context, overlaps []string) {
	for _, o := range overlaps {
		slog.Warn("config: a container bind-mount prefix shares a filesystem with a protected tree; the daemon starts, and mount sources in that tree are refused", "overlap", o)
	}
	d.writeSelfConditionAs(ctx, hostAccessEvaluator, CondHostAccessPrefixOverlap, len(overlaps) > 0, corrosion.SeverityWarning,
		map[string]any{"overlaps": overlaps})
}

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
// registered backup repo. A read that fails denies everything ("/"): a mount
// is never judged against a store list that could not be read.
func (d *Daemon) storeDenyDynamic() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pools, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("container host mounts: this host's storage pools cannot be read; refusing every mount", "err", err)
		return []string{"/"}
	}
	var out []string
	for _, p := range pools {
		out = append(out, p.Source, p.Target)
	}
	repos, err := corrosion.ListBackupRepos(ctx, d.db)
	if err != nil {
		slog.Warn("container host mounts: backup repos cannot be read; refusing every mount", "err", err)
		return []string{"/"}
	}
	for _, r := range repos {
		out = append(out, r.Path)
	}
	return out
}

// vmDiskBlockInUse reports a VM disk on this host that is the block device
// major:minor, compared by device number (never by path, which a symlink or
// a rename changes). A read that fails refuses.
func (d *Daemon) vmDiskBlockInUse(major, minor uint32) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	disks, err := corrosion.HostDiskPaths(ctx, d.db, d.cfg.HostName)
	if err != nil {
		return fmt.Sprintf("this host's VM disks cannot be read (%v)", err)
	}
	return diskWithNumber(disks, major, minor, lxc.BlockDeviceNumber)
}

// diskWithNumber names the VM whose disk is the device major:minor, or "".
func diskWithNumber(disks map[string]string, major, minor uint32, number func(string) (uint32, uint32, bool)) string {
	for path, vm := range disks {
		if ma, mi, ok := number(path); ok && ma == major && mi == minor {
			return "it is the disk of VM " + vm + " (" + path + ")"
		}
	}
	return ""
}

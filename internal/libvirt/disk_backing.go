package libvirt

import (
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/storage"
)

// diskBacking decides how a storage driver's volume identifier has to be
// described to libvirt: the <disk type=…>, the <source> attributes that type
// requires, and the <driver type=…> that matches the medium.
//
// This exists because the drivers do not all return a file path. CreateDisk's
// contract is "the path / identifier to put in libvirt's <disk source>
// element", and the three families differ:
//
//   - local, nfs, dir, btrfs → a .qcow2 file        → type="file",    qcow2
//   - zfs, lvm-thin, iscsi   → a block device node  → type="block",   raw
//   - ceph                   → an "rbd:pool/image"  → type="network", raw
//
// Everything used to be emitted as type="file" with driver type="qcow2", so a
// zvol was handed to libvirt as though it were a qcow2 file and the domain
// simply did not start — after the volume had already been allocated.
//
// The driver type matters as much as the source. A raw block device and an RBD
// image have no qcow2 header; telling qemu to read one makes the disk
// unreadable even where the source is correct.
func diskBacking(path string) (diskType string, src diskSource, driverType string, err error) {
	switch {
	case strings.HasPrefix(path, "rbd:"):
		l, ok := storage.ParseCephLocator(path)
		if !ok {
			return "", diskSource{}, "", fmt.Errorf("ceph disk %q is not rbd:<pool>/<image>", path)
		}
		hosts, auth, unsupported := rbdDomainSource(l)
		if len(unsupported) > 0 {
			// Refuse rather than quietly emit a domain that ignores them: a
			// setting with no domain form would be dropped, and the domain
			// would point at the right image with the DEFAULT credentials and
			// configuration — a failure at start time, after the image was
			// allocated, with nothing reporting why.
			return "", diskSource{}, "", fmt.Errorf(
				"ceph disk %q carries connection option(s) %s that libvirt cannot express in a "+
					"<disk type=\"network\"> source; libvirt authenticates RBD through a ceph "+
					"secret (the litevirt pool's client and keyring) and reads monitors from <host> "+
					"elements (the pool's mon_host, or its conf's)",
				l.Spec, strings.Join(unsupported, ", "))
		}
		return "network", diskSource{Protocol: "rbd", Name: l.Spec, Hosts: hosts, Auth: auth}, "raw", nil
	case strings.HasPrefix(path, "/dev/"):
		return "block", diskSource{Dev: path}, "raw", nil
	default:
		return "file", diskSource{File: path}, "qcow2", nil
	}
}

// rbdDomainSource turns a parsed ceph locator (storage.ParseCephLocator) into
// what the domain carries:
//
//   - id + keyring + lvpool become <auth username=id> naming the ceph secret
//     CephSecretUUID(lvpool, id), which the daemon defines on every host with
//     the pool. A keyring with no id is client.admin's, as for the rbd CLI.
//   - the monitors become <host> elements, looked up NOW (I5): the litevirt
//     pool's current monitors on this host (SetCephMonitorResolver), else the
//     locator's mon_host (a fallback for a host without the pool), else the
//     conf's mon_host read from the file. The default ceph.conf, which qemu
//     reads by itself, may name none; any other conf must.
//
// With none of them the domain carries no <auth> and no <host>, and qemu uses
// ceph's defaults, as before.
func rbdDomainSource(l storage.CephLocator) (hosts []diskSourceHost, auth *diskAuth, unsupported []string) {
	for _, key := range l.Order {
		switch key {
		case "mon_host", "id", "keyring", "conf", "lvpool":
		default:
			// Every other option is reported, not skipped.
			unsupported = append(unsupported, key)
		}
	}
	conf := l.Opts["conf"]
	mons, ok := poolMonitors(l.Opts["lvpool"])
	if !ok {
		if v, has := l.Opts["mon_host"]; has {
			mons = storage.ParseMonHost(v)
		} else if conf != "" {
			m, err := storage.CephMonHosts(conf)
			switch {
			case err == nil:
				mons = m
			case !storage.IsDefaultCephConf(conf):
				unsupported = append(unsupported, "conf ("+err.Error()+")")
			}
		}
	}
	if len(mons) == 0 && conf != "" && !storage.IsDefaultCephConf(conf) && !hasPrefixIn(unsupported, "conf") {
		unsupported = append(unsupported, "conf (it names no mon_host)")
	}
	for _, m := range mons {
		hosts = append(hosts, splitMonHost(m))
	}
	if keyring := l.Opts["keyring"]; keyring != "" {
		if l.Opts["lvpool"] == "" {
			unsupported = append(unsupported, "keyring (no lvpool names its secret)")
		} else {
			id := cephID(l.Opts)
			auth = &diskAuth{Username: id, Secret: diskAuthSecret{Type: "ceph", UUID: CephSecretUUID(l.Opts["lvpool"], id)}}
		}
	} else if l.Opts["id"] != "" {
		// An identity with no key to authenticate it: libvirt can only name a
		// secret, and there is no keyring to define one from.
		unsupported = append(unsupported, "id")
	}
	return hosts, auth, unsupported
}

func hasPrefixIn(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// splitMonHost splits one monitor address into host and port: "h:p",
// "[v6]:p", or a bare host or IPv6 literal (no port).
func splitMonHost(mon string) diskSourceHost {
	if strings.HasPrefix(mon, "[") {
		if end := strings.IndexByte(mon, ']'); end > 0 {
			host, rest := mon[1:end], mon[end+1:]
			return diskSourceHost{Name: host, Port: strings.TrimPrefix(rest, ":")}
		}
	}
	// Only a host:port pair splits; a bare IPv6 literal has colons of its own
	// and is left whole.
	if h, p, found := strings.Cut(mon, ":"); found && !strings.Contains(p, ":") {
		return diskSourceHost{Name: h, Port: p}
	}
	return diskSourceHost{Name: mon}
}

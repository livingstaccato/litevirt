package libvirt

import (
	"fmt"
	"strings"
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
		name, hosts, auth, unsupported := parseRBDLocator(strings.TrimPrefix(path, "rbd:"))
		if len(unsupported) > 0 {
			// Refuse rather than quietly emit a domain that ignores them.
			// libvirt's <source protocol='rbd'> carries monitors as <host>
			// children and an identity as <auth> naming a secret in libvirt's
			// OWN store; a setting with neither form would be dropped, and the
			// domain would point at the right image with the DEFAULT
			// credentials and configuration — a failure at start time, after
			// the image was allocated, with nothing reporting why.
			return "", diskSource{}, "", fmt.Errorf(
				"ceph disk %q carries connection option(s) %s that libvirt cannot express in a "+
					"<disk type=\"network\"> source; libvirt authenticates RBD through a ceph "+
					"secret (the pool's id and keyring) and reads monitors from <host> elements "+
					"(the pool's mon_host, or its conf's)",
				name, strings.Join(unsupported, ", "))
		}
		return "network", diskSource{Protocol: "rbd", Name: name, Hosts: hosts, Auth: auth}, "raw", nil
	case strings.HasPrefix(path, "/dev/"):
		return "block", diskSource{Dev: path}, "raw", nil
	default:
		return "file", diskSource{File: path}, "qcow2", nil
	}
}

// defaultCephConf is the ceph.conf qemu reads when a disk names none.
const defaultCephConf = "/etc/ceph/ceph.conf"

// parseRBDLocator splits qemu's rbd URI body —
// "pool/image[:opt=val[:opt=val]]", with ':' and ';' inside a value escaped
// as "\:" and "\;" — into the image name libvirt wants in <source name=…>,
// the monitors (mon_host), and the identity (id, keyring) the disk
// authenticates as.
//
// The ceph driver writes the pool's id, keyring, conf and monitors into every
// disk's locator (internal/storage/ceph.go diskLocator):
//
//   - id + keyring become <auth username=id> naming the ceph secret
//     CephSecretUUID(id, keyring), which the daemon defines on every host from
//     that keyring. A keyring with no id is client.admin's, as for the rbd CLI.
//   - mon_host becomes <host> elements.
//   - conf has no domain form. It is accepted when its monitors are in the
//     locator (mon_host), or when it is the default ceph.conf, which qemu
//     reads by itself; any other conf is refused.
//
// With none of them the domain carries no <auth> and no <host>, and qemu uses
// ceph's defaults, as before.
func parseRBDLocator(body string) (name string, hosts []diskSourceHost, auth *diskAuth, unsupported []string) {
	parts := splitUnescaped(body, ':')
	name = parts[0]
	opts := map[string]string{}
	var order []string
	for _, opt := range parts[1:] {
		key, value, ok := strings.Cut(opt, "=")
		if !ok {
			continue
		}
		value = strings.ReplaceAll(value, `\;`, ";")
		value = strings.ReplaceAll(value, `\:`, ":")
		if _, dup := opts[key]; !dup {
			order = append(order, key)
		}
		opts[key] = value
	}
	for _, key := range order {
		switch key {
		case "mon_host", "id", "keyring", "conf":
		default:
			// Every other option is reported, not skipped: a setting the
			// caller asked for that the generated domain would not carry.
			unsupported = append(unsupported, key)
		}
	}
	if v, ok := opts["mon_host"]; ok {
		// ceph accepts both "," and ";" between monitors.
		for _, mon := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' }) {
			mon = strings.TrimSpace(mon)
			if mon == "" {
				continue
			}
			hosts = append(hosts, splitMonHost(mon))
		}
	}
	if conf, ok := opts["conf"]; ok && len(hosts) == 0 && conf != defaultCephConf {
		unsupported = append(unsupported, "conf")
	}
	if keyring := opts["keyring"]; keyring != "" {
		id := opts["id"]
		if id == "" {
			id = "admin"
		}
		auth = &diskAuth{Username: id, Secret: diskAuthSecret{Type: "ceph", UUID: CephSecretUUID(id, keyring)}}
	} else if opts["id"] != "" {
		// An identity with no key to authenticate it: libvirt can only name a
		// secret, and there is no keyring to define one from.
		unsupported = append(unsupported, "id")
	}
	return name, hosts, auth, unsupported
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

// splitUnescaped splits s at every sep not preceded by a backslash.
func splitUnescaped(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

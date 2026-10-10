package storage

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A VM disk on ceph is opened by qemu, not by the rbd CLI, and qemu reaches the
// cluster only through what libvirt puts in the domain: monitors as <host>
// elements, and an identity as <auth username=…> naming a libvirt secret that
// holds that client's key. Nothing in a domain can name a keyring FILE. So a
// pool that authenticates with a restricted client key (the only acceptable
// production setup: `profile rbd pool=<pool>`, never client.admin) needs the
// key copied into a libvirt secret on every host that runs its disks.
//
// The identity a disk authenticates as is written into its locator
// ("rbd:<pool>/<image>:id=<id>:keyring=<path>…"), and the secret's UUID is
// derived from that pair (libvirt.CephSecretUUID), so every host that has the
// same keyring at the same path names the same secret — which is what lets a
// live migration's destination open the disk with the domain XML it is handed.

// cephConfDir is where ceph keeps its default ceph.conf and keyrings.
// Overridden in tests.
var cephConfDir = "/etc/ceph"

// DefaultCephConf is the ceph.conf qemu and the rbd CLI read when none is named.
func DefaultCephConf() string { return filepath.Join(cephConfDir, "ceph.conf") }

// CephAuth is the client identity a ceph pool's VM disks authenticate as.
type CephAuth struct {
	// ID is the client name without "client." ("litevirt"), "admin" when the
	// pool names none.
	ID string
	// Keyring is the keyring file holding ID's key.
	Keyring string
}

// CephAuthOf returns the identity a ceph pool's options name. ok is false
// when the pool names no keyring and there is none at ceph's default path for
// its id: such a pool's disks carry no <auth>, and qemu uses ceph's own
// defaults, exactly as before.
func CephAuthOf(opts map[string]string) (CephAuth, bool) {
	id := opts["id"]
	keyring := opts["keyring"]
	if keyring == "" && id != "" {
		// The rbd CLI finds a client's key at this path by itself; the domain
		// has to be told.
		if p := filepath.Join(cephConfDir, "ceph.client."+id+".keyring"); fileExists(p) {
			keyring = p
		}
	}
	if keyring == "" {
		return CephAuth{}, false
	}
	if id == "" {
		id = "admin"
	}
	return CephAuth{ID: id, Keyring: filepath.Clean(keyring)}, true
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// maxCephFile bounds what is read of a keyring or ceph.conf: both are a few
// hundred bytes, and a path naming something else must not be slurped.
const maxCephFile = 1 << 20

func readCephFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCephFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCephFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxCephFile)
	}
	return b, nil
}

// ErrNoCephKey says a keyring holds no key for the client asked for.
var ErrNoCephKey = errors.New("no key for the client in the keyring")

// CephClientKey reads client.<id>'s key from a ceph keyring and returns it
// decoded — the bytes a libvirt ceph secret holds. The key is never part of
// an error.
func CephClientKey(keyringPath, id string) ([]byte, error) {
	b, err := readCephFile(keyringPath)
	if err != nil {
		return nil, fmt.Errorf("read ceph keyring: %w", err)
	}
	want := "client." + id
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != want {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "key" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		key, derr := base64.StdEncoding.DecodeString(v)
		if derr != nil || len(key) == 0 {
			return nil, fmt.Errorf("ceph keyring %s: the key of %s is not base64", keyringPath, want)
		}
		return key, nil
	}
	return nil, fmt.Errorf("ceph keyring %s: %s: %w", keyringPath, want, ErrNoCephKey)
}

// CephMonHosts reads the monitor addresses a ceph.conf names (mon_host, or
// "mon host": ceph treats spaces and underscores in keys alike), as
// "host" or "host:port" entries for libvirt <host> elements. An empty result
// with a nil error means the file names no monitors.
func CephMonHosts(confPath string) ([]string, error) {
	b, err := readCephFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("read ceph conf: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.Join(strings.FieldsFunc(strings.ToLower(k), func(r rune) bool { return r == ' ' || r == '_' || r == '\t' }), "_")
		if k == "mon_host" {
			return ParseMonHost(v), nil
		}
	}
	return nil, nil
}

// ParseMonHost reads a ceph mon_host value into "host" / "host:port" entries.
//
// It accepts the plain form ("10.0.0.1,10.0.0.2:6789") and the address
// vectors cephadm writes ("[v2:10.0.0.1:3300/0,v1:10.0.0.1:6789/0] […]").
// From a vector it takes the v1 (legacy) address when there is one — every
// librbd speaks it, and a bare host:port is read as v1 unless it is on 3300 —
// and the v2 one otherwise. One entry per monitor, in order.
func ParseMonHost(v string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(e string) {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	v = strings.TrimSpace(v)
	for len(v) > 0 {
		switch {
		case v[0] == ' ' || v[0] == ',' || v[0] == ';' || v[0] == '\t':
			v = v[1:]
		case v[0] == '[' && isAddrVector(v):
			end := strings.IndexByte(v, ']')
			if end < 0 {
				end = len(v)
			}
			add(pickFromVector(v[1:end]))
			if end < len(v) {
				v = v[end+1:]
			} else {
				v = ""
			}
		default:
			end := strings.IndexAny(v, " ,;\t")
			if end < 0 {
				end = len(v)
			}
			add(monAddr(v[:end]))
			v = v[end:]
		}
	}
	return out
}

// isAddrVector tells "[v2:…,v1:…]" from a bracketed IPv6 literal "[::1]:6789".
func isAddrVector(v string) bool {
	return strings.HasPrefix(v, "[v1:") || strings.HasPrefix(v, "[v2:") || strings.HasPrefix(v, "[any:")
}

func pickFromVector(body string) string {
	var v1, other string
	for _, a := range strings.Split(body, ",") {
		a = strings.TrimSpace(a)
		switch {
		case strings.HasPrefix(a, "v1:"):
			if v1 == "" {
				v1 = monAddr(a)
			}
		case other == "":
			other = monAddr(a)
		}
	}
	if v1 != "" {
		return v1
	}
	return other
}

// monAddr reduces one ceph address ("v1:10.0.0.1:6789/0") to host[:port].
func monAddr(a string) string {
	for _, p := range []string{"v1:", "v2:", "any:"} {
		a = strings.TrimPrefix(a, p)
	}
	if i := strings.LastIndexByte(a, '/'); i >= 0 {
		a = a[:i]
	}
	return strings.TrimSpace(a)
}

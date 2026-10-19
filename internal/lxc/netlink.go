package lxc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NetLinks reads the bridge each NIC of container name is linked to
// (lxc.net.<N>.link in its config), by N.
func (r *LxcRunner) NetLinks(name string) (map[int]string, error) {
	data, err := os.ReadFile(filepath.Join(r.lxcpath(), name, "config"))
	if err != nil {
		return nil, err
	}
	return parseNetLinks(string(data)), nil
}

func parseNetLinks(cfg string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		k, v, ok := strings.Cut(t, "=")
		if !ok || !strings.HasPrefix(t, "lxc.net.") || !strings.HasSuffix(strings.TrimSpace(k), ".link") {
			continue
		}
		if n, ok := lxcNetOrdinal(t); ok {
			out[n] = strings.TrimSpace(v)
		}
	}
	return out
}

// SetNetLink links NIC n of the (stopped) container name to bridge, in its
// config; the next start plugs it there.
func (r *LxcRunner) SetNetLink(name string, n int, bridge string) error {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return err
	}
	out, ok := setNetLink(string(data), n, bridge)
	if !ok {
		return fmt.Errorf("container %s has no lxc.net.%d.link", name, n)
	}
	return os.WriteFile(cfg, []byte(out), 0o644)
}

func setNetLink(cfg string, n int, bridge string) (string, bool) {
	return setNetKey(cfg, n, "link", bridge)
}

// setNetKey sets lxc.net.<n>.<key> to value on every line that has it.
func setNetKey(cfg string, n int, field, value string) (string, bool) {
	lines := strings.Split(cfg, "\n")
	key := fmt.Sprintf("lxc.net.%d.%s", n, field)
	found := false
	for i, line := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == key {
			lines[i] = key + " = " + value
			found = true
		}
	}
	return strings.Join(lines, "\n"), found
}

// SetNetHWAddr sets the MAC of NIC n in container name's config.
func (r *LxcRunner) SetNetHWAddr(name string, n int, mac string) error {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	data, err := os.ReadFile(cfg)
	if err != nil {
		return err
	}
	out, ok := setNetKey(string(data), n, "hwaddr", mac)
	if !ok {
		if _, has := parseNetLinks(string(data))[n]; !has {
			return fmt.Errorf("container %s has no NIC %d", name, n)
		}
		out = strings.TrimRight(out, "\n") + fmt.Sprintf("\nlxc.net.%d.hwaddr = %s\n", n, mac)
	}
	return os.WriteFile(cfg, []byte(out), 0o644)
}

package fencessh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The files a host holds, all root-owned and all static: everything sshd needs
// to answer a fence is on disk, so a frozen or crashed daemon does not stop
// its host being fenced.
const (
	// DefaultDir holds them.
	DefaultDir = "/etc/litevirt/ssh"
	// KeyName is this host's own fence key (0600); KeyName+".pub" beside it.
	KeyName = "fence_ed25519"
	// AuthorizedKeysName is every verified peer's fence key, restricted
	// (0644); the sshd drop-in adds it to root's AuthorizedKeysFile.
	AuthorizedKeysName = "authorized_keys"
	// KnownHostsName is every verified peer's sshd host keys under its alias
	// (0644).
	KnownHostsName = "known_hosts"
	// CommandName is the forced command (0755).
	CommandName = "fence-command"
	// DefaultHostKeyGlob is where this host's sshd keys are read from.
	DefaultHostKeyGlob = "/etc/ssh/ssh_host_*_key.pub"
)

// Requests a fence key may send. The forced command answers these two and
// refuses everything else.
const (
	requestPrefix = "litevirt-fence v1 "
	// CheckOK is what a check request prints. It is never the fence marker,
	// so a probe can never be read as a fence.
	CheckOK = "litevirt-fence-check-ok"
)

// PoweroffRequest is the request that powers target off.
func PoweroffRequest(target string) string { return requestPrefix + "poweroff " + HexName(target) }

// CheckRequest is the request that proves the path to target without arming.
func CheckRequest(target string) string { return requestPrefix + "check " + HexName(target) }

// ForcedCommand is the only thing a litevirt fence key can run on self. It
// matches SSH_ORIGINAL_COMMAND exactly, quoted, against self's hex name: a
// request naming another host is refused with exit 3 and no marker, so a
// machine reached at the wrong address never powers itself off for a fence
// of another. The marker and the power-off are fence.sshPowerOffCommand's,
// byte for byte, so a fence's result is classified the same way.
func ForcedCommand(self string) []byte {
	h := HexName(self)
	return []byte(`#!/bin/sh
# Written by litevirt. The only thing a litevirt fence key can run on this host.
self='` + h + `'
case "${SSH_ORIGINAL_COMMAND:-}" in
  "` + requestPrefix + `check $self") echo ` + CheckOK + `; exit 0 ;;
  "` + requestPrefix + `poweroff $self") ;;
  *) echo "litevirt-fence: refused" >&2; exit 3 ;;
esac
logger -p auth.crit -t litevirt-fence "forced power-off requested from ${SSH_CLIENT%% *}" 2>/dev/null
printf '%s-%s\n' litevirt-fence armed; sleep 1; systemctl poweroff --force --force || echo o > /proc/sysrq-trigger
`)
}

const renderedHeader = "# Written by litevirt from verified host_fence_ssh rows. Do not edit: it is rewritten.\n"

// AuthorizedKeys renders peers' fence keys, each accepted only from its
// owner's certificate address and only to run the forced command, with
// nothing else allowed (restrict: no pty, no forwarding, no agent, no
// ~/.ssh/rc). Peers are sorted by name; a key line is re-rendered from the
// parsed key, never copied from the row.
func AuthorizedKeys(dir string, peers []*Verified) []byte {
	var b bytes.Buffer
	b.WriteString(renderedHeader)
	for _, v := range sortedPeers(peers) {
		for _, k := range v.FenceKeys {
			fmt.Fprintf(&b, "restrict,from=%q,command=%q %s litevirt-fence:%s:g%d\n",
				v.Addr.String(), filepath.Join(dir, CommandName), KeyLine(k), HexName(v.Host), v.Generation)
		}
	}
	return b.Bytes()
}

// KnownHosts renders peers' sshd host keys, each under its alias.
func KnownHosts(peers []*Verified) []byte {
	var b bytes.Buffer
	b.WriteString(renderedHeader)
	for _, v := range sortedPeers(peers) {
		b.Write(KnownHostsLines(v))
	}
	return b.Bytes()
}

// KnownHostsLines is v's host keys under its alias, one per line.
func KnownHostsLines(v *Verified) []byte {
	var b bytes.Buffer
	for _, k := range v.HostKeys {
		fmt.Fprintf(&b, "%s %s\n", Alias(v.Host), KeyLine(k))
	}
	return b.Bytes()
}

func sortedPeers(peers []*Verified) []*Verified {
	out := append([]*Verified(nil), peers...)
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// writeIfChanged writes data to path by a synced rename when its content or
// mode differs, and reports whether it wrote.
func writeIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() == mode {
			return false, nil
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	return true, nil
}

// readHostKeys reads every sshd public host key glob matches, as canonical
// sorted lines.
func readHostKeys(glob string) (string, error) {
	paths, err := filepath.Glob(glob)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		keys, err := parseKeys(string(raw), "sshd host key "+p)
		if err != nil {
			return "", err
		}
		for _, k := range keys {
			lines = append(lines, KeyLine(k))
		}
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no sshd host key matches %s", glob)
	}
	sort.Strings(lines)
	if len(lines) > maxKeys {
		lines = lines[:maxKeys]
	}
	return strings.Join(lines, "\n"), nil
}

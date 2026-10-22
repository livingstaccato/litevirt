package fencessh

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// SSHDPath is the sshd binary: PATH's, else /usr/sbin/sshd.
func SSHDPath() string {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	return "/usr/sbin/sshd"
}

// SSHDAccepting evaluates this host's effective sshd configuration for a
// root connection from each peer address — `sshd -T -C user=root,addr=<peer>`,
// so a Match Address block that gives root another AuthorizedKeysFile for one
// peer is seen for that peer, not hidden behind 127.0.0.1. The fence key is
// accepted only when, for every peer, root's AuthorizedKeysFile includes
// dir/authorized_keys, public-key authentication is on, and PermitRootLogin
// is not no. configFile "" is sshd's own.
func SSHDAccepting(sshd, configFile, dir string) AcceptingFunc {
	want := filepath.Join(dir, AuthorizedKeysName)
	return func(ctx context.Context, peers []string) (bool, string) {
		if len(peers) == 0 {
			return false, "no peer address to evaluate sshd for"
		}
		for _, addr := range peers {
			args := []string{"-T", "-C", "user=root,host=,addr=" + addr}
			if configFile != "" {
				args = append([]string{"-f", configFile}, args...)
			}
			var stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, sshd, args...)
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return false, fmt.Sprintf("sshd -T for a connection from %s: %v %s", addr, err, strings.TrimSpace(stderr.String()))
			}
			eff := parseSSHDT(out)
			if akf := eff["authorizedkeysfile"]; !slices.Contains(strings.Fields(akf), want) {
				return false, fmt.Sprintf("sshd does not read %s for root from %s (AuthorizedKeysFile %q); "+
					"`lv host install-fence-ssh` adds it", want, addr, akf)
			}
			if v := eff["pubkeyauthentication"]; v != "yes" {
				return false, fmt.Sprintf("sshd has PubkeyAuthentication %s for root from %s", v, addr)
			}
			if v := eff["permitrootlogin"]; v == "no" {
				return false, fmt.Sprintf("sshd has PermitRootLogin no for root from %s; litevirt does not override it", addr)
			}
		}
		return true, ""
	}
}

// parseSSHDT reads `sshd -T` output: one lower-case keyword and its value per
// line; the first value of a keyword stands.
func parseSSHDT(out []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if k == "" {
			continue
		}
		if _, ok := m[k]; !ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

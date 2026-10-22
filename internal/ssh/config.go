package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// userSentinel is the User the wrapper config gives a host that nothing
// configured, so "configured" and "defaulted to the local login" differ even
// when the config names the local login.
const userSentinel = "__lv_unset__"

// configTimeout bounds one `ssh -G` run (a Match exec can run anything).
const configTimeout = 10 * time.Second

// warnf reports a non-fatal config problem to the operator. A variable so a
// test can capture it.
var warnf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

// resolved is what the operator's OpenSSH configuration says about a target,
// reduced to the fields the pure-Go client can act on.
type resolved struct {
	Hostname       string
	User           string // "" when neither the command line nor the config chose one
	Port           string
	IdentityFiles  []string // configured IdentityFile entries, defaults excluded
	IdentitiesOnly bool
	StrictYes      bool     // StrictHostKeyChecking yes/true/on
	KnownHosts     []string // configured UserKnownHostsFile entries, ~/.ssh/known_hosts{,2} excluded
	// GlobalKnownHosts is GlobalKnownHostsFile: OpenSSH's default
	// /etc/ssh/ssh_known_hosts{,2} unless the config names others.
	GlobalKnownHosts []string
	// HostKeyAlias is the name host keys are looked up under instead of the
	// dialled address ("" when unset).
	HostKeyAlias string
	// AgentSet: IdentityAgent chose the agent socket, AgentSock ("" for
	// none). Otherwise SSH_AUTH_SOCK is used.
	AgentSet  bool
	AgentSock string
}

// sshG runs `ssh -G args...` and returns its stdout, giving up after timeout
// even when a Match exec grandchild holds the pipes open: the whole process
// group is killed and WaitDelay stops Wait from blocking on the pipes. A
// variable so a test can stand in for a machine with no ssh binary.
var sshG = func(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh -G: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// resolveConfig asks the system ssh what ~/.ssh/config (the one under $HOME)
// makes of host. OpenSSH is the parser because it already implements Host
// patterns, Match, Include and token expansion exactly as the operator's own
// `ssh <alias>` does. Only the per-user file is read: -F replaces it and also
// makes ssh skip /etc/ssh/ssh_config.
//
// A command-line user or port is passed as -l/-p, so it beats the config the
// way it does for ssh. With no config file the old defaults apply even without
// an ssh binary; a config that ssh -G cannot read is an error.
func resolveConfig(host, usr, port string, userSet, portSet bool, timeout time.Duration) (*resolved, error) {
	// Only hostname, IP-literal and user-name characters reach ssh -G. The
	// host can come from a replicated, peer-writable column (hosts.address),
	// and a config's `Match exec "... %h"` hands it to a shell; OpenSSH before
	// 9.6 did not refuse shell metacharacters there.
	if !validSSHName(host) || strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("invalid SSH host %q", host)
	}
	if userSet && (!validSSHName(usr) || strings.HasPrefix(usr, "-")) {
		return nil, fmt.Errorf("invalid SSH user %q", usr)
	}
	if timeout <= 0 || timeout > configTimeout {
		timeout = configTimeout
	}

	// Wrapper: the operator's config first (ssh keeps the first value it
	// obtains), then a sentinel User for any host that config left without one.
	var wrapper strings.Builder
	haveConfig := false
	defaultKH, defaultKH2 := "", ""
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".ssh", "config")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			fmt.Fprintf(&wrapper, "Include %q\n", p)
			haveConfig = true
		}
		// ssh would default this to the passwd home; pin it to $HOME so the
		// file litevirt checks is the one the rest of litevirt uses.
		defaultKH = filepath.Join(home, ".ssh", "known_hosts")
		defaultKH2 = defaultKH + "2"
	}
	wrapper.WriteString("Host *\n  User " + userSentinel + "\n")
	if defaultKH != "" {
		fmt.Fprintf(&wrapper, "  UserKnownHostsFile %q %q\n", defaultKH, defaultKH2)
	}
	// An unreadable config must not silently drop what it pins (host-key
	// files, StrictHostKeyChecking): with a config present, failing to read it
	// refuses. With none, there is nothing to honour and the old defaults hold.
	fail := func(err error) (*resolved, error) {
		if haveConfig && strings.Contains(err.Error(), "Bad owner or permissions") {
			return nil, fmt.Errorf("cannot read ~/.ssh/config for %s: %w "+
				"(ssh refuses a config not owned by the current user or writable by others; "+
				"under sudo, run litevirt as the config's owner or without `sudo -E`)", host, err)
		}
		if haveConfig {
			return nil, fmt.Errorf("cannot read ~/.ssh/config for %s: %w "+
				"(litevirt reads it with `ssh -G`; fix the config, or move it aside to use lv's defaults)", host, err)
		}
		return nil, nil
	}
	f, err := os.CreateTemp("", "lv-sshcfg-*")
	if err != nil {
		return fail(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(wrapper.String()); err != nil {
		f.Close()
		return fail(err)
	}
	f.Close()

	args := []string{"-F", f.Name()}
	if userSet {
		args = append(args, "-l", usr)
	}
	if portSet {
		args = append(args, "-p", port)
	}
	args = append(args, "--", host)
	out, err := sshG(timeout, args...)
	if err != nil {
		return fail(err)
	}
	got := parseSSHG(out)

	r := &resolved{Hostname: got.one("hostname"), Port: got.one("port")}
	if r.Hostname == "" {
		r.Hostname = host
	}
	if portSet {
		r.Port = port
	}
	if r.Port == "" {
		r.Port = "22"
	}
	if userSet {
		r.User = usr
	} else if u := got.one("user"); u != "" && u != userSentinel {
		r.User = u
	}
	eff := r.User
	if eff == "" {
		eff = "root"
	}
	if a := got.one("hostkeyalias"); a != "" && a != "none" {
		r.HostKeyAlias = a
	}

	// ProxyJump and ProxyCommand are not supported by this client. They are
	// not refused: every caller dialled the address directly before, and a
	// host reachable both ways must keep working.
	if pj := got.one("proxyjump"); pj != "" && pj != "none" {
		warnf("%s sets ProxyJump %s in your ssh config; litevirt does not support it and dials %s:%s directly", host, pj, r.Hostname, r.Port)
	}
	if pc := got.one("proxycommand"); pc != "" && pc != "none" {
		warnf("%s sets ProxyCommand in your ssh config; litevirt does not support it and dials %s:%s directly", host, r.Hostname, r.Port)
	}

	for _, id := range got["identityfile"] {
		if id == "none" || isDefaultIdentity(id) {
			continue
		}
		p, ok := expandIdentity(id, host, r.Hostname, eff, r.Port)
		if !ok {
			warnf("ignoring IdentityFile %q for %s: it uses a %% token litevirt does not expand", id, host)
			continue
		}
		r.IdentityFiles = append(r.IdentityFiles, p)
	}
	r.IdentitiesOnly = strings.EqualFold(got.one("identitiesonly"), "yes")
	switch strings.ToLower(got.one("stricthostkeychecking")) {
	case "yes", "true", "on":
		r.StrictYes = true
	}
	ukh, err := knownHostsPaths(got["userknownhostsfile"], func(p string) (string, bool) {
		return expandIdentity(p, host, r.Hostname, eff, r.Port)
	})
	if err != nil {
		return nil, fmt.Errorf("UserKnownHostsFile for %s: %w", host, err)
	}
	for _, kh := range ukh {
		if kh == defaultKH || kh == defaultKH2 {
			continue // ~/.ssh/known_hosts{,2} are always checked (knownHostsFiles)
		}
		warnIfAbsent("UserKnownHostsFile", kh, host)
		r.KnownHosts = append(r.KnownHosts, kh)
	}
	switch ia := got.one("identityagent"); {
	case ia == "" || ia == "SSH_AUTH_SOCK":
		// the default: SSH_AUTH_SOCK
	case ia == "none":
		r.AgentSet = true
	case strings.HasPrefix(ia, "$"):
		r.AgentSet, r.AgentSock = true, os.Getenv(strings.TrimPrefix(ia, "$"))
	default:
		p, ok := expandIdentity(ia, host, r.Hostname, eff, r.Port)
		if !ok {
			warnf("IdentityAgent %q for %s uses a %% token litevirt does not expand; using no agent", ia, host)
		}
		r.AgentSet, r.AgentSock = true, p
	}
	if v := got["globalknownhostsfile"]; len(v) > 0 {
		gkh, err := knownHostsPaths(v, func(p string) (string, bool) { return expandHome(p), true })
		if err != nil {
			return nil, fmt.Errorf("GlobalKnownHostsFile for %s: %w", host, err)
		}
		for _, kh := range gkh {
			if !slices.Contains(defaultGlobalKnownHosts, kh) {
				warnIfAbsent("GlobalKnownHostsFile", kh, host)
			}
			r.GlobalKnownHosts = append(r.GlobalKnownHosts, kh)
		}
	} else {
		r.GlobalKnownHosts = slices.Clone(defaultGlobalKnownHosts)
	}
	return r, nil
}

// Target is a connection target resolved once through the ssh config. The
// address a command records (certificate SAN, cluster address) and the address
// the client dials come from the same Target, so they cannot differ.
type Target struct {
	user, host, port string
	cfg              *resolved
}

// Resolve applies ~/.ssh/config to target once.
func Resolve(target string) (*Target, error) { return resolveTarget(target, 0) }

func resolveTarget(target string, timeout time.Duration) (*Target, error) {
	u, host, port, userSet, portSet := parseTargetExplicit(target)
	cfg, err := resolveConfig(host, u, port, userSet, portSet, timeout)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &resolved{Hostname: host, Port: port, GlobalKnownHosts: slices.Clone(defaultGlobalKnownHosts)}
	}
	if cfg.User != "" {
		u = cfg.User
	}
	return &Target{user: u, host: host, port: cfg.Port, cfg: cfg}, nil
}

// Host is the address that will be dialled: the config's HostName for an
// alias, the given host otherwise.
func (t *Target) Host() string { return t.cfg.Hostname }

// ResolveHostName returns the address litevirt would dial for target once
// ~/.ssh/config is applied: HostName for an alias, the given host otherwise.
// Provisioning commands use it for the DNS step, the certificate SAN and the
// recorded cluster address, so those and the dial name the same machine.
func ResolveHostName(target string) (string, error) {
	t, err := Resolve(target)
	if err != nil {
		return "", err
	}
	return t.Host(), nil
}

func isDefaultIdentity(p string) bool {
	switch p {
	case "~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519",
		"~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss", "~/.ssh/id_dsa":
		return true
	}
	return false
}

// expandIdentity expands ~ and the tokens ssh accepts in these paths that are
// knowable here (%% %d %h %n %p %r %u); any other token reports ok=false.
func expandIdentity(p, orig, hostname, usr, port string) (string, bool) {
	home, _ := os.UserHomeDir()
	local := ""
	if u, err := user.Current(); err == nil {
		local = u.Username
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			b.WriteByte(p[i])
			continue
		}
		i++
		if i >= len(p) {
			return "", false
		}
		switch p[i] {
		case '%':
			b.WriteByte('%')
		case 'd':
			b.WriteString(home)
		case 'h':
			b.WriteString(hostname)
		case 'n':
			b.WriteString(orig)
		case 'p':
			b.WriteString(port)
		case 'r':
			b.WriteString(usr)
		case 'u':
			b.WriteString(local)
		default:
			return "", false
		}
	}
	return expandHome(b.String()), true
}

// knownHostsPaths splits ssh -G's known-hosts values into paths. ssh -G
// prints them space-separated and unquoted, so a configured path containing a
// space ("/home/x/my keys/kh") arrives as several words; adjacent words are
// joined back while the word alone names no existing file and the joined path
// does. A path with a token expand cannot handle is an error: a known_hosts
// file litevirt cannot name is never silently dropped, since it could hold the
// key that contradicts the others.
func knownHostsPaths(values []string, expand func(string) (string, bool)) ([]string, error) {
	words := strings.Fields(strings.Join(values, " "))
	exists := func(w string) bool {
		p, ok := expand(w)
		if !ok {
			return false
		}
		_, err := os.Stat(p)
		return err == nil
	}
	var out []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w == "none" {
			continue
		}
		if !exists(w) {
			joined := w
			for j := i + 1; j < len(words); j++ {
				joined += " " + words[j]
				if exists(joined) {
					w, i = joined, j
					break
				}
			}
		}
		p, ok := expand(w)
		if !ok {
			return nil, fmt.Errorf("%q uses a %% token litevirt does not expand", w)
		}
		out = append(out, p)
	}
	return out, nil
}

// warnIfAbsent says when a configured known_hosts file does not exist: ssh
// skips it, and so does litevirt, but a pin the operator believes is there
// is not.
func warnIfAbsent(kind, path, host string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		warnf("%s %s for %s does not exist; host keys it would pin are not checked", kind, path, host)
	}
}

// validSSHName reports whether s holds only hostname, IP-literal and
// user-name characters: letters, digits and . _ - :
func validSSHName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':':
		default:
			return false
		}
	}
	return true
}

type sshGOut map[string][]string

func (o sshGOut) one(k string) string {
	if v := o[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func parseSSHG(b []byte) sshGOut {
	o := sshGOut{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		o[k] = append(o[k], strings.TrimSpace(v))
	}
	return o
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

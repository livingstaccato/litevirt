package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
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
	Hostname      string
	User          string // "" when neither the command line nor the config chose one
	Port          string
	IdentityFiles []string // configured IdentityFile entries, defaults excluded
	// IdentitySkipped: a configured IdentityFile was dropped (a % token
	// litevirt cannot expand), so IdentitiesOnly must not widen to the defaults.
	IdentitySkipped bool
	IdentitiesOnly  bool
	StrictYes       bool     // StrictHostKeyChecking yes/true/on
	KnownHosts      []string // configured UserKnownHostsFile entries, ~/.ssh/known_hosts{,2} excluded
	// GlobalKnownHosts is GlobalKnownHostsFile: OpenSSH's default
	// /etc/ssh/ssh_known_hosts{,2} unless the config names others.
	GlobalKnownHosts []string
	// HostKeyAlias is the name host keys are looked up under instead of the
	// dialled address ("" when unset).
	HostKeyAlias string
	// KnownHostsCommand is the configured command ("" when none). litevirt does
	// not run it, so a set one refuses the connection.
	KnownHostsCommand string
	// RevokedHostKeys is the configured revocation file ("" when none).
	RevokedHostKeys string
	// AgentSet: IdentityAgent chose the agent socket, AgentSock ("" for
	// none). Otherwise SSH_AUTH_SOCK is used.
	AgentSet  bool
	AgentSock string
}

// sshG runs `ssh -G args...` and returns its stdout, giving up after timeout
// even when a Match exec grandchild holds the pipes open: the whole process
// group is killed and WaitDelay stops Wait from blocking on the pipes. A
// variable so a test can stand in for a machine with no ssh binary.
const resolverStdoutLimit = 1 << 20
const resolverStderrLimit = 64 << 10

var errResolverOutput = errors.New("SSH configuration output exceeds bound")

type resolverCapture struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (w *resolverCapture) Write(p []byte) (int, error) {
	remaining := w.limit - w.buffer.Len()
	if len(p) > remaining {
		w.overflow = true
		w.cancel()
		_, _ = w.buffer.Write(p[:remaining])
		return remaining, errResolverOutput
	}
	return w.buffer.Write(p)
}

var sshG = func(timeout time.Duration, args ...string) ([]byte, error) {
	return runSSHGContext(context.Background(), timeout, args...)
}

type resolverProcessIdentity struct {
	pid, group, session int
	start               uint64
	state               string
}

func resolverIdentity(pid int) (resolverProcessIdentity, error) {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return resolverProcessIdentity{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return resolverProcessIdentity{}, err
	}
	if len(body) > 4096 {
		return resolverProcessIdentity{}, errors.New("oversize resolver process identity")
	}
	end := strings.LastIndex(string(body), ") ")
	if end < 0 {
		return resolverProcessIdentity{}, errors.New("invalid resolver process identity")
	}
	fields := strings.Fields(string(body)[end+2:])
	if len(fields) < 20 {
		return resolverProcessIdentity{}, errors.New("short resolver process identity")
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return resolverProcessIdentity{}, err
	}
	session, err := strconv.Atoi(fields[3])
	if err != nil {
		return resolverProcessIdentity{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return resolverProcessIdentity{}, err
	}
	return resolverProcessIdentity{pid: pid, group: group, session: session, start: start, state: fields[0]}, nil
}

// The original direct child has not been reaped while this observation runs.
// Its retained PID pins the group number against reuse by an unrelated leader.
func resolverGroupTerminal(original resolverProcessIdentity, deadline time.Time) (bool, error) {
	leader, err := resolverIdentity(original.pid)
	if err != nil {
		return false, err
	}
	if leader.start != original.start || leader.group != original.group || leader.session != original.session {
		return false, errors.New("resolver leader identity changed")
	}
	directory, err := os.Open("/proc")
	if err != nil {
		return false, err
	}
	defer directory.Close()
	for {
		if !time.Now().Before(deadline) {
			return false, errors.New("resolver cleanup observation deadline")
		}
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if !time.Now().Before(deadline) {
				return false, errors.New("resolver cleanup observation deadline")
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 {
				continue
			}
			group, err := syscall.Getpgid(pid)
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				return false, err
			}
			if group != original.group {
				continue
			}
			member, err := resolverIdentity(pid)
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				return false, err
			}
			if member.group != original.group {
				continue
			}
			if member.session != original.session {
				return false, errors.New("resolver group session changed")
			}
			if member.state != "Z" && member.state != "X" {
				return false, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			return true, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func runSSHGContext(parent context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > configTimeout {
		timeout = configTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Cancellation may signal the group only while the original child is
	// retained unreaped. Disable this numeric-group action before final Wait.
	var ownership sync.Mutex
	retained := true
	cmd.Cancel = func() error {
		ownership.Lock()
		defer ownership.Unlock()
		if !retained || cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		stdoutPipe.Close()
		return nil, err
	}
	defer stdoutPipe.Close()
	defer stderrPipe.Close()
	stdout := resolverCapture{limit: resolverStdoutLimit, cancel: cancel}
	stderr := resolverCapture{limit: resolverStderrLimit, cancel: cancel}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ssh -G: %w", err)
	}
	outDone, errDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := io.Copy(&stdout, stdoutPipe); outDone <- err }()
	go func() { _, err := io.Copy(&stderr, stderrPipe); errDone <- err }()
	original, identityErr := resolverIdentity(cmd.Process.Pid)
	if identityErr == nil && original.group != cmd.Process.Pid {
		identityErr = errors.New("resolver did not retain its original process group")
	}
	var cleanupDeadline time.Time
	var cleanupErr error
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			cleanupErr = err
			break
		}
		if info.Signo != 0 {
			break
		}
		if ctx.Err() != nil {
			if cleanupDeadline.IsZero() {
				cleanupDeadline = time.Now().Add(time.Second)
			}
			if !time.Now().Before(cleanupDeadline) {
				cleanupErr = errors.New("resolver leader did not become terminal during cleanup")
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if cleanupDeadline.IsZero() {
		cleanupDeadline = time.Now().Add(time.Second)
	}
	if killErr := cmd.Cancel(); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
		cleanupErr = errors.Join(cleanupErr, killErr)
	}
	cleanupErr = errors.Join(cleanupErr, identityErr)
	if cleanupErr == nil {
		for {
			terminal, err := resolverGroupTerminal(original, cleanupDeadline)
			if err != nil {
				cleanupErr = err
				break
			}
			if terminal {
				break
			}
			if !time.Now().Before(cleanupDeadline) {
				cleanupErr = errors.New("resolver group remained nonterminal")
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	// Drain already-produced output only after all owned group members are
	// non-running. A failed/expired cleanup closes readers and cannot parse a
	// truncated prefix or claim a successful terminal result.
	var outErr, diagnosticErr error
	outJoined, errJoined := false, false
	for cleanupErr == nil && (!outJoined || !errJoined) {
		select {
		case outErr = <-outDone:
			outJoined = true
		case diagnosticErr = <-errDone:
			errJoined = true
		default:
		}
		if outJoined && errJoined {
			break
		}
		if !time.Now().Before(cleanupDeadline) {
			cleanupErr = errors.New("resolver output drain exceeded cleanup deadline")
			break
		}
		time.Sleep(time.Millisecond)
	}
	if cleanupErr != nil {
		stdoutPipe.Close()
		stderrPipe.Close()
	}
	if !outJoined {
		outErr = <-outDone
	}
	if !errJoined {
		diagnosticErr = <-errDone
	}
	ownership.Lock()
	retained = false
	ownership.Unlock()
	waitErr := cmd.Wait()
	if cleanupErr != nil {
		return nil, fmt.Errorf("ssh -G cleanup incomplete for original pid=%d group=%d session=%d start=%d: %w", cmd.Process.Pid, original.group, original.session, original.start, errors.Join(cleanupErr, waitErr, outErr, diagnosticErr))
	}
	if stdout.overflow || stderr.overflow {
		return nil, errResolverOutput
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if err := errors.Join(waitErr, outErr, diagnosticErr); err != nil {
		return nil, fmt.Errorf("ssh -G: %w: %s", err, strings.TrimSpace(stderr.buffer.String()))
	}
	return stdout.buffer.Bytes(), nil
}

// systemSSHConfig is ssh's system-wide config. A variable so tests can point
// it at a file of their own and never read this machine's.
var systemSSHConfig = "/etc/ssh/ssh_config"

// resolveConfig asks the system ssh what ~/.ssh/config (the one under $HOME)
// and then /etc/ssh/ssh_config make of host, in the order ssh reads them, so
// the first value obtained wins as it does for `ssh <alias>`. OpenSSH is the
// parser because it already implements Host patterns, Match, Include and
// token expansion exactly. -F would make ssh skip the system file, so the
// wrapper includes it explicitly: a fleet's RevokedHostKeys, KnownHostsCommand
// or GlobalKnownHostsFile usually lives there.
//
// A command-line user or port is passed as -l/-p, so it beats the config the
// way it does for ssh. With no config file the old defaults apply even without
// an ssh binary; a config that ssh -G cannot read is an error.
func resolveConfig(host, usr, port string, userSet, portSet bool, timeout time.Duration) (*resolved, error) {
	return resolveConfigUsing(host, usr, port, userSet, portSet, timeout, sshG, func(format string, args ...any) error { warnf(format, args...); return nil }, false)
}

func resolveConfigUsing(host, usr, port string, userSet, portSet bool, timeout time.Duration, run func(time.Duration, ...string) ([]byte, error), warning func(string, ...any) error, strict bool) (*resolved, error) {
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
	var configs []string // the config files present, in the order ssh reads them
	defaultKH, defaultKH2 := "", ""
	include := func(p string) {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			fmt.Fprintf(&wrapper, "Include %q\n", p)
			configs = append(configs, p)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		include(filepath.Join(home, ".ssh", "config"))
		// ssh would default this to the passwd home; pin it to $HOME so the
		// file litevirt checks is the one the rest of litevirt uses.
		defaultKH = filepath.Join(home, ".ssh", "known_hosts")
		defaultKH2 = defaultKH + "2"
	}
	if err := checkSystemIncludes(systemSSHConfig, 0); err != nil {
		return nil, err
	}
	include(systemSSHConfig)
	haveConfig := len(configs) > 0
	names := strings.Join(configs, " and ")
	wrapper.WriteString("Host *\n  User " + userSentinel + "\n")
	if defaultKH != "" {
		fmt.Fprintf(&wrapper, "  UserKnownHostsFile %q %q\n", defaultKH, defaultKH2)
	}
	// An unreadable config must not silently drop what it pins (host-key
	// files, StrictHostKeyChecking): with a config present, failing to read it
	// refuses. With none, there is nothing to honour and the old defaults hold.
	fail := func(err error) (*resolved, error) {
		if strict && !haveConfig {
			return nil, err
		}
		if haveConfig && strings.Contains(err.Error(), "Bad owner or permissions") {
			return nil, fmt.Errorf("cannot read the ssh config (%s) for %s: %w "+
				"(ssh refuses a config not owned by the current user or writable by others; "+
				"under sudo, run litevirt as the config's owner or without `sudo -E`)", names, host, err)
		}
		if haveConfig {
			return nil, fmt.Errorf("cannot read the ssh config (%s) for %s: %w "+
				"(litevirt reads it with `ssh -G`; fix the config, or move it aside to use litevirt's defaults)", names, host, err)
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
	out, err := run(timeout, args...)
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
	tk := tokens{orig: host, hostname: r.Hostname, user: eff, port: r.Port, alias: r.HostKeyAlias}

	// ProxyJump and ProxyCommand are not supported by this client. They are
	// not refused: every caller dialled the address directly before, and a
	// host reachable both ways must keep working.
	if pj := got.one("proxyjump"); pj != "" && pj != "none" {
		if err := warning("%s sets ProxyJump %s in your ssh config; litevirt does not support it and dials %s:%s directly", host, pj, r.Hostname, r.Port); err != nil {
			return nil, err
		}
	}
	if pc := got.one("proxycommand"); pc != "" && pc != "none" {
		if err := warning("%s sets ProxyCommand in your ssh config; litevirt does not support it and dials %s:%s directly", host, r.Hostname, r.Port); err != nil {
			return nil, err
		}
	}

	for _, id := range got["identityfile"] {
		if id == "none" || isDefaultIdentity(id) {
			continue
		}
		p, ok := tk.expand(id)
		if !ok {
			if err := warning("ignoring IdentityFile %q for %s: it uses a %% token litevirt does not expand", id, host); err != nil {
				return nil, err
			}
			r.IdentitySkipped = true
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
		return tk.expand(p)
	})
	if err != nil {
		return nil, fmt.Errorf("UserKnownHostsFile for %s: %w", host, err)
	}
	for _, kh := range ukh {
		if kh == defaultKH || kh == defaultKH2 {
			continue // ~/.ssh/known_hosts{,2} are always checked (knownHostsFiles)
		}
		if err := warnIfAbsentUsing("UserKnownHostsFile", kh, host, warning); err != nil {
			return nil, err
		}
		r.KnownHosts = append(r.KnownHosts, kh)
	}
	if c := strings.Join(got["knownhostscommand"], " "); c != "" && c != "none" {
		r.KnownHostsCommand = c
	}
	if rv := strings.Join(got["revokedhostkeys"], " "); rv != "" && rv != "none" {
		p, ok := tk.expand(rv)
		if !ok {
			return nil, fmt.Errorf("RevokedHostKeys %q for %s uses a %% token litevirt does not expand", rv, host)
		}
		r.RevokedHostKeys = p
	}
	switch ia := got.one("identityagent"); {
	case ia == "" || ia == "SSH_AUTH_SOCK":
		// the default: SSH_AUTH_SOCK
	case ia == "none":
		r.AgentSet = true
	case strings.HasPrefix(ia, "$"):
		r.AgentSet, r.AgentSock = true, os.Getenv(strings.TrimPrefix(ia, "$"))
	default:
		p, ok := tk.expand(ia)
		if !ok {
			if err := warning("IdentityAgent %q for %s uses a %% token litevirt does not expand; using no agent", ia, host); err != nil {
				return nil, err
			}
		}
		r.AgentSet, r.AgentSock = true, p
	}
	if v := got["globalknownhostsfile"]; len(v) > 0 {
		gkh, err := knownHostsPaths(v, func(p string) (string, bool) { return expandHome(p), true })
		if err != nil {
			return nil, fmt.Errorf("GlobalKnownHostsFile for %s: %w", host, err)
		}
		if slices.Equal(gkh, openSSHGlobalKnownHosts) {
			// OpenSSH's built-in default: the files defaultGlobalKnownHosts
			// names (the same ones, except under test).
			gkh = slices.Clone(defaultGlobalKnownHosts)
		}
		for _, kh := range gkh {
			if !slices.Contains(defaultGlobalKnownHosts, kh) {
				if err := warnIfAbsentUsing("GlobalKnownHostsFile", kh, host, warning); err != nil {
					return nil, err
				}
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
	return resolveTargetUsing(target, timeout, resolveConfig)
}

func ResolveContext(ctx context.Context, target string, diagnostics *EnrollmentDiagnostics) (*Target, error) {
	if ctx == nil {
		return nil, errors.New("nil SSH resolution context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := diagnostics.admitted(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(configTimeout)
	if diagnostics.deadline.Before(deadline) {
		deadline = diagnostics.deadline
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	stop := interruptOnCancellation(bounded, diagnostics.interrupt)
	defer func() { stop(); cancel() }()
	deadline, _ = bounded.Deadline()
	if err := diagnostics.conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	run := func(timeout time.Duration, args ...string) ([]byte, error) {
		return runSSHGContext(bounded, timeout, args...)
	}
	warning := func(format string, args ...any) error {
		_, err := fmt.Fprintf(diagnostics, "warning: "+format+"\n", args...)
		return err
	}
	resolve := func(host, usr, port string, userSet, portSet bool, timeout time.Duration) (*resolved, error) {
		return resolveConfigUsing(host, usr, port, userSet, portSet, timeout, run, warning, true)
	}
	t, err := resolveTargetUsing(target, configTimeout, resolve)
	if bounded.Err() != nil {
		return nil, bounded.Err()
	}
	return t, err
}

func resolveTargetUsing(target string, timeout time.Duration, resolve func(string, string, string, bool, bool, time.Duration) (*resolved, error)) (*Target, error) {
	u, host, port, userSet, portSet := parseTargetExplicit(target)
	cfg, err := resolve(host, u, port, userSet, portSet, timeout)
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

// localHostname is os.Hostname, a variable so a test can give it a domain.
var localHostname = os.Hostname

// tokens are the values ssh's %-tokens take for one target.
type tokens struct {
	orig, hostname, user, port, alias string
}

// expand expands ~ and the tokens ssh accepts in these paths that are
// knowable here (%% %d %h %i %k %l %L %n %p %r %u); any other token reports
// ok=false.
func (tk tokens) expand(p string) (string, bool) {
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
			b.WriteString(tk.hostname)
		case 'i':
			b.WriteString(strconv.Itoa(os.Getuid()))
		case 'k':
			if tk.alias != "" {
				b.WriteString(tk.alias)
			} else {
				b.WriteString(tk.orig)
			}
		case 'l', 'L':
			h, err := localHostname()
			if err != nil {
				return "", false
			}
			if p[i] == 'L' {
				h, _, _ = strings.Cut(h, ".")
			}
			b.WriteString(h)
		case 'n':
			b.WriteString(tk.orig)
		case 'p':
			b.WriteString(tk.port)
		case 'r':
			b.WriteString(tk.user)
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
	_ = warnIfAbsentUsing(kind, path, host, func(format string, args ...any) error { warnf(format, args...); return nil })
}

func warnIfAbsentUsing(kind, path, host string, warning func(string, ...any) error) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return warning("%s %s for %s does not exist; host keys it would pin are not checked", kind, path, host)
	}
	return nil
}

// maxIncludeDepth is ssh's own limit on nested Include.
const maxIncludeDepth = 16

// checkSystemIncludes refuses a relative Include in the system config or in
// any file it includes. litevirt reads the system file through -F, which
// makes ssh treat it as user config: a relative path would resolve against
// ~/.ssh instead of /etc/ssh, and a file that is not there is skipped
// silently -- dropping whatever the fleet set in it. Only absolute paths are
// unambiguous ("~" also differs, and ssh refuses it in a system file), so any
// other argument refuses, naming the file and line. Absent files are fine.
func checkSystemIncludes(path string, depth int) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read the system ssh config %s: %w", path, err)
	}
	if depth > maxIncludeDepth {
		return fmt.Errorf("system ssh config %s: Include nested more than %d deep", path, maxIncludeDepth)
	}
	for i, line := range strings.Split(string(data), "\n") {
		args := splitConfigLine(line)
		if len(args) == 0 || !strings.EqualFold(args[0], "include") {
			continue
		}
		for _, a := range args[1:] {
			if !filepath.IsAbs(a) || strings.ContainsAny(a, "$%") {
				return fmt.Errorf("system ssh config %s:%d: Include %q is not an absolute path; litevirt "+
					"reads the system config as ssh -F does, which would resolve it against ~/.ssh "+
					"instead of /etc/ssh -- refusing. Write it as an absolute path", path, i+1, a)
			}
			matches, err := filepath.Glob(a)
			if err != nil {
				return fmt.Errorf("system ssh config %s:%d: Include %q: %w", path, i+1, a, err)
			}
			for _, m := range matches {
				if err := checkSystemIncludes(m, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// splitConfigLine splits an ssh_config line as ssh does: a keyword, an
// optional "=", then arguments separated by whitespace, each optionally in
// double or single quotes. A comment line yields nothing.
func splitConfigLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	kw, rest := line, ""
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		kw, rest = line[:i], strings.TrimLeft(line[i:], " \t")
		rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	}
	out := []string{kw}
	var cur strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote, in = c, true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
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

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// resolved is what the operator's OpenSSH configuration says about a target,
// reduced to the fields the pure-Go client can act on.
type resolved struct {
	Hostname      string
	User          string // "" when neither the command line nor the config chose one
	Port          string
	IdentityFiles []string // configured IdentityFile entries, defaults excluded
	StrictYes     bool     // StrictHostKeyChecking yes/true/on
	KnownHosts    []string // configured UserKnownHostsFile entries, defaults excluded
}

// sshG runs `ssh -G args...` and returns its stdout. A variable so a test can
// stand in for a machine with no ssh binary.
var sshG = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// resolveConfig asks the system ssh what ~/.ssh/config (the one under
// $HOME, so a test or a `HOME=... lv` run is honoured) makes of host.
// OpenSSH is the parser because it already implements Host patterns, Match,
// Include and token expansion exactly as the operator's own `ssh <alias>`
// does; the pure-Go client only consumes the answer.
//
// A command-line user or port is passed through to ssh, so it beats the
// config the same way it does for `ssh -l`/`-p`. A missing ssh binary or an
// unreadable config falls back to the old defaults with a warning: provisioning
// from a workstation without OpenSSH worked before and must keep working.
func resolveConfig(host, user, port string, userSet, portSet bool) (*resolved, error) {
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("invalid SSH host %q", host)
	}
	cfgFile := os.DevNull
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".ssh", "config")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			cfgFile = p
		}
	}
	args := []string{"-F", cfgFile}
	if userSet {
		args = append(args, "-l", user)
	}
	if portSet {
		args = append(args, "-p", port)
	}
	args = append(args, "--", host)
	out, err := sshG(args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: not reading ~/.ssh/config for %s (%v); using defaults\n", host, err)
		return nil, nil
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
		r.User = user
	} else if u := got.one("user"); u != "" {
		// ssh -G always prints a user (the local login when nothing set one).
		// Compare with a config-less run to tell "configured" from "defaulted".
		// A config User equal to the local login is indistinguishable and
		// falls to the lv default.
		base, berr := sshG("-F", os.DevNull, "--", host)
		if berr != nil || parseSSHG(base).one("user") != u {
			r.User = u
		}
	}

	if pj := got.one("proxyjump"); pj != "" && pj != "none" {
		return nil, fmt.Errorf("%s uses ProxyJump %s in your ssh config, which lv does not support: "+
			"connect to a directly reachable address, or remove the ProxyJump for this host", host, pj)
	}
	if pc := got.one("proxycommand"); pc != "" && pc != "none" {
		return nil, fmt.Errorf("%s uses ProxyCommand in your ssh config, which lv does not support: "+
			"connect to a directly reachable address, or remove the ProxyCommand for this host", host)
	}

	baseline, _ := sshG("-F", os.DevNull, "--", host)
	bg := parseSSHG(baseline)
	def := map[string]bool{}
	for _, f := range bg["identityfile"] {
		def[f] = true
	}
	for _, f := range got["identityfile"] {
		if f != "none" && !def[f] {
			r.IdentityFiles = append(r.IdentityFiles, expandHome(f))
		}
	}
	switch strings.ToLower(got.one("stricthostkeychecking")) {
	case "yes", "true", "on":
		r.StrictYes = true
	}
	defKH := map[string]bool{}
	for _, f := range strings.Fields(strings.Join(bg["userknownhostsfile"], " ")) {
		defKH[f] = true
	}
	for _, f := range strings.Fields(strings.Join(got["userknownhostsfile"], " ")) {
		if f != "none" && !defKH[f] {
			r.KnownHosts = append(r.KnownHosts, expandHome(f))
		}
	}
	return r, nil
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

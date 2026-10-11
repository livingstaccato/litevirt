// Package e2ehelp holds the pure helpers of tests/e2e that can be unit tested
// without a lab: tests/e2e's own TestMain exits before running anything when
// there is no cluster, so logic that lives there is never exercised by `go
// test ./...`.
package e2ehelp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/tests/e2e/labsecret"
)

// SSHTarget returns what to hand `ssh` to reach a cluster host from a node.
// Cluster host names ("node-2") are litevirt's own and do not resolve in DNS
// on the nodes, so a bare-name ssh fails there. The order is: an
// E2E_SSH_<name> override (dashes as underscores), the host's cluster address,
// then the name itself (a workstation whose resolver knows it).
func SSHTarget(host string, env func(string) string, ips map[string]string) string {
	if v := env("E2E_SSH_" + strings.ReplaceAll(host, "-", "_")); v != "" {
		return v
	}
	if ip := ips[host]; ip != "" {
		return ip
	}
	return host
}

// Eventually calls fn until it returns nil or timeout passes, sleeping
// interval between attempts. It always makes one attempt. The bound is hard: an
// attempt that blocks past the deadline (a hung ssh) is abandoned, not waited
// for, and its goroutine finishes on its own. A timeout returns the last error,
// or a bare timeout error when no attempt had returned, so a failure names what
// it was still waiting for.
func Eventually(timeout, interval time.Duration, fn func() error) error {
	if timeout <= 0 {
		return fn()
	}
	deadline := time.After(timeout)
	last := errors.New("no attempt finished")
	for {
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			if err == nil {
				return nil
			}
			last = err
		case <-deadline:
			return fmt.Errorf("timed out after %v (an attempt was still running): last result: %w", timeout, last)
		}
		select {
		case <-time.After(interval):
		case <-deadline:
			return last
		}
	}
}

// RedactError returns err with every non-empty secret replaced by <redacted>,
// or nil for a nil err. An ssh error quotes the whole remote command, which is
// where a token passed as LV_TOKEN=... ends up.
func RedactError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(labsecret.Redact(err.Error(), secrets...))
}

// Sections splits the output of a script that prints "##name" marker lines.
// Each value keeps its trailing newline.
func Sections(out string) map[string]string {
	got := map[string]string{}
	var cur string
	var have bool
	for _, line := range strings.SplitAfter(out, "\n") {
		if line == "" {
			continue
		}
		if name, ok := strings.CutPrefix(strings.TrimRight(line, "\n"), "##"); ok {
			cur, have = name, true
			got[cur] = ""
			continue
		}
		if have {
			got[cur] += line
		}
	}
	return got
}

// KV parses virsh's "key : value" listings (schedinfo, blkdeviotune, domiftune).
// Lines without a colon are ignored.
func KV(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			if k = strings.TrimSpace(k); k != "" {
				got[k] = strings.TrimSpace(v)
			}
		}
	}
	return got
}

// CPUQuota reads the whole-domain CPU cap, in microseconds per period, from the
// cgroup control files (name=value pairs, paths relative to the domain's
// scope). libvirt 10 puts the global cputune quota on the scope's "libvirt"
// sub-cgroup and leaves the scope itself unlimited, so the sub-cgroup is read
// first; ok is false when no level carries a quota, which means the cap is not
// enforced. cgroup v2 reads cpu.max, v1 reads cpu.cfs_quota_us and
// cpu.cfs_period_us.
func CPUQuota(files map[string]string) (quota, period int64, ok bool) {
	for _, dir := range []string{"libvirt/", ""} {
		if f := strings.Fields(files[dir+"cpu.max"]); len(f) == 2 && f[0] != "max" {
			q, err1 := strconv.ParseInt(f[0], 10, 64)
			p, err2 := strconv.ParseInt(f[1], 10, 64)
			if err1 == nil && err2 == nil {
				return q, p, true
			}
		}
		q, err1 := strconv.ParseInt(strings.TrimSpace(files[dir+"cpu.cfs_quota_us"]), 10, 64)
		p, err2 := strconv.ParseInt(strings.TrimSpace(files[dir+"cpu.cfs_period_us"]), 10, 64)
		if err1 == nil && err2 == nil && q > 0 {
			return q, p, true
		}
	}
	return 0, 0, false
}

// HTBRates lists the rates of the htb classes in `tc class show` output.
func HTBRates(tc string) []string {
	var rates []string
	for _, line := range strings.Split(tc, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "class" || f[1] != "htb" {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "rate" {
				rates = append(rates, f[i+1])
				break
			}
		}
	}
	return rates
}

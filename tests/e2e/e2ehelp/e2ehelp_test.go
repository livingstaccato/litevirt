package e2ehelp

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSSHTarget(t *testing.T) {
	env := map[string]string{"E2E_SSH_node_3": "root@203.0.113.9"}
	get := func(k string) string { return env[k] }
	ips := map[string]string{"node-1": "10.77.0.11", "node-3": "10.77.0.13"}

	if got := SSHTarget("node-1", get, ips); got != "10.77.0.11" {
		t.Errorf("a node with a known address must be dialled by it, got %q", got)
	}
	if got := SSHTarget("node-3", get, ips); got != "root@203.0.113.9" {
		t.Errorf("the per-host override wins, got %q", got)
	}
	if got := SSHTarget("node-9", get, ips); got != "node-9" {
		t.Errorf("an unknown host falls back to its name, got %q", got)
	}
}

func TestEventually(t *testing.T) {
	n := 0
	err := Eventually(time.Second, time.Millisecond, func() error {
		n++
		if n < 3 {
			return errors.New("not yet")
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("err=%v after %d tries, want nil after 3", err, n)
	}

	calls := 0
	start := time.Now()
	err = Eventually(50*time.Millisecond, 5*time.Millisecond, func() error { calls++; return errors.New("never") })
	if err == nil || !strings.Contains(err.Error(), "never") {
		t.Fatalf("a deadline must return the LAST error, got %v", err)
	}
	if calls < 2 || time.Since(start) > 2*time.Second {
		t.Fatalf("calls=%d elapsed=%v: must retry and stay bounded", calls, time.Since(start))
	}
	// The bound is hard: an attempt that never returns cannot hold the poll.
	start = time.Now()
	err = Eventually(50*time.Millisecond, 5*time.Millisecond, func() error { time.Sleep(3 * time.Second); return nil })
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("a hung attempt must end the poll at the deadline: err=%v after %v", err, time.Since(start))
	}
	if err := Eventually(0, time.Millisecond, func() error { return nil }); err != nil {
		t.Fatalf("one attempt is always made, got %v", err)
	}
}

func TestRedactError(t *testing.T) {
	err := errors.New(`ssh node-2 "LV_TOKEN=abc123secret lv role grant": exit 1: denied abc123secret`)
	got := RedactError(err, "abc123secret", "")
	if strings.Contains(got.Error(), "abc123secret") {
		t.Fatalf("secret survived: %v", got)
	}
	if !strings.Contains(got.Error(), "denied") {
		t.Fatalf("the message must survive redaction: %v", got)
	}
	if RedactError(nil, "x") != nil {
		t.Fatal("nil stays nil")
	}
}

func TestSections(t *testing.T) {
	got := Sections("##a\nline1\nline2\n##b\n\n##c\nx : 1\n")
	if got["a"] != "line1\nline2\n" || got["b"] != "\n" || got["c"] != "x : 1\n" || len(got) != 3 {
		t.Fatalf("sections = %q", got)
	}
}

func TestKV(t *testing.T) {
	got := KV("Scheduler      : posix\ncpu_shares     : 2048\nglobal_quota   : 100000\n\nrandom line\ninbound.average: 4000\n")
	for k, v := range map[string]string{"cpu_shares": "2048", "global_quota": "100000", "inbound.average": "4000", "Scheduler": "posix"} {
		if got[k] != v {
			t.Errorf("KV[%q] = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
}

func TestCPUQuota(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		q, p  int64
		ok    bool
	}{
		{"v2 libvirt sub-cgroup", map[string]string{"cpu.max": "max 100000", "libvirt/cpu.max": "150000 100000"}, 150000, 100000, true},
		{"v2 scope", map[string]string{"cpu.max": "100000 100000"}, 100000, 100000, true},
		{"v2 unlimited", map[string]string{"cpu.max": "max 100000", "libvirt/cpu.max": "max 100000"}, 0, 0, false},
		{"v1 sub-cgroup", map[string]string{"cpu.cfs_quota_us": "-1", "libvirt/cpu.cfs_quota_us": "100000", "libvirt/cpu.cfs_period_us": "100000"}, 100000, 100000, true},
		{"v1 unlimited", map[string]string{"cpu.cfs_quota_us": "-1", "libvirt/cpu.cfs_quota_us": "-1", "libvirt/cpu.cfs_period_us": "100000"}, 0, 0, false},
		{"nothing", map[string]string{}, 0, 0, false},
	} {
		q, p, ok := CPUQuota(c.files)
		if q != c.q || p != c.p || ok != c.ok {
			t.Errorf("%s: got (%d, %d, %v), want (%d, %d, %v)", c.name, q, p, ok, c.q, c.p, c.ok)
		}
	}
}

func TestHTBRates(t *testing.T) {
	tc := "class htb 1:1 root leaf 8001: prio 0 rate 32Mbit ceil 32Mbit burst 1600b cburst 1600b\n" +
		"class htb 1:2 parent 1:1 leaf 8002: prio 0 rate 16Mbit ceil 16Mbit\n" +
		"class fq_codel 8001:1 parent 8001:\n"
	got := HTBRates(tc)
	if len(got) != 2 || got[0] != "32Mbit" || got[1] != "16Mbit" {
		t.Fatalf("rates = %v", got)
	}
	if HTBRates("") != nil {
		t.Fatal("no classes, no rates")
	}
}

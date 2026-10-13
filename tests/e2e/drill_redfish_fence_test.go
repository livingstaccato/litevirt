package e2e

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// TestDrill_RedfishFenceRecordsFencedAndRecovers: a host configured with the
// redfish fence strategy is fenced through a real Redfish service (the lab's
// sushy-tools, which powers lab nodes off and on through the lab power agent)
// when its peers see it down. The fence is VERIFIED — PowerState Off observed —
// so the host is recorded 'fenced', not 'offline', its fencing_log row is
// redfish/fenced, the BMC independently reads Off, and its workloads are
// recovered exactly once. It is then powered back on through the same BMC
// (ResetType On) and returns without a second copy anywhere.
//
// Opt-in, on top of the lab variables (tests/e2e/README.md):
//
//	E2E_REDFISH_ENDPOINT   the BMC's base URL, e.g. https://10.77.0.40:8000
//	E2E_REDFISH_HOST       the lab node that BMC powers (the victim)
//	E2E_REDFISH_USER       Redfish user
//	E2E_REDFISH_PASS_FILE  file holding the Redfish password (preferred), or
//	E2E_REDFISH_PASS       the password itself. Either way it reaches lv on
//	                       the node through ssh's stdin (--redfish-pass-file -),
//	                       never through any argv
//	E2E_REDFISH_SYSTEM_ID  the victim's ComputerSystem Id (needed when the
//	                       service lists more than one system)
//	E2E_REDFISH_AUTH       session (default) or basic
//	E2E_REDFISH_CA_FILE    PEM the BMC certificate chains to, on the machine
//	                       running the test (copied to the node that runs lv)
//
// The machine running the test must reach the endpoint too: it reads the power
// state and powers the victim back on itself.
func TestDrill_RedfishFenceRecordsFencedAndRecovers(t *testing.T) {
	endpoint := os.Getenv("E2E_REDFISH_ENDPOINT")
	victim := os.Getenv("E2E_REDFISH_HOST")
	if endpoint == "" || victim == "" {
		t.Skip("set E2E_REDFISH_ENDPOINT and E2E_REDFISH_HOST (and the lab variables) to run the Redfish fence drill")
	}
	cfg := fence.RedfishConfig{
		Endpoint: endpoint,
		User:     os.Getenv("E2E_REDFISH_USER"),
		Pass:     redfishDrillPass(t),
		SystemID: os.Getenv("E2E_REDFISH_SYSTEM_ID"),
		Auth:     os.Getenv("E2E_REDFISH_AUTH"),
	}
	if f := os.Getenv("E2E_REDFISH_CA_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("E2E_REDFISH_CA_FILE: %v", err)
		}
		cfg.CACert = string(b)
	}
	if err := fence.ValidateRedfishConfig(cfg); err != nil {
		t.Fatalf("Redfish settings: %v", err)
	}

	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	q := l.hosts[0]
	if q == victim {
		q = l.hosts[1]
	}
	marker := health.ActivationMarkerPath("/var/lib/litevirt", capabilities.ReleaseToken)
	if out, err := l.ssh(q, 20*time.Second, "test -f "+shellQuote(marker)+" && echo LATCHED"); err != nil || !strings.Contains(out, "LATCHED") {
		t.Skipf("%s has not latched on %s (roll every node to this build first): %v", capabilities.ReleaseToken, q, err)
	}

	// Pre-flight, from here: TLS, credentials and the system all check out,
	// and the victim is on, before the cluster is asked to rely on them.
	ctx := context.Background()
	if st, err := fence.RedfishPowerState(ctx, cfg); err != nil || st != "On" {
		t.Fatalf("pre-flight: %s's ComputerSystem reads %q (%v), want On", victim, st, err)
	}

	prev := l.fenceStrategy(q, victim)
	args := []string{"host", "config", victim, "--fence-strategy", "redfish",
		"--redfish-endpoint", cfg.Endpoint, "--redfish-user", cfg.User, "--redfish-pass-file", "-"}
	if cfg.SystemID != "" {
		args = append(args, "--redfish-system-id", cfg.SystemID)
	}
	if cfg.Auth != "" {
		args = append(args, "--redfish-auth", cfg.Auth)
	}
	if cfg.CACert != "" {
		const caPath = "/tmp/e2e-redfish-ca.pem"
		l.putFile(q, caPath, cfg.CACert)
		args = append(args, "--redfish-ca-file", caPath)
	}
	if out, err := l.lvWithStdin(q, cfg.Pass+"\n", args...); err != nil {
		t.Fatalf("lv host config %s (redfish): %v: %s", victim, err, out)
	}
	t.Cleanup(func() {
		if prev == "" || prev == "redfish" {
			prev = "best-effort"
		}
		if _, err := l.lv(q, "host", "config", victim, "--fence-strategy", prev, "--clear-redfish"); err != nil {
			t.Errorf("restore %s's fence strategy %s: %v", victim, prev, err)
		}
	})
	if got := l.fenceStrategy(q, victim); got != "redfish" {
		t.Fatalf("%s fence strategy = %q after config, want redfish", victim, got)
	}

	l.createVMs(q, "rf", victim)
	keys := l.relocatableOn(q, b, victim)
	l.mark("drill redfish: victim %s (fence redfish via %s), recoverable on victim %v", victim, cfg.Endpoint, keys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, keys, victim)

	thaw := l.freezeDaemon(victim)
	t.Cleanup(func() { _ = thaw() })
	frozen := time.Now()
	if !l.waitHostNot(q, victim, "HOST_ACTIVE", hostDownBy+time.Minute) {
		t.Fatalf("%s was never marked down after its daemon froze", victim)
	}

	recovered := waitEach(s, frozen, recoverBy, keys, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && hs[0] != victim
	})
	for _, k := range keys {
		if _, ok := recovered[k]; !ok {
			t.Errorf("%s not recovered off %s within %v of a Redfish fence\n  %s", k, victim, recoverBy, s.last())
		}
	}

	fences := l.mustSQL(q, "SELECT method, result, detail FROM fencing_log WHERE host_name='"+victim+"' AND timestamp >= '"+since+"'")
	l.saveEvidence("redfish-fencing-log.txt", redfishRows(fences))
	verified := false
	for _, f := range fences {
		if len(f) >= 2 && f[0] == "redfish" && f[1] == "fenced" {
			verified = true
		}
		if len(f) >= 3 && cfg.Pass != "" && strings.Contains(f[2], cfg.Pass) {
			t.Errorf("a fencing_log detail carries the BMC password")
		}
	}
	if !verified {
		t.Errorf("no redfish/fenced fencing_log row for %s since %s: %v", victim, since, fences)
	}
	state := l.mustSQL(q, "SELECT COALESCE((SELECT state FROM host_membership WHERE host_name='"+victim+
		"'), (SELECT state FROM hosts WHERE name='"+victim+"' AND deleted_at IS NULL))")
	if len(state) != 1 || state[0][0] != "fenced" {
		t.Errorf("%s is recorded %v after its Redfish fence, want fenced (a verified power-off)", victim, state)
	}
	if st, err := fence.RedfishPowerState(ctx, cfg); err != nil || st != "Off" {
		t.Errorf("the BMC reads %s as %q (%v) after the fence, want Off", victim, st, err)
	}
	// Its return, through the same BMC.
	if err := fence.RedfishPowerOn(ctx, cfg); err != nil {
		t.Errorf("Redfish power on %s: %v; falling back to the lab power agent", victim, err)
		if err := l.powerOn(victim); err != nil {
			t.Errorf("power on %s: %v", victim, err)
		}
	} else {
		l.mark("power: %s on via Redfish", victim)
		if err := l.waitDaemon(victim, 6*time.Minute); err != nil {
			t.Errorf("%s did not come back after a Redfish power on: %v", victim, err)
		}
	}
	l.waitAllActive(q, 6*time.Minute)
	time.Sleep(returnWatch)
	assertExactlyOnceNow(t, s, keys)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
}

func redfishRows(rows [][]string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(strings.Join(r, " | "))
		b.WriteString("\n")
	}
	return b.String()
}

// redfishDrillPass is the BMC password from E2E_REDFISH_PASS_FILE or
// E2E_REDFISH_PASS.
func redfishDrillPass(t *testing.T) string {
	t.Helper()
	if f := os.Getenv("E2E_REDFISH_PASS_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("E2E_REDFISH_PASS_FILE: %v", err)
		}
		return strings.TrimRight(string(b), "\r\n")
	}
	return os.Getenv("E2E_REDFISH_PASS")
}

// lvWithStdin runs the CLI on host with stdin fed from in, so a secret reaches
// it without appearing in any argv (ours, ssh's, or the remote shell's).
func (l *lab) lvWithStdin(host, in string, args ...string) (string, error) {
	q := []string{shellQuote(l.lvPath)}
	for _, a := range args {
		q = append(q, shellQuote(a))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh", append(l.sshArgs(host), strings.Join(q, " "))...)
	c.Stdin = strings.NewReader(in)
	c.WaitDelay = 2 * time.Second
	out, err := c.CombinedOutput()
	return string(out), err
}

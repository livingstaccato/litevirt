package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Completion follows the actual owned enrollment start, while its setup tail
// enables the unit with restart deferred until installation/configuration ends.
func TestHostInitLocal_SaysTheDaemonIsRunning(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "started", true: "start-failed"}[failStart], func(t *testing.T) {
			addOperatorPKI(t)
			useConfig(t, "")
			t.Setenv("SUDO_USER", "")
			dir := t.TempDir()
			oldEtc, oldConfig := etcLitevirtDir, daemonConfigPath
			etcLitevirtDir, daemonConfigPath = filepath.Join(dir, "etc"), filepath.Join(dir, "config.yaml")
			t.Cleanup(func() { etcLitevirtDir, daemonConfigPath = oldEtc, oldConfig })
			out, err := os.Create(filepath.Join(dir, "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			oldStdout := os.Stdout
			os.Stdout = out
			t.Cleanup(func() { os.Stdout = oldStdout })
			calls := filepath.Join(dir, "calls")
			t.Setenv("ENROLL_TEST_CALLS", calls)
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ENROLL_TEST_CALLS\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			at := strings.LastIndex(setupScriptContent, "systemctl enable litevirt.service")
			if at < 0 {
				t.Fatal("production setup service tail missing")
			}
			_, ops, events := enrollmentFixture(t)
			ops.configure = func(ctx context.Context, _ HostEnrollmentRequest) error {
				*events = append(*events, "configure")
				cmd := exec.CommandContext(ctx, "bash", "-s")
				cmd.Stdin = strings.NewReader(setupScriptContent[at:])
				cmd.Env = append(os.Environ(), "LITEVIRT_DEFER_START=1")
				if b, err := cmd.CombinedOutput(); err != nil {
					return errors.New(string(b) + err.Error())
				}
				if got := string(mustRead(t, calls)); got != "enable litevirt.service\n" {
					t.Fatalf("setup did not enable with start deferred: %q", got)
				}
				return nil
			}
			ops.start = func(ctx context.Context, _ HostEnrollmentRequest) error {
				*events = append(*events, "start")
				if info, err := out.Stat(); err != nil || info.Size() != 0 {
					t.Fatal("completion was printed before owned start succeeded", err)
				}
				if failStart {
					return errors.New("start refused")
				}
				return exec.CommandContext(ctx, "systemctl", "restart", "litevirt.service").Run()
			}
			oldEnroll := enrollLocalHost
			enrollLocalHost = func(ctx context.Context, r HostEnrollmentRequest) error { return runHostEnrollment(ctx, r, ops) }
			t.Cleanup(func() { enrollLocalHost = oldEnroll })
			err = HostInitLocal(context.Background(), "node-5", "127.0.0.1", false)
			if (err != nil) != failStart {
				t.Fatalf("local init start failure=%v: %v", failStart, err)
			}
			if got := strings.Join(*events, ","); got != "prepare,stop,binary,configure,start" {
				t.Fatalf("owned installation/configuration/start order: %s", got)
			}
			got := string(mustRead(t, out.Name()))
			if failStart {
				if got != "" {
					t.Fatalf("failed start printed completion: %q", got)
				}
				return
			}
			if calls := string(mustRead(t, calls)); calls != "enable litevirt.service\nrestart litevirt.service\n" {
				t.Fatalf("actual service order: %q", calls)
			}
			for _, bad := range []string{"Start the daemon", "enable --now", "litevirt daemon"} {
				if strings.Contains(got, bad) {
					t.Errorf("completion tells the operator to start a running daemon: %q", got)
				}
			}
			if !strings.Contains(got, "enabled and running") {
				t.Errorf("output = %q, want running completion", got)
			}
		})
	}
}

// enforcementSnippet is the setup script's enforcement step, writing to cfg
// instead of /etc/litevirt/config.yaml.
func enforcementSnippet(t *testing.T, cfg string) string {
	t.Helper()
	s, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(s, `if [ -n "${ENFORCEMENT_B64:-}" ]; then`)
	if start < 0 {
		t.Fatal("setup script has no enforcement step")
	}
	end := strings.Index(s[start:], "\nfi\n")
	if end < 0 {
		t.Fatal("enforcement step does not end")
	}
	return strings.ReplaceAll(s[start:start+end+len("\nfi\n")], "/etc/litevirt/config.yaml", cfg)
}

// The same step printed "enforcement config propagated from the adding
// node" during an init, which has no adding node. Run as setup runs it: an
// init (LITEVIRT_GENESIS=1, foundingSetupEnv) names the cluster it founds,
// an add the adding node; both write the block.
//
// Mutation: drop the LITEVIRT_GENESIS branch — "init" prints the adding node.
func TestSetupScript_EnforcementMessageNamesItsSource(t *testing.T) {
	block := "enforcement:\n  audit_signature: true\n"
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"init", []string{foundingSetupEnv}, "enforcement config written for the cluster this host founds"},
		{"add", nil, "enforcement config propagated from the adding node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			cmd := exec.Command("bash", "-c", enforcementSnippet(t, cfg))
			cmd.Env = append(append(os.Environ(), "ENFORCEMENT_B64="+base64.StdEncoding.EncodeToString([]byte(block))), tc.env...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if strings.TrimSpace(string(out)) != tc.want {
				t.Errorf("printed %q, want %q", out, tc.want)
			}
			if got := string(mustRead(t, cfg)); got != block {
				t.Errorf("wrote %q, want the block", got)
			}
		})
	}
}

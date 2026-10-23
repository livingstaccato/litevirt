package cli

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Lab 4 finding 6: after `lv host init --local`, whose setup script has
// already run `systemctl enable` and `restart litevirt.service`, the CLI
// told the operator to start the daemon (`systemctl enable --now`, or run
// `litevirt daemon` by hand beside the running service).
//
// Mutation: put the "Start the daemon" line back — this goes red.
func TestHostInitLocal_SaysTheDaemonIsRunning(t *testing.T) {
	s, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "systemctl enable litevirt.service\nsystemctl restart litevirt.service\n") {
		t.Fatal("the setup script no longer starts the daemon: this output would be wrong")
	}
	var out bytes.Buffer
	printLocalInitDone(&out, "node-5")
	got := out.String()
	for _, bad := range []string{"Start the daemon", "enable --now", "litevirt daemon"} {
		if strings.Contains(got, bad) {
			t.Errorf("output tells the operator to start a daemon setup started: %q", got)
		}
	}
	if !strings.Contains(got, "enabled and running") {
		t.Errorf("output = %q, want it to say the daemon runs", got)
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

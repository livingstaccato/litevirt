package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// config.yaml may carry an auth realm's inline bind_password or client_secret,
// and /etc/litevirt is searchable by every local user (the fence agent's forced
// command needs o+x), so a config at the umask's 0644 hands those secrets to
// anyone with a shell on the host. Every writer keeps it owner-only.

const configWithInlineSecret = "host_name: \"node-1\"\njoin_peers: []\n" +
	"auth:\n  realms:\n    - name: corp\n      kind: ldap\n      ldap:\n        url: ldaps://dc\n        bind_password: hunter2\n"

// Mutation: os.WriteFile(cfgPath, out, 0644) in place of secretfile.Write —
// the mode is 0644 and the inode is the old one.
func TestEnsureLocalPeer_RewritesOwnerOnlyByRename(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(configWithInlineSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946); err != nil {
		t.Fatalf("ensureLocalPeer: %v", err)
	}

	after, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o600 {
		t.Errorf("config.yaml is %04o after the rewrite, want 0600: it can hold an inline "+
			"auth secret and /etc/litevirt is searchable by every user", after.Mode().Perm())
	}
	// A new inode means the content was renamed into place: a crash part-way
	// through leaves the old config, never a truncated one.
	if os.SameFile(before, after) {
		t.Error("config.yaml was rewritten in place (same inode), so a crash or a full disk " +
			"mid-write leaves it empty or partial")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(cfgPath), ".config.yaml.tmp*")); len(left) != 0 {
		t.Errorf("temp files left beside the config: %v", left)
	}
}

// An operator's tighter mode is kept: the cap never widens.
func TestEnsureLocalPeer_KeepsATighterMode(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(configWithInlineSecret), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946); err != nil {
		t.Fatalf("ensureLocalPeer: %v", err)
	}
	if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o400 {
		t.Errorf("config.yaml is %04o, want the operator's 0400 kept", st.Mode().Perm())
	}
}

// A symlinked config (config management) is rewritten at its target; the
// rename must not replace the link with a regular file.
func TestEnsureLocalPeer_ASymlinkedConfigStaysALink(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "cm", "litevirt.yaml")
	if err := os.MkdirAll(filepath.Dir(managed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte(configWithInlineSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(managed, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalPeer(link, "10.0.50.11", 7946); err != nil {
		t.Fatalf("ensureLocalPeer: %v", err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the config symlink was replaced by a file (%v)", err)
	}
	if !strings.Contains(string(mustRead(t, managed)), "10.0.50.11:7946") {
		t.Errorf("the link's target was not updated:\n%s", mustRead(t, managed))
	}
}

// Two `lv host add` runs on one machine each read the config, add their peer
// and write it back. Without the lock, the later write drops the earlier peer.
//
// Mutation: drop the configLock call — peers go missing.
func TestEnsureLocalPeer_ConcurrentAddsKeepEveryPeer(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(configWithInlineSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- ensureLocalPeer(cfgPath, fmt.Sprintf("10.0.51.%d", i+1), 7946)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("ensureLocalPeer: %v", err)
		}
	}
	got := string(mustRead(t, cfgPath))
	var lost []string
	for i := 0; i < n; i++ {
		if p := fmt.Sprintf("10.0.51.%d:7946", i+1); !strings.Contains(got, p) {
			lost = append(lost, p)
		}
	}
	if len(lost) != 0 {
		t.Errorf("concurrent adds lost %d of %d join_peers: %v", len(lost), n, lost)
	}
}

// The host-init setup script writes config.yaml owner-only on every path: a new
// file, an existing loose one it overwrites, and the one `lv host add`
// installed and setup keeps. It runs the script's own text, with the path
// pointed at a temp dir, under the common 022 umask.
//
// "new, umask only" runs the script without its final chmod, so it pins that
// a new file is never 0644 even for the moment before that chmod.
//
// Mutations: drop the `umask 077` subshell — "new, umask only" is 0644; drop
// the trailing chmod — "existing" and "kept" stay 0644.
func TestConfigWriteScript_WritesOwnerOnly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	enf := base64.StdEncoding.EncodeToString([]byte("enforcement:\n    audit_signature: true\n"))
	for _, tc := range []struct {
		name      string
		seed      *os.FileMode
		installed bool
		noChmod   bool
		want      os.FileMode
	}{
		{"new", nil, false, false, 0o600},
		{"new, umask only", nil, false, true, 0o600},
		{"existing", modePtr(0o644), false, false, 0o600},
		{"kept", modePtr(0o644), true, false, 0o600},
		{"kept tighter", modePtr(0o400), true, false, 0o400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.yaml")
			if tc.seed != nil {
				if err := os.WriteFile(cfg, []byte(configWithInlineSecret), *tc.seed); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(cfg, *tc.seed); err != nil {
					t.Fatal(err)
				}
			}
			script := configWriteScript
			if tc.noChmod {
				const chmod = "chmod go-rwx /etc/litevirt/config.yaml"
				if !strings.Contains(script, chmod) {
					t.Fatalf("configWriteScript has no %q", chmod)
				}
				script = strings.ReplaceAll(script, chmod, ":")
			}
			script = strings.ReplaceAll(script, "/etc/litevirt/config.yaml", cfg)
			cmd := exec.Command("bash", "-euo", "pipefail", "-c", "umask 022\n"+script)
			cmd.Env = append(os.Environ(), "HOST_NAME=node-9", "UI_TLS=auto", "ENFORCEMENT_B64="+enf)
			if tc.installed {
				cmd.Env = append(cmd.Env, "CONFIG_INSTALLED=1")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("script: %v\n%s", err, out)
			}
			st, err := os.Stat(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != tc.want {
				t.Errorf("config.yaml is %04o, want %04o", st.Mode().Perm(), tc.want)
			}
			body := string(mustRead(t, cfg))
			if !tc.installed && (!strings.Contains(body, `host_name: "node-9"`) || !strings.Contains(body, "audit_signature: true")) {
				t.Errorf("the script did not write the config:\n%s", body)
			}
		})
	}
	if !strings.Contains(setupScriptContent, configWriteScript) {
		t.Fatal("setupScriptContent does not include configWriteScript")
	}
}

func modePtr(m os.FileMode) *os.FileMode { return &m }

package daemon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, y string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", p)
	return LoadConfig()
}

const dns01Base = `host_name: "n"
acme:
  directory_url: "https://ca.example/dir"
  domains: ["ui.example.com", "*.hv.example.com"]
  challenge: dns-01
  dns:
    provider: rfc2136
    rfc2136:
      nameserver: "10.0.0.53"
      zone: "example.com."
      tsig_key_name: "k"
      tsig_secret_path: "/etc/litevirt/acme-tsig.key"
`

// A dns-01 block that cannot work fails load, naming the field — not hours
// later at the first issuance. Above all, no TSIG means no updates.
//
// Mutations: drop the tsig_secret_path requirement — the keyless block loads;
// drop the zone-suffix check — the out-of-zone domain loads.
func TestLoadConfig_ACMEDNS01Validation(t *testing.T) {
	if _, err := loadYAML(t, dns01Base); err != nil {
		t.Fatalf("a valid dns-01 block was refused: %v", err)
	}
	for name, tc := range map[string]struct{ from, to, want string }{
		"no tsig secret": {`      tsig_secret_path: "/etc/litevirt/acme-tsig.key"` + "\n", "", "tsig_secret_path"},
		"out of zone":    {`"*.hv.example.com"`, `"ui.example.org"`, "not in acme.dns.rfc2136.zone"},
		"bad provider":   {"provider: rfc2136", "provider: route53", "not a supported provider"},
		"bad challenge":  {"challenge: dns-01", "challenge: tls-alpn-01", "acme.challenge"},
		"bad algorithm":  {`tsig_key_name: "k"`, "tsig_key_name: \"k\"\n      tsig_algorithm: hmac-md5", "tsig_algorithm"},
	} {
		y := strings.Replace(dns01Base, tc.from, tc.to, 1)
		if y == dns01Base {
			t.Fatalf("%s: fixture edit did not apply", name)
		}
		_, err := loadYAML(t, y)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error naming %q", name, err, tc.want)
		}
	}
	if _, err := loadYAML(t, "host_name: n\nui_tls: always\n"); err == nil {
		t.Error("ui_tls: always loaded")
	}
	for _, v := range []string{"auto", "on", `""`} {
		if _, err := loadYAML(t, "host_name: n\nui_tls: "+v+"\n"); err != nil {
			t.Errorf("ui_tls: %s refused: %v", v, err)
		}
	}
}

// The TSIG secret is read tightened to 0600, from a bare secret or a BIND key
// file, and an error never echoes the file.
//
// Mutation: drop the TightenKeyMode call — the file stays 0644.
func TestReadTSIGSecret(t *testing.T) {
	dir := t.TempDir()
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	bare := filepath.Join(dir, "bare")
	if err := os.WriteFile(bare, []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTSIGSecret(bare)
	if err != nil || got != secret {
		t.Fatalf("bare: %q, %v", got, err)
	}
	if fi, _ := os.Stat(bare); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the TSIG secret file was left mode %04o", fi.Mode().Perm())
	}
	bind := filepath.Join(dir, "bind.key")
	keyFile := "key \"litevirt-acme\" {\n\talgorithm hmac-sha256;\n\tsecret \"" + secret + "\";\n};\n"
	if err := os.WriteFile(bind, []byte(keyFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readTSIGSecret(bind); err != nil || got != secret {
		t.Fatalf("BIND key file: %q, %v", got, err)
	}
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not*base64!secretvalue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTSIGSecret(junk); err == nil || strings.Contains(err.Error(), "secretvalue") {
		t.Fatalf("junk secret: %v", err)
	}
}

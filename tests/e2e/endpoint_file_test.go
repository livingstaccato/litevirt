package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLab_EndpointFileServesANonRootLv: config.yaml is root's and 0600, so a
// non-root lv on a node finds its daemon through /run/litevirt/endpoint, which
// the daemon writes at start. The unit tests pin the writer and the reader;
// only a real node shows the daemon wrote it where lv looks, as root, with the
// node's own values, and that an unprivileged lv then connects without
// falling back to the defaults.
func TestLab_EndpointFileServesANonRootLv(t *testing.T) {
	l := newLab(t)
	h := l.hosts[0]
	const short = 30 * time.Second

	// The file: root:root 0644, regular, in a root-owned directory only root
	// can write.
	if got := strings.TrimSpace(l.mustSSH(h, short, "stat -c '%u %g %a %F' /run/litevirt/endpoint")); got != "0 0 644 regular file" {
		t.Fatalf("/run/litevirt/endpoint on %s: %q, want root:root 0644 regular file", h, got)
	}
	dir := strings.Fields(l.mustSSH(h, short, "stat -c '%u %a' /run/litevirt"))
	mode, merr := uint64(0), error(nil)
	if len(dir) == 2 {
		mode, merr = strconv.ParseUint(dir[1], 8, 32)
	}
	if len(dir) != 2 || merr != nil || dir[0] != "0" || mode&0o022 != 0 || mode&0o005 != 0o005 {
		t.Fatalf("/run/litevirt on %s: %v, want root-owned, writable by root alone, and searchable by every user", h, dir)
	}

	// Its values are the node's: grpc_port and pki_dir from config.yaml, or
	// their defaults, and nothing else.
	wantPort := strings.TrimSpace(l.mustSSH(h, short, `awk '/^grpc_port:/{print $2}' /etc/litevirt/config.yaml`))
	if wantPort == "" {
		wantPort = "7443"
	}
	wantPKI := strings.TrimSpace(l.mustSSH(h, short, `awk '/^pki_dir:/{print $2}' /etc/litevirt/config.yaml`))
	if wantPKI == "" {
		wantPKI = "/etc/litevirt/pki"
	}
	got := l.mustSSH(h, short, "cat /run/litevirt/endpoint")
	if want := fmt.Sprintf("grpc_port: %s\npki_dir: %s\n", wantPort, wantPKI); got != want {
		t.Fatalf("/run/litevirt/endpoint on %s = %q, want %q", h, got, want)
	}

	// A non-root user with a CLI bundle and no LV_HOST: lv connects to the
	// local daemon through the file, with no fallback notice.
	const user = "lv-e2e-endpoint"
	setup := fmt.Sprintf(`set -e
id -u %[1]s >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin %[1]s
home=$(getent passwd %[1]s | cut -d: -f6)
src=/etc/litevirt/pki
[ -f "$src/client.crt" ] || src=/root/.config/litevirt/pki
install -d -o %[1]s -m 0700 "$home/.config" "$home/.config/litevirt" "$home/.config/litevirt/pki"
install -o %[1]s -m 0644 "$src/ca.crt" "$src/client.crt" "$home/.config/litevirt/pki/"
install -o %[1]s -m 0600 "$src/client.key" "$home/.config/litevirt/pki/"
echo "$home"`, user)
	home := strings.TrimSpace(l.mustSSH(h, short, setup))
	t.Cleanup(func() { _, _ = l.ssh(h, short, "userdel -r "+user+" 2>/dev/null; true") })

	out := l.mustSSH(h, 2*time.Minute, fmt.Sprintf(
		"cd / && runuser -u %s -- env -u LV_HOST -u LV_TOKEN -u LV_CONFIG_DIR HOME=%s %s ls 2>&1; echo rc=$?",
		user, shellQuote(home), shellQuote(l.lvPath)))
	for _, bad := range []string{"using the defaults", "ignoring the daemon's endpoint file", "LV_HOST not set", "cannot be read by this user"} {
		if strings.Contains(out, bad) {
			t.Fatalf("non-root lv on %s fell back (%q):\n%s", h, bad, out)
		}
	}
	// Reached the daemon: the command ran (a bearerless lv-cli certificate is
	// served while strict mTLS identity is off), or the daemon's own refusal
	// of that certificate once it is on. Anything about the TLS handshake
	// itself, or no listener, is a failure.
	answered := strings.Contains(out, "rc=0") ||
		strings.Contains(out, "client certificate without a session: run `lv login`")
	for _, bad := range []string{"x509:", "tls:", "connection refused"} {
		if strings.Contains(out, bad) {
			answered = false
		}
	}
	if !answered {
		t.Fatalf("non-root lv on %s did not reach the daemon over mTLS:\n%s", h, out)
	}
}

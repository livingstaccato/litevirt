package pki

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests run real QEMU migrations over QEMU's own TLS (GnuTLS), with
// credential sets laid out the way InstallQemuMigrationTLS lays them out, for
// each pairing a migration-CA rotation produces. They prove what the rotation
// assumes of QEMU: a ca-cert.pem holding two CAs is loaded whole, so hosts on
// the old and the new CA keep migrating through trust-both and reissue, and a
// pair with no CA in common is refused at the handshake.
//
// They need qemu-system-x86_64 (TCG, no KVM, no root, no libvirt) and run
// only with LITEVIRT_QEMU_TLS=1.

type qemuTLSCA struct{ cert, key string }

func newQemuTLSCA(t *testing.T) qemuTLSCA {
	t.Helper()
	dir := t.TempDir()
	ca := qemuTLSCA{filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")}
	if err := GenerateMigrationCA(ca.cert, ca.key); err != nil {
		t.Fatal(err)
	}
	return ca
}

// qemuTLSDir lays out QEMU's TLS directory: trust (the CAs, in order) as
// ca-cert.pem, and one certificate from issuer for 127.0.0.1 as both server
// and client pair, as InstallQemuMigrationTLS does.
func qemuTLSDir(t *testing.T, issuer qemuTLSCA, trust ...qemuTLSCA) string {
	t.Helper()
	src := t.TempDir()
	cert, key := filepath.Join(src, "host.crt"), filepath.Join(src, "host.key")
	if err := GenerateHostCert(issuer.cert, issuer.key, cert, key, "node", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	var bundle []byte
	for _, ca := range trust {
		bundle = append(bundle, mustRead(t, ca.cert)...)
	}
	if _, _, err := ValidateMigrationCredentials(bundle, mustRead(t, cert), mustRead(t, key), time.Now()); err != nil {
		t.Fatalf("the test's own set does not validate: %v", err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"ca-cert.pem": bundle, "server-cert.pem": mustRead(t, cert), "client-cert.pem": mustRead(t, cert),
		"server-key.pem": mustRead(t, key), "client-key.pem": mustRead(t, key),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type qmp struct {
	conn net.Conn
	r    *bufio.Reader
}

func (q *qmp) cmd(t *testing.T, name string, args map[string]any) (map[string]any, error) {
	t.Helper()
	req := map[string]any{"execute": name}
	if args != nil {
		req["arguments"] = args
	}
	b, _ := json.Marshal(req)
	if _, err := q.conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, err
		}
		if _, ok := m["event"]; ok {
			continue
		}
		if e, ok := m["error"]; ok {
			return nil, fmt.Errorf("%s: %v", name, e)
		}
		ret, _ := m["return"].(map[string]any)
		return ret, nil
	}
}

// startQEMU starts a paused, unaccelerated QEMU with tls0 for endpoint, and
// returns its QMP connection, capabilities negotiated.
func startQEMU(t *testing.T, sockDir, name, tlsDir, endpoint string, incoming bool) *qmp {
	t.Helper()
	sock := filepath.Join(sockDir, name+".qmp")
	args := []string{"-nodefaults", "-display", "none", "-machine", "q35", "-accel", "tcg", "-m", "32", "-S",
		"-object", fmt.Sprintf("tls-creds-x509,id=tls0,dir=%s,endpoint=%s,verify-peer=on", tlsDir, endpoint),
		"-qmp", "unix:" + sock + ",server=on,wait=off"}
	if incoming {
		args = append(args, "-incoming", "defer")
	}
	cmd := exec.Command("qemu-system-x86_64", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("%s stderr: %s", name, stderr.String())
		}
	})
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("%s QMP: %v (stderr: %s)", name, err, stderr.String())
	}
	t.Cleanup(func() { conn.Close() })
	q := &qmp{conn: conn, r: bufio.NewReader(conn)}
	if _, err := q.r.ReadBytes('\n'); err != nil { // greeting
		t.Fatal(err)
	}
	if _, err := q.cmd(t, "qmp_capabilities", nil); err != nil {
		t.Fatal(err)
	}
	return q
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// migrateOverTLS migrates a paused guest from a QEMU holding srcDir to one
// holding dstDir over QEMU's TLS, and returns the source's final status
// ("completed" or "failed") and its error description.
func migrateOverTLS(t *testing.T, srcDir, dstDir string) (string, string) {
	t.Helper()
	sockDir, err := os.MkdirTemp(os.Getenv("HOME"), "qtls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	dst := startQEMU(t, sockDir, "dst", dstDir, "server", true)
	src := startQEMU(t, sockDir, "src", srcDir, "client", false)
	uri := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	for _, q := range []*qmp{dst, src} {
		if _, err := q.cmd(t, "migrate-set-parameters", map[string]any{"tls-creds": "tls0"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dst.cmd(t, "migrate-incoming", map[string]any{"uri": uri}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.cmd(t, "migrate", map[string]any{"uri": uri}); err != nil {
		return "failed", err.Error()
	}
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		info, err := src.cmd(t, "query-migrate", nil)
		if err != nil {
			t.Fatal(err)
		}
		switch st, _ := info["status"].(string); st {
		case "completed":
			return st, ""
		case "failed", "cancelled":
			desc, _ := info["error-desc"].(string)
			return st, desc
		}
	}
	t.Fatal("migration neither completed nor failed in 60s")
	return "", ""
}

func TestQemuMigrationTLS_RotationPairings(t *testing.T) {
	if os.Getenv("LITEVIRT_QEMU_TLS") != "1" {
		t.Skip("set LITEVIRT_QEMU_TLS=1 to run real QEMU migrations over TLS")
	}
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Fatal("LITEVIRT_QEMU_TLS=1 but qemu-system-x86_64 is not installed")
	}
	old, nw := newQemuTLSCA(t), newQemuTLSCA(t)
	for _, tc := range []struct {
		name     string
		src, dst func() string
		want     string
	}{
		// Before the rotation: one CA everywhere.
		{"before", func() string { return qemuTLSDir(t, old, old) }, func() string { return qemuTLSDir(t, old, old) }, "completed"},
		// trust-both, half pushed: the set check refuses this pair, but QEMU
		// would carry it either way.
		{"trust-both: updated to not yet", func() string { return qemuTLSDir(t, old, old, nw) }, func() string { return qemuTLSDir(t, old, old) }, "completed"},
		{"trust-both: not yet to updated", func() string { return qemuTLSDir(t, old, old) }, func() string { return qemuTLSDir(t, old, old, nw) }, "completed"},
		// reissue, half pushed: one bundle everywhere, certificates from
		// either CA. The set check passes this pair, so QEMU must carry it.
		{"reissue: new cert to old cert", func() string { return qemuTLSDir(t, nw, old, nw) }, func() string { return qemuTLSDir(t, old, old, nw) }, "completed"},
		{"reissue: old cert to new cert", func() string { return qemuTLSDir(t, old, old, nw) }, func() string { return qemuTLSDir(t, nw, old, nw) }, "completed"},
		// drop-old done.
		{"drop-old: done", func() string { return qemuTLSDir(t, nw, nw) }, func() string { return qemuTLSDir(t, nw, nw) }, "completed"},
		// Controls: no CA in common is refused at the handshake, so the
		// cases above are real verification, not a channel that accepts
		// anything.
		{"control: new only to old only", func() string { return qemuTLSDir(t, nw, nw) }, func() string { return qemuTLSDir(t, old, old) }, "failed"},
		{"control: old only to new only", func() string { return qemuTLSDir(t, old, old) }, func() string { return qemuTLSDir(t, nw, nw) }, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, desc := migrateOverTLS(t, tc.src(), tc.dst())
			t.Logf("%s: %s %s", tc.name, got, desc)
			if got != tc.want {
				t.Fatalf("migration %s (%s); want %s", got, desc, tc.want)
			}
		})
	}
}

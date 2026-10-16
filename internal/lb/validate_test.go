package lb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// inject re-opens haproxy's global section from inside a value.
const inject = "x\nglobal\n    pidfile /etc/litevirt/pki/host.key"

func validSettings() Settings {
	return Settings{
		Algorithm: "leastconn",
		Sticky:    true,
		Health:    &HealthConfig{Type: "http", Path: "/healthz?probe=1"},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "http", RedirectHTTPS: true},
			{Listen: 443, Target: 8080, Protocol: "http", TLS: &TLSConfig{Cert: CertDir + "/a.crt", Key: CertDir + "/a.key"}},
		},
	}
}

// TestCheckSettings_RefusesEachFieldFamily: every value that reaches a
// rendered config is refused at ingress when it is outside its enum or is
// not one plain token, field by field, with a newline-injection payload.
//
// Mutations (each red): drop a case from CheckSettings (algorithm,
// protocol, health type, health path, TLS path, redirect).
func TestCheckSettings_RefusesEachFieldFamily(t *testing.T) {
	if ps := CheckSettings(validSettings()); len(ps) != 0 {
		t.Fatalf("valid settings refused: %v", ps)
	}
	cases := map[string]func(*Settings){
		"algorithm":                func(s *Settings) { s.Algorithm = "roundrobin\n" + inject },
		"ports[0].protocol":        func(s *Settings) { s.Ports[0].Protocol = "http\n" + inject },
		"health.type":              func(s *Settings) { s.Health.Type = "http\n" + inject },
		"health.path":              func(s *Settings) { s.Health.Path = "/" + inject },
		"ports[1].tls.cert":        func(s *Settings) { s.Ports[1].TLS.Cert = CertDir + "/a\n" + inject },
		"ports[1].tls.key":         func(s *Settings) { s.Ports[1].TLS.Key = "relative.key" },
		"ports[0].redirect-https":  func(s *Settings) { s.Ports[0].Protocol = "tcp" },
		"ports[1].redirect-https":  func(s *Settings) { s.Ports[1].RedirectHTTPS = true },
		"ports[0].redirect-https ": func(s *Settings) { s.Ports = s.Ports[:1] },
	}
	for field, mutate := range cases {
		s := validSettings()
		mutate(&s)
		ps := CheckSettings(s)
		want := strings.TrimSpace(field)
		found := false
		for _, p := range ps {
			if p.Field == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: problems %v, want one for %s", field, ps, want)
		}
	}
	// Health paths a real check uses pass; anything with a space, quote,
	// '#' or backslash does not.
	for _, ok := range []string{"/", "/healthz", "/api/v1/ping?full=1&x=%20", "/a-b_c.d~e"} {
		s := validSettings()
		s.Health.Path = ok
		if ps := CheckSettings(s); len(ps) != 0 {
			t.Errorf("path %q refused: %v", ok, ps)
		}
	}
	for _, bad := range []string{"healthz", "/a b", `/a"b`, "/a#b", `/a\b`, "/a'b", "/a{b}", "/" + strings.Repeat("a", 600)} {
		s := validSettings()
		s.Health.Path = bad
		if ps := CheckSettings(s); len(ps) == 0 {
			t.Errorf("path %q accepted", bad)
		}
	}
}

func renderableConfig() Config {
	return Config{
		Name: "web-lb", VIP: "10.0.1.100", VIPPrefix: 24, Interface: "br0", VRID: 9, Priority: 100,
		Algorithm: "roundrobin", Health: &HealthConfig{Type: "http", Path: "/h"},
		Backends:    []Backend{{Name: "vm1", IP: "10.0.1.10", Port: 8080}},
		Ports:       []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		SNATEnabled: true, LocalIP: "192.0.2.1", PeerIP: "192.0.2.2", Subnet: "10.0.1.0/24", SyncInterface: "eth0",
	}
}

// TestRender_RefusesInjection: the renderers refuse, rather than escape, a
// config whose values would not stay one token, whichever field carries it.
//
// Mutation: make checkRender return nil — red.
func TestRender_RefusesInjection(t *testing.T) {
	render := func(c Config) error {
		for _, r := range []func(Config) (string, error){RenderHAProxy, RenderKeepalived, RenderConntrackd, RenderNotifyScript} {
			if _, err := r(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := render(renderableConfig()); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	cases := map[string]func(*Config){
		"name":           func(c *Config) { c.Name = "../../profile.d/$(id)" },
		"vip":            func(c *Config) { c.VIP = "10.0.1.100\n" + inject },
		"interface":      func(c *Config) { c.Interface = "br0\"\n" + inject },
		"algorithm":      func(c *Config) { c.Algorithm = "roundrobin\n" + inject },
		"health type":    func(c *Config) { c.Health.Type = "http\r" + inject },
		"health path":    func(c *Config) { c.Health.Path = "/" + inject },
		"backend name":   func(c *Config) { c.Backends[0].Name = "vm1\n" + inject },
		"backend ip":     func(c *Config) { c.Backends[0].IP = "10.0.1.10 " + inject },
		"protocol":       func(c *Config) { c.Ports[0].Protocol = "tcp\n" + inject },
		"local ip":       func(c *Config) { c.LocalIP = "192.0.2.1\n" + inject },
		"peer ip":        func(c *Config) { c.PeerIP = "192.0.2.2}" },
		"subnet":         func(c *Config) { c.Subnet = "10.0.1.0/24\x00" },
		"sync interface": func(c *Config) { c.SyncInterface = "eth0#" },
	}
	for name, mutate := range cases {
		c := renderableConfig()
		mutate(&c)
		if err := render(c); err == nil {
			t.Errorf("%s: injected config rendered", name)
		}
	}
}

// TestApply_RefusesUnsafeNameBeforeWriting: a traversal or shell-metachar
// LB name is refused at the top of Apply and Remove, before any file exists.
//
// Mutation: drop the ValidateName call at the top of Apply — red (the
// config dir is created).
func TestApply_RefusesUnsafeNameBeforeWriting(t *testing.T) {
	m := testManager(t)
	for _, name := range []string{"../../profile.d/$(id)-lb", "a;b-lb", "a b-lb", "..", ""} {
		cfg := renderableConfig()
		cfg.Name = name
		if err := m.Apply(context.Background(), cfg); err == nil {
			t.Errorf("Apply(%q) succeeded", name)
		}
		if err := m.Remove(context.Background(), name); err == nil {
			t.Errorf("Remove(%q) succeeded", name)
		}
	}
	if _, err := os.Stat(m.configDir); !os.IsNotExist(err) {
		t.Errorf("config dir exists after refused applies: %v", err)
	}
}

// TestReadTLSFile_ChecksTheFileActuallyRead: the TLS reader follows a
// symlink (a Let's Encrypt live/ -> archive/ name reads) and applies every
// check to the file it opens: it refuses a device, a FIFO (without hanging),
// a file over the size cap, litevirt's own keys whether named, linked to or
// reached through a symlinked directory, the LB config dir, and a path
// swapped to point into the PKI dir between resolving and opening.
//
// Mutations (each red): drop the opened-name comparison; drop the
// protected-dir check on the opened name; drop the regular-file check; drop
// the size cap.
func TestReadTLSFile_ChecksTheFileActuallyRead(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	old := append([]string(nil), protectedDirs...)
	SetProtectedDirs(pki)
	t.Cleanup(func() { SetProtectedDirs(old...) })

	write := func(p string, b []byte) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, name string) string {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
		return name
	}
	good := write(filepath.Join(dir, "certs", "a.crt"), []byte("CERT"))
	hostKey := write(filepath.Join(pki, "host.key"), []byte("SECRET"))
	write(filepath.Join(pki, "a.crt"), []byte("PKI"))
	big := write(filepath.Join(dir, "certs", "big.crt"), make([]byte, maxTLSFile+1))
	inLBDir := write(filepath.Join(m.configDir, "other-lb-443.pem"), []byte("OTHER"))
	// Let's Encrypt's shape: live/<name>/fullchain.pem -> ../../archive/<name>/fullchain1.pem
	write(filepath.Join(dir, "le", "archive", "web", "fullchain1.pem"), []byte("LE"))
	le := link("../../archive/web/fullchain1.pem", filepath.Join(dir, "le", "live", "web", "fullchain.pem"))
	toPKI := link(hostKey, filepath.Join(dir, "certs", "sneaky.key"))
	pkiDirLink := link(pki, filepath.Join(dir, "pkilink"))
	fifo := filepath.Join(dir, "certs", "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, p := range map[string]string{"plain file": good, "Let's Encrypt live/ symlink": le} {
		if _, err := m.readTLSFile(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, p := range map[string]string{
		"/dev/zero": "/dev/zero", "fifo": fifo, "oversize": big,
		"pki/host.key": hostKey, "symlink into pki": toPKI, "pki via a symlinked dir": filepath.Join(pkiDirLink, "host.key"),
		"LB config dir": inLBDir, "relative": "certs/a.crt",
	} {
		done := make(chan error, 1)
		go func() { _, err := m.readTLSFile(p); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: read", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: read hung", name)
		}
	}

	// Swapped between resolving and opening: certs/ becomes a symlink to the
	// PKI dir, so opening the resolved path would read pki/a.crt.
	certs := filepath.Join(dir, "certs")
	beforeTLSOpen = func() {
		if err := os.Rename(certs, certs+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(pki, certs); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeTLSOpen = func() {} })
	if b, err := m.readTLSFile(good); err == nil {
		t.Errorf("swapped path read %q", b)
	}

	// Swapped to somewhere unprotected: still not the file that was
	// resolved and checked, so refused.
	other := filepath.Join(dir, "other")
	write(filepath.Join(other, "a.crt"), []byte("OTHER"))
	good2 := write(filepath.Join(dir, "certs2", "a.crt"), []byte("CERT"))
	certs2 := filepath.Dir(good2)
	beforeTLSOpen = func() {
		if err := os.Rename(certs2, certs2+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(other, certs2); err != nil {
			t.Error(err)
		}
	}
	if b, err := m.readTLSFile(good2); err == nil {
		t.Errorf("path swapped to another file read %q", b)
	}
}

// TestReadTLSFile_CertDirMustBeTrusted: a path inside CertDir is read only
// while CertDir is a real directory owned by the daemon's user and writable
// by no one else: what it holds, links included, was put there by root.
//
// Mutation: drop the checkCertDir call — red.
func TestReadTLSFile_CertDirMustBeTrusted(t *testing.T) {
	m := testManager(t)
	root := t.TempDir()
	cd := filepath.Join(root, "lb-certs")
	if err := os.Mkdir(cd, 0o750); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cd, "a.crt")
	if err := os.WriteFile(f, []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := certDir
	certDir = cd
	t.Cleanup(func() { certDir = old })

	if _, err := m.readTLSFile(f); err != nil {
		t.Fatalf("trusted cert dir: %v", err)
	}
	if err := os.Chmod(cd, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readTLSFile(f); err == nil {
		t.Error("read from a world-writable cert dir")
	}
	if err := os.Chmod(cd, 0o750); err != nil {
		t.Fatal(err)
	}
	// A cert dir that is itself a symlink is not trusted either.
	real := filepath.Join(root, "elsewhere")
	if err := os.Rename(cd, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, cd); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readTLSFile(f); err == nil {
		t.Error("read through a symlinked cert dir")
	}
}

// TestReadTLSFile_CertDirSubdirsMustBeTrusted (M-R2): every directory between
// CertDir and the file is trust-checked too, so a subdirectory handed to
// another user cannot plant a link to another service's key.
//
// Mutation: check only CertDir itself (checkCertDir(certDir)) — red.
func TestReadTLSFile_CertDirSubdirsMustBeTrusted(t *testing.T) {
	m := testManager(t)
	cd := filepath.Join(t.TempDir(), "lb-certs")
	sub := filepath.Join(cd, "acme", "web")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "a.crt")
	if err := os.WriteFile(f, []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := certDir
	certDir = cd
	t.Cleanup(func() { certDir = old })

	if _, err := m.readTLSFile(f); err != nil {
		t.Fatalf("trusted subdirectories: %v", err)
	}
	acme := filepath.Join(cd, "acme")
	if err := os.Chmod(acme, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readTLSFile(f); err == nil {
		t.Error("read under a group-writable subdirectory")
	}
	if err := os.Chmod(acme, 0o750); err != nil {
		t.Fatal(err)
	}
	// A subdirectory that is a symlink (to somewhere its owner controls).
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Rename(acme, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, acme); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readTLSFile(f); err == nil {
		t.Error("read through a symlinked subdirectory")
	}
}

// TestApply_TLSRefusedWritesNothing: a refused TLS file fails the apply
// before any config is written.
func TestApply_TLSRefusedWritesNothing(t *testing.T) {
	m := testManager(t)
	cfg := renderableConfig()
	cfg.SNATEnabled = false
	key := filepath.Join(t.TempDir(), "a.key")
	if err := os.WriteFile(key, []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Ports = []Port{{Listen: 443, Target: 8080, Protocol: "tcp", TLS: &TLSConfig{Cert: "/dev/zero", Key: key}}}
	if err := m.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply with /dev/zero as cert succeeded")
	}
	if _, err := os.Stat(filepath.Join(m.configDir, "web-lb-haproxy.cfg")); !os.IsNotExist(err) {
		t.Errorf("haproxy config written before the TLS check: %v", err)
	}
}

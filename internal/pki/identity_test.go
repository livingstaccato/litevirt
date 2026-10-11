package pki

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// mintInto writes a fresh host pair for cn, signed by the CA in caDir, into dir
// under host.crt/host.key — via a rename, as every real installer does.
func mintInto(t *testing.T, caDir, dir, cn string) string {
	t.Helper()
	stage := t.TempDir()
	crt, key := filepath.Join(stage, "host.crt"), filepath.Join(stage, "host.key")
	if err := GenerateHostCert(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"),
		crt, key, cn, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(key, filepath.Join(dir, "host.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(crt, filepath.Join(dir, "host.crt")); err != nil {
		t.Fatal(err)
	}
	s, err := CertSerial(filepath.Join(dir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// handshakeSerials completes one handshake against srvCfg and returns the serial
// the server presented and the serial the client presented.
func handshakeSerials(t *testing.T, srvCfg, cliCfg *tls.Config) (server, client string) {
	t.Helper()
	lis, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	got := make(chan string, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			got <- "handshake: " + err.Error()
			return
		}
		st := tc.ConnectionState()
		if len(st.PeerCertificates) == 0 {
			got <- ""
			return
		}
		got <- st.PeerCertificates[0].SerialNumber.Text(16)
	}()
	cfg := cliCfg.Clone()
	cfg.ServerName = "test-host"
	conn, err := tls.Dial("tcp", lis.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	server = conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
	client = <-got
	return server, client
}

// The listener built at boot presents a renewed certificate from the next
// handshake on — no restart.
func TestHostIdentity_ServerPresentsARenewedCertificateWithoutRestart(t *testing.T) {
	dir := setupPKI(t)
	srv, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ClientTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := handshakeSerials(t, srv, cli)
	renewed := mintInto(t, dir, dir, "test-host")
	after, _ := handshakeSerials(t, srv, cli)
	if after == before || after != renewed {
		t.Fatalf("the listener still serves %s after a renewal to %s (was %s)", after, renewed, before)
	}
}

// The peer config the health checker caches for the life of the process
// presents the renewed certificate as a CLIENT too.
func TestHostIdentity_PeerClientPresentsARenewedCertificate(t *testing.T) {
	dir := setupPKI(t)
	srv, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := PeerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, before := handshakeSerials(t, srv, peer)
	renewed := mintInto(t, dir, dir, "test-host")
	_, after := handshakeSerials(t, srv, peer)
	if after != renewed {
		t.Fatalf("the cached peer config presented %s after a renewal to %s (was %s)", after, renewed, before)
	}
}

// A replacement that lands one file at a time is never served half-written:
// the old pair stays until the matching key arrives.
func TestHostIdentity_ATornReplacementKeepsTheServedPair(t *testing.T) {
	dir := setupPKI(t)
	src := hostIdentitySource(dir)
	old, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	crt, key := filepath.Join(stage, "host.crt"), filepath.Join(stage, "host.key")
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		crt, key, "test-host", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(crt, filepath.Join(dir, "host.crt")); err != nil {
		t.Fatal(err)
	}
	mid, err := src.Leaf()
	if err != nil {
		t.Fatalf("a half-written pair took the identity away: %v", err)
	}
	if mid.SerialNumber.Cmp(old.SerialNumber) != 0 {
		t.Fatal("a certificate was served without its key")
	}
	if err := os.Rename(key, filepath.Join(dir, "host.key")); err != nil {
		t.Fatal(err)
	}
	done, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	if done.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Fatal("the completed pair was not adopted")
	}
}

// A replacement from another CA, or naming another host, would cut the node
// off from every peer; it is refused and the current identity stays.
func TestHostIdentity_AForeignOrRenamedReplacementIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, cn string
		foreign  bool
	}{
		{"foreign CA", "test-host", true},
		{"other host name", "other-host", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupPKI(t)
			src := hostIdentitySource(dir)
			old, err := src.Leaf()
			if err != nil {
				t.Fatal(err)
			}
			caDir := dir
			if tc.foreign {
				caDir = t.TempDir()
				if err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key")); err != nil {
					t.Fatal(err)
				}
			}
			mintInto(t, caDir, dir, tc.cn)
			now, err := src.Leaf()
			if err != nil {
				t.Fatal(err)
			}
			if now.SerialNumber.Cmp(old.SerialNumber) != 0 {
				t.Fatalf("adopted a replacement it should have refused (%s)", tc.name)
			}
		})
	}
}

// A served identity survives its files being deleted out from under it.
func TestHostIdentity_DeletedFilesKeepTheServedPair(t *testing.T) {
	dir := setupPKI(t)
	src := hostIdentitySource(dir)
	if _, err := src.Get(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "host.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Get(); err != nil {
		t.Fatalf("a deleted key took a running identity away: %v", err)
	}
}

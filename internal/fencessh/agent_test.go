package fencessh_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/pki"
)

// openGate is a release gate whose fence_ssh is open.
type openGate struct{ t *testing.T }

func (openGate) ReleaseFeatureAvailable(capabilities.Feature) bool { return true }
func (g openGate) WithReleaseFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

// publisher is n's own agent, publishing through an open gate, with an sshd
// configuration evaluation that says accepting.
func (n *node) publisher(accepting bool, selfCheck bool) *fencessh.Agent {
	return fencessh.New(fencessh.Config{
		Self: n.name, PKIDir: n.pkiDir, DB: n.w.db, Gate: openGate{n.w.t}, Dir: n.dir, SSHUser: n.w.user,
		HostKeyGlob: n.hkPath + ".pub", SelfCheck: selfCheck,
		Accepting: func(context.Context, []string) (bool, string, error) {
			if accepting {
				return true, "", nil
			}
			return false, "modelled: sshd does not read it", nil
		},
	})
}

func (n *node) row() (corrosion.HostFenceSSHRow, bool) {
	n.w.t.Helper()
	r, ok, err := corrosion.GetHostFenceSSH(context.Background(), n.w.db, n.name)
	if err != nil {
		n.w.t.Fatal(err)
	}
	return r, ok
}

// TestPublish_AcceptingIsTheRunningSSHD: the configuration on disk says sshd
// reads the rendered file (a drop-in written, its reload failed), but the
// running sshd does not: the host must not publish that it accepts the
// managed key. With the running sshd reading it, it does.
func TestPublish_AcceptingIsTheRunningSSHD(t *testing.T) {
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	x.skipRendered = true
	x.start(false)
	x.hostRow(x.ip, x.port)
	y.start(false)
	y.hostRow(y.ip, y.port)

	if err := x.publisher(true, true).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, ok := x.row(); !ok || r.Accepting || !strings.Contains(r.Detail, "the running sshd does not accept it") {
		t.Fatalf("node-x's row = %+v (%v), want not accepting: its running sshd does not read the file", r, ok)
	}
	if err := y.publisher(true, true).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, ok := y.row(); !ok || !r.Accepting || !r.EverAccepting {
		t.Fatalf("node-y's row = %+v (%v), want accepting", r, ok)
	}
}

// TestPublish_EverAcceptingFollowsTheCertificateLineage: the bit is carried
// from a previous row signed by this host's current certificate or the one it
// renewed, never from one under another certificate of the same name (a
// removed machine's, before a re-admission).
func TestPublish_EverAcceptingFollowsTheCertificateLineage(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.publish(true, true, "127.0.0.3", 22) // the previous machine's row

	// The new machine under the name: a fresh certificate, not a renewal.
	if err := pki.GenerateHostCert(filepath.Join(w.ca, "ca.crt"), filepath.Join(w.ca, "ca.key"),
		filepath.Join(x.pkiDir, "host.crt"), filepath.Join(x.pkiDir, "host.key"), "node-x", net.ParseIP(x.ip)); err != nil {
		t.Fatal(err)
	}
	if err := x.publisher(false, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); r.EverAccepting {
		t.Fatalf("the new machine inherited ever_accepting from another certificate's row: %+v", r)
	}

	// Its own row, accepting; then a renewal; then not accepting: carried.
	if err := x.publisher(true, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pki.RenewLocal(filepath.Join(w.ca, "ca.crt"), filepath.Join(w.ca, "ca.key"), x.pkiDir, "node-x"); err != nil {
		t.Fatal(err)
	}
	if err := x.publisher(false, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); !r.EverAccepting || r.Accepting {
		t.Fatalf("after a renewal = %+v, want ever_accepting carried, not accepting", r)
	}
}

// TestPublish_NoFenceAddressNoRow: a host whose certificate names no address
// besides 127.0.0.1 publishes nothing, so its peers keep fencing it the
// legacy way rather than refuse a row that could never verify.
func TestPublish_NoFenceAddressNoRow(t *testing.T) {
	w := newWorld(t)
	x := w.node("node-x", "")
	if err := os.MkdirAll(x.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	x.hostRow("127.0.0.3", 22)
	if err := x.publisher(true, false).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, ok := x.row(); ok {
		t.Fatalf("a host with no fence address published %+v", r)
	}
}

// TestPublish_GenerationNeverGoesBack: a node that lost its own row (a
// rebuilt database, a replay of an older one) publishes above every
// generation it published before.
func TestPublish_GenerationNeverGoesBack(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.hostRow("127.0.0.3", 22)
	ag := x.publisher(true, false)
	if err := ag.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// A new sshd host key: generation 2.
	x.hostKey = writeOpenSSHKey(t, x.hkPath)
	writeFile(t, x.hkPath+".pub", fencessh.KeyLine(x.hostKey)+"\n", 0o644)
	if err := ag.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); r.Generation != 2 {
		t.Fatalf("generation after a host-key change = %d, want 2", r.Generation)
	}
	if _, err := w.db.DB().Exec(`DELETE FROM host_fence_ssh WHERE host_name = 'node-x'`); err != nil {
		t.Fatal(err)
	}
	if err := x.publisher(true, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); r.Generation <= 2 {
		t.Fatalf("generation after the row was lost = %d, want above 2", r.Generation)
	}
}

// TestPublish_AFailedEvaluationKeepsWhatWasPublished: an sshd -T that could
// not run (fork failure under memory pressure, an upgrade in flight) is no
// answer, so the host does not republish itself as not accepting — which,
// for a host that then hangs, would stand for good.
func TestPublish_AFailedEvaluationKeepsWhatWasPublished(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.hostRow("127.0.0.3", 22)
	if err := x.publisher(true, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	failing := fencessh.New(fencessh.Config{
		Self: x.name, PKIDir: x.pkiDir, DB: w.db, Gate: openGate{t}, Dir: x.dir, HostKeyGlob: x.hkPath + ".pub",
		Accepting: func(context.Context, []string) (bool, string, error) {
			return false, "", errors.New("fork/exec /usr/sbin/sshd: cannot allocate memory")
		},
	})
	// The sync still reports it, so the agent's last_error shows it: `lv
	// doctor fence` warns, and `lv host install-fence-ssh` does not confirm
	// a row carried over from before as a fresh answer.
	err := failing.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "could not be evaluated") || !strings.Contains(err.Error(), "cannot allocate memory") {
		t.Fatalf("Sync after a failed evaluation: %v, want it reported", err)
	}
	if !strings.Contains(failing.LastError(), "could not be evaluated") {
		t.Fatalf("last_error %q does not show the failed evaluation", failing.LastError())
	}
	if r, _ := x.row(); !r.Accepting || !r.EverAccepting {
		t.Fatalf("after a failed evaluation the row = %+v, want still accepting", r)
	}

	// A first row, published while sshd cannot be evaluated, is published
	// (not accepting) and the sync reports it too.
	y := w.node("node-y", "127.0.0.4")
	y.hostRow("127.0.0.4", 22)
	first := fencessh.New(fencessh.Config{
		Self: y.name, PKIDir: y.pkiDir, DB: w.db, Gate: openGate{t}, Dir: y.dir, HostKeyGlob: y.hkPath + ".pub",
		Accepting: func(context.Context, []string) (bool, string, error) {
			return false, "", errors.New("fork/exec /usr/sbin/sshd: cannot allocate memory")
		},
	})
	if err := first.Sync(ctx); err == nil || !strings.Contains(err.Error(), "could not be evaluated") {
		t.Fatalf("first Sync with a failed evaluation: %v, want it reported", err)
	}
	if r, ok := y.row(); !ok || r.Accepting || !strings.Contains(r.Detail, "could not be evaluated") {
		t.Fatalf("first row with a failed evaluation = %+v (published %v)", r, ok)
	}
}

// TestPublish_LegacyKeepsAnExistingRowSigned: a host that published, then
// was switched to enforcement.fence_ssh: legacy (an incident stand-down), and
// then renewed its certificate, re-signs its row with the renewed one —
// otherwise the replaced certificate's revocation stays owed for good, and
// once it is revoked every peer refuses to fence the host.
func TestPublish_LegacyKeepsAnExistingRowSigned(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.hostRow("127.0.0.3", 22)
	if err := x.publisher(true, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, next, err := pki.RenewLocal(filepath.Join(w.ca, "ca.crt"), filepath.Join(w.ca, "ca.key"), x.pkiDir, "node-x"); err != nil {
		t.Fatal(err)
	} else {
		legacy := fencessh.New(fencessh.Config{
			Self: x.name, PKIDir: x.pkiDir, DB: w.db, Gate: openGate{t}, Dir: x.dir, HostKeyGlob: x.hkPath + ".pub",
			Mode:      func() string { return fencessh.ModeLegacy },
			Accepting: func(context.Context, []string) (bool, string, error) { return true, "", nil },
		})
		if err := legacy.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		r, _ := x.row()
		cert, err := pki.ParseCertPEM([]byte(r.CertPEM))
		if err != nil || !strings.EqualFold(cert.SerialNumber.Text(16), next) {
			t.Fatalf("the legacy host's row is signed by %v (%v), want the renewed %s", cert.SerialNumber, err, next)
		}
	}
}

// TestPublish_LegacyReplacesARetiredRow: re-admission retires a host's row
// on every node, and peers refuse to fence through a tombstone. A host on
// enforcement.fence_ssh: legacy publishes no FIRST row, but it must replace
// its own tombstone, or the re-admitted host is never fenceable again.
func TestPublish_LegacyReplacesARetiredRow(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	a.hostRow("127.0.0.2", 22)
	x.hostRow("127.0.0.3", 22)
	if err := x.publisher(true, false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.db.DB().Exec(`UPDATE host_fence_ssh SET fence_pubkeys = '', sshd_hostkeys = '', accepting = 0,
		ever_accepting = 0, signature = '', deleted_at = updated_at WHERE host_name = 'node-x'`); err != nil {
		t.Fatal(err)
	}
	if sf := a.agent(fencessh.ModeLegacy).FenceConfig(ctx, "node-x"); sf.Refusal == "" {
		t.Fatalf("fence through the tombstone = %+v, want refused", sf)
	}
	legacy := fencessh.New(fencessh.Config{
		Self: x.name, PKIDir: x.pkiDir, DB: w.db, Gate: openGate{t}, Dir: x.dir, HostKeyGlob: x.hkPath + ".pub",
		Mode:      func() string { return fencessh.ModeLegacy },
		Accepting: func(context.Context, []string) (bool, string, error) { return true, "", nil },
	})
	if err := legacy.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, ok := x.row(); !ok || r.Deleted || r.SSHDHostkeys == "" {
		t.Fatalf("after a legacy sync over its tombstone the row = %+v (present %v), want republished", r, ok)
	}
	if sf := a.agent(fencessh.ModeLegacy).FenceConfig(ctx, "node-x"); sf.Refusal != "" || sf.Path != fence.SSHPathPinned {
		t.Fatalf("fence of the re-admitted host = %+v, want pinned", sf)
	}
}

// TestPublish_LegacyNeverMakesTheFirstRow: enforcement.fence_ssh: legacy
// publishes nothing for a host that has no row, so the release feature stays
// unused and a rollback below release_2026_12_v1 stays possible.
func TestPublish_LegacyNeverMakesTheFirstRow(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.hostRow("127.0.0.3", 22)
	legacy := fencessh.New(fencessh.Config{
		Self: x.name, PKIDir: x.pkiDir, DB: w.db, Gate: openGate{t}, Dir: x.dir, HostKeyGlob: x.hkPath + ".pub",
		Mode:      func() string { return fencessh.ModeLegacy },
		Accepting: func(context.Context, []string) (bool, string, error) { return true, "", nil },
	})
	if err := legacy.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, ok := x.row(); ok {
		t.Fatalf("a legacy host with no row published %+v", r)
	}
}

// TestRender_AnExpiredPeerIsPinnedButNotTrusted: a peer whose certificate has
// expired is still fenced pinned to its sshd keys, but its fence key is not
// rendered into this host's authorized_keys: expiry keeps the pin, never the
// authority to power this host off.
func TestRender_AnExpiredPeerIsPinnedButNotTrusted(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	x.hostRow("127.0.0.3", 22)
	y.hostRow("127.0.0.4", 22)
	certPEM, key := expiredHostCert(t, w, "node-y", "127.0.0.4")
	row, err := fencessh.Sign(fencessh.Publication{HostName: "node-y", Generation: 1,
		FencePubkeys: fencessh.KeyLine(y.fenceKy), SSHDHostkeys: fencessh.KeyLine(y.hostKey), CertPEM: certPEM}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutHostFenceSSH(ctx, w.db, capabilities.GrantForTest(t, capabilities.FeatureFenceSSH), row); err != nil {
		t.Fatal(err)
	}
	ag := x.publisher(true, false)
	if err := ag.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	ak, err := os.ReadFile(filepath.Join(x.dir, fencessh.AuthorizedKeysName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ak), fencessh.KeyLine(y.fenceKy)) {
		t.Fatalf("an expired peer's fence key is trusted:\n%s", ak)
	}
	if sf := ag.FenceConfig(ctx, "node-y"); sf.Refusal != "" || sf.Path != fence.SSHPathPinned ||
		!strings.Contains(string(sf.KnownHosts), fencessh.KeyLine(y.hostKey)) {
		t.Fatalf("fence of the expired peer = %+v, want pinned to its sshd key", sf)
	}
}

// expiredHostCert mints name's host certificate, already expired, from the
// world's CA.
func expiredHostCert(t *testing.T, w *world, name, ip string) (string, crypto.Signer) {
	t.Helper()
	caPEM, _ := os.ReadFile(filepath.Join(w.ca, "ca.crt"))
	caCert, err := pki.ParseCertPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(w.ca, "ca.key"))
	blk, _ := pem.Decode(keyPEM)
	caKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77001), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: caCert.NotBefore, NotAfter: caCert.NotBefore.Add(time.Second),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP(ip), net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), k
}

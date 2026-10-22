package fencessh_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	if err := failing.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := x.row(); !r.Accepting || !r.EverAccepting {
		t.Fatalf("after a failed evaluation the row = %+v, want still accepting", r)
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

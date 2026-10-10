package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
)

// dirTarget is a renewTarget over a local directory standing in for the host's
// /etc/litevirt/pki.
type dirTarget struct {
	dir      string
	failMv   bool
	reloaded bool
}

func (d *dirTarget) local(path string) string {
	return filepath.Join(d.dir, strings.TrimPrefix(path, remotePKIDir+"/"))
}

func (d *dirTarget) ReadFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(d.local(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (d *dirTarget) Install(files []installFile) error {
	for _, f := range files {
		st := d.local(stagedPath(f.path))
		if err := os.WriteFile(st, f.data, f.mode); err != nil {
			return err
		}
		if err := os.Chmod(st, f.mode); err != nil {
			return err
		}
	}
	for _, f := range files {
		if b, err := os.ReadFile(d.local(f.path)); err == nil {
			if err := os.WriteFile(d.local(f.path+preRenewSuffix), b, 0o600); err != nil {
				return err
			}
		}
	}
	if d.failMv {
		return errors.New("mv: injected failure")
	}
	for _, f := range files {
		if err := os.Rename(d.local(stagedPath(f.path)), d.local(f.path)); err != nil {
			return err
		}
	}
	return nil
}

func (d *dirTarget) Rollback(files []installFile) error {
	for _, f := range files {
		b := d.local(f.path + preRenewSuffix)
		if _, err := os.Stat(b); err == nil {
			if err := os.Rename(b, d.local(f.path)); err != nil {
				return err
			}
		}
		os.Remove(d.local(stagedPath(f.path)))
	}
	return nil
}

func (d *dirTarget) Commit(files []installFile) error {
	for _, f := range files {
		os.Remove(d.local(f.path + preRenewSuffix))
	}
	return nil
}

func (d *dirTarget) ReloadLibvirtTLS() error { d.reloaded = true; return nil }

type renewTestClient struct {
	pb.LiteVirtClient
	recorded  func() string
	published int
}

func (c *renewTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "node-r", Address: "10.0.0.9", CertSerial: c.recorded()}}}, nil
}

func (c *renewTestClient) PublishCRL(context.Context, *pb.PublishCRLRequest, ...grpc.CallOption) (*pb.PublishCRLResponse, error) {
	c.published++
	return &pb.PublishCRLResponse{Version: 3}, nil
}

type renewFixture struct {
	op, host   string // operator pki dir, host pki dir
	prevSerial string
	target     *dirTarget
	client     *renewTestClient
}

func newRenewFixture(t *testing.T) *renewFixture {
	t.Helper()
	cfg := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", cfg)
	op := PKIDir()
	if err := os.MkdirAll(op, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(op, "ca.crt"), filepath.Join(op, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateClientCert(filepath.Join(op, "ca.crt"), filepath.Join(op, "ca.key"),
		filepath.Join(op, "client.crt"), filepath.Join(op, "client.key"), "lv-cli"); err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	caPEM, _ := os.ReadFile(filepath.Join(op, "ca.crt"))
	if err := os.WriteFile(filepath.Join(host, "ca.crt"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(filepath.Join(op, "ca.crt"), filepath.Join(op, "ca.key"),
		filepath.Join(host, "host.crt"), filepath.Join(host, "host.key"), "node-r", net.ParseIP("10.0.0.9")); err != nil {
		t.Fatal(err)
	}
	prev, err := pki.CertSerial(filepath.Join(host, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	f := &renewFixture{op: op, host: host, prevSerial: strings.ToLower(prev), target: &dirTarget{dir: host}}
	// The daemon's re-record: the cluster follows whatever the host serves.
	f.client = &renewTestClient{recorded: func() string {
		c, err := pki.ServedHostCertificate(host)
		if err != nil {
			return f.prevSerial
		}
		return strings.ToLower(c.SerialNumber.Text(16))
	}}
	// The running daemon has loaded its identity before any renewal.
	if _, err := pki.ServedHostCertificate(host); err != nil {
		t.Fatal(err)
	}
	return f
}

// probe is the running daemon: the certificate its identity source serves.
func (f *renewFixture) probe(context.Context) (*x509.Certificate, error) {
	return pki.ServedHostCertificate(f.host)
}

func (f *renewFixture) run(t *testing.T, opts RenewCertOptions, probe servedCertProbe) error {
	t.Helper()
	if opts.Wait == 0 {
		opts.Wait = time.Millisecond
	}
	return renewHostCert(context.Background(), f.client, f.target, probe, "node-r", opts)
}

func crlHas(t *testing.T, op, serial string) bool {
	t.Helper()
	serials, err := pki.LoadCRL(filepath.Join(op, "crl.pem"))
	if err != nil {
		return false
	}
	for _, s := range serials {
		if strings.EqualFold(s, serial) {
			return true
		}
	}
	return false
}

// A renewal installs a successor (key 0600), the running host serves it, and
// only then is the old certificate revoked and the CRL published.
//
// Mutations: install the key with mode 0644 — the mode check fails; skip
// revokeHostCert — the old serial is not in the CRL.
func TestRenewHostCert_InstallsConfirmsAndRevokes(t *testing.T) {
	f := newRenewFixture(t)
	if err := f.run(t, RenewCertOptions{}, f.probe); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(f.host, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("renewed host.key is mode %04o", fi.Mode().Perm())
	}
	served, err := pki.ServedHostCertificate(f.host)
	if err != nil {
		t.Fatal(err)
	}
	if from, ok := pki.RenewedFromSerial(served); !ok || from != f.prevSerial {
		t.Fatalf("the host serves %s, not a successor of %s", served.SerialNumber.Text(16), f.prevSerial)
	}
	if !crlHas(t, f.op, f.prevSerial) || f.client.published != 1 {
		t.Fatalf("the replaced certificate was not revoked and published (published=%d)", f.client.published)
	}
	if crlHas(t, f.op, served.SerialNumber.Text(16)) {
		t.Fatal("the renewed certificate was revoked")
	}
	for _, n := range []string{"host.crt" + preRenewSuffix, "host.key" + preRenewSuffix, ".host.key.renew"} {
		if _, err := os.Stat(filepath.Join(f.host, n)); err == nil {
			t.Fatalf("%s was left behind (a second copy of a key)", n)
		}
	}
	if !f.target.reloaded {
		t.Fatal("libvirt's TLS listener was not asked to reload")
	}
}

// A host that does not start presenting the successor gets its old pair back,
// and nothing is revoked — revoking a certificate the host still presents
// would cut it off from every peer.
//
// Mutation: drop the Rollback in the probe-failure branch — host.crt stays the
// unserved successor; or revoke before confirming — the CRL holds the old serial.
func TestRenewHostCert_RollsBackWhenTheHostDoesNotPresentIt(t *testing.T) {
	f := newRenewFixture(t)
	prevPEM, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	stuck := func(context.Context) (*x509.Certificate, error) { return pki.ParseCertPEM(prevPEM) }
	if err := f.run(t, RenewCertOptions{}, stuck); err == nil {
		t.Fatal("a renewal the host never presented reported success")
	}
	now, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	if string(now) != string(prevPEM) {
		t.Fatal("the previous certificate was not restored")
	}
	if crlHas(t, f.op, f.prevSerial) || f.client.published != 0 {
		t.Fatal("a certificate the host still presents was revoked")
	}
	if _, err := tlsPairMatches(f.host); err != nil {
		t.Fatalf("the restored pair does not match: %v", err)
	}
}

// When the cluster's record and the installed certificate disagree, nothing is
// touched: a successor of an unrecorded certificate is refused by every peer.
//
// Mutation: drop the recorded-serial comparison — the renewal proceeds.
func TestRenewHostCert_RefusesWhenTheRecordDisagrees(t *testing.T) {
	f := newRenewFixture(t)
	f.client.recorded = func() string { return "deadbeef" }
	before, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	err := f.run(t, RenewCertOptions{}, f.probe)
	if err == nil || !strings.Contains(err.Error(), "records certificate deadbeef") {
		t.Fatalf("got %v, want a refusal naming the recorded serial", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	if string(after) != string(before) {
		t.Fatal("the host certificate was changed despite the refusal")
	}
}

// --keep-old renews without revoking.
func TestRenewHostCert_KeepOldDoesNotRevoke(t *testing.T) {
	f := newRenewFixture(t)
	if err := f.run(t, RenewCertOptions{KeepOld: true}, f.probe); err != nil {
		t.Fatal(err)
	}
	if crlHas(t, f.op, f.prevSerial) || f.client.published != 0 {
		t.Fatal("--keep-old revoked the previous certificate")
	}
}

// A re-added host's audit admission record is bound to its certificate serial;
// the renewal re-signs it so the daemon still honours it on the next start.
//
// Mutation: skip resignedRejoin — LoadAuditRejoin rejects the record as
// "left over from an earlier admission".
func TestRenewHostCert_CarriesTheAuditRejoinRecord(t *testing.T) {
	f := newRenewFixture(t)
	rj, err := corrosion.SignAuditRejoin(f.op, "node-r", f.prevSerial, 12, "abc")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(rj)
	if err := os.WriteFile(filepath.Join(f.host, corrosion.AuditRejoinFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, RenewCertOptions{}, f.probe); err != nil {
		t.Fatal(err)
	}
	got, ok, err := corrosion.LoadAuditRejoin(f.host, "node-r")
	if err != nil || !ok {
		t.Fatalf("the admission record no longer applies after the renewal: %v", err)
	}
	if got.Seq != 12 || got.Hash != "abc" {
		t.Fatalf("the admission record's position changed: %+v", got)
	}
}

// A record that does not verify is not laundered into a valid one.
func TestRenewHostCert_RefusesToResignAForgedRejoinRecord(t *testing.T) {
	f := newRenewFixture(t)
	forged := corrosion.AuditRejoin{Host: "node-r", CertSerial: f.prevSerial, Seq: 1, Hash: "x", Signature: "00"}
	data, _ := json.Marshal(forged)
	if err := os.WriteFile(filepath.Join(f.host, corrosion.AuditRejoinFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, RenewCertOptions{}, f.probe); err == nil {
		t.Fatal("re-signed an admission record the CA never signed")
	}
}

func tlsPairMatches(dir string) (bool, error) {
	_, err := pki.NewKeyPairSource(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), nil).Get()
	return err == nil, err
}

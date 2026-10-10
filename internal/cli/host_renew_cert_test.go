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

// dirTarget is the host side over a test directory.
type dirTarget = LocalRemotePKI

type renewTestClient struct {
	pb.LiteVirtClient
	recorded  func() string
	versions  map[string]string
	published int
	// hold makes RevokeReplacedCertificate answer "owed".
	hold      bool
	revokeReq []string // serials asked to revoke via RevokeReplacedCertificate
}

func (c *renewTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	hosts := []*pb.Host{{Name: "node-r", Address: "10.0.0.9", CertSerial: c.recorded(), Version: c.versions["node-r"]},
		{Name: "node-o", Address: "10.0.0.10", CertSerial: "0ddba11", Version: c.versions["node-o"]}}
	return &pb.ListHostsResponse{Hosts: hosts}, nil
}

func (c *renewTestClient) PublishCRL(context.Context, *pb.PublishCRLRequest, ...grpc.CallOption) (*pb.PublishCRLResponse, error) {
	c.published++
	return &pb.PublishCRLResponse{Version: 3}, nil
}

func (c *renewTestClient) RevokeReplacedCertificate(_ context.Context, req *pb.RevokeReplacedCertificateRequest, _ ...grpc.CallOption) (*pb.RevokeReplacedCertificateResponse, error) {
	listed := false
	for _, s := range pki.CRLSerials([]byte(req.CrlPem)) {
		listed = listed || s == req.Serial
	}
	if !listed {
		return nil, errors.New("CRL does not list the serial")
	}
	c.revokeReq = append(c.revokeReq, req.Serial)
	if c.hold {
		return &pb.RevokeReplacedCertificateResponse{Held: true, Reason: "voter generation 3 would not verify"}, nil
	}
	c.published++
	return &pb.RevokeReplacedCertificateResponse{Revoked: true, Version: 4}, nil
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
	f := &renewFixture{op: op, host: host, prevSerial: strings.ToLower(prev), target: &dirTarget{Dir: host}}
	// The daemon's re-record: the cluster follows whatever the host serves.
	f.client = &renewTestClient{versions: map[string]string{"node-r": "v1", "node-o": "v1"}, recorded: func() string {
		c, err := pki.ServedHostCertificate(host)
		if err != nil {
			return f.prevSerial
		}
		return strings.ToLower(c.SerialNumber.Text(16))
	}}
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
		opts.Wait = 10 * time.Millisecond
	}
	return renewHostCert(context.Background(), f.client, f.target, probe, "node-r", opts)
}

func (f *renewFixture) served(t *testing.T) string {
	t.Helper()
	c, err := pki.ServedHostCertificate(f.host)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(c.SerialNumber.Text(16))
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

func noKeyFilesUnder(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".key") && !strings.HasSuffix(p, "ca.key") && !strings.HasSuffix(p, "client.key") {
			t.Errorf("a private key landed on the CA machine: %s", p)
		}
		return nil
	})
}

// A renewal: the host generates the key, the CA signs only the request, the
// running host serves the successor, and the replaced certificate is revoked
// through the cluster (RevokeReplacedCertificate), after which this machine's
// crl.pem carries it.
//
// Mutations: skip revokeReplaced — nothing is revoked; skip the crl.pem update
// on a published revocation — the local CRL misses the serial.
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
	if len(f.client.revokeReq) != 1 || f.client.revokeReq[0] != f.prevSerial || !crlHas(t, f.op, f.prevSerial) {
		t.Fatalf("the replaced certificate was not revoked (asked %v)", f.client.revokeReq)
	}
	if crlHas(t, f.op, served.SerialNumber.Text(16)) {
		t.Fatal("the renewed certificate was revoked")
	}
	if _, err := os.Stat(filepath.Join(f.host, "host.d", f.prevSerial)); !os.IsNotExist(err) {
		t.Fatal("the replaced key was left on the host")
	}
	noKeyFilesUnder(t, f.op)
	if !f.target.reloaded {
		t.Fatal("libvirt's TLS listener was not asked to reload")
	}
}

// When the cluster holds the revocation as owed, this machine's crl.pem must
// NOT carry the serial: the next CRL minted here would publish it early.
//
// Mutation: write the minted CRL to crl.pem on a held answer too.
func TestRenewHostCert_AnOwedRevocationStaysOutOfTheLocalCRL(t *testing.T) {
	f := newRenewFixture(t)
	f.client.hold = true
	if err := f.run(t, RenewCertOptions{}, f.probe); err != nil {
		t.Fatal(err)
	}
	if len(f.client.revokeReq) != 1 {
		t.Fatal("the revocation was not handed to the cluster")
	}
	if crlHas(t, f.op, f.prevSerial) {
		t.Fatal("a held revocation was written to the local crl.pem")
	}
}

// A host that demonstrably still presents the old certificate, with the new
// one unrecorded, is switched back — and the successor nobody presents is
// revoked.
//
// Mutation: skip abandonIssued after the rollback — the successor stays valid.
func TestRenewHostCert_RollsBackAndRevokesTheUnusedSuccessor(t *testing.T) {
	f := newRenewFixture(t)
	prevPEM, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	old, _ := pki.ParseCertPEM(prevPEM)
	f.client.recorded = func() string { return f.prevSerial }
	stuck := func(context.Context) (*x509.Certificate, error) { return old, nil }
	err := f.run(t, RenewCertOptions{}, stuck)
	if err == nil {
		t.Fatal("a renewal the host never presented reported success")
	}
	if got := f.served(t); got != f.prevSerial {
		t.Fatalf("the host was not switched back (serves %s)", got)
	}
	if crlHas(t, f.op, f.prevSerial) {
		t.Fatal("the certificate the host still presents was revoked")
	}
	var successor string
	for _, e := range readRenewalLog(f.op) {
		if e.State == "abandoned" {
			successor = e.Serial
		}
	}
	if successor == "" || !crlHas(t, f.op, successor) {
		t.Fatalf("the unused successor %q was not revoked", successor)
	}
	if _, err := os.Stat(filepath.Join(f.host, "host.d", successor)); !os.IsNotExist(err) {
		t.Fatal("the unused successor's key pair was left on the host, for start-up recovery to find")
	}
}

// A probe that only FAILS proves nothing: when the cluster already records the
// successor, the host adopted it, and rolling back would cut it off.
//
// Mutation: roll back on any probe error — the host ends on the old
// certificate while the cluster records the new one.
func TestRenewHostCert_AProbeErrorAfterAdoptionDoesNotRollBack(t *testing.T) {
	f := newRenewFixture(t)
	blind := func(ctx context.Context) (*x509.Certificate, error) {
		_, _ = f.probe(ctx) // the daemon still adopts at its own handshakes
		return nil, errors.New("connection refused")
	}
	if err := f.run(t, RenewCertOptions{}, blind); err != nil {
		t.Fatal(err)
	}
	if got := f.served(t); got == f.prevSerial {
		t.Fatal("rolled back a renewal the cluster had recorded")
	}
	if !crlHas(t, f.op, f.prevSerial) {
		t.Fatal("the replaced certificate was not revoked")
	}
}

// A probe that fails while nothing is recorded: leave everything as it is.
func TestRenewHostCert_AnUnconfirmedRenewalIsLeftAlone(t *testing.T) {
	f := newRenewFixture(t)
	f.client.recorded = func() string { return f.prevSerial }
	blind := func(context.Context) (*x509.Certificate, error) { return nil, errors.New("timeout") }
	if err := f.run(t, RenewCertOptions{}, blind); err == nil {
		t.Fatal("an unconfirmed renewal reported success")
	}
	if got := f.served(t); got == f.prevSerial {
		t.Fatal("rolled back on a probe that proved nothing")
	}
	if f.client.published != 0 || len(f.client.revokeReq) != 0 {
		t.Fatal("revoked something without knowing what the host presents")
	}
}

// An install that reports an error after the switch (a dropped connection)
// is recognised from the host's files and completes.
func TestRenewHostCert_AnErrorAfterTheSwitchCompletes(t *testing.T) {
	f := newRenewFixture(t)
	f.target.FailInstallAfterSwitch = true
	if err := f.run(t, RenewCertOptions{}, f.probe); err != nil {
		t.Fatal(err)
	}
	if !crlHas(t, f.op, f.prevSerial) {
		t.Fatal("the renewal did not complete")
	}
}

// When the cluster's record and the installed certificate disagree, nothing is
// touched.
//
// Mutation: drop the recorded-serial comparison — the renewal proceeds.
func TestRenewHostCert_RefusesWhenTheRecordDisagrees(t *testing.T) {
	f := newRenewFixture(t)
	f.client.recorded = func() string { return "deadbeef" }
	before, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	err := f.run(t, RenewCertOptions{}, f.probe)
	if err == nil || !strings.Contains(err.Error(), `records certificate "deadbeef"`) {
		t.Fatalf("got %v, want a refusal naming the recorded serial", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.host, "host.crt"))
	if string(after) != string(before) {
		t.Fatal("the host certificate was changed despite the refusal")
	}
}

// Mixed builds refuse without --force.
//
// Mutation: drop sameBuildEverywhere — the renewal proceeds.
func TestRenewHostCert_RefusesMixedBuildsWithoutForce(t *testing.T) {
	f := newRenewFixture(t)
	f.client.versions["node-o"] = "v0"
	if err := f.run(t, RenewCertOptions{}, f.probe); err == nil || !strings.Contains(err.Error(), "different build") {
		t.Fatalf("got %v, want a mixed-build refusal", err)
	}
	if err := f.run(t, RenewCertOptions{Force: true}, f.probe); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

// --keep-old renews without revoking.
func TestRenewHostCert_KeepOldDoesNotRevoke(t *testing.T) {
	f := newRenewFixture(t)
	if err := f.run(t, RenewCertOptions{KeepOld: true}, f.probe); err != nil {
		t.Fatal(err)
	}
	if crlHas(t, f.op, f.prevSerial) || f.client.published != 0 || len(f.client.revokeReq) != 0 {
		t.Fatal("--keep-old revoked the previous certificate")
	}
}

// A re-added host's audit admission record is re-signed for the new serial.
//
// Mutation: skip resignedRejoin — LoadAuditRejoin rejects the record.
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

// A record that does not verify is not laundered; the signed successor is
// revoked since it will never be installed.
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
	if f.served(t) != f.prevSerial {
		t.Fatal("installed a renewal after refusing")
	}
}

// revoke-cert accepts only a serial known to be the host's, and fences
// nothing by accident.
//
// Mutations: drop the other-host check (another host's live certificate is
// revoked); drop the probe-failure refusal; drop the known-serial check.
func TestHostRevokeCert_Guards(t *testing.T) {
	f := newRenewFixture(t)
	ctx := context.Background()
	if err := f.run(t, RenewCertOptions{KeepOld: true}, f.probe); err != nil {
		t.Fatal(err)
	}
	live := f.served(t)
	ok := f.probe
	down := func(context.Context) (*x509.Certificate, error) { return nil, errors.New("unreachable") }

	// Even a serial this machine's log (wrongly) attributes to node-r is
	// refused while another host is recorded with it.
	logRenewal(f.op, renewalEntry{Host: "node-r", Serial: "0ddba11", State: "issued"})
	if err := hostRevokeCert(ctx, f.client, "node-r", "0ddba11", false, ok, 0); err == nil ||
		!strings.Contains(err.Error(), "records for node-o") {
		t.Errorf("another host's live certificate was not refused as node-o's: %v", err)
	}
	if err := hostRevokeCert(ctx, f.client, "node-r", "0ddba11", true, ok, 0); err == nil {
		t.Error("--force revoked ANOTHER host's live certificate")
	}
	if err := hostRevokeCert(ctx, f.client, "node-r", live, false, ok, 0); err == nil ||
		!strings.Contains(err.Error(), "FENCED") {
		t.Errorf("revoked the host's live certificate without --force: %v", err)
	}
	if err := hostRevokeCert(ctx, f.client, "node-r", "abcdef", false, ok, 0); err == nil {
		t.Error("revoked a serial nobody knows to be this host's")
	}
	if err := hostRevokeCert(ctx, f.client, "node-r", f.prevSerial, false, down, 0); err == nil {
		t.Error("revoked without being able to read what the host presents")
	}
	if crlHas(t, f.op, f.prevSerial) || crlHas(t, f.op, live) {
		t.Fatal("a refused revocation reached the CRL")
	}
	if err := hostRevokeCert(ctx, f.client, "node-r", f.prevSerial, false, ok, 0); err != nil {
		t.Fatal(err)
	}
	if !crlHas(t, f.op, f.prevSerial) {
		t.Fatal("the replaced certificate was not revoked")
	}
}

// The CA machine's copy of the replaced key (left by `lv host init`) is removed
// by the renewal; a file there that is not that key is left alone.
//
// Mutation: skip removeCAMachineCopy — the copy outlives the renewal.
func TestRenewHostCert_RemovesTheCAMachinesCopyOfTheReplacedKey(t *testing.T) {
	f := newRenewFixture(t)
	key, _ := os.ReadFile(filepath.Join(f.host, "host.key"))
	if err := os.WriteFile(filepath.Join(f.op, "node-r.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.op, "node-o.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, RenewCertOptions{}, f.probe); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.op, "node-r.key")); !os.IsNotExist(err) {
		t.Fatal("the CA machine still holds a copy of the replaced key")
	}
	if _, err := os.Stat(filepath.Join(f.op, "node-o.key")); err != nil {
		t.Fatal("a file for another host was removed")
	}
}

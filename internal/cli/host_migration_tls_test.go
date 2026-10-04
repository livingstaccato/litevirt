package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

type fakeMigrationHost struct {
	name, address string
	provisioned   bool
	pushed        []migrationFile
}

func (h *fakeMigrationHost) Name() string    { return h.name }
func (h *fakeMigrationHost) Address() string { return h.address }
func (h *fakeMigrationHost) Provisioned(context.Context) (bool, error) {
	return h.provisioned, nil
}
func (h *fakeMigrationHost) Push(_ context.Context, files []migrationFile) error {
	h.pushed = files
	h.provisioned = true
	return nil
}

func pushedCert(t *testing.T, h *fakeMigrationHost, name string) *x509.Certificate {
	t.Helper()
	for _, f := range h.pushed {
		if filepath.Base(f.remote) != name {
			continue
		}
		data, err := os.ReadFile(f.local)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(data)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatalf("%s was not pushed to %s", name, h.name)
	return nil
}

// Every unprovisioned host gets a certificate from the cluster's migration CA,
// issued for the address peers dial, with its key 0600.
func TestInstallMigrationTLS_ProvisionsEveryHostFromOneMigrationCA(t *testing.T) {
	pkiDir := t.TempDir()
	a := &fakeMigrationHost{name: "node-1", address: "10.0.0.1"}
	b := &fakeMigrationHost{name: "node-2", address: "10.0.0.2"}
	var out bytes.Buffer
	if err := InstallMigrationTLS(context.Background(), pkiDir, []MigrationTLSHost{a, b}, false, &out); err != nil {
		t.Fatalf("InstallMigrationTLS: %v", err)
	}
	caA, caB := pushedCert(t, a, pki.MigrationCAName), pushedCert(t, b, pki.MigrationCAName)
	if !caA.Equal(caB) {
		t.Fatal("the two hosts got different migration CAs; neither could verify the other's certificate")
	}
	cert := pushedCert(t, b, pki.MigrationHostCertName)
	if len(cert.IPAddresses) == 0 || cert.IPAddresses[0].String() != "10.0.0.2" {
		t.Errorf("node-2's migration certificate carries IPs %v; libvirt checks it against 10.0.0.2", cert.IPAddresses)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caB)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("node-2's migration certificate does not verify against the migration CA: %v", err)
	}
	for _, f := range b.pushed {
		if filepath.Base(f.remote) == pki.MigrationHostKeyName && f.mode != 0o600 {
			t.Errorf("the migration key is pushed mode %04o, want 0600", f.mode)
		}
	}
}

// An already-provisioned host is left alone unless --reissue.
func TestInstallMigrationTLS_LeavesProvisionedHostsAlone(t *testing.T) {
	pkiDir := t.TempDir()
	first := &fakeMigrationHost{name: "node-1", address: "10.0.0.1"}
	if err := InstallMigrationTLS(context.Background(), pkiDir, []MigrationTLSHost{first}, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	first.pushed = nil
	if err := InstallMigrationTLS(context.Background(), pkiDir, []MigrationTLSHost{first}, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if first.pushed != nil {
		t.Error("a provisioned host was re-provisioned without --reissue")
	}
	if err := InstallMigrationTLS(context.Background(), pkiDir, []MigrationTLSHost{first}, true, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if first.pushed == nil {
		t.Error("--reissue did not re-provision the host")
	}
}

// A machine with no migration CA must not mint one while a host already holds
// credentials: they came from another CA, and a second one would issue
// certificates the provisioned hosts cannot verify.
func TestInstallMigrationTLS_RefusesASecondMigrationCA(t *testing.T) {
	held := &fakeMigrationHost{name: "node-1", address: "10.0.0.1", provisioned: true}
	err := InstallMigrationTLS(context.Background(), t.TempDir(),
		[]MigrationTLSHost{held, &fakeMigrationHost{name: "node-2", address: "10.0.0.2"}}, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "node-1") {
		t.Fatalf("err = %v; want a refusal naming node-1, which already holds credentials", err)
	}
}

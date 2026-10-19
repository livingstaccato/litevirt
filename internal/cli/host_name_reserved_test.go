package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// unsafeHostNames each collide with a fixed file in the operator's PKI
// directory, or with another host's pair, or leave the directory.
var unsafeHostNames = []string{
	"ca", "CA", "client", "host", "gossip", "migration-ca", "ui", "audit-signing", "lv-cli",
	"node-1-migration", "../esc", "/../esc", "a/b", "..", ".", "", "-rf", ".hidden",
}

// dirSnapshot is every file under root with its contents.
func dirSnapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				t.Fatal(rerr)
			}
			out[p] = b
		}
		return nil
	})
	return out
}

// sameTree fails when a file under root was added, removed or changed.
func sameTree(t *testing.T, name, root string, before map[string][]byte) {
	t.Helper()
	after := dirSnapshot(t, root)
	for p, b := range before {
		a, ok := after[p]
		if !ok {
			t.Errorf("%q: %s was removed", name, p)
		} else if !bytes.Equal(a, b) {
			t.Errorf("%q: %s was replaced", name, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%q: %s was written", name, p)
		}
	}
}

// operatorPKIUnder is an operator PKI directory one level below a temporary
// root, so a name with ".." in it lands somewhere the snapshot sees.
func operatorPKIUnder(t *testing.T) (root, dir string) {
	t.Helper()
	root = t.TempDir()
	t.Setenv("LV_CONFIG_DIR", filepath.Join(root, "cfg"))
	dir = PKIDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustCA(t, dir)
	if err := pki.GenerateClientCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"), "lv-cli"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureLocalGossipKey(dir); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

// `lv host init --local --name ca` minted the host pair over ca.crt and
// ca.key: the cluster CA was gone.
//
// Mutation: drop the name check in mintLocalHostCert — ca.crt is replaced and
// "../esc" writes beside the config directory.
func TestMintLocalHostCert_RefusesAnUnsafeName(t *testing.T) {
	for _, name := range unsafeHostNames {
		root, dir := operatorPKIUnder(t)
		before := dirSnapshot(t, root)
		if err := mintLocalHostCert(dir, name, "10.0.0.1"); err == nil {
			t.Errorf("mintLocalHostCert(%q) = nil, want a refusal", name)
		}
		sameTree(t, name, root, before)
	}
}

// The whole command refuses before it touches anything: with no client
// certificate yet, init would mint one before it reached the host pair.
//
// Mutation: drop the check at the top of HostInitLocal — client.crt is
// written before mintLocalHostCert refuses.
func TestHostInitLocal_RefusesAnUnsafeName(t *testing.T) {
	useConfig(t, "")
	for _, name := range []string{"ca", "client", "../esc"} {
		root, dir := operatorPKIUnder(t)
		for _, n := range []string{"client.crt", "client.key"} {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
		before := dirSnapshot(t, root)
		err := HostInitLocal(context.Background(), name, "10.0.0.1", false)
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("HostInitLocal(%q) = %v, want the name refused", name, err)
		}
		sameTree(t, name, root, before)
	}
}

// The remote form refuses before it parses the target or dials it.
//
// Mutation: drop the check at the top of HostInit — the error is the SSH
// target's, not the name's.
func TestHostInit_RefusesAnUnsafeNameBeforeConnecting(t *testing.T) {
	for _, name := range []string{"ca", "../esc"} {
		root, _ := operatorPKIUnder(t)
		before := dirSnapshot(t, root)
		err := HostInit(context.Background(), "root@", name, false)
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("HostInit(%q) = %v, want the name refused", name, err)
		}
		sameTree(t, name, root, before)
	}
}

// The remote add refuses before it parses the target or dials it.
//
// Mutation: drop the check at the top of HostAdd — the error is the SSH
// target's, not the name's.
func TestHostAddRemote_RefusesAnUnsafeNameBeforeConnecting(t *testing.T) {
	for _, name := range []string{"ca", "../esc"} {
		root, _ := operatorPKIUnder(t)
		before := dirSnapshot(t, root)
		err := HostAdd(context.Background(), nil, "root@", name, []string{"10.0.0.1:7946"})
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("HostAdd(%q) = %v, want the name refused", name, err)
		}
		sameTree(t, name, root, before)
	}
}

// mintStaged is where an add's pair is written; it refuses on its own.
//
// Mutation: drop the check in mintStaged — ".ca.crt.add" is written, and
// "/../esc" mints beside the PKI directory.
func TestMintStaged_RefusesAnUnsafeName(t *testing.T) {
	for _, name := range unsafeHostNames {
		root, dir := operatorPKIUnder(t)
		before := dirSnapshot(t, root)
		var local []string
		if _, _, err := mintStaged(dir, name, net.IPv4(10, 0, 0, 9), &local); err == nil {
			t.Errorf("mintStaged(%q) = nil, want a refusal", name)
		}
		sameTree(t, name, root, before)
	}
}

// `lv host add --name ca` minted ".ca.crt.add" and, once admitted, kept it as
// ca.crt — the operator's CA replaced by a host certificate. Nothing is asked
// of the cluster or pushed to the machine either.
//
// Mutation: drop the check in hostAddTo — the resume of an admitted "ca" or
// "/../esc" mints its migration pair under the name; drop it and mintStaged's
// too — "ca" is admitted and keeps its pair over ca.crt.
func TestHostAdd_RefusesAnUnsafeName(t *testing.T) {
	for _, name := range unsafeHostNames {
		f := newAddFixture(t)
		root := filepath.Dir(filepath.Dir(f.opPKI))
		before := dirSnapshot(t, root)
		err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9")
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("HostAddOn(%q) = %v, want the name refused", name, err)
		}
		if len(f.client.admitted) != 0 {
			t.Errorf("%q: AdmitHost was asked: %v", name, f.client.admitted)
		}
		if len(f.target.Events) != 0 {
			t.Errorf("%q: the machine was touched: %v", name, f.target.Events)
		}
		sameTree(t, name, root, before)
	}
	// Resuming an add the cluster already admitted (joining) under such a
	// name mints no host pair, so mintStaged's own check is never reached; the
	// migration pair is still minted under the name.
	for _, name := range []string{"ca", "/../esc"} {
		f := newAddFixture(t)
		serial, err := pki.CertSerial(filepath.Join(f.targetPKI, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		f.client.hosts = append(f.client.hosts, &pb.Host{Name: name, Address: "10.0.0.9",
			State: pb.HostState_HOST_JOINING, CertSerial: strings.ToLower(serial)})
		root := filepath.Dir(filepath.Dir(f.opPKI))
		before := dirSnapshot(t, root)
		err = HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9")
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("resume HostAddOn(%q) = %v, want the name refused", name, err)
		}
		if len(f.target.Events) != 0 {
			t.Errorf("resume %q: the machine was touched: %v", name, f.target.Events)
		}
		sameTree(t, "resume "+name, root, before)
	}
}

// `lv host migration-tls` issues a pair for every row of the replicated hosts
// table, which a peer can write, as <name>-migration.crt in the operator's
// directory. A row named "../esc" wrote outside it.
//
// Mutation: drop the check in issueMigrationCredentials — "../esc" writes
// ../esc-migration.crt.
func TestIssueMigrationCredentials_RefusesAnUnsafeName(t *testing.T) {
	for _, name := range unsafeHostNames {
		root, dir := operatorPKIUnder(t)
		if _, _, _, err := ensureLocalMigrationCA(dir, nil); err != nil {
			t.Fatal(err)
		}
		before := dirSnapshot(t, root)
		if _, err := issueMigrationCredentials(dir, name, net.IPv4(10, 0, 0, 9), nil); err == nil {
			t.Errorf("issueMigrationCredentials(%q) = nil, want a refusal", name)
		}
		sameTree(t, name, root, before)
	}
}

// A renewal removes the operator's copy of the replaced pair, <name>.key and
// <name>.crt. In a directory a pre-fix `lv host init --name ca` already
// overwrote, ca.key IS the replaced host key, and the renewal of "ca" deleted
// the cluster CA files outright.
//
// Mutation: drop the check in removeCAMachineCopy — ca.key and ca.crt are
// removed.
func TestRemoveCAMachineCopy_LeavesReservedFiles(t *testing.T) {
	root, dir := operatorPKIUnder(t)
	// What the pre-fix init left: the host pair over the CA's files.
	ca2 := filepath.Join(root, "ca2")
	if err := os.MkdirAll(ca2, 0o700); err != nil {
		t.Fatal(err)
	}
	mustCA(t, ca2)
	if err := pki.GenerateHostCert(filepath.Join(ca2, "ca.crt"), filepath.Join(ca2, "ca.key"),
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), "ca", net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	prev := mustParseCert(t, filepath.Join(dir, "ca.crt"))
	before := dirSnapshot(t, root)
	removeCAMachineCopy(dir, "ca", prev)
	sameTree(t, "ca", root, before)
}

// An operator directory written before the rule — the cluster's files and a
// pair per host — keeps working: a renewal still removes an existing host's
// replaced pair, and a new host is added beside the others.
//
// Mutation: make removeCAMachineCopy refuse every name — host-a's pair stays.
func TestHostNames_AnOldLayoutDirectoryStillWorks(t *testing.T) {
	f := newAddFixture(t)
	for _, n := range []string{"host-a", "Node_1"} {
		if err := pki.GenerateHostCert(filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key"),
			filepath.Join(f.opPKI, n+".crt"), filepath.Join(f.opPKI, n+".key"), n, net.IPv4(10, 0, 0, 2)); err != nil {
			t.Fatal(err)
		}
	}
	ca := mustRead(t, filepath.Join(f.opPKI, "ca.crt"))
	if err := f.add(t); err != nil {
		t.Fatalf("add beside an old-layout directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.opPKI, "node-9.crt")); err != nil {
		t.Errorf("the added host's pair was not kept: %v", err)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(f.opPKI, "ca.crt")), ca) {
		t.Error("ca.crt changed")
	}
	for _, n := range []string{"host-a", "Node_1"} {
		prev := mustParseCert(t, filepath.Join(f.opPKI, n+".crt"))
		removeCAMachineCopy(f.opPKI, n, prev)
		for _, ext := range []string{".crt", ".key"} {
			if _, err := os.Stat(filepath.Join(f.opPKI, n+ext)); !os.IsNotExist(err) {
				t.Errorf("%s%s was not removed after its renewal: %v", n, ext, err)
			}
		}
	}
}

func mustParseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	c, err := pki.ParseCertPEM(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

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
// directory, or with another host's pair, or leave the directory: refused
// as a NEW name.
var unsafeHostNames = []string{
	"ca", "CA", "client", "host", "gossip", "migration-ca", "ui", "audit-signing", "lv-cli",
	"node-1-migration", "../esc", "/../esc", "a/b", "..", ".", "", "-rf", ".hidden",
}

// traversalHostNames leave the directory, or read as an option: refused for
// every host, including one an older build admitted.
var traversalHostNames = []string{"../esc", "/../esc", "a/b", `a\b`, "..", ".", "", "-rf", "a\x00b"}

// pairUnsafeHostNames are traversalHostNames plus the names whose
// <name>.crt|.key is one of the directory's own files.
var pairUnsafeHostNames = append([]string{"ca", "CA", "client", "host", "gossip", "migration-ca", "ui",
	"audit-signing", "lv-cli"}, traversalHostNames...)

// legacyHostNames are names an older build admitted (it had no rule) that the
// new-name rule refuses, and that must keep their maintenance paths.
var legacyHostNames = []string{"Host", "ui", "web-migration", "node+1"}

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
	for _, name := range pairUnsafeHostNames {
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

// `lv host install-migration-tls` issues a pair for every row of the
// replicated hosts table, which a peer can write, as <name>-migration.crt in
// the operator's directory. A row named "../esc" wrote outside it.
//
// Mutation: drop the check in issueMigrationCredentials — "../esc" writes
// ../esc-migration.crt.
func TestIssueMigrationCredentials_RefusesAnUnsafeName(t *testing.T) {
	for _, name := range traversalHostNames {
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
// Mutation: drop the operator-file check in removeCAMachineCopy — ca.key and
// ca.crt are removed.
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
	if err := removeCAMachineCopy(dir, "ca", prev); err == nil || !strings.Contains(err.Error(), "ca.key was left") {
		t.Errorf("removeCAMachineCopy(ca) = %v, want it to report ca.key left", err)
	}
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
		if err := removeCAMachineCopy(f.opPKI, n, prev); err != nil {
			t.Errorf("removeCAMachineCopy(%s) = %v", n, err)
		}
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

// writeLegacyPair writes a host pair named name into dir from dir's CA, the
// way an older lv host init/add kept it.
func writeLegacyPair(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	return writeLegacyPairAt(t, dir, dir, name)
}

func writeLegacyPairAt(t *testing.T, caDir, dir, name string) *x509.Certificate {
	t.Helper()
	crt, key := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := pki.GenerateHostCert(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"),
		crt, key, name, net.IPv4(10, 0, 0, 7)); err != nil {
		t.Fatal(err)
	}
	return mustParseCert(t, crt)
}

// Older builds had no host-name rule, so a cluster can hold "Host", "ui",
// "web-migration" or "node+1". A renewal of one removes this machine's copy
// of its replaced pair as for any host; the new-name rule silently skipped it.
//
// Mutation: check the new-name rule (pki.ValidateHostName) in
// removeCAMachineCopy — every legacy pair stays.
func TestRemoveCAMachineCopy_RemovesALegacyNamesPair(t *testing.T) {
	for _, name := range legacyHostNames {
		_, dir := operatorPKIUnder(t)
		prev := writeLegacyPair(t, dir, name)
		if err := removeCAMachineCopy(dir, name, prev); err != nil {
			t.Errorf("removeCAMachineCopy(%q) = %v", name, err)
		}
		for _, ext := range []string{".crt", ".key"} {
			if _, err := os.Stat(filepath.Join(dir, name+ext)); !os.IsNotExist(err) {
				t.Errorf("%s%s was not removed after its renewal: %v", name, ext, err)
			}
		}
		for _, n := range []string{"ca.crt", "ca.key", "client.crt", "client.key"} {
			if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
				t.Errorf("%q: %s is gone: %v", name, n, err)
			}
		}
	}
}

// A name that leaves the directory is refused loudly, never skipped: the
// renewal reports the copy it did not look for, and nothing outside the
// directory is read or removed.
//
// Mutation: drop the path check in removeCAMachineCopy — "../esc" removes
// the pair beside the PKI directory.
func TestRemoveCAMachineCopy_RefusesATraversalNameLoudly(t *testing.T) {
	root, dir := operatorPKIUnder(t)
	prev := writeLegacyPairAt(t, dir, filepath.Dir(dir), "esc")
	before := dirSnapshot(t, root)
	for _, name := range []string{"../esc", "/../esc"} {
		if err := removeCAMachineCopy(dir, name, prev); err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("removeCAMachineCopy(%q) = %v, want the name refused", name, err)
		}
	}
	sameTree(t, "../esc", root, before)
}

// install-migration-tls provisions a host an older build admitted under a name
// the new-name rule refuses: <name>-migration.* can never be one of the
// directory's own files, so only containment is asked of it. The new-name
// rule stopped the whole loop at the first such host.
//
// Mutation: check the new-name rule in issueMigrationCredentials — no legacy
// host, and no host after it, is provisioned.
func TestInstallMigrationTLS_ProvisionsLegacyNames(t *testing.T) {
	for _, name := range legacyHostNames {
		_, dir := operatorPKIUnder(t)
		legacy := &fakeMigrationHost{name: name, address: "10.0.0.1"}
		next := &fakeMigrationHost{name: "node-2", address: "10.0.0.2"}
		var out bytes.Buffer
		if err := InstallMigrationTLS(context.Background(), dir, []MigrationTLSHost{legacy, next}, false, &out); err != nil {
			t.Errorf("InstallMigrationTLS with %q = %v\n%s", name, err, out.String())
		}
		if !legacy.provisioned || !next.provisioned {
			t.Errorf("%q: provisioned %s=%v node-2=%v", name, name, legacy.provisioned, next.provisioned)
		}
		if _, err := os.Stat(filepath.Join(dir, name+"-migration.crt")); err != nil {
			t.Errorf("%q: this machine's copy of its migration pair: %v", name, err)
		}
	}
}

// A host it cannot provision (a traversal name from a peer-written row, an
// address that is not IPv4, a name whose migration pair is another host's) is
// reported, the rest are still provisioned, and the command fails at the end
// naming each one.
//
// Mutations: return on the first failure — node-2 is not provisioned; drop
// the final error — the command succeeds; drop migrationPairOwner — "web"
// replaces this machine's copy of host web-migration's pair.
func TestInstallMigrationTLS_ContinuesPastARefusedHost(t *testing.T) {
	root, dir := operatorPKIUnder(t)
	writeLegacyPair(t, dir, "web-migration")
	keep := mustRead(t, filepath.Join(dir, "web-migration.crt"))
	esc := &fakeMigrationHost{name: "../esc", address: "10.0.0.1"}
	badAddr := &fakeMigrationHost{name: "node-3", address: "fe80::1"}
	web := &fakeMigrationHost{name: "web", address: "10.0.0.4"}
	webMig := &fakeMigrationHost{name: "web-migration", address: "10.0.0.5"}
	next := &fakeMigrationHost{name: "node-2", address: "10.0.0.2"}
	var out bytes.Buffer
	err := InstallMigrationTLS(context.Background(), dir, []MigrationTLSHost{esc, badAddr, web, webMig, next}, false, &out)
	if err == nil {
		t.Fatalf("InstallMigrationTLS succeeded with three refused hosts\n%s", out.String())
	}
	for _, n := range []string{"../esc", "node-3", "web"} {
		if !strings.Contains(err.Error(), n) || !strings.Contains(out.String(), n+": NOT provisioned") {
			t.Errorf("%s is not reported: err=%v\n%s", n, err, out.String())
		}
	}
	if esc.provisioned || badAddr.provisioned || web.provisioned {
		t.Error("a refused host was provisioned")
	}
	if !next.provisioned || !webMig.provisioned {
		t.Errorf("a host after a refused one was not provisioned: node-2=%v web-migration=%v", next.provisioned, webMig.provisioned)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, "web-migration.crt")), keep) {
		t.Error("this machine's copy of host web-migration's pair was replaced")
	}
	if _, err := os.Stat(filepath.Join(root, "cfg", "esc-migration.crt")); !os.IsNotExist(err) {
		t.Errorf("../esc wrote outside the PKI directory: %v", err)
	}
}

// issueMigrationCredentials itself keeps every legacy name.
func TestIssueMigrationCredentials_KeepsLegacyNames(t *testing.T) {
	for _, name := range legacyHostNames {
		_, dir := operatorPKIUnder(t)
		if _, err := issueMigrationCredentials(dir, name, net.IPv4(10, 0, 0, 9), nil); err != nil {
			t.Errorf("issueMigrationCredentials(%q) = %v", name, err)
		}
	}
}

// Resuming an add an older lv started under a name the new-name rule refuses
// (the cluster lists it joining) finishes it: the name is not new.
//
// Mutation: apply the new-name rule regardless of a live row in checkAddName
// — the resume is refused.
func TestHostAdd_ResumesALegacyName(t *testing.T) {
	for _, name := range []string{"node+1", "web-migration", "Node 1"} {
		f := newAddFixture(t)
		serial, err := pki.CertSerial(filepath.Join(f.targetPKI, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		f.client.hosts = append(f.client.hosts, &pb.Host{Name: name, Address: "10.0.0.9",
			State: pb.HostState_HOST_JOINING, CertSerial: strings.ToLower(serial)})
		if err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9"); err != nil {
			t.Errorf("resume HostAddOn(%q) = %v", name, err)
		}
	}
}

// A new host "web" beside a live host an older build admitted as
// "web-migration" would keep its migration pair over that host's pair.
//
// Mutation: drop the loop in checkAddName — the add proceeds.
func TestHostAdd_RefusesANameWhoseMigrationPairIsAnotherHosts(t *testing.T) {
	f := newAddFixture(t)
	f.client.hosts = append(f.client.hosts, &pb.Host{Name: "web-migration", Address: "10.0.0.5",
		State: pb.HostState_HOST_ACTIVE, CertSerial: "c1"})
	err := HostAddOn(context.Background(), f.client, f.target, "web", "10.0.0.9")
	if err == nil || !strings.Contains(err.Error(), "web-migration") {
		t.Fatalf("HostAddOn(web) = %v, want a refusal naming web-migration", err)
	}
	if len(f.client.admitted) != 0 || len(f.target.Events) != 0 {
		t.Errorf("the refused add went ahead: admitted=%v events=%v", f.client.admitted, f.target.Events)
	}
}

// publicAddProbes stubs the two SSH reads `lv host add` makes of the join
// peers before it reaches the target (their config, and whether they hold
// migration credentials), and counts them.
func publicAddProbes(t *testing.T) *int {
	t.Helper()
	n := 0
	oldCfg, oldMig := readPeerConfig, peerHoldsMigrationCredentials
	t.Cleanup(func() { readPeerConfig, peerHoldsMigrationCredentials = oldCfg, oldMig })
	readPeerConfig = func(string) (string, bool, error) {
		n++
		return "enforcement:\n  operation_protocol: true\n", true, nil
	}
	peerHoldsMigrationCredentials = func(string) (bool, error) {
		n++
		return false, nil
	}
	return &n
}

// The public `lv host add` decided whether a name was NEW only after it had
// minted the migration CA and the client pair here and dialled the target, so
// a refused new name ("node+1", ".hidden", "web-migration") still changed this
// machine's PKI directory. The name is decided from the cluster's hosts first.
// Port 1 on loopback refuses at once: reaching the target is an error that is
// not the name's.
//
// Mutation: drop the ListHosts/checkAddName preflight in HostAdd — the
// migration CA and client pair are minted and the target is dialled.
func TestHostAddPublic_RefusesANewNameBeforeAnyEffect(t *testing.T) {
	useConfig(t, "")
	for _, name := range []string{"node+1", ".hidden", "web-migration"} {
		root, dir := operatorPKIUnder(t)
		for _, n := range []string{"client.crt", "client.key"} {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
		probes := publicAddProbes(t)
		c := &hostAddTestClient{hosts: []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}}
		before := dirSnapshot(t, root)
		err := HostAdd(context.Background(), c, "root@127.0.0.1:1", name, []string{"10.0.0.1:7946"})
		if err == nil || !strings.Contains(err.Error(), "invalid host name") {
			t.Errorf("HostAdd(%q) = %v, want the name refused", name, err)
		}
		if *probes != 0 {
			t.Errorf("%q: %d SSH read(s) of the join peers before the refusal", name, *probes)
		}
		sameTree(t, name, root, before)
	}
}

// The same entry still takes a name a live row holds (an add an older lv
// started): the preflight lets it through to the target, which here refuses
// the connection.
//
// Mutation: apply the new-name rule regardless of a live row — "node+1" is
// refused by name.
func TestHostAddPublic_KeepsALiveLegacyName(t *testing.T) {
	useConfig(t, "")
	for _, name := range []string{"node+1", "web-migration"} {
		operatorPKIUnder(t)
		publicAddProbes(t)
		c := &hostAddTestClient{hosts: []*pb.Host{
			{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"},
			{Name: name, Address: "127.0.0.1", State: pb.HostState_HOST_JOINING, CertSerial: "b2"},
		}}
		err := HostAdd(context.Background(), c, "root@127.0.0.1:1", name, []string{"10.0.0.1:7946"})
		if err == nil || strings.Contains(err.Error(), "invalid host name") || !strings.Contains(err.Error(), "SSH connect") {
			t.Errorf("HostAdd(%q) over its live row = %v, want it to reach the target", name, err)
		}
	}
}

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hostAddTestClient admits as the daemon does: a new name, or a live one
// under the same serial (a retry); a live name under another serial is
// refused. target is the machine being added, so AdmitHost can record what
// had already been written to it.
type hostAddTestClient struct {
	pb.LiteVirtClient
	hosts    []*pb.Host
	admitErr error
	admitted []string // serials AdmitHost was asked for
	target   *LocalAddTarget
	// atAdmit is what had reached the target when AdmitHost ran.
	atAdmit []string
}

func (c *hostAddTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: c.hosts}, nil
}

func (c *hostAddTestClient) AdmitHost(_ context.Context, req *pb.AdmitHostRequest, _ ...grpc.CallOption) (*pb.AdmitHostResponse, error) {
	c.admitted = append(c.admitted, req.GetCertSerial())
	if c.atAdmit == nil { // the first: an add asks again before it installs
		c.atAdmit = append([]string{}, c.target.Events...)
	}
	if c.admitErr != nil {
		return nil, c.admitErr
	}
	for _, h := range c.hosts {
		if h.GetName() != req.GetName() {
			continue
		}
		if strings.EqualFold(h.GetCertSerial(), req.GetCertSerial()) {
			return &pb.AdmitHostResponse{AuditPositionProven: true}, nil
		}
		return nil, status.Errorf(codes.FailedPrecondition, "admit host: host %q is already active", req.GetName())
	}
	c.hosts = append(c.hosts, &pb.Host{Name: req.GetName(), Address: req.GetAddress(),
		State: pb.HostState_HOST_JOINING, CertSerial: req.GetCertSerial()})
	return &pb.AdmitHostResponse{AuditPositionProven: true}, nil
}

// addFixture is an operator machine with the cluster CA and a target machine
// whose pki directory already holds an identity (a previous machine's).
type addFixture struct {
	opPKI, targetPKI string
	target           *LocalAddTarget
	client           *hostAddTestClient
	// before is the target's host.crt and host.key as they were.
	before map[string][]byte
}

func newAddFixture(t *testing.T) *addFixture {
	t.Helper()
	opPKI := addOperatorPKI(t)
	useConfig(t, "")
	root := t.TempDir()
	targetPKI := filepath.Join(root, "etc", "litevirt", "pki")
	if err := os.MkdirAll(targetPKI, 0o700); err != nil {
		t.Fatal(err)
	}
	// The previous identity on the machine, from the same CA.
	if err := pki.GenerateHostCert(filepath.Join(opPKI, "ca.crt"), filepath.Join(opPKI, "ca.key"),
		filepath.Join(targetPKI, "host.crt"), filepath.Join(targetPKI, "host.key"), "old-name", net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(bin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &addFixture{opPKI: opPKI, targetPKI: targetPKI, before: map[string][]byte{}}
	f.target = &LocalAddTarget{Root: root, PKIDir: targetPKI, Binary: bin}
	f.client = &hostAddTestClient{target: f.target,
		hosts: []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}}
	for _, n := range []string{"host.crt", "host.key"} {
		f.before[n] = mustRead(t, filepath.Join(targetPKI, n))
	}
	return f
}

func (f *addFixture) add(t *testing.T) error {
	t.Helper()
	return HostAddOn(context.Background(), f.client, f.target, "node-9", "10.0.0.9")
}

func (f *addFixture) identityUnchanged(t *testing.T) {
	t.Helper()
	for n, want := range f.before {
		if got := mustRead(t, filepath.Join(f.targetPKI, n)); !bytes.Equal(got, want) {
			t.Errorf("the machine's %s was replaced", n)
		}
	}
}

// staged lists the files left at staged paths on the target.
func (f *addFixture) staged(t *testing.T) []string {
	t.Helper()
	return stagedOnTarget(t, f.target.Root)
}

// isStagedWrite reports whether event e is an upload to a staged path.
func isStagedWrite(e string) bool {
	return strings.HasPrefix(e, "write ") && strings.Contains(filepath.Base(e), ".add-")
}

// installedLive reports whether anything was moved into place or run on the
// target, other than uploads to staged paths and their removal.
func installedLive(events []string) []string {
	var live []string
	for _, e := range events {
		switch {
		case isStagedWrite(e):
		case e == "sh mkdir", e == "sh unstage", e == "sh config", e == "sh records",
			e == "sh "+stateProbeKind, e == "sh "+daemonProbeKind:
		default:
			live = append(live, e)
		}
	}
	return live
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// otherOperator points `lv` at a second operator machine that holds only the
// cluster CA (copied from dir): none of the first one's minted pairs.
func otherOperator(t *testing.T, dir string) {
	t.Helper()
	cfg := t.TempDir()
	op := filepath.Join(cfg, "pki")
	if err := os.MkdirAll(op, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ca.crt", "ca.key", pki.MigrationCACertName, pki.MigrationCAKeyName} {
		if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			if err := os.WriteFile(filepath.Join(op, n), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("LV_CONFIG_DIR", cfg)
}

// F8/A8: `lv host add` pushed host.crt and host.key BEFORE AdmitHost, so an
// add the daemon refused (an active name) had already replaced the key of the
// machine on disk; on the lab the live host was then held as superseded and
// cut off. Everything is uploaded to staged paths first, AdmitHost is asked,
// and a refusal removes the staged files: nothing live is touched.
//
// Mutation: install before AdmitHost — the refused add replaced host.key.
func TestHostAdd_ARefusedAdmissionInstallsNothing(t *testing.T) {
	f := newAddFixture(t)
	f.client.admitErr = status.Error(codes.FailedPrecondition, `admit host: host "node-9" is already active`)
	if err := f.add(t); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("add = %v, want the daemon's refusal", err)
	}
	if live := installedLive(f.target.Events); len(live) != 0 {
		t.Errorf("a refused add reached the machine's live files: %v", live)
	}
	if left := f.staged(t); len(left) != 0 {
		t.Errorf("a refused add left staged files: %v", left)
	}
	f.identityUnchanged(t)
	if m, _ := filepath.Glob(filepath.Join(f.opPKI, "*node-9*")); len(m) != 0 {
		t.Errorf("a refused add left minted files with the operator: %v", m)
	}
}

// I1: the binary and every identity file are uploaded BEFORE the admission,
// so the slow transfers cannot fail after it and strand a joining row (a
// voter that never answers). A failed upload asks nothing of the cluster.
//
// Mutations: upload the binary after AdmitHost — "staged first" sees no
// binary write before admission; admit before uploading — "upload fails"
// sees an AdmitHost.
func TestHostAdd_UploadsEverythingBeforeTheAdmission(t *testing.T) {
	t.Run("staged first", func(t *testing.T) {
		f := newAddFixture(t)
		if err := f.add(t); err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{"write /usr/local/bin/.litevirt.add-": false, "write /etc/litevirt/pki/.host.key.add-": false}
		for _, e := range f.client.atAdmit {
			for w := range want {
				if strings.HasPrefix(e, w) {
					want[w] = true
				}
			}
		}
		for e, seen := range want {
			if !seen {
				t.Errorf("%q had not happened when AdmitHost ran: %v", e, f.client.atAdmit)
			}
		}
		if live := installedLive(f.client.atAdmit); len(live) != 0 {
			t.Errorf("live changes before AdmitHost: %v", live)
		}
	})
	t.Run("upload fails", func(t *testing.T) {
		f := newAddFixture(t)
		f.target.FailWrite = map[string]error{"/usr/local/bin/.litevirt.add": errors.New("connection lost")}
		err := f.add(t)
		if err == nil || !strings.Contains(err.Error(), "nothing was admitted") {
			t.Fatalf("add = %v, want the upload failure", err)
		}
		if len(f.client.admitted) != 0 {
			t.Errorf("AdmitHost was asked after a failed upload: %v", f.client.admitted)
		}
		if left := f.staged(t); len(left) != 0 {
			t.Errorf("staged files left: %v", left)
		}
		f.identityUnchanged(t)
	})
}

// After a successful add the machine serves the admitted certificate, the
// copies of the files it replaced are removed (m2), and the old daemon was
// stopped before anything was installed (m4).
//
// Mutations: drop the discard — copies left; drop the stop — no stop
// precedes the install.
func TestHostAdd_InstallsAfterStoppingTheDaemonAndCleansUp(t *testing.T) {
	f := newAddFixture(t)
	if err := f.add(t); err != nil {
		t.Fatal(err)
	}
	served := installedSerial(mustRead(t, filepath.Join(f.targetPKI, "host.crt")))
	if !oneSerial(f.client.admitted) || served != f.client.admitted[0] {
		t.Errorf("the machine serves %s, admitted %v", served, f.client.admitted)
	}
	if m, _ := filepath.Glob(filepath.Join(f.targetPKI, "*.pre-add-*")); len(m) != 0 {
		t.Errorf("copies left after a successful add: %v", m)
	}
	if left := f.staged(t); len(left) != 0 {
		t.Errorf("staged files left: %v", left)
	}
	stop, install := -1, -1
	for i, e := range f.target.Events {
		if strings.HasPrefix(e, "run ") && strings.Contains(e, "systemctl stop litevirt") && stop < 0 {
			stop = i
		}
		if e == "sh install" && install < 0 {
			install = i
		}
	}
	if stop < 0 || install < 0 || stop > install {
		t.Errorf("the daemon is not stopped before the install: %v", f.target.Events)
	}
}

// An add that fails after the admission (here: setup) puts the machine's
// previous host.crt and host.key back, keeps the admitted pair staged on the
// host, and names both the rerun and `lv host rm`. A rerun from ANOTHER
// operator machine (m1) finishes the add with the admitted certificate.
//
// Mutations: drop the Restore — the machine keeps the new key; restore by
// deleting the new files — the rerun finds no admitted pair; mint on the
// rerun — the daemon refuses it as already active.
func TestHostAdd_AFailedAddRestoresAndARerunFromAnywhereFinishes(t *testing.T) {
	f := newAddFixture(t)
	f.target.FailSetup = errors.New("setup failed")
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "lv host add --name node-9") || !strings.Contains(err.Error(), "lv host rm node-9") {
		t.Fatalf("add = %v, want the setup failure naming the rerun and lv host rm", err)
	}
	f.identityUnchanged(t)
	if _, err := os.Stat(filepath.Join(f.targetPKI, "migration", pki.MigrationHostKeyName)); !os.IsNotExist(err) {
		t.Errorf("a file the failed add created is still in place (stat: %v)", err)
	}
	if m, _ := filepath.Glob(filepath.Join(f.targetPKI, "*.pre-add-*")); len(m) != 0 {
		t.Errorf("copies left after the restore: %v", m)
	}

	otherOperator(t, f.opPKI)
	f.target.FailSetup = nil
	if err := f.add(t); err != nil {
		t.Fatalf("the rerun: %v", err)
	}
	if len(f.client.admitted) < 2 || !oneSerial(f.client.admitted) {
		t.Errorf("admitted %v, want the first admission's certificate again", f.client.admitted)
	}
	if got := installedSerial(mustRead(t, filepath.Join(f.targetPKI, "host.crt"))); got != f.client.admitted[0] {
		t.Errorf("the machine serves %s, want %s", got, f.client.admitted[0])
	}
}

// m1(b): a rerun after the add DID finish (its reply lost, say) finds the
// host up under its admitted certificate and says so, instead of refusing it
// as another member or telling the operator to remove it.
//
// Mutation: drop the already-added case — the rerun mints, and the daemon
// refuses it as already active.
func TestHostAdd_ARerunAfterTheAddFinishedIsANoOp(t *testing.T) {
	f := newAddFixture(t)
	if err := f.add(t); err != nil {
		t.Fatal(err)
	}
	f.client.hosts[len(f.client.hosts)-1].State = pb.HostState_HOST_ACTIVE
	n, asked := len(f.target.Events), len(f.client.admitted)
	if err := f.add(t); err != nil {
		t.Fatalf("the rerun of a finished add: %v", err)
	}
	if len(f.client.admitted) != asked {
		t.Errorf("AdmitHost asked again: %v", f.client.admitted)
	}
	if extra := f.target.Events[n:]; len(extra) != 0 {
		t.Errorf("the rerun reached the machine: %v", extra)
	}
}

// A machine that is another live member is refused before the admission and
// before anything is uploaded: by the certificate it serves, or (I3) by its
// address, which catches a member whose served serial is not the recorded
// one (a held runtime swap, a renewal in progress).
//
// Mutations: drop the serial check — "serial" passes; drop the address
// check — "address" passes.
func TestHostAdd_RefusesAMachineThatIsAnotherMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  func(f *addFixture) *pb.Host
	}{
		{"serial", func(f *addFixture) *pb.Host {
			return &pb.Host{Name: "node-3", Address: "10.0.0.3", State: pb.HostState_HOST_ACTIVE,
				CertSerial: strings.ToUpper(installedSerial(f.before["host.crt"]))}
		}},
		{"address", func(*addFixture) *pb.Host {
			return &pb.Host{Name: "node-3", Address: "10.0.0.9", State: pb.HostState_HOST_ACTIVE, CertSerial: "beef"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			f.client.hosts = append(f.client.hosts, tc.row(f))
			err := f.add(t)
			if err == nil || !strings.Contains(err.Error(), "node-3") || !strings.Contains(err.Error(), "lv host rm node-3") {
				t.Fatalf("add = %v, want a refusal naming node-3", err)
			}
			if len(f.client.admitted) != 0 {
				t.Errorf("AdmitHost was asked (%v) for a machine that is a live member", f.client.admitted)
			}
			if len(f.target.Events) != 0 {
				t.Errorf("reached a live member: %v", f.target.Events)
			}
			f.identityUnchanged(t)
		})
	}
}

// A3: the binary lands by rename at 0755, so a running daemon's executable is
// replaced rather than opened for writing (ETXTBSY).
func TestHostAdd_PushesTheBinaryByRenameAtItsMode(t *testing.T) {
	f := newAddFixture(t)
	if err := f.add(t); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(f.target.Root, "usr", "local", "bin", "litevirt"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("binary: %v, %v; want 0755", st, err)
	}
	for _, e := range f.target.Events {
		if strings.Contains(e, "chmod") && strings.Contains(e, "/usr/local/bin/litevirt") {
			t.Errorf("the binary's mode is set after it lands: %q", e)
		}
	}
}

// The file commands, run by sh over a directory as they run on the host.
//
//   - install keeps a copy of each file it replaces: its CONTENT, also of a
//     symlinked key, at 0600 whatever the original's mode (m2), and syncs
//     before and after each rename (m3);
//   - restore puts each copy back and returns the installed file to its
//     staged path; a file that did not exist is not left in place;
//   - exists names only the files present.
//
// Mutations: drop the cp — no copy; cp -P (no dereference) — the copy is a
// symlink; drop the chmod — the copy of a 0644 key is 0644; drop the sync —
// "syncs" fails; restore by rm — the admitted file is lost; exists printing
// every path — the new file is "restored" to nothing.
func TestAddInstallCommands_KeepAndRestore(t *testing.T) {
	dir := t.TempDir()
	// Root "/" maps every path outside /etc/litevirt/pki to itself.
	r := &LocalAddTarget{Root: "/", PKIDir: dir}
	key, added := filepath.Join(dir, "host.key"), filepath.Join(dir, "gossip.key")
	real := filepath.Join(dir, "host.d", "current", "host.key")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, key); err != nil {
		t.Fatal(err)
	}
	paths := []string{key, added}
	out, err := r.Shell("exists", existsCmd(r, paths))
	if err != nil {
		t.Fatal(err)
	}
	existed := existsSet(r, paths, out)
	if existed[key] != "644" || existed[added] != "" {
		t.Fatalf("exists = %v, want only %s", existed, key)
	}
	for _, p := range paths {
		if err := os.WriteFile(addStagedPath(p, "ab"), []byte("new "+filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const suffix = ".pre-add-x"
	cmd := installCmd(r, paths, suffix, "ab")
	if strings.Index(cmd, "sync") < 0 || strings.Index(cmd, "sync") > strings.Index(cmd, "mv -fT") ||
		strings.LastIndex(cmd, "sync") < strings.LastIndex(cmd, "mv -fT") {
		t.Errorf("install does not sync before and after its renames:\n%s", cmd)
	}
	if _, err := r.Shell("install", cmd); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, key)); got != "new host.key" {
		t.Fatalf("installed key = %q", got)
	}
	st, err := os.Lstat(key + suffix)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("the copy of a symlinked 0644 key: %v, %v; want a regular 0600 file", st, err)
	}
	if got := string(mustRead(t, key+suffix)); got != "old" {
		t.Fatalf("kept copy = %q, want the old key", got)
	}
	if _, err := r.Shell("restore", restoreCmd(r, paths, existed, stagedHashes(paths), suffix, "ab")); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, key)); got != "old" {
		t.Errorf("restored key = %q, want the old key", got)
	}
	// fd re-review 2 N2-m1: put back at its own mode, not the copy's 0600.
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("the restored key: %v, %v; want its own 0644", st, err)
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Errorf("a file the add created is still in place (stat: %v)", err)
	}
	for _, p := range paths {
		if got := string(mustRead(t, addStagedPath(p, "ab"))); got != "new "+filepath.Base(p) {
			t.Errorf("the admitted %s is not back at its staged path: %q", filepath.Base(p), got)
		}
	}
	if _, err := os.Stat(key + suffix); !os.IsNotExist(err) {
		t.Errorf("the copy survived the restore (stat: %v)", err)
	}
}

const operatorConfig = `# operator notes
host_name: "node-2"
grpc_port: 7443
pki_dir: /srv/litevirt/pki

data_dir: /var/lib/litevirt   # big disk
advertise_address: "10.0.0.2"
join_peers: ["10.0.0.5:7946"]
migration:
    network: 10.78.1.0/24     # storage VLAN
enforcement:
  audit_signature: false
  partition_pause: false
ui_tls: off
`

// What the add makes of operatorConfig in a cluster with no enforcement
// block (HostAddOn): only the keys it must set change, in place; the
// machine's own enforcement block goes; every other byte is the operator's.
const mergedOperatorConfig = `# operator notes
host_name: "node-9"
grpc_port: 7443
pki_dir: /etc/litevirt/pki

data_dir: /var/lib/litevirt   # big disk
advertise_address: "10.0.0.9"
join_peers: []
migration:
    network: 10.78.1.0/24     # storage VLAN
ui_tls: off
`

func writeTargetConfig(t *testing.T, f *addFixture, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(f.target.Root, "etc", "litevirt", "config.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// Lab recheck3 anomaly 4: `lv host add` wrote a re-added machine's
// config.yaml afresh, and the operator's `migration.network` was lost. The
// add edits in place only the keys it must set, and keeps every other byte
// (fd re-review N-m2). The machine's own enforcement block goes when the
// cluster has none (N-I1: a re-added host must not keep its old kill
// switches), and pki_dir is the directory the add installs to (N-I2). The
// file keeps its mode, and a symlinked config stays a symlink. The copy of
// the original is kept, 0600, after a successful add, and put back on a
// failure.
//
// Mutations: keep the machine's enforcement block when the cluster has none
// — "merged" differs; leave pki_dir — "merged" differs; re-emit the whole
// document — "merged" differs (indentation, blank line, comments); write
// at 0644 — "mode" fails; replace the symlink — "symlink" fails; discard
// the config's copy — "merged" finds none.
func TestHostAdd_KeepsTheMachinesConfig(t *testing.T) {
	t.Run("merged", func(t *testing.T) {
		f := newAddFixture(t)
		cfg := writeTargetConfig(t, f, operatorConfig, 0o640)
		if err := f.add(t); err != nil {
			t.Fatal(err)
		}
		if got := string(mustRead(t, cfg)); got != mergedOperatorConfig {
			t.Errorf("merged config:\n%s\nwant:\n%s", got, mergedOperatorConfig)
		}
		if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
			t.Errorf("the config is %o, want its own 0640", st.Mode().Perm())
		}
		setup := ""
		for _, e := range f.target.Events {
			if strings.Contains(e, "bash -s") {
				setup = e
			}
		}
		if !strings.Contains(setup, "CONFIG_INSTALLED='1'") {
			t.Errorf("setup is not told the config is installed: %q", setup)
		}
		m, _ := filepath.Glob(cfg + ".pre-add-*")
		if len(m) != 1 || string(mustRead(t, m[0])) != operatorConfig {
			t.Fatalf("the original config is not kept beside it: %v", m)
		}
		if st, _ := os.Stat(m[0]); st.Mode().Perm() != 0o600 {
			t.Errorf("the kept config is %o, want 0600", st.Mode().Perm())
		}
		if k, _ := filepath.Glob(filepath.Join(f.targetPKI, "*.pre-add-*")); len(k) != 0 {
			t.Errorf("copies of replaced keys left: %v", k)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		f := newAddFixture(t)
		managed := filepath.Join(f.target.Root, "srv", "cm", "litevirt.yaml")
		if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(managed, []byte(operatorConfig), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(f.target.Root, "etc", "litevirt", "config.yaml")
		if err := os.Symlink(managed, link); err != nil {
			t.Fatal(err)
		}
		if err := f.add(t); err != nil {
			t.Fatal(err)
		}
		if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the config symlink was replaced by a file (%v)", err)
		}
		if got := string(mustRead(t, managed)); got != mergedOperatorConfig {
			t.Errorf("the link's target was not merged:\n%s", got)
		}
	})
	t.Run("failed", func(t *testing.T) {
		f := newAddFixture(t)
		cfg := writeTargetConfig(t, f, operatorConfig, 0o640)
		f.target.FailSetup = errors.New("setup failed")
		if err := f.add(t); err == nil {
			t.Fatal("the add succeeded")
		}
		if got := string(mustRead(t, cfg)); got != operatorConfig {
			t.Errorf("the config was not put back:\n%s", got)
		}
		if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
			t.Errorf("the config was put back at %o, want its own 0640", st.Mode().Perm())
		}
	})
	for _, tc := range []struct{ name, body, want string }{
		{"unparsable", "migration: [unclosed\n", "config.yaml"},
		{"two documents", "host_name: a\n---\nhost_name: b\n", "document"},
		// N2-n1: gossip stays reachable (memberlist advertises its port); the
		// 7946 seeds that later adds write are what break.
		{"gossip port", "host_name: a\ngossip_port: 7950\n", "gossip_port is 7950: peers and later adds seed the host at 7946"},
		{"grpc port", "host_name: a\ngrpc_port: 7500\n", "grpc_port is 7500: peers dial the host at 7443, so it would be unreachable"},
		// The refusal says why another key would change.
		{"alias into a replaced key", "enforcement: &e\n  audit_signature: true\nother: *e\n", "an alias to an anchor in a key it replaced"},
		// N3-n1: a refusal with another cause does not blame an alias.
		{"quoted key", "\"host_name\": a\n", "a layout it cannot edit line by line"},
		{"too large", "host_name: a\n# " + strings.Repeat("x", 1<<20) + "\n", "1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			writeTargetConfig(t, f, tc.body, 0o644)
			err := f.add(t)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("add = %v, want a refusal naming %q", err, tc.want)
			}
			if tc.name == "quoted key" && strings.Contains(err.Error(), "alias") {
				t.Errorf("a refusal not caused by an alias blames one: %v", err)
			}
			// Only the reads of the existing state, the add records and the
			// config reached the host. A config that does not parse is refused
			// by the state check, which cannot tell where its data dir is.
			want := "sh existing-state,sh existing-daemon,sh records,sh config"
			if tc.name == "unparsable" {
				want = ""
			}
			if len(f.client.admitted) != 0 || strings.Join(f.target.Events, ",") != want {
				t.Errorf("the add went ahead: admitted %v, events %v", f.client.admitted, f.target.Events)
			}
		})
	}
}

// With an enforcement block in the cluster, the machine's is replaced by it;
// a key the file lacks is appended.
func TestMergeAddConfig_ReplacesTheEnforcementBlock(t *testing.T) {
	p := hostAddPlan{hostName: "node-9", hostAddr: "10.0.0.9", peersYAML: `["10.0.0.1:7946"]`,
		enforcement: "enforcement:\n  audit_signature: true\n  partition_pause: true\n"}
	got, err := mergeAddConfig([]byte("data_dir: /d\nenforcement:\n  audit_signature: false\n# tail\n"), p)
	if err != nil {
		t.Fatal(err)
	}
	want := "data_dir: /d\nenforcement:\n  audit_signature: true\n  partition_pause: true\n# tail\n" +
		"host_name: \"node-9\"\nadvertise_address: \"10.0.0.9\"\njoin_peers: [\"10.0.0.1:7946\"]\npki_dir: /etc/litevirt/pki\n"
	if string(got) != want {
		t.Errorf("merged:\n%s\nwant:\n%s", got, want)
	}
}

// The setup script writes its template config only when the add did not
// install one.
func TestSetupScript_LeavesAnInstalledConfigAlone(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	guard := strings.Index(script, `"${CONFIG_INSTALLED:-}" = 1`)
	write := strings.Index(script, "cat > /etc/litevirt/config.yaml")
	if guard < 0 || write < 0 || guard > write {
		t.Errorf("the template write is not guarded by CONFIG_INSTALLED")
	}
}

// fd re-review N-m1: install fails, and moves nothing into place, when the
// sync of a staged file fails.
//
// Mutation: restore the `|| sync` fallback in syncCmd — the install succeeds.
func TestAddInstallCommands_AFailedSyncDoesNotRename(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "sync"), []byte("#!/bin/sh\n# fails a file sync (EIO); a global sync succeeds\n[ $# -gt 0 ] && exit 1\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	dir := t.TempDir()
	r := &LocalAddTarget{Root: "/", PKIDir: dir}
	key := filepath.Join(dir, "host.key")
	if err := os.WriteFile(key, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(addStagedPath(key, "ab"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Shell("install", installCmd(r, []string{key}, ".pre-add-x", "ab")); err == nil {
		t.Error("an install whose sync failed reported success")
	}
	if got := string(mustRead(t, key)); got != "old" {
		t.Errorf("the key was replaced after a failed sync: %q", got)
	}
}

// fd re-review N-m3: a resumed add installs the admitted certificate with the
// key beside it, so the key must be that certificate's: one left by another
// partial attempt would leave a daemon that cannot load its pair while the
// add reported success. The rerun refuses and names `lv host rm`.
//
// Mutation: skip the pair check — the rerun installs the mismatched key.
func TestHostAdd_AResumeChecksTheKeyMatchesTheCertificate(t *testing.T) {
	f := newAddFixture(t)
	f.target.FailSetup = errors.New("setup failed")
	if err := f.add(t); err == nil {
		t.Fatal("the first add succeeded")
	}
	// Another attempt's key replaced the staged one.
	other := t.TempDir()
	if err := pki.GenerateHostCert(filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key"),
		filepath.Join(other, "x.crt"), filepath.Join(other, "x.key"), "node-9", net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	staged, _ := filepath.Glob(addStagedPath(filepath.Join(f.targetPKI, "host.key"), f.client.admitted[0]+"-") + "*")
	if len(staged) != 1 {
		t.Fatalf("staged keys of the admission: %v, want one", staged)
	}
	if err := os.WriteFile(staged[0], mustRead(t, filepath.Join(other, "x.key")), 0o600); err != nil {
		t.Fatal(err)
	}
	f.target.FailSetup = nil
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), "lv host rm node-9") {
		t.Fatalf("the resume over a mismatched key = %v, want a refusal naming lv host rm", err)
	}
	f.identityUnchanged(t)
}

// fd re-review 2 N2-m5: layouts PyYAML and Ansible emit, and commented-out
// options at column 0, are merged rather than refused: a block sequence at
// the key's own indent, a flow sequence closed at column 0, and a column-0
// comment inside a block.
//
// Mutation: end a key's lines at any column-0 line again — each case is
// refused.
func TestMergeAddConfig_TakesCommonLayouts(t *testing.T) {
	p := hostAddPlan{hostName: "node-9", hostAddr: "10.0.0.9", peersYAML: `["10.0.0.1:7946"]`,
		enforcement: "enforcement:\n  audit_signature: true\n"}
	tail := "host_name: \"node-9\"\nadvertise_address: \"10.0.0.9\"\npki_dir: /etc/litevirt/pki\n"
	for _, tc := range []struct{ name, in, want string }{
		{"block sequence at the key's indent",
			"join_peers:\n- 10.0.0.5:7946\n- 10.0.0.6:7946\nmigration:\n  network: 10.78.1.0/24\n",
			"join_peers: [\"10.0.0.1:7946\"]\nmigration:\n  network: 10.78.1.0/24\n" + tail + "enforcement:\n  audit_signature: true\n"},
		{"flow sequence closed at column 0",
			"join_peers: [\n  \"10.0.0.5:7946\",\n]\nmigration:\n  network: 10.78.1.0/24\n",
			"join_peers: [\"10.0.0.1:7946\"]\nmigration:\n  network: 10.78.1.0/24\n" + tail + "enforcement:\n  audit_signature: true\n"},
		{"commented-out option inside a block",
			"enforcement:\n  audit_signature: false\n# partition_pause: false\n  recovery_claim: false\nmigration:\n  network: 10.78.1.0/24\n",
			"enforcement:\n  audit_signature: true\nmigration:\n  network: 10.78.1.0/24\n" +
				"host_name: \"node-9\"\nadvertise_address: \"10.0.0.9\"\njoin_peers: [\"10.0.0.1:7946\"]\npki_dir: /etc/litevirt/pki\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeAddConfig([]byte(tc.in), p)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("merged:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// stagedHashes is what TestAddInstallCommands_KeepAndRestore stages at each
// path ("new <base>"), by sha256, as hostAddTo records its own.
func stagedHashes(paths []string) map[string]string {
	out := map[string]string{}
	for _, p := range paths {
		sum := sha256.Sum256([]byte("new " + filepath.Base(p)))
		out[p] = hex.EncodeToString(sum[:])
	}
	return out
}

// Codex ec8 I2: a rollback moved whatever was at a path whose own stage was
// gone back to that stage and restored its copy over it, so a rollback after
// another add had installed there undid that add. It moves back only a file
// that is what this attempt installed; one holding anything else is left in
// place, with the copy beside it, and the rollback fails.
//
// Mutation: drop the hash check — the other add's key is moved aside and the
// old key restored over it.
func TestAddInstallCommands_ARollbackLeavesAFileItDidNotInstall(t *testing.T) {
	dir := t.TempDir()
	r := &LocalAddTarget{Root: "/", PKIDir: dir}
	key := filepath.Join(dir, "host.key")
	if err := os.WriteFile(key, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(addStagedPath(key, "ab"), []byte("new host.key"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{key}
	out, err := r.Shell("exists", existsCmd(r, paths))
	if err != nil {
		t.Fatal(err)
	}
	existed := existsSet(r, paths, out)
	if _, err := r.Shell("install", installCmd(r, paths, ".pre-add-x", "ab")); err != nil {
		t.Fatal(err)
	}
	// Another add installs its own key here before this one rolls back.
	if err := os.WriteFile(key, []byte("another add's key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Shell("restore", restoreCmd(r, paths, existed, stagedHashes(paths), ".pre-add-x", "ab")); err == nil {
		t.Error("a rollback that left another add's file reported success")
	}
	if got := string(mustRead(t, key)); got != "another add's key" {
		t.Errorf("the rollback replaced another add's key: %q", got)
	}
	if got := string(mustRead(t, key+".pre-add-x")); got != "old" {
		t.Errorf("the copy of the old key is not kept beside it: %q", got)
	}
}

// oneSerial reports whether every admission asked for names one serial.
func oneSerial(admitted []string) bool {
	for _, a := range admitted {
		if a != admitted[0] {
			return false
		}
	}
	return len(admitted) > 0
}

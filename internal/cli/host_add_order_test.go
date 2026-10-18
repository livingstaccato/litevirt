package cli

import (
	"bytes"
	"context"
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
	c.atAdmit = append([]string(nil), c.target.Events...)
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
	var out []string
	_ = filepath.Walk(f.target.Root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".add") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// installedLive reports whether anything was moved into place or run on the
// target, other than uploads to staged paths and their removal.
func installedLive(events []string) []string {
	var live []string
	for _, e := range events {
		switch {
		case strings.HasPrefix(e, "write ") && strings.HasSuffix(e, ".add"):
		case strings.HasPrefix(e, "run mkdir -p"), e == "sh unstage":
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
		want := map[string]bool{"write /usr/local/bin/.litevirt.add": false, "write /etc/litevirt/pki/.host.key.add": false}
		for _, e := range f.client.atAdmit {
			if _, ok := want[e]; ok {
				want[e] = true
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
	if len(f.client.admitted) != 1 || served != f.client.admitted[0] {
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
		if strings.HasPrefix(e, "run systemctl stop litevirt") && stop < 0 {
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
	if len(f.client.admitted) != 2 || f.client.admitted[0] != f.client.admitted[1] {
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
	n := len(f.target.Events)
	if err := f.add(t); err != nil {
		t.Fatalf("the rerun of a finished add: %v", err)
	}
	if len(f.client.admitted) != 1 {
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
	if !existed[key] || existed[added] {
		t.Fatalf("exists = %v, want only %s", existed, key)
	}
	for _, p := range paths {
		if err := os.WriteFile(addStagedPath(p), []byte("new "+filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const suffix = ".pre-add-x"
	cmd := installCmd(r, paths, suffix)
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
	if _, err := r.Shell("restore", restoreCmd(r, paths, existed, suffix)); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, key)); got != "old" {
		t.Errorf("restored key = %q, want the old key", got)
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Errorf("a file the add created is still in place (stat: %v)", err)
	}
	for _, p := range paths {
		if got := string(mustRead(t, addStagedPath(p))); got != "new "+filepath.Base(p) {
			t.Errorf("the admitted %s is not back at its staged path: %q", filepath.Base(p), got)
		}
	}
	if _, err := os.Stat(key + suffix); !os.IsNotExist(err) {
		t.Errorf("the copy survived the restore (stat: %v)", err)
	}
}

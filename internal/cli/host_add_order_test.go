package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
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
	// wroteAtAdmit is how many writes the target had seen when AdmitHost ran.
	wroteAtAdmit int
}

func (c *hostAddTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: c.hosts}, nil
}

func (c *hostAddTestClient) AdmitHost(_ context.Context, req *pb.AdmitHostRequest, _ ...grpc.CallOption) (*pb.AdmitHostResponse, error) {
	c.admitted = append(c.admitted, req.GetCertSerial())
	c.wroteAtAdmit = len(c.target.Wrote)
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

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// F8/A8: `lv host add` pushed host.crt and host.key BEFORE AdmitHost, so an
// add the daemon refused (an active name) had already replaced the key of the
// machine on disk; on the lab the live host was then held as superseded and
// cut off. The admission is asked first, and a refusal pushes nothing.
//
// Mutation: push the identity before AdmitHost — the refused add has
// written to the machine and replaced its host.key.
func TestHostAdd_ARefusedAdmissionPushesNothing(t *testing.T) {
	f := newAddFixture(t)
	f.client.admitErr = status.Error(codes.FailedPrecondition, `admit host: host "node-9" is already active`)
	if err := f.add(t); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("add = %v, want the daemon's refusal", err)
	}
	if len(f.target.Wrote) != 0 || len(f.target.Commands) != 0 {
		t.Errorf("a refused add reached the machine: wrote %v, ran %v", f.target.Wrote, f.target.Commands)
	}
	f.identityUnchanged(t)
	// The operator's copy of a live host's pair is not replaced either.
	if _, err := os.Stat(filepath.Join(f.opPKI, "node-9.crt")); !os.IsNotExist(err) {
		t.Errorf("a refused add left a minted node-9.crt on this machine (stat: %v)", err)
	}
}

// The admission precedes every write to the machine, and the files the push
// replaces are kept beside it.
//
// Mutations: AdmitHost after the push — wroteAtAdmit > 0; install without the
// copies — no .pre-add copy holds the old key.
func TestHostAdd_AdmitsBeforeThePushAndKeepsTheReplacedKey(t *testing.T) {
	f := newAddFixture(t)
	if err := f.add(t); err != nil {
		t.Fatal(err)
	}
	if f.client.wroteAtAdmit != 0 {
		t.Errorf("%d write(s) reached the machine before AdmitHost", f.client.wroteAtAdmit)
	}
	served := installedSerial(mustRead(t, filepath.Join(f.targetPKI, "host.crt")))
	if len(f.client.admitted) != 1 || served != f.client.admitted[0] {
		t.Errorf("the machine serves %s, admitted %v", served, f.client.admitted)
	}
	for n, want := range f.before {
		matches, _ := filepath.Glob(filepath.Join(f.targetPKI, n+".pre-add-*"))
		if len(matches) != 1 || !bytes.Equal(mustRead(t, matches[0]), want) {
			t.Errorf("no copy of the replaced %s kept (%v)", n, matches)
			continue
		}
		if n == "host.key" {
			if st, _ := os.Stat(matches[0]); st.Mode().Perm() != 0o600 {
				t.Errorf("the kept host.key is %o, want 0600", st.Mode().Perm())
			}
		}
	}
}

// An add that fails after the push (here: setup) puts the machine's previous
// host.crt and host.key back, and removes the files it added; a rerun then
// finishes the add with the certificate already admitted.
//
// Mutations: drop the Restore — the machine keeps the new key; mint a fresh
// certificate on the rerun — the daemon refuses it as already active.
func TestHostAdd_AFailedAddRestoresTheKeyAndARerunFinishes(t *testing.T) {
	f := newAddFixture(t)
	f.target.FailSetup = errors.New("setup failed")
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "lv host add --name node-9") {
		t.Fatalf("add = %v, want the setup failure naming the rerun", err)
	}
	f.identityUnchanged(t)
	if _, err := os.Stat(filepath.Join(f.targetPKI, "migration", pki.MigrationHostKeyName)); !os.IsNotExist(err) {
		t.Errorf("a file the failed add created is still there (stat: %v)", err)
	}
	if m, _ := filepath.Glob(filepath.Join(f.targetPKI, "*.pre-add-*")); len(m) != 0 {
		t.Errorf("copies left after the restore: %v", m)
	}

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

// A machine serving a live member's current certificate is that member: the
// add is refused before the admission and before anything is pushed, even
// under a new name the daemon would admit (a mistyped address).
//
// Mutation: drop the check — node-3's key on the machine is replaced.
func TestHostAdd_RefusesAMachineServingALiveMember(t *testing.T) {
	f := newAddFixture(t)
	live := installedSerial(f.before["host.crt"])
	f.client.hosts = append(f.client.hosts, &pb.Host{Name: "node-3", Address: "10.0.0.3",
		State: pb.HostState_HOST_ACTIVE, CertSerial: strings.ToUpper(live)})
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "node-3") || !strings.Contains(err.Error(), "lv host rm node-3") {
		t.Fatalf("add = %v, want a refusal naming node-3", err)
	}
	if len(f.client.admitted) != 0 {
		t.Errorf("AdmitHost was asked (%v) for a machine that is a live member", f.client.admitted)
	}
	if len(f.target.Wrote) != 0 {
		t.Errorf("wrote %v to a live member", f.target.Wrote)
	}
	f.identityUnchanged(t)
}

// A3: the binary is written by rename, so a running daemon's executable is
// replaced rather than opened for writing (ETXTBSY), and it lands 0755.
func TestHostAdd_PushesTheBinaryByRenameAtItsMode(t *testing.T) {
	f := newAddFixture(t)
	if err := f.add(t); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(f.target.Root, "usr", "local", "bin", "litevirt"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("binary: %v, %v; want 0755", st, err)
	}
	for _, c := range f.target.Commands {
		if strings.Contains(c, "chmod") && strings.Contains(c, "/usr/local/bin/litevirt") {
			t.Errorf("the binary's mode is set after it lands: %q", c)
		}
	}
}

// The commands sshAddRemote runs on the machine, run here by sh over a
// directory: install keeps a copy of each file it replaces (at its mode) and
// moves the staged file in; restore puts each copy back and removes a file
// that did not exist before; exists names only the files present.
//
// Mutations: drop the cp from installKeepingCmd — no copy, and the restore
// cannot put the key back; restore by "rm" for every file — the old key is
// lost; existsCmd printing every path — the new file is "restored" to nothing.
func TestAddInstallCommands_KeepAndRestore(t *testing.T) {
	dir := t.TempDir()
	key, added := filepath.Join(dir, "host.key"), filepath.Join(dir, "gossip.key")
	if err := os.WriteFile(key, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []installFile{{path: key, data: []byte("new"), mode: 0o600}, {path: added, data: []byte("g"), mode: 0o600}}
	sh := func(cmd string) string {
		t.Helper()
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}
	existed := map[string]bool{}
	for _, l := range strings.Split(sh(existsCmd([]string{key, added})), "\n") {
		if l != "" {
			existed[l] = true
		}
	}
	if !existed[key] || existed[added] {
		t.Fatalf("exists = %v, want only %s", existed, key)
	}
	for _, f := range files {
		if err := os.WriteFile(addStagedPath(f.path), f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	const suffix = ".pre-add-x"
	sh(installKeepingCmd(files, suffix))
	if got := string(mustRead(t, key)); got != "new" {
		t.Fatalf("installed key = %q", got)
	}
	if got := string(mustRead(t, key+suffix)); got != "old" {
		t.Fatalf("kept copy = %q, want the old key", got)
	}
	if st, _ := os.Stat(key + suffix); st.Mode().Perm() != 0o600 {
		t.Errorf("the copy is %o, want 0600", st.Mode().Perm())
	}
	sh(restoreCmd(files, existed, suffix))
	if got := string(mustRead(t, key)); got != "old" {
		t.Errorf("restored key = %q, want the old key", got)
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Errorf("a file the add created survived the restore (stat: %v)", err)
	}
	if _, err := os.Stat(key + suffix); !os.IsNotExist(err) {
		t.Errorf("the copy survived the restore (stat: %v)", err)
	}
}

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// sharedAdmissions is one cluster that several operators' `lv host add`
// reach: it admits as hostAddTestClient does, under a lock.
type sharedAdmissions struct {
	mu    sync.Mutex
	hosts []*pb.Host
}

// operatorClient is one operator's connection to sharedAdmissions. before
// runs when its AdmitHost arrives, after once the cluster has answered it.
type operatorClient struct {
	pb.LiteVirtClient
	s             *sharedAdmissions
	before, after func()
	admitted      string
}

func (c *operatorClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	out := make([]*pb.Host, len(c.s.hosts))
	for i, h := range c.s.hosts {
		out[i] = proto.Clone(h).(*pb.Host)
	}
	return &pb.ListHostsResponse{Hosts: out}, nil
}

func (c *operatorClient) AdmitHost(_ context.Context, req *pb.AdmitHostRequest, _ ...grpc.CallOption) (*pb.AdmitHostResponse, error) {
	if c.before != nil {
		c.before()
	}
	resp, err := c.s.admit(req)
	if err == nil {
		c.admitted = req.GetCertSerial()
	}
	if c.after != nil {
		c.after()
	}
	return resp, err
}

func (s *sharedAdmissions) admit(req *pb.AdmitHostRequest) (*pb.AdmitHostResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if h.GetName() != req.GetName() {
			continue
		}
		if strings.EqualFold(h.GetCertSerial(), req.GetCertSerial()) {
			return &pb.AdmitHostResponse{AuditPositionProven: true}, nil
		}
		return nil, status.Errorf(codes.FailedPrecondition, "admit host: host %q is already active", req.GetName())
	}
	s.hosts = append(s.hosts, &pb.Host{Name: req.GetName(), Address: req.GetAddress(),
		State: pb.HostState_HOST_JOINING, CertSerial: req.GetCertSerial()})
	return &pb.AdmitHostResponse{AuditPositionProven: true}, nil
}

// secondOperatorPKI is another operator machine's pki directory: the cluster
// CA and migration CA copied from dir, none of its minted pairs.
func secondOperatorPKI(t *testing.T, dir string) string {
	t.Helper()
	op := filepath.Join(t.TempDir(), "pki")
	if err := os.MkdirAll(op, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ca.crt", "ca.key", pki.MigrationCACertName, pki.MigrationCAKeyName} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(op, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return op
}

// servesItsAdmittedPair fails unless the target's installed host.crt is
// serial's and host.key is its key.
func servesItsAdmittedPair(t *testing.T, targetPKI, serial string) {
	t.Helper()
	crt := mustRead(t, filepath.Join(targetPKI, "host.crt"))
	if got := installedSerial(crt); got != serial {
		t.Errorf("the machine serves %s, want the admitted %s", got, serial)
	}
	if _, err := tls.X509KeyPair(crt, mustRead(t, filepath.Join(targetPKI, "host.key"))); err != nil {
		t.Errorf("the machine's host.key is not its certificate's: %v", err)
	}
}

// stagedOnTarget is every staged file (".<name>.add", with or without an
// attempt's tag) left on the target.
func stagedOnTarget(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), ".") &&
			(strings.HasSuffix(info.Name(), ".add") || strings.Contains(info.Name(), ".add-")) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// Codex cand30 I2: two operators adding the same fresh name to the same
// machine both staged to one fixed .host.crt.add / .host.key.add. B's
// staging, between A's staging and A's install, replaced A's bytes, and A
// installed B's identity while admitted with its own serial; B's refusal
// cleanup, before A's install, deleted the files A needed. Each attempt
// stages under its own name now, the install takes only its own, and a
// refused attempt removes only its own.
//
// Mutations: stage at a fixed path again — "B stages before A admits" serves
// B's certificate; unstage every attempt's files — "B's cleanup before A
// installs" fails A's install.
func TestHostAdd_ConcurrentAddsOfOneNameKeepTheirOwnStaging(t *testing.T) {
	for _, tc := range []struct {
		name string
		// bAdmitsAfterAInstalls: B's refusal (and cleanup) comes after A's
		// whole add; otherwise between A's admission and its install.
		bAdmitsAfterAInstalls bool
	}{
		{"B stages before A admits", true},
		{"B's cleanup before A installs", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			if _, _, _, err := ensureLocalMigrationCA(f.opPKI, nil); err != nil {
				t.Fatal(err)
			}
			opB := secondOperatorPKI(t, f.opPKI)
			cluster := &sharedAdmissions{hosts: f.client.hosts}
			a := &operatorClient{s: cluster}
			b := &operatorClient{s: cluster}
			aStaged, bStaged, aAdmitted, aDone, bDone := make(chan struct{}), make(chan struct{}),
				make(chan struct{}), make(chan struct{}), make(chan struct{})
			a.before = func() { close(aStaged); <-bStaged }
			if tc.bAdmitsAfterAInstalls {
				b.before = func() { close(bStaged); <-aDone }
			} else {
				a.after = func() { close(aAdmitted); <-bDone }
				b.before = func() { close(bStaged); <-aAdmitted }
			}
			// Two targets over the one machine: each attempt's own event log.
			ta := &LocalAddTarget{Root: f.target.Root, PKIDir: f.targetPKI, Binary: f.target.Binary}
			tb := &LocalAddTarget{Root: f.target.Root, PKIDir: f.targetPKI, Binary: f.target.Binary}
			plan := func(dir string) hostAddPlan {
				return hostAddPlan{pkiDir: dir, hostName: "node-9", hostAddr: "10.0.0.9", peersYAML: "[]",
					binPath: f.target.Binary, rerun: "lv host add --name node-9 root@10.0.0.9"}
			}
			var errA, errB error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer close(aDone)
				errA = hostAddTo(context.Background(), a, ta, plan(f.opPKI))
			}()
			go func() {
				defer wg.Done()
				defer close(bDone)
				<-aStaged
				errB = hostAddTo(context.Background(), b, tb, plan(opB))
			}()
			finished := make(chan struct{})
			go func() { wg.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(60 * time.Second):
				t.Fatal("the two adds did not finish")
			}
			if errA != nil {
				t.Fatalf("A, admitted first: %v", errA)
			}
			if errB == nil || !strings.Contains(errB.Error(), "already active") {
				t.Fatalf("B = %v, want the cluster's refusal", errB)
			}
			if a.admitted == "" || b.admitted != "" {
				t.Fatalf("admitted A %q, B %q; want only A", a.admitted, b.admitted)
			}
			servesItsAdmittedPair(t, f.targetPKI, a.admitted)
			if left := stagedOnTarget(t, f.target.Root); len(left) != 0 {
				t.Errorf("staged files left on the machine: %v", left)
			}
		})
	}
}

// Codex cand30 I2: the install takes the pair staged for the serial it was
// admitted with, and checks it is that certificate and its key first. A
// staged pair that is not (replaced after the upload) is refused before
// anything is installed, naming the rerun.
//
// Mutation: drop the check — the machine serves a certificate it was not
// admitted with.
func TestHostAdd_InstallsOnlyThePairItWasAdmittedWith(t *testing.T) {
	f := newAddFixture(t)
	other := t.TempDir()
	if err := pki.GenerateHostCert(filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key"),
		filepath.Join(other, "x.crt"), filepath.Join(other, "x.key"), "node-9", net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	cluster := &sharedAdmissions{hosts: f.client.hosts}
	c := &operatorClient{s: cluster}
	c.before = func() {
		for _, n := range []string{"crt", "key"} {
			m, _ := filepath.Glob(filepath.Join(f.targetPKI, ".host."+n+".add*"))
			if len(m) != 1 {
				t.Errorf("staged host.%s: %v, want one", n, m)
				continue
			}
			if err := os.WriteFile(m[0], mustRead(t, filepath.Join(other, "x."+n)), 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	err := hostAddTo(context.Background(), c, f.target, hostAddPlan{pkiDir: f.opPKI, hostName: "node-9",
		hostAddr: "10.0.0.9", peersYAML: "[]", binPath: f.target.Binary, rerun: "lv host add --name node-9 root@10.0.0.9"})
	if err == nil || !strings.Contains(err.Error(), "lv host rm node-9") {
		t.Fatalf("add over a replaced staged pair = %v, want a refusal naming lv host rm", err)
	}
	f.identityUnchanged(t)
	for _, e := range f.target.Events {
		if e == "sh install" {
			t.Errorf("installed over a staged pair that is not the admitted one: %v", f.target.Events)
		}
	}
}

// Codex cand30: the operator's copy of a minted pair was staged as
// .<name>.crt.add in its pki directory and kept as <name>.crt, so a host named
// "ca" overwrote the cluster CA's certificate and key, and one named "host"
// this machine's own host pair. Neither path is derived from the name now
// except under a directory of their own.
//
// Mutation: keep at <pki>/<name>.crt again — "ca" replaces ca.crt.
func TestHostAdd_AHostNamedLikeAPKIFileTouchesNone(t *testing.T) {
	for _, name := range []string{"ca", "host"} {
		t.Run(name, func(t *testing.T) {
			f := newAddFixture(t)
			// This machine's own host pair, as a node holds it.
			if err := pki.GenerateHostCert(filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key"),
				filepath.Join(f.opPKI, "host.crt"), filepath.Join(f.opPKI, "host.key"), "node-1", net.IPv4(10, 0, 0, 1)); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			ents, err := os.ReadDir(f.opPKI)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if !e.IsDir() {
					before[e.Name()] = mustRead(t, filepath.Join(f.opPKI, e.Name()))
				}
			}
			if err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9"); err != nil {
				t.Fatal(err)
			}
			for n, want := range before {
				if got, err := os.ReadFile(filepath.Join(f.opPKI, n)); err != nil || !bytes.Equal(got, want) {
					t.Errorf("adding a host named %q replaced the operator's %s (%v)", name, n, err)
				}
			}
			// The admitted pair is still kept with the operator, out of the way.
			kept := filepath.Join(f.opPKI, "hosts", name, "host.crt")
			if got := installedSerial(mustRead(t, kept)); got != f.client.admitted[0] {
				t.Errorf("kept %s serves %s, want the admitted %s", kept, got, f.client.admitted[0])
			}
			if left, _ := filepath.Glob(filepath.Join(f.opPKI, ".*")); len(left) != 0 {
				t.Errorf("staging left in the operator's pki directory: %v", left)
			}
		})
	}
}

// An add an earlier release's `lv host add` admitted, and left its pair
// staged at the untagged .host.crt.add / .host.key.add, is finished by a
// rerun from this release: the pair is staged again at the rerun's own paths
// and installed, and the untagged copies go once it has.
//
// Mutation: drop the legacy lookup — the rerun refuses, finding the pair
// neither installed nor staged.
func TestHostAdd_ARerunFinishesAnEarlierReleasesStagedAdd(t *testing.T) {
	f := newAddFixture(t)
	tmp := t.TempDir()
	if err := pki.GenerateHostCert(filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key"),
		filepath.Join(tmp, "h.crt"), filepath.Join(tmp, "h.key"), "node-9", net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	crt := mustRead(t, filepath.Join(tmp, "h.crt"))
	serial := installedSerial(crt)
	for n, b := range map[string][]byte{".host.crt.add": crt, ".host.key.add": mustRead(t, filepath.Join(tmp, "h.key"))} {
		if err := os.WriteFile(filepath.Join(f.targetPKI, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.client.hosts = append(f.client.hosts, &pb.Host{Name: "node-9", Address: "10.0.0.9",
		State: pb.HostState_HOST_JOINING, CertSerial: strings.ToUpper(serial)})
	if err := f.add(t); err != nil {
		t.Fatalf("the rerun: %v", err)
	}
	if len(f.client.admitted) != 1 || f.client.admitted[0] != serial {
		t.Errorf("admitted %v, want the earlier admission's %s", f.client.admitted, serial)
	}
	servesItsAdmittedPair(t, f.targetPKI, serial)
	if left := stagedOnTarget(t, f.target.Root); len(left) != 0 {
		t.Errorf("staged files left on the machine: %v", left)
	}
}

// Codex 612c78ba I2: a staging tag of the admitted serial is not an
// attempt's own. A rerun from another operator while the admitted attempt is
// still in flight took the same serial, wrote the same staged CA, migration,
// config and binary paths, and its failed upload removed the files the first
// attempt was about to install. Each attempt's staged files carry its own
// nonce now: the rerun stages copies of its own, and its failed upload, or
// its failed setup and rollback, touches only those.
//
// Mutations: tag staged files with the serial alone — "the rerun's upload
// fails" fails A's install; unstage by the serial — the same.
func TestHostAdd_ARerunWhileTheAdmittedAddIsInFlightLeavesItsFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(tb *LocalAddTarget)
	}{
		{"the rerun's upload fails", func(tb *LocalAddTarget) {
			tb.FailWrite = map[string]error{"/usr/local/bin/.litevirt.add": errors.New("connection lost")}
		}},
		{"the rerun's setup fails and it rolls back", func(tb *LocalAddTarget) {
			tb.FailSetup = errors.New("setup failed")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			if _, _, _, err := ensureLocalMigrationCA(f.opPKI, nil); err != nil {
				t.Fatal(err)
			}
			opB := secondOperatorPKI(t, f.opPKI)
			cluster := &sharedAdmissions{hosts: f.client.hosts}
			a := &operatorClient{s: cluster}
			b := &operatorClient{s: cluster}
			aAdmitted, bDone := make(chan struct{}), make(chan struct{})
			// A is admitted, then waits for B's whole rerun before installing.
			a.after = func() { close(aAdmitted); <-bDone }
			ta := &LocalAddTarget{Root: f.target.Root, PKIDir: f.targetPKI, Binary: f.target.Binary}
			tb := &LocalAddTarget{Root: f.target.Root, PKIDir: f.targetPKI, Binary: f.target.Binary}
			tc.break_(tb)
			plan := func(dir string) hostAddPlan {
				return hostAddPlan{pkiDir: dir, hostName: "node-9", hostAddr: "10.0.0.9", peersYAML: "[]",
					binPath: f.target.Binary, rerun: "lv host add --name node-9 root@10.0.0.9"}
			}
			var errA, errB error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				errA = hostAddTo(context.Background(), a, ta, plan(f.opPKI))
			}()
			go func() {
				defer wg.Done()
				defer close(bDone)
				<-aAdmitted
				errB = hostAddTo(context.Background(), b, tb, plan(opB))
			}()
			finished := make(chan struct{})
			go func() { wg.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(60 * time.Second):
				t.Fatal("the add and its rerun did not finish")
			}
			if errB == nil {
				t.Fatal("the broken rerun succeeded")
			}
			if errA != nil {
				t.Fatalf("the admitted add, after the rerun failed: %v", errA)
			}
			servesItsAdmittedPair(t, f.targetPKI, a.admitted)
			if _, err := os.Stat(filepath.Join(f.targetPKI, "migration", pki.MigrationHostKeyName)); err != nil {
				t.Errorf("the admitted add's migration key is not in place: %v", err)
			}
		})
	}
}

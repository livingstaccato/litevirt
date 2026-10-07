package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// promotedFrom reports whether vm was promoted from replica in dir: the
// promoted live disk is named after the replica it was built from.
func promotedFrom(dir, vm, replica string) bool {
	stem := replica[:len(replica)-len(filepath.Ext(replica))]
	_, err := os.Stat(filepath.Join(dir, vm+"-promoted-"+stem+".qcow2"))
	return err == nil
}

func setPast(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// NC1: an operator-named replica works as on main when the file is the VM's
// project's by record — its replica, or an upload into the project's pool —
// or the caller is an admin, whatever its name. Another project's upload is
// never taken.
func TestPoolRound7_ANamedReplicaTheProjectOwnsIsPromoted(t *testing.T) {
	s, disks := disksPoolServer(t)
	own := filepath.Join(s.dataDir, "pools", "pa")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pa", Driver: "dir", Target: own, Project: "acme"})
	for _, vm := range []string{"web", "api", "db"} {
		insertPromotableVM(t, s, vm, "acme", "dead-host", "root")
	}
	insertPromotableVM(t, s, "bvm", "bravo", "dead-host", "root")
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	img := string(qcow2Bytes(t))

	// Seeded by upload into acme's own pool, then named.
	if err := uploadAs(pat, s, "pa", "web-root-20261006-120000.qcow2", img); err != nil {
		t.Fatal(err)
	}
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "pa", Replica: "web-root-20261006-120000.qcow2", NoLocalize: true}); err != nil {
		t.Errorf("promoting an uploaded replica acme named: %v", err)
	}
	// A hand-named copy from before this build, named by an operator.
	writeQcow2(t, filepath.Join(own, "api-root-pre-upgrade.qcow2"))
	setPast(t, filepath.Join(own, "api-root-pre-upgrade.qcow2"), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "api", TargetPool: "pa", Replica: "api-root-pre-upgrade.qcow2", NoLocalize: true}); err != nil {
		t.Errorf("promoting a hand-named pre-upgrade copy: %v", err)
	}
	// An admin names any file.
	writeQcow2(t, filepath.Join(disks, "restored-from-offsite.qcow2"))
	if err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "default", Replica: "restored-from-offsite.qcow2", NoLocalize: true}); err != nil {
		t.Errorf("an admin promoting a file it named: %v", err)
	}
	for _, vm := range []string{"web", "api", "db"} {
		if !s.virt.DomainExists(vm) {
			t.Errorf("%s was not promoted", vm)
		}
	}

	// bravo's VM never takes acme's upload named like its replica, named or
	// not.
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pb", Driver: "dir", Target: own, Project: "bravo"})
	if err := uploadAs(pat, s, "pa", "bvm-root-20261006-120000.qcow2", img); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*pb.PromoteReplicaRequest{
		{VmName: "bvm", TargetPool: "pb", NoLocalize: true},
		{VmName: "bvm", TargetPool: "pb", Replica: "bvm-root-20261006-120000.qcow2", NoLocalize: true},
	} {
		if err := promote(bob, s, req); err == nil || s.virt.DomainExists("bvm") {
			t.Errorf("bravo's bvm was promoted from acme's upload (replica %q, err %v)", req.Replica, err)
		}
	}
}

// NC2: a pre-upgrade replica is the VM's unless another project's VM AND disk
// write the same prefix. bravo's web has a disk "data", not "prod-root", so
// acme's web-prod/root replicas are acme's: promoted (manually and by
// failover) and pruned. When bravo's web does have a disk prod-root, the file
// is refused — except to an admin who names it.
func TestPoolRound7_PrefixVMOfAnotherProjectWithoutTheDiskDoesNotClaim(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertProjectVM(t, s, "web", "bravo", "data", filepath.Join(disks, "web-data.qcow2"), "default")
	insertPromotableVM(t, s, "web-prod", "acme", s.hostName, "root")
	insertReplicationSchedule(t, s, "web-prod", "default")
	pre := time.Now().Add(-time.Hour)
	for _, ago := range []time.Duration{3 * time.Hour, 2 * time.Hour} {
		p := filepath.Join(disks, "web-prod-root-"+stampAgo(ago)+".qcow2")
		writeQcow2(t, p)
		setPast(t, p, pre.Add(-ago))
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	names := func() []string {
		ents, _ := os.ReadDir(disks)
		var out []string
		for _, e := range ents {
			if len(e.Name()) > 14 && e.Name()[:14] == "web-prod-root-" {
				out = append(out, e.Name())
			}
		}
		return out
	}
	newest := names()[1]
	if err := s.AutoPromoteReplica(context.Background(), "web-prod", "", 0); err != nil {
		t.Fatalf("failover promotion of acme's web-prod from its pre-upgrade replica: %v", err)
	}
	if !promotedFrom(disks, "web-prod", newest) {
		t.Errorf("web-prod was not promoted from %s", newest)
	}
	// Pruning applies to them again: a run keeping 1 leaves only its own.
	sched, _ := s.replicationScheduleForVM(adminCtx(), "web-prod")
	sched.KeepReplicas = 1
	if err := s.RunReplication(adminCtx(), sched, time.Now()); err != nil {
		t.Fatalf("replication run: %v", err)
	}
	if got := names(); len(got) != 1 {
		t.Errorf("after a keep-1 run, web-prod's replicas = %v, want only the new one", got)
	}

	// bravo's web has a prod-root disk after all: the name is ambiguous.
	s2, disks2 := disksPoolServer(t)
	insertProjectVM(t, s2, "web", "bravo", "prod-root", filepath.Join(disks2, "web-prod-root.qcow2"), "default")
	insertPromotableVM(t, s2, "web-prod", "acme", "dead-host", "root")
	amb := "web-prod-root-20261005-120000.qcow2"
	writeQcow2(t, filepath.Join(disks2, amb))
	setPast(t, filepath.Join(disks2, amb), time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	pat2 := hostPathEngineCtx(t, s2, "pat", "Operator", projectRBACBase("acme"))
	_ = pat
	for _, req := range []*pb.PromoteReplicaRequest{
		{VmName: "web-prod", TargetPool: "default", NoLocalize: true},
		{VmName: "web-prod", TargetPool: "default", Replica: amb, NoLocalize: true},
	} {
		if err := promote(pat2, s2, req); err == nil || s2.virt.DomainExists("web-prod") {
			t.Errorf("an operator promoted an ambiguous file (replica %q, err %v)", req.Replica, err)
		}
	}
	if err := promote(adminCtx(), s2, &pb.PromoteReplicaRequest{VmName: "web-prod", TargetPool: "default", Replica: amb, NoLocalize: true}); err != nil {
		t.Errorf("an admin naming the ambiguous file: %v", err)
	}
}

// twoHostsOnOneExport is h1 and h2 with the global dir pool "shared" on the
// same NFS export, mounted at the same directory, in one cluster state.
func twoHostsOnOneExport(t *testing.T) (h1, h2 *Server, dir string) {
	t.Helper()
	dir = t.TempDir()
	overrideMounts(t, nfsMountLine(dir, "nas:/shared"))
	h1 = newPoolTestServer(t)
	h1.hostName = "h1"
	h2 = &Server{hostName: "h2", dataDir: t.TempDir(), db: h1.db, virt: libvirtfake.New(), events: events.NewBus()}
	h2.images = image.NewStore(h2.dataDir)
	h1.db.SetClusterPolicyGate(func() bool { return true })
	for _, h := range []string{"h1", "h2"} {
		if err := corrosion.InsertHost(context.Background(), h1.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, h1, corrosion.StoragePoolRecord{HostName: h, Name: "shared", Driver: "dir", Target: dir,
			Options: map[string]string{"nfs_export": "nas:/shared"}})
	}
	// Both hosts start.
	h1.SweepStaleStaging(context.Background())
	h2.SweepStaleStaging(context.Background())
	return h1, h2, dir
}

// NI1: acme uploads a file named like bravo's newest replica into a pool two
// hosts share, through h1. On h2 it is neither promoted as bravo's VM nor
// counted among bravo's replicas when pruning; bravo's genuine pre-upgrade
// replica still promotes.
func TestPoolRound7_APlantedUploadOnASharedPoolIsNotAReplicaOnAnotherHost(t *testing.T) {
	h1, h2, dir := twoHostsOnOneExport(t)
	legacy := "bvm-root-20261001-120000.qcow2"
	writeQcow2(t, filepath.Join(dir, legacy))
	setPast(t, filepath.Join(dir, legacy), time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	insertPromotableVM(t, h1, "bvm", "bravo", "h2", "root")
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, corrosion.BackupScheduleRecord{
		VMName: "bvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h2", KeepReplicas: 2,
	}); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, h1, "pat", "Operator", poolRBACPathFor("", "shared"))
	plant := "bvm-root-20991231-235959.qcow2"
	if err := uploadAs(pat, h1, "shared", plant, string(qcow2Bytes(t))); err != nil {
		t.Fatalf("acme's upload through h1: %v", err)
	}
	if err := promote(adminCtx(), h2, &pb.PromoteReplicaRequest{VmName: "bvm", TargetPool: "shared", TargetHost: "h2", NoLocalize: true}); err != nil {
		t.Fatalf("promoting bvm on h2: %v", err)
	}
	if promotedFrom(dir, "bvm", plant) || !promotedFrom(dir, "bvm", legacy) {
		t.Errorf("bvm on h2 was promoted from acme's planted file, not its own replica %s", legacy)
	}
	sched, _ := h2.replicationScheduleForVM(adminCtx(), "bvm")
	if err := h2.RunReplication(adminCtx(), sched, time.Now()); err != nil {
		t.Fatalf("bvm's replication run on h2: %v", err)
	}
	for _, n := range []string{legacy, plant} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("bvm's keep-2 run removed %s: %v", n, err)
		}
	}
}

// A future-stamped replica name is never taken by name, nor auto-promoted.
func TestPoolRound7_AFutureStampIsNotAReplica(t *testing.T) {
	if err := checkAutoPromoteReplicaAge("web-root-20991231-235959.qcow2", time.Now(), autoPromoteMaxReplicaAge); err == nil {
		t.Errorf("a replica stamped in 2099 passed the automatic age bound")
	}
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "web", "", "dead-host", "root")
	writeQcow2(t, filepath.Join(disks, "web-root-20991231-235959.qcow2"))
	setPast(t, filepath.Join(disks, "web-root-20991231-235959.qcow2"), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "default", NoLocalize: true}); err == nil {
		t.Errorf("a future-stamped file was promoted as web's newest replica")
	}
}

// n1: a content call that must be forwarded is never sent on bare when the
// caller has no bearer to relay and is not an admin.
func TestPoolRound7_ABearerlessNonAdminIsNotForwardedBare(t *testing.T) {
	s, _ := twoProjectsOnDisks(t)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: "host-b", Name: "pa", Driver: "local", Project: "acme"})
	op := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	_, err := s.ListStoragePoolContents(op, &pb.ListStoragePoolContentsRequest{PoolName: "pa", Host: "host-b"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("a bearerless non-admin's forwarded listing: got %v, want PermissionDenied", err)
	}
}

// r7CertCtx is an incoming mTLS context presenting cert from addr.
func r7CertCtx(cert *x509.Certificate, addr net.Addr, md metadata.MD) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr:     addr,
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}},
	})
	if md != nil {
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	return ctx
}

// The invariant forwardContentCall and the pool host's bearerless view rest
// on: whatever a bearerless caller's certificate says beyond its CN —
// organisation, unit, SANs, key usages — and wherever it comes from, it is an
// admin over mTLS or refused. A bearer-free identity that is not an admin
// would be confined on the entry node and then forwarded bare.
func TestPoolRound7_EveryBearerlessIdentityIsAdminOrRefused(t *testing.T) {
	u, _ := url.Parse("spiffe://cluster/user/op")
	attrs := []func(*x509.Certificate){
		func(*x509.Certificate) {},
		func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"ops"} },
		func(c *x509.Certificate) { c.Subject.Organization = []string{"acme"} },
		func(c *x509.Certificate) { c.URIs = []*url.URL{u} },
		func(c *x509.Certificate) { c.DNSNames = []string{"op.acme"} },
		func(c *x509.Certificate) { c.EmailAddresses = []string{"op@acme"} },
		func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		func(c *x509.Certificate) {
			c.Subject.Names = []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 12}, Value: "operator"}}
		},
	}
	addrs := []net.Addr{tcpAddr("10.0.0.9"), tcpAddr("127.0.0.1"), &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1}, nonTCPAddr{"bufconn"}, nil}
	mds := []metadata.MD{nil, metadata.Pairs("x-litevirt-pool-content-view", "all"), metadata.Pairs("x-litevirt-role", "operator", "x-litevirt-user", "op")}
	for _, strict := range []bool{false, true} {
		s := strictServer(t, strict, strict, "peer-1", "self")
		for _, cn := range []string{"peer-1", "self", "lv-cli", "op", ""} {
			for i, attr := range attrs {
				for _, addr := range addrs {
					for _, md := range mds {
						cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
						attr(cert)
						ctx, err := s.authenticate(r7CertCtx(cert, addr, md))
						if err != nil {
							continue
						}
						if callerRole(ctx) != "admin" || callerAuthMethod(ctx) != authMethodMTLS {
							t.Errorf("bearerless %q (attr %d) at %v strict=%v is %q via %q", cn, i, addr, strict, callerRole(ctx), callerAuthMethod(ctx))
						}
					}
				}
			}
		}
		// No transport identity at all (an in-process call).
		if ctx, err := s.authenticate(context.Background()); err == nil && (callerRole(ctx) != "admin" || callerAuthMethod(ctx) != authMethodMTLS) {
			t.Errorf("an in-process bearerless call is %q via %q", callerRole(ctx), callerAuthMethod(ctx))
		}
	}
}

// A remote peer's bearerless call, authenticated as the interceptor does,
// sees every file of a shared pool directory (the daemon, or a node not yet
// upgraded).
func TestPoolRound7_AnAuthenticatedRemotePeerSeesEverything(t *testing.T) {
	s, _ := twoProjectsOnDisks(t)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-9", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	ctx, err := s.authenticate(mtlsPeerCtx("peer-9", tcpAddr("10.0.0.9"), ""))
	if err != nil || callerPrincipalKind(ctx) != principalKindPeer {
		t.Fatalf("authenticate a remote peer: kind %q, err %v", callerPrincipalKind(ctx), err)
	}
	got := listNames(t, s, ctx, "pa")
	if len(got) < 3 {
		t.Errorf("a remote peer's listing = %v, want every file", got)
	}
}

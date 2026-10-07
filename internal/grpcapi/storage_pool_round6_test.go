package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The metadata a replication or promote content call carries to say which
// VM's disk it is about (replicaContentCtx). Spelled out so these tests also
// compile on a tree that predates them.
const (
	r6ReplicaVMKey      = "x-litevirt-replica-vm"
	r6ReplicaDiskKey    = "x-litevirt-replica-disk"
	r6ReplicaProjectKey = "x-litevirt-replica-project"
)

// replicaContentCtx is the daemon's own content call about (vm, disk) of
// project, as it reaches the pool's host from a peer.
func replicaContentCtx(peer context.Context, vm, project, disk string) context.Context {
	ctx := withContentView(peer, "replicas")
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(r6ReplicaVMKey, vm)
	md.Set(r6ReplicaDiskKey, disk)
	md.Set(r6ReplicaProjectKey, project)
	return metadata.NewIncomingContext(ctx, md)
}

// qcow2Bytes is a real (empty) qcow2 image, so a promote's qemu-img copy of
// it succeeds.
func qcow2Bytes(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeQcow2(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, qcow2Bytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
}

// insertPromotableVM records a VM of project whose root disk was on host, with
// a spec promotion can define it from.
func insertPromotableVM(t *testing.T, s *Server, name, project, host, disk string) {
	t.Helper()
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
	src := filepath.Join(t.TempDir(), name+"-"+disk+".qcow2")
	writeQcow2(t, src)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: name, Project: project, HostName: host, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: disk, HostName: host, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
}

// recordReplicaForTest writes the upload record a replica gets on its pool's
// host, naming the VM and disk it is a replica of.
func recordReplicaForTest(t *testing.T, s *Server, pool, vm, project, disk, path string) {
	t.Helper()
	id, err := fileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(s.dataDir, "pool-uploads.json")
	m := map[string]map[string]any{}
	if b, err := os.ReadFile(file); err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber() // mtime_ns does not survive a float64
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
	}
	m[filepath.Clean(path)] = map[string]any{
		"pool": pool, "project": project, "vm": vm, "disk": disk,
		"ino": id.ino, "size": id.size, "mtime_ns": id.mtimeNs,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func promote(ctx context.Context, s *Server, req *pb.PromoteReplicaRequest) error {
	return s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx})
}

func stampAgo(d time.Duration) string {
	return time.Now().Add(-d).UTC().Format("20060102-150405")
}

// disksPoolServer is a host whose global default pool is its <data_dir>/disks,
// as an older cluster's is.
func disksPoolServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "default", Driver: "local", Target: disks})
	return s, disks
}

// CR1: a replica another host's replication runner uploads into a pool on
// <data_dir>/disks lands where promote reads it, and is promoted — by the
// failover's automatic promotion and by an operator's manual one.
func TestPoolRound6_ReplicaUploadedIntoADisksPoolIsPromotable(t *testing.T) {
	s, disks := disksPoolServer(t)
	peer := bareEntryPeer(t, s)
	for _, vm := range []string{"web", "api"} {
		insertPromotableVM(t, s, vm, "", "dead-host", "root")
		insertReplicationSchedule(t, s, vm, "default")
		name := vm + "-root-" + stampAgo(10*time.Minute) + ".qcow2"
		if err := uploadAs(replicaContentCtx(peer, vm, "", "root"), s, "default", name, string(qcow2Bytes(t))); err != nil {
			t.Fatalf("the replication runner's upload of %s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(disks, name)); err != nil {
			t.Errorf("replica %s did not land in the pool directory: %v", name, err)
		}
	}
	if err := s.AutoPromoteReplica(context.Background(), "web", "", 0); err != nil {
		t.Errorf("automatic promotion of a replica in the disks pool: %v", err)
	}
	if err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "api", TargetPool: "default"}); err != nil {
		t.Errorf("manual promotion of a replica in the disks pool: %v", err)
	}
	for _, vm := range []string{"web", "api"} {
		if !s.virt.DomainExists(vm) {
			t.Errorf("%s was not promoted", vm)
		}
	}
}

// Promotion takes the next-older replica when the newest is missing or
// unreadable, unless the operator named the replica.
func TestPoolRound6_PromoteFallsBackToAnOlderReplica(t *testing.T) {
	s, disks := disksPoolServer(t)
	// The newest of web's is a symlink to an image outside the pool — never
	// followed — and the newest of api's a symlink to nothing. The next of
	// each is empty. The oldest is good.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.qcow2")
	writeQcow2(t, elsewhere)
	missing, good := map[string]string{}, map[string]string{}
	for _, vm := range []string{"web", "api"} {
		insertPromotableVM(t, s, vm, "", "dead-host", "root")
		insertReplicationSchedule(t, s, vm, "default")
		good[vm] = vm + "-root-" + stampAgo(30*time.Minute)
		writeQcow2(t, filepath.Join(disks, good[vm]+".qcow2"))
		empty := filepath.Join(disks, vm+"-root-"+stampAgo(20*time.Minute)+".qcow2")
		writePoolFile(t, empty, "")
		missing[vm] = vm + "-root-" + stampAgo(10*time.Minute) + ".qcow2"
		target := filepath.Join(disks, "no-such-file")
		if vm == "web" {
			target = elsewhere
		}
		if err := os.Symlink(target, filepath.Join(disks, missing[vm])); err != nil {
			t.Fatal(err)
		}
	}
	if err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "api", TargetPool: "default", Replica: missing["api"]}); err == nil {
		t.Errorf("a named replica that is missing was replaced by another")
	}
	if err := s.AutoPromoteReplica(context.Background(), "web", "", 0); err != nil {
		t.Errorf("automatic promotion with the newest replica missing and the next unreadable: %v", err)
	}
	if err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "api", TargetPool: "default"}); err != nil {
		t.Errorf("manual promotion with the newest replica missing and the next unreadable: %v", err)
	}
	for _, vm := range []string{"web", "api"} {
		if !s.virt.DomainExists(vm) {
			t.Errorf("%s was not promoted from its older replica", vm)
		}
		if _, err := os.Stat(filepath.Join(disks, vm+"-promoted-"+good[vm]+".qcow2")); err != nil {
			t.Errorf("%s was not promoted from its oldest, good replica: %v", vm, err)
		}
	}
}

// CR2: promote and prune pick a VM's replicas by record, and an unrecorded
// file only by an exact <vm>-<disk>-<stamp> name that no VM of another project
// could also have. acme's VM bvm-root with a disk named 20261006 never boots
// or prunes bravo's bvm-root-20261006-*.qcow2, recorded or not.
func TestPoolRound6_PromoteAndPruneNeverTakeAnotherProjectsReplica(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertProjectVM(t, s, "bvm", "bravo", "root", filepath.Join(disks, "bvm-root.qcow2"), "default")
	insertPromotableVM(t, s, "bvm-root", "acme", s.hostName, "20261006")
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))

	bravos := map[string][2]string{ // file → recorded as (vm, disk) of bravo; "" = unrecorded
		"bvm-root-20261006-120000.qcow2":          {"", ""},
		"bvm-root-20261006-20261006-120000.qcow2": {"", ""},
		"bvm-root-20261006-130000.qcow2":          {"bvm", "root"},
		"bvm-root-20261006-20261006-130000.qcow2": {"bvm", "root-20261006"},
	}
	for n, rec := range bravos {
		p := filepath.Join(disks, n)
		writeQcow2(t, p)
		if rec[0] != "" {
			recordReplicaForTest(t, s, "default", rec[0], "bravo", rec[1], p)
		}
	}
	err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "bvm-root", TargetPool: "default", NoLocalize: true})
	if err == nil || s.virt.DomainExists("bvm-root") {
		t.Errorf("acme's bvm-root was promoted from bravo's replica (err %v)", err)
	}

	// acme's schedule for bvm-root into the same pool, keeping one replica:
	// its run prunes only acme's own.
	if err := corrosion.UpsertBackupSchedule(adminCtx(), s.db, corrosion.BackupScheduleRecord{
		VMName: "bvm-root", Scope: "vm", Repo: "default", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "default", TargetHost: s.hostName, KeepReplicas: 1,
	}); err != nil {
		t.Fatal(err)
	}
	sched, ok := s.replicationScheduleForVM(adminCtx(), "bvm-root")
	if !ok {
		t.Fatal("no schedule")
	}
	if err := s.RunReplication(adminCtx(), sched, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("replication run: %v", err)
	}
	for n := range bravos {
		if _, err := os.Stat(filepath.Join(disks, n)); err != nil {
			t.Errorf("acme's replication pruned bravo's %s: %v", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(disks, "bvm-root-20261006-20261007-000000.qcow2")); err != nil {
		t.Errorf("acme's own replica was not written: %v", err)
	}
	// acme's own replica — recorded, though its name is as ambiguous as
	// bravo's — is the one promoted.
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "bvm-root", TargetPool: "default", NoLocalize: true}); err != nil {
		t.Fatalf("promoting acme's own replica: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, "bvm-root-promoted-bvm-root-20261006-20261007-000000.qcow2")); err != nil {
		t.Errorf("acme's bvm-root was not promoted from its own replica: %v", err)
	}
}

// A file another project's VM uses as its disk is never a replica, whatever
// its name.
func TestPoolRound6_AFileAnotherProjectsDiskUsesIsNotAReplica(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "solo", "acme", "dead-host", "root")
	name := filepath.Join(disks, "solo-root-20261006-120000.qcow2")
	writeQcow2(t, name)
	insertProjectVM(t, s, "thief", "bravo", "root", name, "default")
	err := promote(adminCtx(), s, &pb.PromoteReplicaRequest{VmName: "solo", TargetPool: "default", NoLocalize: true})
	if err == nil || s.virt.DomainExists("solo") {
		t.Errorf("acme's solo was promoted from bravo's disk (err %v)", err)
	}
}

// A replica made before this build has no record. It is still its VM's,
// by its exact name, and promoted.
func TestPoolRound6_UnrecordedReplicaOfTheVMsOwnIsPromoted(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "avm", "acme", "dead-host", "root")
	insertProjectVM(t, s, "bvm", "bravo", "root", filepath.Join(disks, "bvm-root.qcow2"), "default")
	writeQcow2(t, filepath.Join(disks, "avm-root-20261006-120000.qcow2"))
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "avm", TargetPool: "default", NoLocalize: true}); err != nil {
		t.Fatalf("promoting the VM's own pre-upgrade replica: %v", err)
	}
	if !s.virt.DomainExists("avm") {
		t.Errorf("avm was not promoted")
	}
}

// I-A: a caller with a verified host certificate and no bearer is the daemon
// itself, a node that is not upgraded yet, or root on a node using the
// mTLS-as-admin fallback. It sees and changes every file, as on main.
func TestPoolRound6_BearerlessHostCertCallersSeeEverything(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	peer := bareEntryPeer(t, s)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: s.hostName, Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	root := mtlsPeerCtx(s.hostName, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}, "")
	root, err := s.authenticate(root)
	if err != nil || callerPrincipalKind(root) != principalKindLocalRoot {
		t.Fatalf("on-node root: kind %q, err %v", callerPrincipalKind(root), err)
	}
	for who, ctx := range map[string]context.Context{"an older node's peer call": peer, "on-node root": root} {
		got := listNames(t, s, ctx, "pa")
		for _, n := range []string{"avm-root.qcow2", "debian.iso", "stray.qcow2"} {
			if !slices.Contains(got, n) {
				t.Errorf("%s's listing = %v, lacks %s", who, got, n)
			}
		}
	}
	writePoolFile(t, filepath.Join(disks, "stray2.qcow2"), "x")
	for who, c := range map[string]struct {
		ctx  context.Context
		file string
	}{"an older node's peer call": {peer, "stray.qcow2"}, "on-node root": {root, "stray2.qcow2"}} {
		if _, err := s.DeleteStoragePoolContent(c.ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: c.file}); err != nil {
			t.Errorf("%s deleting an unowned file: %v", who, err)
		}
	}
	// On-node root's upload is a user's: out of the VM disks' namespace.
	if err := uploadAs(root, s, "pa", "root.iso", "iso"); err != nil {
		t.Fatalf("on-node root's upload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, "uploads", "root.iso")); err != nil {
		t.Errorf("on-node root's upload did not land in disks/uploads: %v", err)
	}
	// An older node's replica upload carries no marker: it still lands
	// among the disks, where promote reads it.
	name := "avm-root-" + stampAgo(time.Minute) + ".qcow2"
	if err := uploadAs(peer, s, "pa", name, "replica"); err != nil {
		t.Fatalf("an older node's replica upload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, name)); err != nil {
		t.Errorf("an older node's replica did not land among the disks: %v", err)
	}
}

// Every identity that is not an admin carries a bearer. A bearerless caller
// is a host certificate (the daemon, a peer, on-node root) or the lv-cli
// client certificate, and every one of them is admin — or is refused.
func TestPoolRound6_NonAdminIdentitiesAlwaysCarryABearer(t *testing.T) {
	remote, loop := tcpAddr("10.0.0.9"), tcpAddr("127.0.0.1")
	for _, strict := range []bool{false, true} {
		s := strictServer(t, strict, strict, "peer-1", "self")
		for _, c := range []struct {
			cn   string
			addr net.Addr
		}{{"peer-1", remote}, {"self", loop}, {"lv-cli", remote}, {"ghost", remote}, {"", remote}, {"peer-1", loop}} {
			ctx, err := s.authenticate(mtlsPeerCtx(c.cn, c.addr, ""))
			if err != nil {
				continue
			}
			if callerRole(ctx) != "admin" || callerAuthMethod(ctx) != authMethodMTLS {
				t.Errorf("bearerless %q at %v (strict %v) is role %q via %q, want admin via mTLS", c.cn, c.addr, strict, callerRole(ctx), callerAuthMethod(ctx))
			}
		}
	}
}

// m1: a session minted on the entry node a moment ago may not have reached the
// pool's host yet. A content call forwarded for it waits for the session
// briefly instead of failing at once.
func TestPoolRound6_ForwardedSessionIsAwaitedBriefly(t *testing.T) {
	s, _ := twoProjectsOnDisks(t)
	_ = hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	peer := bareEntryPeer(t, s)
	was := forwardedIdentityWait
	forwardedIdentityWait = 2 * time.Second
	t.Cleanup(func() { forwardedIdentityWait = was })
	now := time.Now().UTC()
	sess := corrosion.SessionRecord{
		ID: "lagging-session", Username: "pat", Realm: "local", IP: "10.0.0.9", UserAgent: "test",
		CreatedAt: now.Format(time.RFC3339), LastUsedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = corrosion.InsertSession(context.Background(), s.db, sess)
	}()
	via := withFwdBearer(peer, "Bearer "+SessionTokenPrefix+sess.ID)
	resp, err := s.ListStoragePoolContents(via, &pb.ListStoragePoolContentsRequest{PoolName: "pa"})
	if err != nil {
		t.Fatalf("a call forwarded for a session still replicating: %v", err)
	}
	var got []string
	for _, c := range resp.Contents {
		got = append(got, c.Name)
	}
	if slices.Contains(got, "stray.qcow2") || !slices.Contains(got, "avm-root.qcow2") {
		t.Errorf("the awaited caller's listing = %v, want acme's files only", got)
	}
	// A session that never arrives still fails, and says why.
	gone := withFwdBearer(peer, "Bearer "+SessionTokenPrefix+"never-minted")
	if _, err := s.ListStoragePoolContents(gone, &pb.ListStoragePoolContentsRequest{PoolName: "pa"}); status.Code(err) != codes.Unavailable {
		t.Errorf("a session that never replicates: got %v, want Unavailable", err)
	}
}

// m3: a crashed upload's temp file in disks/uploads is swept at start.
func TestPoolRound6_StaleUploadTempsInDisksUploadsAreSwept(t *testing.T) {
	s, disks := disksPoolServer(t)
	up := filepath.Join(disks, "uploads")
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(up, ".upload-123.tmp")
	writePoolFile(t, tmp, "partial")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(tmp, old, old); err != nil {
		t.Fatal(err)
	}
	s.SweepStaleStaging(adminCtx())
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stale upload temp in disks/uploads survived the sweep: %v", err)
	}
}

// m5: when an upload and a file at the root of disks/ share a name, the
// listing and a delete act on the same file: the upload.
func TestPoolRound6_ListingAndDeleteAgreeOnACollidingName(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	if err := uploadAs(adminCtx(), s, "pa", "same.qcow2", "the upload"); err != nil {
		t.Fatal(err)
	}
	writePoolFile(t, filepath.Join(disks, "same.qcow2"), "a later file at the root")
	resp, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "pa"})
	if err != nil {
		t.Fatal(err)
	}
	listed := ""
	for _, c := range resp.Contents {
		if c.Name == "same.qcow2" {
			listed = c.Path
		}
	}
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: "same.qcow2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(listed); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the listing showed %s but the delete removed another file", listed)
	}
}

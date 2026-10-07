package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// Round 8 (restore-pool-rereview-3.md): operator copies are not replicas,
// records survive a remount, shared records cover every network filesystem
// and degrade to name matching wherever they cannot be seen.

// ownPoolServer is a host with acme's dir pool "pa" in pools/pa, and acme's
// VM web (disk root) running on it.
func ownPoolServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := disksPoolServer(t)
	own := filepath.Join(s.dataDir, "pools", "pa")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pa", Driver: "dir", Target: own, Project: "acme"})
	insertPromotableVM(t, s, "web", "acme", s.hostName, "root")
	return s, own
}

func replicateVolume(ctx context.Context, s *Server, vm, disk, pool, target string) error {
	return s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: vm, DiskName: disk, TargetPool: pool, TargetPath: target},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: ctx})
}

// stampedReplicas lists the runner's replicas (<prefix>-<stamp>.<ext>) in dir.
func stampedReplicas(t *testing.T, dir, prefix string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if p, ok := replicaNamePrefix(e.Name()); ok && p == prefix {
			out = append(out, e.Name())
		}
	}
	return out
}

func runKeep(t *testing.T, s *Server, vm string, keep int, at time.Time) {
	t.Helper()
	sched, ok := s.replicationScheduleForVM(adminCtx(), vm)
	if !ok {
		t.Fatalf("%s has no replication schedule", vm)
	}
	sched.KeepReplicas = keep
	if err := s.RunReplication(adminCtx(), sched, at); err != nil {
		t.Fatalf("%s's replication run: %v", vm, err)
	}
}

// C1, the default name: a replicate-volume copy web-root.qcow2 sorts after
// every stamped replica. It is not a replica: a keep-1 run keeps the replica
// it just made, and failover promotes that replica, not the copy.
func TestPoolRound8_ADefaultNamedCopyIsNotTheNewestReplica(t *testing.T) {
	s, own := ownPoolServer(t)
	if err := replicateVolume(adminCtx(), s, "web", "root", "pa", ""); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	insertReplicationSchedule(t, s, "web", "pa")
	runKeep(t, s, "web", 1, time.Now())
	fresh := stampedReplicas(t, own, "web-root")
	if len(fresh) != 1 {
		t.Fatalf("after a keep-1 run web's replicas = %v, want the one it made", fresh)
	}
	if _, err := os.Stat(filepath.Join(own, "web-root.qcow2")); err != nil {
		t.Errorf("the operator's copy was pruned: %v", err)
	}
	if err := s.AutoPromoteReplica(context.Background(), "web", "", 0); err != nil {
		t.Fatalf("failover promotion of web: %v", err)
	}
	if !promotedFrom(own, "web", fresh[0]) {
		t.Errorf("web was not promoted from its newest replica %s", fresh[0])
	}
}

// C1, a custom name: offsite-copy.qcow2 sorts before every replica. Runs
// past keep never prune it, and it is still promotable by name.
func TestPoolRound8_ACustomNamedCopySurvivesPruning(t *testing.T) {
	s, own := ownPoolServer(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if err := replicateVolume(pat, s, "web", "root", "pa", "offsite-copy.qcow2"); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	insertReplicationSchedule(t, s, "web", "pa")
	for i := 3; i >= 1; i-- {
		runKeep(t, s, "web", 1, time.Now().Add(-time.Duration(i)*time.Hour))
	}
	if _, err := os.Stat(filepath.Join(own, "offsite-copy.qcow2")); err != nil {
		t.Errorf("three keep-1 runs removed the operator's copy: %v", err)
	}
	if got := stampedReplicas(t, own, "web-root"); len(got) != 1 {
		t.Errorf("web's replicas after three keep-1 runs = %v, want 1", got)
	}
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "pa", Replica: "offsite-copy.qcow2", NoLocalize: true}); err != nil {
		t.Errorf("promoting the copy by name: %v", err)
	}
}

// C1, a .raw name: a qcow2 copy named zzz.raw is never the base an
// incremental replica forks from.
func TestPoolRound8_ARawNamedCopyIsNeverAnIncrementBase(t *testing.T) {
	s, own := ownPoolServer(t)
	if err := replicateVolume(adminCtx(), s, "web", "root", "pa", "zzz.raw"); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	runner := "web-root-" + stampAgo(time.Hour) + ".raw"
	p := filepath.Join(own, runner)
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	if err := s.recordPoolReplica(context.Background(), "pa", k, p); err != nil {
		t.Fatal(err)
	}
	if got := s.newestRawReplica(context.Background(), "pa", s.hostName, k); got != runner {
		t.Errorf("increment base = %q, want the runner's %q", got, runner)
	}
}

// setRecordDev rewrites the device number of every local record, as a reboot
// or remount that numbers the filesystem anew does.
func setRecordDev(t *testing.T, s *Server, dev uint64) { setRecordField(t, s, "dev", dev) }

// setRecordField rewrites one field of every local record.
func setRecordField(t *testing.T, s *Server, field string, v uint64) {
	t.Helper()
	file := filepath.Join(s.dataDir, "pool-uploads.json")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // mtime_ns does not survive a float64
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	for _, r := range m {
		r[field] = v
	}
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// C2: a record is not bound to the device number, which a reboot or remount
// may change. A project's upload stays its own after one: listed and
// deletable by its operators.
func TestPoolRound8_AnUploadStaysOwnedAcrossARemount(t *testing.T) {
	s, _ := disksPoolServer(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", poolRBACPathFor("", "default"))
	if err := uploadAs(pat, s, "default", "pats.qcow2", "x"); err != nil {
		t.Fatal(err)
	}
	setRecordDev(t, s, 4242)
	if got := listNames(t, s, pat, "default"); !slices.Contains(got, "pats.qcow2") {
		t.Errorf("after a remount pat's listing %v lacks pat's upload", got)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "default", Filename: "pats.qcow2"}); err != nil {
		t.Errorf("pat deleting its own upload after a remount: %v", err)
	}
}

// C2: on shared storage a stale local record never shadows the valid shared
// one, and a replica whose every record went stale is matched by its name —
// never refused for it.
func TestPoolRound8_AStaleRecordNeverRefusesAReplica(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h1", KeepReplicas: 5,
	}); err != nil {
		t.Fatal(err)
	}
	runKeep(t, h1, "cvm", 5, time.Now())
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	setRecordDev(t, h1, 4242)
	if got := h1.replicaNames(context.Background(), "shared", "", k, "", false); len(got) != 1 {
		t.Errorf("after a remount h1 sees cvm's replicas %v, want the one it wrote", got)
	}
	// h1's own record no longer describes the file (another inode); the
	// shared record, by size and time, still does, and is not shadowed.
	setRecordField(t, h1, "ino", 1)
	if got := h1.replicaNames(context.Background(), "shared", "", k, "", false); len(got) != 1 {
		t.Errorf("a stale local record shadows the valid shared one: h1 sees %v", got)
	}
	if m, err := h1.loadPoolUploads(context.Background(), dir); err != nil {
		t.Fatal(err)
	} else if got := stampedReplicas(t, dir, "cvm-root"); len(got) != 1 {
		t.Fatalf("cvm's replicas = %v", got)
	} else if u, ok := h1.poolUploadOf(m, filepath.Join(dir, got[0])); !ok || u.VM != "cvm" {
		t.Errorf("a stale local record shadows the valid shared one: %+v %v", u, ok)
	}
	// Every record stale: the file was rewritten in place (a restore by hand).
	reps := stampedReplicas(t, dir, "cvm-root")
	if len(reps) != 1 {
		t.Fatalf("cvm's replicas = %v", reps)
	}
	p := filepath.Join(dir, reps[0])
	b, _ := os.ReadFile(p)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, make([]byte, 512)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := h1.replicaNames(context.Background(), "shared", "", k, "", false); !slices.Equal(got, reps) {
		t.Errorf("a replica whose records are stale is not matched by its name: %v", got)
	}
}

// twoHostsOnMount is h1 and h2 with the global dir pool "shared" on dir, each
// seeing the mount line its function gives (as it would on its own machine),
// with the options each host's pool row records.
type mountSwitch struct {
	line func(host, dir string) string
	dir  string
	cur  string
}

func (m *mountSwitch) as(host string) { m.cur = m.line(host, m.dir) }

func twoHostsOnMount(t *testing.T, line func(host, dir string) string, opts map[string]map[string]string) (h1, h2 *Server, ms *mountSwitch) {
	t.Helper()
	ms = &mountSwitch{line: line, dir: t.TempDir()}
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) { return []byte(ms.cur + "\n"), nil }))
	t.Cleanup(storage.OverrideNFSResolverForTest(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}))
	h1 = newPoolTestServer(t)
	h1.hostName = "h1"
	h2 = &Server{hostName: "h2", dataDir: t.TempDir(), db: h1.db, virt: libvirtfake.New(), events: events.NewBus()}
	h2.images = image.NewStore(h2.dataDir)
	h1.db.SetClusterPolicyGate(func() bool { return true })
	for _, h := range []string{"h1", "h2"} {
		if err := corrosion.InsertHost(context.Background(), h1.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, h1, corrosion.StoragePoolRecord{HostName: h, Name: "shared", Driver: "dir", Target: ms.dir, Options: opts[h]})
	}
	ms.as("h1")
	h1.SweepStaleStaging(context.Background())
	ms.as("h2")
	h2.SweepStaleStaging(context.Background())
	return h1, h2, ms
}

// replicateOnH1 runs cvm's replication on h1 into "shared".
func replicateOnH1(t *testing.T, h1 *Server, ms *mountSwitch) {
	t.Helper()
	ms.as("h1")
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	sched := corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h1", KeepReplicas: 2,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	if err := h1.RunReplication(adminCtx(), sched, time.Now()); err != nil {
		t.Fatalf("cvm's replication on h1: %v", err)
	}
}

// C3: a pool on CephFS is shared storage. The replica h1 recorded is h2's to
// promote when h1 is gone, by its cluster-wide record.
func TestPoolRound8_ACephFSPoolFailsOverViaAnotherHost(t *testing.T) {
	h1, h2, ms := twoHostsOnMount(t, func(_, dir string) string {
		return fmt.Sprintf("41 1 0:61 / %s rw,nosuid,nodev,noexec,relatime - ceph 10.0.0.1:6789,10.0.0.2:6789:/vols/shared rw,name=admin,secret=<hidden>,acl", dir)
	}, nil)
	replicateOnH1(t, h1, ms)
	ms.as("h2")
	reps := stampedReplicas(t, ms.dir, "cvm-root")
	if len(reps) != 1 {
		t.Fatalf("cvm's replicas = %v", reps)
	}
	m, err := h2.loadPoolUploads(context.Background(), ms.dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := h2.poolUploadOf(m, filepath.Join(ms.dir, reps[0])); !ok || u.VM != "cvm" {
		t.Errorf("h2 does not hold h1's record of cvm's replica on CephFS: %+v %v", u, ok)
	}
	if err := corrosion.UpdateVMHost(adminCtx(), h1.db, "cvm", "h2", "running"); err != nil {
		t.Fatal(err)
	}
	if err := promote(adminCtx(), h2, &pb.PromoteReplicaRequest{VmName: "cvm", TargetPool: "shared", TargetHost: "h2", NoLocalize: true}); err != nil {
		t.Fatalf("promoting cvm on h2 from h1's replica on CephFS: %v", err)
	}
	if !promotedFrom(ms.dir, "cvm", reps[0]) {
		t.Errorf("cvm was not promoted from %s", reps[0])
	}
}

// C3: one NFS export spelled two ways — a name on h1, its address on h2 —
// is one export: h2 holds h1's records.
func TestPoolRound8_AnNFSExportSpelledTwoWaysIsOne(t *testing.T) {
	src := map[string]string{"h1": "nas:/shared", "h2": "10.0.0.5:/shared"}
	h1, h2, ms := twoHostsOnMount(t, func(host, dir string) string {
		return fmt.Sprintf("40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow,relatime - nfs4 %s rw,vers=4.2,addr=10.0.0.5", dir, src[host])
	}, map[string]map[string]string{"h1": {"nfs_export": src["h1"]}, "h2": {"nfs_export": src["h2"]}})
	replicateOnH1(t, h1, ms)
	ms.as("h2")
	reps := stampedReplicas(t, ms.dir, "cvm-root")
	m, err := h2.loadPoolUploads(context.Background(), ms.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("cvm's replicas = %v", reps)
	}
	if u, ok := h2.poolUploadOf(m, filepath.Join(ms.dir, reps[0])); !ok || u.VM != "cvm" {
		t.Errorf("h2 does not hold h1's record made under another spelling: %+v %v", u, ok)
	}
}

// C3: where this host cannot see a pool's shared records — a network
// filesystem it cannot identify, or an export spelled differently with
// nothing to reconcile the spellings — a replica is matched by its name,
// as before records.
func TestPoolRound8_WithoutVisibleSharedRecordsAReplicaIsMatchedByName(t *testing.T) {
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	type tc struct {
		line func(host, dir string) string
		opts map[string]map[string]string
	}
	cases := map[string]tc{
		"ocfs2": {line: func(_, dir string) string {
			return fmt.Sprintf("41 1 8:17 / %s rw,nosuid,nodev,noexec,relatime - ocfs2 /dev/sdb1 rw", dir)
		}},
		"nfs spelled two ways": {line: func(host, dir string) string {
			src := map[string]string{"h1": "nas:/shared", "h2": "nas.lan:/shared"}[host]
			return fmt.Sprintf("40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow,relatime - nfs4 %s rw,vers=4.2", dir, src)
		}, opts: map[string]map[string]string{"h1": {"nfs_export": "nas:/shared"}, "h2": {"nfs_export": "nas.lan:/shared"}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h1, h2, ms := twoHostsOnMount(t, c.line, c.opts)
			replicateOnH1(t, h1, ms)
			ms.as("h2")
			if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); len(got) != 1 {
				t.Errorf("h2 sees cvm's replicas %v, want h1's, matched by its name", got)
			}
		})
	}
}

// I1: a replica whose record cannot be written fails the run and is not left
// behind, unpromotable.
func TestPoolRound8_AReplicaThatCannotBeRecordedFailsTheRun(t *testing.T) {
	s, own := ownPoolServer(t)
	insertReplicationSchedule(t, s, "web", "pa")
	// The records file cannot be read or written.
	if err := os.Mkdir(filepath.Join(s.dataDir, "pool-uploads.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	sched, _ := s.replicationScheduleForVM(adminCtx(), "web")
	if err := s.RunReplication(adminCtx(), sched, time.Now()); err == nil {
		t.Errorf("a full replication whose replica was not recorded succeeded")
	}
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	name := "web-root-" + stampAgo(0) + ".raw"
	if err := s.applyIncrementLocal(context.Background(), "pa", name, "", 4096, bytes.NewReader(make([]byte, 4096)), [][2]int64{{0, 4096}}, k); err == nil {
		t.Errorf("an incremental replica that was not recorded was applied")
	}
	if got := stampedReplicas(t, own, "web-root"); len(got) != 0 {
		t.Errorf("unrecorded replicas left behind: %v", got)
	}
}

// I2: a VM name reused by another project inherits none of the old
// project's replicas on shared storage.
func TestPoolRound8_AReusedNameInAnotherProjectInheritsNothing(t *testing.T) {
	h1, h2, dir := twoHostsOnOneExport(t)
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h1", KeepReplicas: 5,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	insertPromotableVM(t, h1, "web", "bravo", "h1", "root")
	if err := h1.RunReplication(adminCtx(), sched, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	bravos := stampedReplicas(t, dir, "web-root")
	if err := corrosion.DeleteVM(adminCtx(), h1.db, "web"); err != nil {
		t.Fatal(err)
	}
	insertPromotableVM(t, h1, "web", "acme", "h1", "root")
	if err := h1.RunReplication(adminCtx(), sched, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var acmes []string
	for _, n := range stampedReplicas(t, dir, "web-root") {
		if !slices.Contains(bravos, n) {
			acmes = append(acmes, n)
		}
	}
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); len(bravos) != 1 || !slices.Equal(got, acmes) {
		t.Errorf("acme's web on h2 has replicas %v, want only its own %v (bravo's: %v)", got, acmes, bravos)
	}
}

// Concern 2: each host writes only its own replica row; readers take the
// union. A VM that moved from h1 to h2 keeps both hosts' replicas recorded.
func TestPoolRound8_EachHostWritesItsOwnReplicaRow(t *testing.T) {
	h1, h2, dir := twoHostsOnOneExport(t)
	sched := corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", KeepReplicas: 5,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	sched.TargetHost = "h1"
	if err := h1.RunReplication(adminCtx(), sched, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, err := corrosion.ListPoolRecords(context.Background(), h1.db, corrosion.PoolReplicasKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMHost(adminCtx(), h1.db, "cvm", "h2", "running"); err != nil {
		t.Fatal(err)
	}
	sched.TargetHost = "h2"
	if err := h2.RunReplication(adminCtx(), sched, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := corrosion.ListPoolRecords(context.Background(), h1.db, corrosion.PoolReplicasKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for key, v := range before {
		if after[key] != v {
			t.Errorf("h2's record rewrote h1's row %s", key)
		}
	}
	if len(after) < 2 {
		t.Errorf("replica rows after two writers = %d, want one per writer", len(after))
	}
	h3 := &Server{hostName: "h3", dataDir: t.TempDir(), db: h1.db}
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	m, err := h3.loadPoolUploads(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	reps := stampedReplicas(t, dir, "cvm-root")
	if len(reps) != 2 {
		t.Fatalf("cvm's replicas = %v", reps)
	}
	for _, n := range reps {
		if !h3.isReplicaFor(context.Background(), m, filepath.Join(dir, n), k) {
			t.Errorf("the union of both rows lacks %s", n)
		}
	}
}

// I3: deleting a VM sweeps its default-named replicate-volume copy from
// <data_dir>/disks, as main's sweep did; a user's upload of that shape stays.
func TestPoolRound8_TheDeleteSweepTakesTheVMsDefaultCopy(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "web", "acme", s.hostName, "root")
	if err := replicateVolume(adminCtx(), s, "web", "root", "default", ""); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	upload := filepath.Join(disks, "web-old.qcow2")
	writeQcow2(t, upload)
	if err := s.recordPoolUpload(context.Background(), "default", "bravo", "bob@local", upload); err != nil {
		t.Fatal(err)
	}
	s.sweepVMDiskDebris(context.Background(), "web")
	if _, err := os.Stat(filepath.Join(disks, "web-root.qcow2")); err == nil {
		t.Errorf("the VM's default-named copy outlived the sweep")
	}
	if _, err := os.Stat(upload); err != nil {
		t.Errorf("the sweep removed bravo's upload: %v", err)
	}
}

// Upload records on shared storage do not grow with history: uploading and
// deleting many names leaves a row per writing host, not one per name.
func TestPoolRound8_UploadRecordsDoNotGrowWithHistory(t *testing.T) {
	h1, _, _ := twoHostsOnOneExport(t)
	pat := hostPathEngineCtx(t, h1, "pat", "Operator", poolRBACPathFor("", "shared"))
	for i := range 12 {
		name := fmt.Sprintf("f%d.img", i)
		if err := uploadAs(pat, h1, "shared", name, "x"); err != nil {
			t.Fatal(err)
		}
		if _, err := h1.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: name}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := corrosion.ListPoolRecords(context.Background(), h1.db, corrosion.PoolUploadKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > 2 {
		t.Errorf("12 uploads and deletes left %d upload record rows", len(rows))
	}
}

// n5: on shared storage, pruning keeps a replica another host's live disk
// uses (a promotion there that kept it as its backing file).
func TestPoolRound8_SharedPruneKeepsAReplicaAnotherHostsDiskUses(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "web", "acme", "h1", "root")
	old, newer := "web-root-20261001-120000.qcow2", "web-root-20261002-120000.qcow2"
	for _, n := range []string{old, newer} {
		p := filepath.Join(dir, n)
		writeQcow2(t, p)
		setPast(t, p, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	}
	if err := corrosion.InsertVM(adminCtx(), h1.db, corrosion.VMRecord{Name: "web-dr", Project: "acme", HostName: "h2", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: "h2", Path: filepath.Join(dir, old), StorageType: "local", StorageVolume: "shared"}}); err != nil {
		t.Fatal(err)
	}
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	h1.pruneLocalReplicas(context.Background(), dir, k, 1)
	if _, err := os.Stat(filepath.Join(dir, old)); err != nil {
		t.Errorf("h1's prune removed the replica h2's web-dr runs on: %v", err)
	}
}

// m6: a replica whose stamp is in the future is refused saying so.
func TestPoolRound8_AFutureStampIsRefusedSayingSo(t *testing.T) {
	s, _ := disksPoolServer(t)
	peer := bareEntryPeer(t, s)
	name := "zvm-root-" + time.Now().Add(time.Hour).UTC().Format("20060102-150405") + ".qcow2"
	err := uploadAs(replicaContentCtx(peer, "zvm", "acme", "root"), s, "default", name, "x")
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Errorf("a replica stamped an hour ahead: got %v, want a refusal naming the future stamp", err)
	}
}

// I1, shared: a replica whose cluster-wide record cannot be written is
// withdrawn and fails the run (other hosts could never match it).
func TestPoolRound8_AReplicaThatCannotBeSharedFailsTheRun(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	setFor(t, &sharedWriteAttempts, 1)
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	sched := corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h1", KeepReplicas: 2,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	// Every write to the replicated rows fails from here on.
	if err := h1.db.Execute(context.Background(), `CREATE TRIGGER no_pool_rows BEFORE INSERT ON cluster_policies BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if err := h1.RunReplication(adminCtx(), sched, time.Now()); err == nil {
		t.Errorf("a replication whose replica was not shared succeeded")
	}
	if got := stampedReplicas(t, dir, "cvm-root"); len(got) != 0 {
		t.Errorf("unshared replicas left behind: %v", got)
	}
}

// A host's upload row holds only files that exist: files another host
// deleted leave it the next time this host writes it.
func TestPoolRound8_AnUploadRowDropsFilesDeletedElsewhere(t *testing.T) {
	h1, h2, dir := twoHostsOnOneExport(t)
	pat := hostPathEngineCtx(t, h1, "pat", "Operator", poolRBACPathFor("", "shared"))
	for i := range 5 {
		name := fmt.Sprintf("g%d.img", i)
		if err := uploadAs(pat, h1, "shared", name, "x"); err != nil {
			t.Fatal(err)
		}
		if _, err := h2.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: name}); err != nil {
			t.Fatal(err)
		}
	}
	if err := uploadAs(pat, h1, "shared", "last.img", "x"); err != nil {
		t.Fatal(err)
	}
	v, _, err := corrosion.GetPoolRecord(context.Background(), h1.db, uploadRowKey(sharedStoreOf(dir).ID, "h1"))
	if err != nil {
		t.Fatal(err)
	}
	var row uploadRow
	if err := json.Unmarshal([]byte(v), &row); err != nil {
		t.Fatal(err)
	}
	if len(row.Files) != 1 {
		t.Errorf("h1's upload row holds %d files, want only last.img", len(row.Files))
	}
}

// n5, remote: the daemon's prune reaching the pool's host never deletes a
// replica another host's live disk uses, on shared storage.
func TestPoolRound8_ARemotePruneKeepsAReplicaAnotherHostsDiskUses(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "web", "acme", "h3", "root")
	old := "web-root-20261001-120000.qcow2"
	p := filepath.Join(dir, old)
	writeQcow2(t, p)
	setPast(t, p, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := corrosion.InsertVM(adminCtx(), h1.db, corrosion.VMRecord{Name: "web-dr", Project: "acme", HostName: "h2", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: "h2", Path: p, StorageType: "local", StorageVolume: "shared"}}); err != nil {
		t.Fatal(err)
	}
	ctx := replicaContentCtx(bareEntryPeer(t, h1), "web", "acme", "root")
	if _, err := h1.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "shared", Filename: old}); err == nil {
		t.Errorf("the prune's delete removed the replica h2's web-dr runs on")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("replica gone: %v", err)
	}
}

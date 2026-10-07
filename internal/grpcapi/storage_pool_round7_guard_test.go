package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// NI1: a replica h1 writes into a pool on shared storage is recorded for the
// whole cluster, so h2 takes it for cvm's replica — though it was made after every host began
// recording, when an unrecorded file is never taken by its name.
func TestPoolRound7_ASharedReplicaIsRecordedForEveryHost(t *testing.T) {
	h1, h2, _ := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "cvm", "bravo", "h1", "root")
	sched := corrosion.BackupScheduleRecord{
		VMName: "cvm", Scope: "vm", Repo: "shared", Cron: "0 0 * * *", Enabled: true,
		Type: "replication", TargetPool: "shared", TargetHost: "h1", KeepReplicas: 2,
	}
	if err := corrosion.UpsertBackupSchedule(adminCtx(), h1.db, sched); err != nil {
		t.Fatal(err)
	}
	if err := poolEraReplicate(t, h1, sched, time.Now()); err != nil {
		t.Fatalf("cvm's replication on h1: %v", err)
	}
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	got := h2.replicaNames(context.Background(), "shared", "", k, "", false)
	if len(got) != 1 {
		t.Fatalf("h2 sees cvm's replicas %v, want the one h1 wrote", got)
	}
	// findReplicaHost on h2 chooses from exactly this list.
}

// NI1: an unrecorded file is a replica made before records only if it was
// made before every host began recording; one made since is never taken by
// its name, however exact. A user upload made through h1 is recorded for h2.
func TestPoolRound7_AnUnrecordedFileMadeAfterTheEpochIsNotLegacy(t *testing.T) {
	h1, h2, dir := twoHostsOnOneExport(t)
	insertPromotableVM(t, h1, "dvm", "bravo", "h2", "root")
	k := replicaKey{VM: "dvm", Disk: "root", Project: "bravo"}
	name := "dvm-root-" + stampAgo(time.Hour) + ".qcow2"
	p := filepath.Join(dir, name)
	writeQcow2(t, p)
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); len(got) != 0 {
		t.Errorf("an unrecorded file made after the epoch was taken for dvm's replica: %v", got)
	}
	setPast(t, p, time.Now().Add(-48*time.Hour))
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); !slices.Equal(got, []string{name}) {
		t.Errorf("a file from before the epoch is not dvm's legacy replica: %v", got)
	}

	pat := hostPathEngineCtx(t, h1, "pat", "Operator", poolRBACPathFor("", "shared"))
	if err := uploadAs(pat, h1, "shared", "pats.img", "x"); err != nil {
		t.Fatal(err)
	}
	m, err := h2.loadPoolUploads(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := h2.poolUploadOf(m, filepath.Join(dir, "pats.img")); !ok || u.Uploader != "pat@local" {
		t.Errorf("h2 does not hold pat's upload record made through h1: %+v %v", u, ok)
	}
}

// NC1: an upload into a global pool is the VM's project's when its uploader
// may create that VM; another project's user's upload is not.
func TestPoolRound7_AGlobalPoolUploadIsItsUploadersProjects(t *testing.T) {
	s, _ := disksPoolServer(t)
	insertPromotableVM(t, s, "web", "acme", "dead-host", "root")
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	for _, u := range []string{"pat", "bob"} {
		if err := corrosion.InsertRoleBinding(context.Background(), s.db, corrosion.RoleBindingRecord{
			ID: u + "-pool", Path: poolRBACPathFor("", "default"), Role: "Operator", Principal: "user:" + u + "@local", Propagate: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.authEngine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	img := string(qcow2Bytes(t))
	if err := uploadAs(bob, s, "default", "web-root-bobs.qcow2", img); err != nil {
		t.Fatal(err)
	}
	if err := uploadAs(pat, s, "default", "web-root-pats.qcow2", img); err != nil {
		t.Fatal(err)
	}
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "default", Replica: "web-root-bobs.qcow2", NoLocalize: true}); err == nil {
		t.Errorf("acme's web was promoted from bravo's user's upload")
	}
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "default", Replica: "web-root-pats.qcow2", NoLocalize: true}); err != nil {
		t.Errorf("promoting web from an upload by a user who may create it: %v", err)
	}
}

// NC2: a deleted VM of another project whose disks are no longer known
// claims the name (fail closed); one whose kept rows show no such disk does
// not.
func TestPoolRound7_ADeletedVMWithUnknownDisksClaims(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "web-prod", "acme", "dead-host", "root")
	name := "web-prod-root-20261005-120000.qcow2"
	writeQcow2(t, filepath.Join(disks, name))
	k := replicaKey{VM: "web-prod", Disk: "root", Project: "acme"}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "web", Project: "bravo", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := s.replicaNames(context.Background(), "default", "", k, "", false); !slices.Equal(got, []string{name}) {
		t.Errorf("a live VM web of bravo with no prod-root disk claimed %s: %v", name, got)
	}
	if err := corrosion.DeleteVM(adminCtx(), s.db, "web"); err != nil {
		t.Fatal(err)
	}
	if got := s.replicaNames(context.Background(), "default", "", k, "", false); len(got) != 0 {
		t.Errorf("a deleted VM web of bravo whose disks are unknown did not claim %s: %v", name, got)
	}

	// A live VM of bravo that had a prod-root disk, since detached, claims
	// it too: the file may be that disk's replica.
	s2, disks2 := disksPoolServer(t)
	insertPromotableVM(t, s2, "web-prod", "acme", "dead-host", "root")
	writeQcow2(t, filepath.Join(disks2, name))
	insertProjectVM(t, s2, "web", "bravo", "prod-root", filepath.Join(disks2, "web-prod-root.qcow2"), "default")
	if err := corrosion.SoftDeleteDisk(adminCtx(), s2.db, "web", "prod-root"); err != nil {
		t.Fatal(err)
	}
	if got := s2.replicaNames(context.Background(), "default", "", k, "", false); len(got) != 0 {
		t.Errorf("bravo's web with a detached prod-root disk did not claim %s: %v", name, got)
	}
}

// n4: a replica call for a VM whose name a deleted VM of another project
// last had (the new VM's row not here yet) is not refused.
func TestPoolRound7_AReplicaCallIsNotRefusedByADeletedNamesake(t *testing.T) {
	s, disks := disksPoolServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "zvm", Project: "bravo", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(adminCtx(), s.db, "zvm"); err != nil {
		t.Fatal(err)
	}
	peer := bareEntryPeer(t, s)
	name := "zvm-root-" + stampAgo(time.Minute) + ".qcow2"
	if err := uploadAs(replicaContentCtx(peer, "zvm", "acme", "root"), s, "default", name, "x"); err != nil {
		t.Errorf("acme's zvm replica upload refused over bravo's deleted zvm: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, name)); err != nil {
		t.Errorf("replica not written: %v", err)
	}
}

// n5: local pruning never removes a replica a live disk uses.
func TestPoolRound7_LocalPruneKeepsAReplicaALiveDiskUses(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertPromotableVM(t, s, "web", "acme", "dead-host", "root")
	old, newer := "web-root-20261001-120000.qcow2", "web-root-20261002-120000.qcow2"
	for _, n := range []string{old, newer} {
		writeQcow2(t, filepath.Join(disks, n))
	}
	insertProjectVM(t, s, "web-dr", "acme", "root", filepath.Join(disks, old), "default")
	k := replicaKey{VM: "web", Disk: "root", Project: "acme"}
	if n := s.pruneLocalReplicas(context.Background(), disks, k, 1); n != 0 {
		t.Errorf("pruned %d", n)
	}
	if _, err := os.Stat(filepath.Join(disks, old)); err != nil {
		t.Errorf("pruning removed a replica web-dr's disk uses: %v", err)
	}
}

// NC1: a replicate-volume copy into a pool is the VM's replica by record,
// whatever it is named, and a manual promotion may name it.
func TestPoolRound7_AReplicateVolumeCopyIsTheVMsReplica(t *testing.T) {
	s, _ := disksPoolServer(t)
	own := filepath.Join(s.dataDir, "pools", "pa")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pa", Driver: "dir", Target: own, Project: "acme"})
	insertPromotableVM(t, s, "web", "acme", s.hostName, "root")
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	// The daemon names an operator's copy; only an admin names the file.
	copyRec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: pat}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "web", DiskName: "root", TargetPool: "pa"}, copyRec); err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	copyName := filepath.Base(copyRec.Sent[len(copyRec.Sent)-1].GetTargetPath())
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "web", TargetPool: "pa", Replica: copyName, NoLocalize: true}); err != nil {
		t.Errorf("promoting the replicate-volume copy by name: %v", err)
	}
}

package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Post-breaker fix 2 (diskiso-rereview-6.md): a VM promoted from a raw replica
// whose disk now sits on a snapshot overlay copies (N-C2); a backup pins its
// base on the VM's host, whatever repo or host the manifest lands in (N-I1).

// ── N-C2 ─────────────────────────────────────────────────────────────────────

// snapShape is what a snapshot create → revert or delete left on a VM promoted
// with --no-localize from the raw replica R, its overlay P built by main's
// naming (mainPromotedName): the row on S = <P's stem>.snap1 in the same
// directory, and S on P (viaP) or straight on R (P committed into S).
// recorded: this build's promotion — R a recorded replica in the source VM's
// owner directory, and the row records backing_disk R.
type snapShape struct{ viaP, recorded bool }

// otherStem names S's qcow2 parent another VM's overlay (a different stem,
// no row) instead of P. claimedBy: P is claimed by a row of VM "db" in
// project b.
type snapNeg struct {
	otherStem bool
	claimedBy bool
}

func promotedOnSnapshot(t *testing.T, s *Server, sh snapShape, neg snapNeg) (d corrosion.DiskRecord, raw []byte, parent, parentFmt string) {
	t.Helper()
	ctx := context.Background()
	pool := t.TempDir()
	registerPool(t, s, "dr", "dir", "", pool, "")
	victim := filepath.Join(pool, "db-root.qcow2")
	filledQcow2(t, victim, "PROJECT-B ")
	crafted := filepath.Join(t.TempDir(), "crafted.qcow2")
	if err := qcow2.CreateWithBacking(crafted, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(crafted)
	raw = append(raw, make([]byte, (1<<20)-len(raw))...)
	var replica string
	if sh.recorded {
		// This build's replica: recorded, in web's owner directory.
		var err error
		replica, err = publishRecordedReplica(ctx, pool, newReplicaRecord("a", "web", "root", "web/dr", "20261013-000000", "raw"),
			func(tmp string) error { return os.WriteFile(tmp, raw, 0o600) })
		if err != nil {
			t.Fatal(err)
		}
	} else {
		replica = filepath.Join(pool, mainReplicaName("web", "root", time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)))
		if err := os.WriteFile(replica, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Both builds name the overlay by the same formula (promote.go:867-868
	// here, :887-888 at 3e4ba50b).
	replicaName := filepath.Base(replica)
	p := filepath.Join(pool, mainPromotedName("pv", replicaName))
	snap := diskStem(p) + ".snap1"
	if neg.otherStem {
		p = filepath.Join(pool, mainPromotedName("other", replicaName))
	}
	parent, parentFmt = p, "qcow2"
	if sh.viaP {
		if err := qcow2.CreateWithBackingFormat(p, replica, "raw", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.CreateWithBacking(snap, p, 0, nil); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := qcow2.CreateWithBackingFormat(snap, replica, "raw", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		parent, parentFmt = replica, "raw"
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pv", Cpu: 1, MemoryMib: 256, Project: "a"})
	d = corrosion.DiskRecord{VMName: "pv", DiskName: "root", HostName: s.hostName, Path: snap,
		SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr"}
	if sh.recorded {
		d.BackingDisk = replica
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "pv", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{d}); err != nil {
		t.Fatal(err)
	}
	if neg.claimedBy {
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: "db", HostName: s.hostName, State: "stopped", Project: "b"}, nil,
			[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: s.hostName, Path: p, StorageType: "dir", StorageVolume: "dr"}}); err != nil {
			t.Fatal(err)
		}
	}
	return d, raw, parent, parentFmt
}

var snapShapes = map[string]snapShape{
	"main-era/S-P-R":   {viaP: true},
	"main-era/S-R":     {viaP: false},
	"this-build/S-P-R": {viaP: true, recorded: true},
	"this-build/S-R":   {viaP: false, recorded: true},
}

func TestPromotedVMOnASnapshotOverlay_EveryCopyPathWorks(t *testing.T) {
	for sname, sh := range snapShapes {
		t.Run(sname+"/move", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, raw, _, _ := promotedOnSnapshot(t, s, sh, snapNeg{})
			if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"},
				&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
				t.Fatalf("move: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "pv")
			if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
				t.Error("the moved disk does not hold the guest view")
			}
		})
		t.Run(sname+"/replicate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, raw, _, _ := promotedOnSnapshot(t, s, sh, snapNeg{})
			rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
			if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
				t.Fatalf("replicate: %v", err)
			}
			if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, raw) {
				t.Error("the copy does not hold the guest view")
			}
		})
		t.Run(sname+"/full-clone", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			_, raw, _, _ := promotedOnSnapshot(t, s, sh, snapNeg{})
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "pv", Target: "pv2", Mode: "full"}); err != nil {
				t.Fatalf("full clone: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "pv2")
			if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
				t.Error("the clone does not hold the guest view")
			}
		})
		t.Run(sname+"/build-image", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			_, raw, _, _ := promotedOnSnapshot(t, s, sh, snapNeg{})
			if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "pv", ImageName: "golden"}); err != nil {
				t.Fatalf("BuildImage: %v", err)
			}
			if got := guestView(t, s.images.ImagePath("golden")); !bytes.Equal(got, raw) {
				t.Error("the image does not hold the guest view")
			}
		})
		t.Run(sname+"/cold-migrate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			d, raw, _, _ := promotedOnSnapshot(t, s, sh, snapNeg{})
			if got := coldFlatten(t, s, d); !bytes.Equal(got, raw) {
				t.Error("the flat copy does not hold the guest view")
			}
		})
		t.Run(sname+"/restore-in-place", func(t *testing.T) {
			needQemuImg(t)
			f := newRestoreFixture(t)
			f.s.virt = libvirtfake.New()
			d, raw, parent, parentFmt := promotedOnSnapshot(t, f.s, sh, snapNeg{})
			want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], raw[65536:]...)
			if err := os.Remove(d.Path); err != nil {
				t.Fatal(err)
			}
			overlayWithData(t, d.Path, parent, parentFmt, want)
			const ts = "2026-10-11T12:00:00Z"
			pushVMWithIdentity(t, f, "pv", d.Path, ts, pbsstore.ContentDiskFile, "", nil)
			if err := inPlace(f, "pv", ts); err != nil {
				t.Fatalf("in-place restore: %v", err)
			}
			requireRestoredOnto(t, d.Path, parent, want)
		})
	}
}

// N-C2, red: only the disk's own layers (same directory, same stem, no row of
// their own) take its row. A parent overlay of another stem, or one another
// project's VM claims, does not — its raw replica stays refused.
func TestPromotedVMOnASnapshotOverlay_AnotherVMsLayerDoesNotInherit(t *testing.T) {
	for name, neg := range map[string]snapNeg{
		"another-stem":           {otherStem: true},
		"claimed-by-another-row": {claimedBy: true},
	} {
		for _, recorded := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/main-era", true: "/this-build"}[recorded], func(t *testing.T) {
				s := testServer(t)
				s.dataDir = t.TempDir()
				registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
				promotedOnSnapshot(t, s, snapShape{viaP: true, recorded: recorded}, neg)
				err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"},
					&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "raw backing") {
					t.Errorf("move: got %v, want FailedPrecondition naming the raw backing", err)
				}
			})
		}
	}
}

// ── N-I1 ─────────────────────────────────────────────────────────────────────

// A stopped VM's disk-file backup to a sink host: the manifest lives on the
// sink, never on the VM's host. The VM is deleted and its image refreshed;
// the prune on the VM's host still keeps the base the backup was taken on, and
// a restore of that backup to a new file still reads.
func TestPruneImages_KeepsTheBaseOfABackupOnASinkHost(t *testing.T) {
	sink := newPeerAuthServer(t)
	sinkRepoDir := t.TempDir()
	if _, err := pbsstore.Init(sinkRepoDir); err != nil {
		t.Fatal(err)
	}
	sink.SetBackupRepos(map[string]string{"r1": sinkRepoDir})

	owner := pruneServer(t)
	owner.hostName = "owner-host"
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, owner.db, corrosion.HostRecord{Name: sink.hostName, Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	owner.peerClientOverride = func(_ context.Context, _ string) (pb.LiteVirtClient, func(), error) {
		return &fakeLVClient{srv: sink, peerCtx: mtlsCtx("peer-1")}, func() {}, nil
	}
	a := publishVersion(t, owner, "ubuntu", "A ", "")
	disk, err := owner.images.CreateOverlayDisk("vm1", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, owner.db, corrosion.VMRecord{Name: "vm1", HostName: owner.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: owner.hostName, Path: disk, BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	const ts = "2026-10-07T10:00:00Z"
	if err := owner.BackupSnapshot(&pb.BackupSnapshotRequest{VmName: "vm1", DiskName: "root", RepoPath: "r1", Timestamp: ts, SinkHost: sink.hostName},
		&progressStream[pb.BackupSnapshotProgress]{ctx: mtlsAdminCtx(sink.hostName)}); err != nil {
		t.Fatalf("backup to the sink: %v", err)
	}
	// The VM is deleted; the image refreshed twice.
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, owner.db, "vm1"); err != nil {
		t.Fatal(err)
	}
	b := publishVersion(t, owner, "ubuntu", "B ", "")
	publishVersion(t, owner, "ubuntu", "C ", "")
	dry, err := owner.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Removed) != 1 || dry.Removed[0] != b {
		t.Errorf("a dry run would remove %v, want only %s", dry.Removed, b)
	}
	resp, err := owner.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(a) {
		t.Fatal("the base a sink-host backup was taken on was pruned")
	}
	if len(resp.Removed) != 1 || resp.Removed[0] != b {
		t.Errorf("removed %v, want only %s", resp.Removed, b)
	}
	repo, err := pbsstore.Open(sinkRepoDir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := repo.GetManifest("vm1", ts, "root")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "restored.qcow2")
	if err := pbsstore.RestoreToFile(ctx, repo, m, out, pbsstore.RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := guestView(t, out); len(got) < 2 || string(got[:2]) != "A " {
		t.Error("the backup restored to a new file does not read its base")
	}
}

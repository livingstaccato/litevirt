package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 5 (diskiso-rereview-4.md): a VM left on an overlay named after a
// deleted snapshot (C-2), VMs an earlier build promoted with --no-localize
// (I-2), and per-host pruning of image versions (I-1).

// ── C-2: the overlay of a reverted / deleted snapshot ────────────────────────

// snapshotLeftVM is project a's VM "sv" after create → revert → delete of
// snapshot s1 (and, with two, of s1 and s2 with s1 deleted first): its record
// names the overlay <data_dir>/disks/sv-root.s<n>, on the base
// sv-root.qcow2 (and sv-root.s1), with no snapshot recorded.
func snapshotLeftVM(t *testing.T, s *Server, layers int) (corrosion.DiskRecord, []byte) {
	t.Helper()
	disks := filepath.Join(s.dataDir, "disks")
	base := filepath.Join(disks, "sv-root.qcow2")
	want := filledQcow2(t, base, "SNAPBASE ")
	top := base
	for i := 1; i <= layers; i++ {
		next := filepath.Join(disks, "sv-root.s"+string(rune('0'+i)))
		runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", top, "-F", "qcow2", next)
		top = next
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "sv", Cpu: 1, MemoryMib: 256, Project: "a"})
	rec := corrosion.DiskRecord{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: top, SizeBytes: 1 << 20, StorageType: "local"}
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "sv", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{rec}); err != nil {
		t.Fatal(err)
	}
	return rec, want
}

func TestDeletedSnapshotOverlay_EveryCopyPathWorks(t *testing.T) {
	for _, layers := range []int{1, 2} {
		name := map[int]string{1: "one-snapshot", 2: "two-snapshots"}[layers]
		t.Run(name+"/move", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, want := snapshotLeftVM(t, s, layers)
			if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "sv", DiskName: "root", TargetPool: "fast"},
				&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
				t.Fatalf("move: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "sv")
			if got := guestView(t, disks[0].Path); !bytes.Equal(got, want) {
				t.Error("the moved disk does not hold the guest view")
			}
		})
		t.Run(name+"/replicate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, want := snapshotLeftVM(t, s, layers)
			rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
			if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "sv", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
				t.Fatalf("replicate: %v", err)
			}
			if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, want) {
				t.Error("the copy does not hold the guest view")
			}
		})
		t.Run(name+"/full-clone", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			_, want := snapshotLeftVM(t, s, layers)
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "sv", Target: "sv2", Mode: "full"}); err != nil {
				t.Fatalf("full clone: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "sv2")
			if got := guestView(t, disks[0].Path); !bytes.Equal(got, want) {
				t.Error("the clone does not hold the guest view")
			}
		})
		t.Run(name+"/build-image", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			_, want := snapshotLeftVM(t, s, layers)
			if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "sv", ImageName: "golden"}); err != nil {
				t.Fatalf("BuildImage: %v", err)
			}
			if got := guestView(t, s.images.ImagePath("golden")); !bytes.Equal(got, want) {
				t.Error("the image does not hold the guest view")
			}
		})
		t.Run(name+"/cold-migrate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			d, want := snapshotLeftVM(t, s, layers)
			if got := coldFlatten(t, s, d); !bytes.Equal(got, want) {
				t.Error("the flat copy does not hold the guest view")
			}
		})
		t.Run(name+"/restore-in-place", func(t *testing.T) {
			needQemuImg(t)
			f := newRestoreFixture(t)
			f.s.virt = libvirtfake.New()
			d, base := snapshotLeftVM(t, f.s, layers)
			parent := filepath.Join(f.s.dataDir, "disks", "sv-root.qcow2")
			if layers == 2 {
				parent = filepath.Join(f.s.dataDir, "disks", "sv-root.s1")
			}
			want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], base[65536:]...)
			if err := os.Remove(d.Path); err != nil {
				t.Fatal(err)
			}
			overlayWithData(t, d.Path, parent, "qcow2", want)
			const ts = "2026-10-11T10:00:00Z"
			pushVM(t, f, "sv", d.Path, ts, pbsstore.ContentDiskFile, "")
			if err := inPlace(f, "sv", ts); err != nil {
				t.Fatalf("in-place restore: %v", err)
			}
			requireRestoredOnto(t, d.Path, parent, want)
		})
	}
}

// C-2, red: a base with the VM's stem beside its overlay, but claimed by
// another VM's row — another project's — is refused.
func TestDeletedSnapshotOverlay_ABaseAnotherVMClaimsIsRefused(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
	d, _ := snapshotLeftVM(t, s, 1)
	base := filepath.Join(s.dataDir, "disks", "sv-root.qcow2")
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "sv-x", HostName: s.hostName, State: "stopped", Project: "b"}, nil,
		[]corrosion.DiskRecord{{VMName: "sv-x", DiskName: "root", HostName: s.hostName, Path: base, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "sv", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("move onto a base another project's VM claims: got %v, want FailedPrecondition", err)
	}
	if _, err := s.coldDiskSourceCheck(d, "qcow2"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cold-migration check: got %v, want FailedPrecondition", err)
	}
}

// ── I-2: a VM an earlier build promoted with --no-localize ───────────────────

// mainPromotedVM is what main's promote --no-localize left: in pool "dr"'s
// directory, the raw replica web-root-<ts>.raw (no record) and the overlay
// web-promoted-<ts>.qcow2 on it (declared raw), recorded as project a's VM
// "pv" disk "root" with no backing_disk. Returns the record and the raw
// bytes (a qcow2 header naming victim, never to be followed).
func mainPromotedVM(t *testing.T, s *Server, replicaDir func(pool string) string) (corrosion.DiskRecord, []byte) {
	t.Helper()
	pool := t.TempDir()
	registerPool(t, s, "dr", "dir", "", pool, "")
	victim := filepath.Join(pool, "db-root.qcow2")
	filledQcow2(t, victim, "PROJECT-B ")
	crafted := filepath.Join(t.TempDir(), "crafted.qcow2")
	if err := qcow2.CreateWithBacking(crafted, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(crafted)
	raw = append(raw, make([]byte, (1<<20)-len(raw))...)
	const ts = "20261013-000000"
	rdir := pool
	if replicaDir != nil {
		rdir = replicaDir(pool)
	}
	if err := os.MkdirAll(rdir, 0o755); err != nil {
		t.Fatal(err)
	}
	replica := filepath.Join(rdir, "web-root-"+ts+".raw")
	if err := os.WriteFile(replica, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(pool, "pv-promoted-"+ts+".qcow2")
	if err := qcow2.CreateWithBackingFormat(overlay, replica, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pv", Cpu: 1, MemoryMib: 256, Project: "a"})
	rec := corrosion.DiskRecord{VMName: "pv", DiskName: "root", HostName: s.hostName, Path: overlay,
		SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr"}
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "pv", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{rec}); err != nil {
		t.Fatal(err)
	}
	return rec, raw
}

func TestMainPromotedVM_EveryCopyPathWorks(t *testing.T) {
	layouts := map[string]func(string) string{
		"flat-pool-dir": nil,
		"owner-dir":     func(pool string) string { return replicaOwnerDir(pool, "a", "pv") },
	}
	for lname, layout := range layouts {
		t.Run(lname+"/move", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, raw := mainPromotedVM(t, s, layout)
			if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"},
				&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
				t.Fatalf("move: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "pv")
			if got := guestView(t, disks[0].Path); !bytes.Equal(got, raw) {
				t.Error("the moved disk does not hold the guest view")
			}
		})
		t.Run(lname+"/replicate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			_, raw := mainPromotedVM(t, s, layout)
			rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
			if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"}, rec); err != nil {
				t.Fatalf("replicate: %v", err)
			}
			if got := guestView(t, rec.Sent[len(rec.Sent)-1].TargetPath); !bytes.Equal(got, raw) {
				t.Error("the copy does not hold the guest view")
			}
		})
		t.Run(lname+"/full-clone", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			_, raw := mainPromotedVM(t, s, layout)
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "pv", Target: "pv2", Mode: "full"}); err != nil {
				t.Fatalf("full clone: %v", err)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "pv2")
			got := guestView(t, disks[0].Path)
			if bytes.Contains(got, []byte("PROJECT-B")) || !bytes.Equal(got, raw) {
				t.Error("the clone does not hold the replica's raw bytes")
			}
		})
		t.Run(lname+"/cold-migrate", func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			d, raw := mainPromotedVM(t, s, layout)
			if got := coldFlatten(t, s, d); !bytes.Equal(got, raw) {
				t.Error("the flat copy does not hold the replica's raw bytes")
			}
		})
		t.Run(lname+"/restore-in-place", func(t *testing.T) {
			needQemuImg(t)
			f := newRestoreFixture(t)
			f.s.virt = libvirtfake.New()
			d, raw := mainPromotedVM(t, f.s, layout)
			replica, _ := qcow2.Info(d.Path)
			want := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], raw[65536:]...)
			if err := os.Remove(d.Path); err != nil {
				t.Fatal(err)
			}
			overlayWithData(t, d.Path, replica.BackingFile, "raw", want)
			const ts = "2026-10-11T11:00:00Z"
			pushVMWithIdentity(t, f, "pv", d.Path, ts, pbsstore.ContentDiskFile, "", nil) // main recorded no identity
			if err := inPlace(f, "pv", ts); err != nil {
				t.Fatalf("in-place restore: %v", err)
			}
			requireRestoredOnto(t, d.Path, replica.BackingFile, want)
		})
	}
}

// I-2, red: the raw file sits in ANOTHER project's replica directory — or is
// claimed by another VM's row — and is refused.
func TestMainPromotedVM_AReplicaNotTheVMsIsRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server){
		"other-projects-replica-dir": func(t *testing.T, s *Server) {
			mainPromotedVM(t, s, func(pool string) string { return replicaOwnerDir(pool, "b", "pv") })
		},
		"another-vms-replica-dir": func(t *testing.T, s *Server) {
			mainPromotedVM(t, s, func(pool string) string { return replicaOwnerDir(pool, "a", "db") })
		},
		"claimed-by-a-row": func(t *testing.T, s *Server) {
			d, _ := mainPromotedVM(t, s, nil)
			info, _ := qcow2.Info(d.Path)
			if err := corrosion.InsertVM(context.Background(), s.db,
				corrosion.VMRecord{Name: "db", HostName: s.hostName, State: "stopped", Project: "b"}, nil,
				[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: s.hostName, Path: info.BackingFile, StorageType: "dir", StorageVolume: "dr"}}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			registerPool(t, s, "fast", "dir", "", t.TempDir(), "")
			setup(t, s)
			err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "pv", DiskName: "root", TargetPool: "fast"},
				&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "raw backing") {
				t.Errorf("move: got %v, want FailedPrecondition naming the raw backing", err)
			}
		})
	}
}

// ── I-1: per-host pruning of image versions ──────────────────────────────────

// TestPruneImages_NeverRemovesAVersionADiskIsBuiltOn: three versions of
// "ubuntu" — v1 under a recorded disk, v2 under a disk file whose row is not
// written yet, v3 unused — and the current v4. A prune removes v3 only.
func TestPruneImages_NeverRemovesAVersionADiskIsBuiltOn(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	publish := func(fill string) string {
		t.Helper()
		src := filepath.Join(t.TempDir(), "v.qcow2")
		filledQcow2(t, src, fill)
		b, _ := os.ReadFile(src)
		tmp := filepath.Join(s.images.ImageDir(), "import-"+fill+".tmp")
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			t.Fatal(err)
		}
		pub, err := s.images.Publish("ubuntu", tmp, sha256Hex(b))
		if err != nil {
			t.Fatal(err)
		}
		return pub.Path
	}
	v1 := publish("V1 ")
	recorded, err := s.images.CreateOverlayDisk("rec", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "rec", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "rec", DiskName: "root", HostName: s.hostName, Path: recorded, BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	v2 := publish("V2 ")
	if _, err := s.images.CreateOverlayDisk("inflight", "root", "ubuntu", "1M"); err != nil { // no row yet
		t.Fatal(err)
	}
	v3 := publish("V3 ")
	v4 := publish("V4 ")
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp.Removed, []string{v3}) {
		t.Fatalf("dry run would remove %v, want only the unused %s", resp.Removed, v3)
	}
	if _, err := os.Stat(v3); err != nil {
		t.Fatal("a dry run removed a file")
	}
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{v1, v2, v4} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed: a disk is built on it, or it is current", kept)
		}
	}
	if _, err := os.Stat(v3); err == nil {
		t.Error("the unused version was not removed")
	}
	if got := guestView(t, recorded); !bytes.Contains(got, []byte("V1 ")) {
		t.Error("the recorded disk lost its base")
	}
}

// I-1: a refresh prunes the image's unused versions itself, keeping the one it
// superseded, the current one, and every version a disk is built on — even
// while disks are built on the image by name.
func TestPullImage_RefreshPrunesUnusedVersions(t *testing.T) {
	needQemuImg(t)
	s, old, overlay, _ := imageServer(t)
	versions := map[string]bool{}
	for _, fill := range []string{"A ", "B ", "C "} {
		src := filepath.Join(t.TempDir(), "n.qcow2")
		filledQcow2(t, src, fill)
		b, _ := os.ReadFile(src)
		if err := s.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}}); err != nil {
			t.Fatal(err)
		}
		versions[s.images.ImagePath("ubuntu")] = true
	}
	files := s.images.ImageFiles("ubuntu")
	if !slices.Contains(files, old) {
		t.Fatal("the version an existing disk is built on was pruned")
	}
	if len(files) != 3 { // old (in use), B (superseded by the last refresh), C (current)
		t.Errorf("files after three refreshes = %v, want the used, the superseded and the current", files)
	}
	if got := guestView(t, overlay); bytes.Contains(got, []byte("A ")) {
		t.Error("the existing disk reads another base")
	}
}

// C-2, red: an overlay naming a file of ANOTHER stem beside it — not a base a
// snapshot of this disk could have left — is refused.
func TestDeletedSnapshotOverlay_ABaseOfAnotherStemIsRefused(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	disks := filepath.Join(s.dataDir, "disks")
	loose := filepath.Join(disks, "loose.qcow2")
	filledQcow2(t, loose, "LOOSE ")
	overlay := filepath.Join(disks, "sv-root.s1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", loose, "-F", "qcow2", overlay)
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "sv", HostName: s.hostName, State: "stopped", Project: "a"}, nil,
		[]corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: overlay, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	d := corrosion.DiskRecord{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: overlay}
	if _, err := s.coldDiskSourceCheck(d, "qcow2"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an overlay on a file of another stem: got %v, want FailedPrecondition", err)
	}
}

// m-new-3: another host's row for the same path names THAT host's file; it
// does not make this host's file owned by its project.
func TestDiskChainRule_AnotherHostsRowDoesNotOwnALocalFile(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(disks, "tpla-root.qcow2")
	if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(disks, "x-root.qcow2")
	for _, v := range []struct{ name, host, path string }{{"tpla", "other-host", base}, {"x", s.hostName, layer}} {
		if err := corrosion.InsertVM(context.Background(), s.db,
			corrosion.VMRecord{Name: v.name, HostName: v.host, State: "stopped", Project: "a"}, nil,
			[]corrosion.DiskRecord{{VMName: v.name, DiskName: "root", HostName: v.host, Path: v.path}}); err != nil {
			t.Fatal(err)
		}
	}
	rule := s.diskChainRule(context.Background(), corrosion.DiskRecord{VMName: "x", DiskName: "root", HostName: s.hostName, Path: layer})
	if err := rule(layer, resolvedOr(base), "qcow2"); err == nil {
		t.Error("another host's row made a local file in <data_dir>/disks count as owned")
	}
}

// m-new-4: a layered image — an image built on another image in the store —
// is a base, as on main: a VM on it copies.
func TestCloneVM_FullCloneOfAVMOnALayeredImage(t *testing.T) {
	s, _ := provableCreateServer(t)
	lower := s.images.CanonicalImagePath("lower")
	want := filledQcow2(t, lower, "LOWER ")
	upper := s.images.CanonicalImagePath("upper")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", lower, "-F", "qcow2", upper)
	disk, err := s.images.CreateOverlayDisk("ly", "root", "upper", "1M")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "ly", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "ly", HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "ly", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20, StorageType: "local", BackingImage: "upper"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "ly", Target: "ly2", Mode: "full"}); err != nil {
		t.Fatalf("full clone of a VM on a layered image: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "ly2")
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, want) {
		t.Error("the clone does not hold the layered image's content")
	}
}

// m8: the precheck judges every layer's file type before it opens it: a FIFO
// named as a qcow2 backing is refused at once, not blocked on.
func TestPrecheckChain_AFIFOLayerIsRefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	overlay := filepath.Join(dir, "o.qcow2")
	if err := qcow2.CreateWithBacking(overlay, fifo, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := precheckChain(overlay, func(string, string, string) error { return nil })
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO layer was accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the precheck blocked opening a FIFO layer")
	}
}

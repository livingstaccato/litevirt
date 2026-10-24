package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// keptNoteFixture seeds web's disk files: root noted as a kept disk, data
// noted as a file a kept disk backs on, swap not noted (debris).
func keptNoteFixture(t *testing.T) (*Server, string, string, string) {
	t.Helper()
	s, _ := provableCreateServer(t)
	seed := func(disk string) string {
		p := s.images.DiskPath("web", disk)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("kept "+disk), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	root, data, swap := seed("root"), seed("data"), seed("swap")
	if err := health.NoteKeptDisks(s.dataDir, "web", []string{root}); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptBackingFiles(s.dataDir, "web", []string{data}); err != nil {
		t.Fatal(err)
	}
	return s, root, data, swap
}

func mustExist(t *testing.T, what, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("%s %s went: %v", what, filepath.Base(p), err)
	}
}

// The delete and rebuild debris sweep keeps every file this host's kept-disk
// note names, as a kept disk or as a file one backs on, and still removes
// the debris: a same-name VM that came here by migration, deleted or rebuilt
// here, used to sweep a disk an earlier VM of the name was deleted with and
// kept (re-review 2, F1). A note that cannot be read keeps every candidate.
//
// Mutation: drop the note from sweepVMDiskDebrisIn's keep set: red.
func TestSweepVMDiskDebris_KeepsWhatTheHostsKeptNoteNames(t *testing.T) {
	s, root, data, swap := keptNoteFixture(t)
	s.sweepVMDiskDebris(adminCtx(), "web")
	mustExist(t, "the noted kept disk", root)
	mustExist(t, "the noted file a kept disk backs on", data)
	if _, err := os.Stat(swap); !os.IsNotExist(err) {
		t.Errorf("web's debris %s survived (%v): the sweep did nothing, so this proves nothing", filepath.Base(swap), err)
	}

	t.Run("unreadable note", func(t *testing.T) {
		s, root, data, swap := keptNoteFixture(t)
		note := filepath.Join(s.dataDir, "kept-disks", "web.json")
		if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.sweepVMDiskDebris(adminCtx(), "web")
		for _, p := range []string{root, data, swap} {
			mustExist(t, "a candidate under an unreadable note", p)
		}
	})
}

// Every other path that removes a VM's disk file on this host keeps a file
// the host's kept-disk note names: the recorded-location delete (VM delete,
// cutover cleanup), a VM's own snapshot layers, and the reference check the
// migration, volume-move and detached-disk cleanups ask (F1).
//
// Mutations: drop the note check from deleteDiskAtRecordedLocation,
// removeOwnDiskLayers or pathStillReferenced: red.
func TestKeptNote_OtherRemovalsKeepItsFiles(t *testing.T) {
	t.Run("recorded location", func(t *testing.T) {
		s, root, _, _ := keptNoteFixture(t)
		d := &corrosion.DiskRecord{VMName: "web", DiskName: "root", HostName: s.hostName, Path: root, StorageType: "local"}
		if err := s.deleteDiskAtRecordedLocation(adminCtx(), d); !isDiskHeld(err) {
			t.Fatalf("deleteDiskAtRecordedLocation = %v, want the hold", err)
		}
		mustExist(t, "the noted kept disk", root)
	})
	t.Run("own snapshot layers", func(t *testing.T) {
		s, _, data, _ := keptNoteFixture(t)
		s.removeOwnDiskLayers(adminCtx(), "web", []string{data})
		mustExist(t, "the noted file a kept disk backs on", data)
	})
	t.Run("reference check", func(t *testing.T) {
		s, root, data, swap := keptNoteFixture(t)
		for _, p := range []string{root, data} {
			if ref, why, _ := s.pathStillReferenced(adminCtx(), p, "web", "root"); !ref {
				t.Errorf("%s, in the kept-disk note, reads as unreferenced", filepath.Base(p))
			} else if why == "" {
				t.Errorf("%s: referenced with no reason", filepath.Base(p))
			}
		}
		if ref, why, err := s.pathStillReferenced(adminCtx(), swap, "web", "root"); ref || err != nil {
			t.Errorf("%s, in no note, reads as referenced (%s, %v)", filepath.Base(swap), why, err)
		}
	})
}

// `lv storage rm` of a file this host's kept-disk note names is refused,
// naming the note, in a pool with its own directory, where an admin may
// otherwise delete a disk file no live row references (re-review 3, F1-a).
// Another file there is still deleted.
//
// Mutation: drop the note check from DeleteStoragePoolContent: red.
func TestDeleteStoragePoolContent_RefusesAFileAKeptNoteNames(t *testing.T) {
	s := newPoolTestServer(t)
	dir := filepath.Join(s.dataDir, "pools", "fast")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "fast", Driver: "dir", Target: dir})
	kept, other := filepath.Join(dir, "sv-root.qcow2"), filepath.Join(dir, "old-root.qcow2")
	writePoolFile(t, kept, "kept")
	writePoolFile(t, other, "other")
	if err := health.NoteKeptDisks(s.dataDir, "sv", []string{kept}); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "fast", Filename: "sv-root.qcow2"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), filepath.Join("kept-disks", "sv.json")) {
		t.Fatalf("lv storage rm of a kept disk = %v; want FailedPrecondition naming the note", err)
	}
	mustExist(t, "the noted kept disk", kept)
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "fast", Filename: "old-root.qcow2"}); err != nil {
		t.Fatalf("lv storage rm of a file no note names: %v", err)
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Errorf("%s survived (%v): the delete does nothing here, so this proves nothing", filepath.Base(other), err)
	}
}

// snapRAMFixture is VM vmx with no domain anywhere (DeleteVM's stale-record
// path) and these snapshot records: none (disk-only, this host), ram (a RAM
// image here), stuck (its RAM path a non-empty directory, so its removal
// fails), other (held by another host) and legacy (no host recorded, its RAM
// image not here). It returns the server and the RAM path of each.
func snapRAMFixture(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	s := firmwareSnapshotVM(t, "vmx")
	ctx := adminCtx()
	paths := map[string]string{}
	for _, sn := range []struct{ name, host string }{
		{"none", s.hostName}, {"ram", s.hostName}, {"stuck", s.hostName}, {"other", "host-b"}, {"legacy", ""},
	} {
		rec := corrosion.SnapshotRecord{ID: "snap-" + sn.name, VMName: "vmx", HostName: sn.host, Name: sn.name, State: "ok", Type: "disk"}
		if sn.name != "none" {
			p, err := lv.SafeVMStatePath(s.dataDir, "vmx", sn.name)
			if err != nil {
				t.Fatal(err)
			}
			rec.Type, rec.VMStatePath = "memory", p
			paths[sn.name] = p
		}
		if err := corrosion.InsertSnapshot(ctx, s.db, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(paths["ram"]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["ram"], []byte("ram"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["other"], []byte("not this host's record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(paths["stuck"], "busy"), 0o700); err != nil {
		t.Fatal(err)
	}
	return s, paths
}

func liveSnapshotNames(t *testing.T, s *Server, vm string) []string {
	t.Helper()
	snaps, err := corrosion.ListSnapshots(adminCtx(), s.db, vm)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, sn := range snaps {
		out = append(out, sn.Name)
	}
	slices.Sort(out)
	return out
}

// A plain `lv rm` tombstones only the snapshot records whose files on this
// host are gone (re-review 3, N1-b, N1-c): a disk-only one, and one whose RAM
// image it removed. A record another host holds stays, as does its file; one
// whose RAM image could not be removed stays; and a legacy record with no
// host whose RAM image is not here stays, since its image may be on another
// host.
//
// Mutations: drop the host filter in removeVMSnapshotRAMImages; count a
// failed removal as gone; count a missing legacy image as gone: red.
func TestDeleteVM_TombstonesOnlySnapshotRecordsWhoseFilesAreGone(t *testing.T) {
	s, paths := snapRAMFixture(t)
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vmx", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if got, want := liveSnapshotNames(t, s, "vmx"), []string{"legacy", "other", "stuck"}; !slices.Equal(got, want) {
		t.Errorf("snapshot records after the delete = %v, want %v", got, want)
	}
	if _, err := os.Stat(paths["ram"]); !os.IsNotExist(err) {
		t.Errorf("this host's RAM image survived (%v): the delete removed nothing, so this proves nothing", err)
	}
	mustExist(t, "the file another host's record names", paths["other"])
}

// The stale-record delete keeps the snapshots' RAM images and firmware
// bundles, and so the records naming them, while a peer did not answer
// whether the VM runs there, as it keeps the disks in that case: nothing it
// cannot prove unreferenced is removed.
//
// Red on e5871bcbe for the bundle. Mutations: remove RAM images, or the
// firmware bundles, whatever the peers answered: red.
func TestDeleteVM_StaleRecordKeepsRAMImagesWhileAPeerDidNotAnswer(t *testing.T) {
	s, paths := snapRAMFixture(t)
	bundle := lv.SnapshotFirmwareBundlePath(s.dataDir, "vmx", "ram")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte("nvram and vTPM state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "node-9", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("injected: no answer from " + host)
	}
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vmx", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	mustExist(t, "this host's RAM image", paths["ram"])
	mustExist(t, "the snapshot's firmware bundle", bundle)
	if got, want := liveSnapshotNames(t, s, "vmx"), []string{"legacy", "none", "other", "ram", "stuck"}; !slices.Equal(got, want) {
		t.Errorf("snapshot records after the delete = %v; want every one kept with its files (%v)", got, want)
	}
}

// The same refusal for a file in a pool's replica area, named with the VM
// the listing shows beside it (ReplicaVm), which deleteAreaReplica serves
// (re-review 4, N2). Another replica there is still deleted.
//
// Mutation: drop the note check from deleteAreaReplica: red.
func TestDeleteStoragePoolContent_RefusesAReplicaAKeptNoteNames(t *testing.T) {
	f := newPoolFixture(t)
	kept := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
	other := areaReplica(t, f.dr, "a", "app", "1", "20261007-120000")
	if err := health.NoteKeptDisks(f.s.dataDir, "web", []string{kept}); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(kept), ReplicaVm: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), filepath.Join("kept-disks", "web.json")) {
		t.Fatalf("deleting a replica a kept-disk note names = %v; want FailedPrecondition naming the note", err)
	}
	mustExist(t, "the noted replica", kept)
	if _, err := f.s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(other), ReplicaVm: "app"}); err != nil {
		t.Fatalf("deleting a replica no note names: %v", err)
	}
	if present(other) {
		t.Errorf("%s survived: the delete does nothing here, so this proves nothing", filepath.Base(other))
	}
}

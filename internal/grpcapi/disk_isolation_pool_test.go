package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A global file pool is one directory every project may use. These tests pin
// that a project-A Operator, using only their own VMs and schedules, cannot
// read, overwrite or delete project B's files in it: B's replicas, and the
// live disk of B's stopped VM.
//
// Names are chosen to collide the way the old by-name matching collided:
//   - A's VM "web" has one disk "1", so its replicas used to be "web-1-…",
//     the same prefix as B's VM "web-1" with disk "root".
//   - A's VM "a" has disk "b-root", whose derived file "a-b-root.qcow2" is the
//     file of B's VM "a-b", disk "root".

type poolFixture struct {
	s       *Server
	dr      string // the global pool's directory
	alice   context.Context
	bFiles  map[string][]byte // project B's files in dr, by name, with content
	bDiskAB string            // B's VM a-b root disk (a live disk in dr)
}

const (
	bReplicaQcow = "web-1-root-20261001-000000.qcow2"
	bReplicaRaw  = "web-1-root-20261002-000000.raw"
	bLiveWeb1    = "web-1-root.qcow2"
	bLiveAB      = "a-b-root.qcow2"
)

func newPoolFixture(t *testing.T) *poolFixture {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	dr := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dr", Driver: "dir", Target: dr, Project: "", State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool dr: %v", err)
	}

	s.SetStoragePoolsByName(map[string]StoragePoolRef{"dr": {Driver: "dir", Target: dr}})

	// B's files are real images, so a path that selects one gets as far as
	// using it.
	f := &poolFixture{s: s, dr: dr, bFiles: map[string][]byte{}}
	for _, name := range []string{bReplicaQcow, bReplicaRaw, bLiveWeb1, bLiveAB} {
		path := filepath.Join(dr, name)
		if filepath.Ext(name) == ".raw" {
			if err := os.WriteFile(path, bytes.Repeat([]byte("project-b "), 1<<16), 0o600); err != nil {
				t.Fatal(err)
			}
		} else if err := qcow2.Create(path, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f.bFiles[name] = data
	}
	f.bDiskAB = filepath.Join(dr, bLiveAB)

	insert := func(name, project, disk, path, pool, storage string) {
		spec, _ := json.Marshal(&pb.VMSpec{Name: name, Project: project, Cpu: 1, MemoryMib: 256})
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: name, HostName: s.hostName, State: "stopped", Project: project, Spec: string(spec)},
			nil,
			[]corrosion.DiskRecord{{VMName: name, DiskName: disk, HostName: s.hostName, Path: path,
				SizeBytes: 1 << 20, StorageType: storage, StorageVolume: pool}},
		); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	// Project B.
	insert("web-1", "b", "root", filepath.Join(dr, bLiveWeb1), "dr", "dir")
	insert("a-b", "b", "root", f.bDiskAB, "dr", "dir")
	// Project A: real images outside the pool, so a copy of them works.
	own := t.TempDir()
	for _, n := range []string{"web-1.qcow2", "a-b-root.qcow2"} {
		if err := qcow2.Create(filepath.Join(own, n), 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	insert("web", "a", "1", filepath.Join(own, "web-1.qcow2"), "", "local")
	insert("a", "a", "b-root", filepath.Join(own, "a-b-root.qcow2"), "", "local")

	f.alice = grantUser(t, s, "alice", "/projects/a", "Operator")
	return f
}

// grantPoolWrite gives alice Operator on the global pool too, which is what
// lets any project write pool content there.
func (f *poolFixture) grantPoolWrite(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertRoleBinding(ctx, f.s.db, corrosion.RoleBindingRecord{
		ID: "alice@dr", Path: "/storage_pools/dr", Role: "Operator",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(f.s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.s.SetAuthEngine(engine)
}

// assertBIntact fails for any project-B file that is gone or changed.
func (f *poolFixture) assertBIntact(t *testing.T) {
	t.Helper()
	for name, want := range f.bFiles {
		got, err := os.ReadFile(filepath.Join(f.dr, name))
		if err != nil {
			t.Errorf("project B's %s is gone: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("project B's %s was overwritten", name)
		}
	}
}

// C2 overwrite: a non-admin may not name ReplicateVolume's destination at all.
func TestReplicateVolume_ProjectOperatorCannotNameTarget(t *testing.T) {
	f := newPoolFixture(t)
	err := f.s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "web", DiskName: "1", TargetPool: "dr", TargetPath: bLiveAB,
	}, &streamRecorder[pb.ReplicateVolumeProgress]{ctx: f.alice})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("ReplicateVolume with a target_path as a project operator: got %v, want PermissionDenied", err)
	}
	f.assertBIntact(t)
}

// C2 overwrite: the derived destination of A's (a, b-root) is B's a-b-root.qcow2.
// It must not be overwritten.
func TestReplicateVolume_DerivedNameNeverOverwrites(t *testing.T) {
	f := newPoolFixture(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: f.alice}
	if err := f.s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "a", DiskName: "b-root", TargetPool: "dr",
	}, rec); err != nil {
		t.Fatalf("ReplicateVolume of A's own disk: %v", err)
	}
	f.assertBIntact(t)
	got := rec.Sent[len(rec.Sent)-1].TargetPath
	if filepath.Dir(got) != f.dr || !strings.HasPrefix(filepath.Base(got), "a-b-root-copy-") {
		t.Errorf("copy written to %q, want a new a-b-root-copy-… file in the pool", got)
	}
}

// An admin may name the destination, but never an existing file.
func TestReplicateVolume_AdminTargetNeverOverwrites(t *testing.T) {
	f := newPoolFixture(t)
	err := f.s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "web", DiskName: "1", TargetPool: "dr", TargetPath: bLiveAB,
	}, &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("admin ReplicateVolume onto an existing file: got %v, want AlreadyExists", err)
	}
	f.assertBIntact(t)
}

// C2 overwrite: moving A's (a, b-root) into dr lands on B's a-b-root.qcow2.
// The move must refuse, and must not delete B's file on the way out.
func TestMoveVolume_NameCollisionNeverOverwrites(t *testing.T) {
	f := newPoolFixture(t)
	f.s.virt = nil // no domain to repoint: the offline copy is the whole move
	err := f.s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "a", DiskName: "b-root", TargetPool: "dr",
	}, &streamRecorder[pb.MoveVolumeProgress]{ctx: f.alice})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("move onto another project's file: got %v, want AlreadyExists", err)
	}
	f.assertBIntact(t)
}

// U: an upload never replaces a file in the pool, a live disk of another
// project included.
func TestUpload_NeverReplacesAnotherProjectsDisk(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	st := &fakeUploadStream{ctx: f.alice, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "dr", Filename: bLiveAB},
		{Chunk: []byte("attacker image")},
	}}
	if err := f.s.UploadStoragePoolContent(st); status.Code(err) != codes.AlreadyExists {
		t.Errorf("upload over another project's disk: got %v, want AlreadyExists", err)
	}
	f.assertBIntact(t)
}

// Promote builds the live disk at "<new-name>-promoted-<stamp>.qcow2" in the
// pool, and the new name is the caller's. A file already there — here project
// B's disk — is refused, not replaced, and not removed by the error path.
func TestPromoteReplica_LiveDiskNeverOverwrites(t *testing.T) {
	f := newPoolFixture(t)
	ownReplica := seedOwnReplica(t, f, "web", "1")
	livePath := filepath.Join(f.dr, promotedLiveName(t, "x", ownReplica))
	if err := qcow2.Create(livePath, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(livePath)
	f.bFiles[filepath.Base(livePath)] = data

	for _, noLocalize := range []bool{true, false} {
		err := f.s.PromoteReplica(&pb.PromoteReplicaRequest{
			VmName: "web", TargetPool: "dr", Replica: ownReplica, NewName: "x", NoLocalize: noLocalize,
		}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: f.alice})
		if status.Code(err) != codes.AlreadyExists {
			t.Errorf("no_localize=%v: promote onto an existing file: got %v, want AlreadyExists", noLocalize, err)
		}
	}
	f.assertBIntact(t)
}

// seedOwnReplica gives project a's (vm, disk) one recorded replica in dr and
// returns its name.
func seedOwnReplica(t *testing.T, f *poolFixture, vm, disk string) string {
	t.Helper()
	rec := newReplicaRecord("a", vm, disk, vm+"/dr", "20261003-000000", "qcow2")
	img := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(img, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishRecordedReplica(context.Background(), f.dr, rec, func(tmp string) error {
		return os.WriteFile(tmp, data, 0o600) // the temp exists; qcow2.Create never overwrites
	}); err != nil {
		t.Fatal(err)
	}
	return rec.File
}

// promotedLiveName is the live-disk name doPromoteLocal derives.
func promotedLiveName(t *testing.T, newName, replica string) string {
	t.Helper()
	return newName + "-promoted-" + strings.TrimSuffix(strings.TrimSuffix(replica, ".qcow2"), ".raw") + ".qcow2"
}

// A live move's destination is preallocated as a new qcow2; a file already at
// the derived name is refused, not replaced.
func TestPreallocate_NeverReplacesAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a-b-root.qcow2")
	if err := os.WriteFile(path, []byte("project B's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preallocate(path, 1<<20); status.Code(err) != codes.AlreadyExists {
		t.Errorf("preallocate over a file: got %v, want AlreadyExists", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "project B's disk" {
		t.Errorf("file was replaced (%d bytes), want it untouched", len(got))
	}
}

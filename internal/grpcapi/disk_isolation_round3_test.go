package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 3 of the disk-isolation review.

// promotedOverRawReplica builds what a --no-localize promotion leaves: a qcow2
// overlay at <pool>/<vm>-promoted.qcow2 whose backing is a RAW replica in the
// pool's replica area, declared raw. The replica's bytes are guest content and
// here they are a qcow2 header naming victim — another project's disk full of
// "PROJECT-B". Returns the overlay, the replica path and the raw bytes.
func promotedOverRawReplica(t *testing.T, pool, victim string) (overlay, replica string, raw []byte) {
	t.Helper()
	crafted := filepath.Join(t.TempDir(), "crafted.qcow2")
	if err := qcow2.CreateWithBacking(crafted, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(crafted)
	raw = append(raw, make([]byte, (1<<20)-len(raw))...)
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261013-000000", "raw")
	replica, err := publishRecordedReplica(context.Background(), pool, rec, func(tmp string) error {
		return os.WriteFile(tmp, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	overlay = filepath.Join(pool, "web-promoted.qcow2")
	if err := qcow2.CreateWithBackingFormat(overlay, replica, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	return overlay, replica, raw
}

// victimDisk is another project's qcow2 holding "PROJECT-B" everywhere.
func victimDisk(t *testing.T) string {
	t.Helper()
	needQemuImg(t)
	raw := filepath.Join(t.TempDir(), "b.raw")
	if err := os.WriteFile(raw, bytes.Repeat([]byte("PROJECT-B "), 1<<20/10+1)[:1<<20], 0o600); err != nil {
		t.Fatal(err)
	}
	v := filepath.Join(t.TempDir(), "b-root.qcow2")
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", raw, v)
	return v
}

// C-1, the pure-Go flattener: a raw backing is raw — whatever its bytes look
// like — and its guest-written qcow2 header is never followed.
func TestQcow2Convert_RawBackingIsNeverParsed(t *testing.T) {
	victim := victimDisk(t)
	overlay, _, raw := promotedOverRawReplica(t, t.TempDir(), victim)
	out := filepath.Join(t.TempDir(), "flat.qcow2")
	if err := qcow2.Convert(context.Background(), overlay, out, &qcow2.Options{Uncompressed: true}); err != nil {
		t.Fatalf("flatten of an overlay on a raw backing: %v", err)
	}
	got := guestView(t, out)
	if bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the flatten read the other project's disk the raw backing's bytes named")
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("the flattened disk does not hold the raw backing's bytes")
	}
}

// C-1 through the daemon: a full clone of a --no-localize promoted VM holds
// the replica's raw bytes, never the disk its bytes name.
func TestCloneVM_FullCloneOfAPromotedVMNeverReadsWhatTheReplicaNames(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	victim := victimDisk(t)
	pool := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dr", Driver: "dir", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	overlay, replica, raw := promotedOverRawReplica(t, pool, victim)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web-dr", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web-dr", HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: s.hostName, Path: overlay,
			SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr", BackingDisk: replica}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "web-dr", Target: "copy", Mode: "full"}); err != nil {
		t.Fatalf("full clone of a promoted VM: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "copy")
	got := guestView(t, disks[0].Path)
	if bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the full clone read the other project's disk the replica's bytes named")
	}
	if !bytes.Equal(got, raw) {
		t.Error("the full clone does not hold the replica's raw bytes")
	}
}

// C-1: an image built from a promoted VM is its guest content, not the disk
// the replica's bytes name.
func TestBuildImage_FromAPromotedVMNeverReadsWhatTheReplicaNames(t *testing.T) {
	s, _ := provableCreateServer(t)
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	victim := victimDisk(t)
	pool := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dr", Driver: "dir", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	overlay, replica, _ := promotedOverRawReplica(t, pool, victim)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web-dr", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web-dr", HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: s.hostName, Path: overlay,
			SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr", BackingDisk: replica}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "web-dr", ImageName: "golden"}); err != nil {
		t.Fatalf("build image from a promoted VM: %v", err)
	}
	if got := guestView(t, s.images.ImagePath("golden")); bytes.Contains(got, []byte("PROJECT-B")) {
		t.Fatal("the built image holds the other project's disk the replica's bytes named")
	}
}

// C-1: a backing outside the disk's pool and the image store is not followed.
func TestQcow2ConvertConfined_RefusesABackingOutsideTheRoots(t *testing.T) {
	victim := victimDisk(t)
	pool := t.TempDir()
	overlay := filepath.Join(pool, "o.qcow2")
	if err := qcow2.CreateWithBacking(overlay, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	err := qcow2.ConvertConfined(context.Background(), overlay, filepath.Join(t.TempDir(), "x.qcow2"), nil,
		func(resolved string) error { return confineTo(resolved, pool) })
	if err == nil {
		t.Fatal("a flatten followed a backing outside the allowed roots")
	}
}

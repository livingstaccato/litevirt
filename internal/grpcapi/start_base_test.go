package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// startOnBase records a stopped VM whose root disk is an overlay on the image
// file base, written straight to disk (as an image stored before arrival
// checks existed, or changed in the store since).
func startOnBase(t *testing.T, s *Server, name, base string) *corrosion.VMRecord {
	t.Helper()
	disk := filepath.Join(t.TempDir(), name+"-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: name, HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20, StorageType: "local", BackingImage: filepath.Base(base)}}); err != nil {
		t.Fatal(err)
	}
	return vmRecord(t, s, name)
}

// Every start judges the image-store base a VM disk is an overlay on: a base
// that names a file outside the store (or an external data file) would have
// qemu open that file for the guest, and the start is refused. A layered
// image — built on another image in the store — starts as on main.
func TestStart_AnImageStoreBaseIsJudgedAtEveryStart(t *testing.T) {
	s, _ := provableCreateServer(t)
	victim := filepath.Join(t.TempDir(), "host-secret.qcow2")
	if err := qcow2.Create(victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	evil := s.images.CanonicalImagePath("evil")
	if err := os.MkdirAll(filepath.Dir(evil), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(evil, victim, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), startOnBase(t, s, "ev", evil)); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("start on a base naming a host file: got %v, want FailedPrecondition", err)
	}

	lower := s.images.CanonicalImagePath("lower")
	if err := qcow2.Create(lower, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	upper := s.images.CanonicalImagePath("upper")
	if err := qcow2.CreateWithBacking(upper, lower, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), startOnBase(t, s, "ly", upper)); err != nil {
		t.Errorf("start on a layered image: %v", err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), startOnBase(t, s, "pl", lower)); err != nil {
		t.Errorf("start on a standalone image: %v", err)
	}
}

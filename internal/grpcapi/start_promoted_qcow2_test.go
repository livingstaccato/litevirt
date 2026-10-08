package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// C-A (final-rereview-integrate-3.md): a VM main (3e4ba50b) promoted with
// --no-localize from a full replica — a qcow2 — in the default pool on
// <data_dir>/disks starts on this build, as it did on main.

// mainQcow2ReplicaName is the name main gave a full replica of disk of vm run
// at runAt (replication_runner.go:98 for ts, and :194 local / :222 cross-host
// at 3e4ba50b):
//
//	dstPath := filepath.Join(dstDir, fmt.Sprintf("%s-%s-%s.qcow2", sched.VMName, src.DiskName, ts))
func mainQcow2ReplicaName(vm, disk string, runAt time.Time) string {
	ts := runAt.UTC().Format("20060102-150405")
	return fmt.Sprintf("%s-%s-%s.qcow2", vm, disk, ts)
}

// mainPromotedQcow2VM is what main's promote --no-localize of replicaName as
// "pv" left in the default pool (local, no target: <data_dir>/disks):
// promote.go:887-888 named the overlay <target>-promoted-<replica stem>.qcow2
// in the pool directory, :901-910 built it over the replica with backing
// format qcow2 (the replica's suffix), and :976-979 recorded project a's VM
// "pv" disk "root" with StorageVolume = the pool and no backing_disk. The
// replica is a standalone qcow2 no record names. Returns pv's record and the
// replica's path.
func mainPromotedQcow2VM(t *testing.T, s *Server, replicaName, overlayName, poolProject string) (*corrosion.VMRecord, string) {
	t.Helper()
	registerPool(t, s, "default", "local", "", "", poolProject)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	replica := filepath.Join(disks, replicaName)
	if err := qcow2.Create(replica, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(disks, overlayName)
	if err := qcow2.CreateWithBackingFormat(overlay, replica, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pv", Cpu: 1, MemoryMib: 256, Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "pv", HostName: s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "pv", DiskName: "root", HostName: s.hostName, Path: overlay,
			SizeBytes: 1 << 20, StorageType: "local", StorageVolume: "default", TargetDev: "vda", Bus: "virtio"}}); err != nil {
		t.Fatal(err)
	}
	return vmRecord(t, s, "pv"), replica
}

func promotedQcow2Server(t *testing.T) *Server {
	t.Helper()
	s := testServerWithLocks(t)
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	return s
}

var promotedAt = time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)

func TestStart_AMainPromotedVMOnAQcow2ReplicaInTheDefaultPoolStarts(t *testing.T) {
	s := promotedQcow2Server(t)
	replicaName := mainQcow2ReplicaName("web", "root", promotedAt)
	vm, _ := mainPromotedQcow2VM(t, s, replicaName, mainPromotedName("pv", replicaName), "")
	startAllowed(t, s, vm, "a main-era --no-localize VM on a qcow2 replica in <data_dir>/disks")
	if _, err := s.PrepareHardwareForStart(context.Background(), vm); err != nil {
		t.Fatalf("the start preflight refuses the main-era promoted VM: %v", err)
	}
}

// The exception is the raw case's, with the same bounds: the replica must be
// the one the overlay's name was built from, of the row's own disk, in a pool
// the VM's project may use, unclaimed by any disk row, with no other
// project's record — and its declared format must be its suffix's.
func TestStart_AMainPromotedQcow2ExceptionKeepsItsBounds(t *testing.T) {
	web := mainQcow2ReplicaName("web", "root", promotedAt)
	cases := map[string]struct {
		replica, overlay, poolProject string
		after                         func(t *testing.T, s *Server, replica string)
	}{
		"another-disk": {replica: mainQcow2ReplicaName("web", "data", promotedAt),
			overlay: mainPromotedName("pv", mainQcow2ReplicaName("web", "data", promotedAt))},
		"another-stem": {replica: mainQcow2ReplicaName("db", "root", promotedAt), overlay: mainPromotedName("pv", web)},
		"no-timestamp": {replica: "web-root-2026101x-000000.qcow2", overlay: mainPromotedName("pv", "web-root-2026101x-000000.qcow2")},
		"raw-suffix-declared-qcow2": {replica: strings.TrimSuffix(web, ".qcow2") + ".raw",
			overlay: mainPromotedName("pv", web)},
		"another-projects-pool": {replica: web, overlay: mainPromotedName("pv", web), poolProject: "b"},
		"claimed-by-a-row": {replica: web, overlay: mainPromotedName("pv", web),
			after: func(t *testing.T, s *Server, replica string) {
				if err := corrosion.InsertVM(context.Background(), s.db,
					corrosion.VMRecord{Name: "db", HostName: s.hostName, State: "stopped", Project: "b"}, nil,
					[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: s.hostName, Path: replica, StorageType: "local", StorageVolume: "default"}}); err != nil {
					t.Fatal(err)
				}
			}},
		"another-projects-upload": {replica: web, overlay: mainPromotedName("pv", web),
			after: func(t *testing.T, s *Server, replica string) {
				if err := s.recordPoolUpload(context.Background(), "default", "b", "bob", replica); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := promotedQcow2Server(t)
			vm, replica := mainPromotedQcow2VM(t, s, c.replica, c.overlay, c.poolProject)
			if c.after != nil {
				c.after(t, s, replica)
			}
			startRefused(t, s, vm, name)
		})
	}
}

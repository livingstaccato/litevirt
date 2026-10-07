package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// I-4. Every start judges a local disk's whole backing chain, layer by layer,
// by the rule every copy path judges it by. On main a pool root disk's
// header named its image by a bare relative name ("ubuntu"), which qemu finds
// beside the disk in the pool directory. A main-era VM whose chain is intact
// starts; one whose base is missing, or whose base is a file a user uploaded
// under that name naming another project's disk, does not.

type startChainFixture struct {
	s      *Server
	pa     string // project a's pool
	global string // a pool every project uses
	bDisk  string // project b's VM disk, in the global pool
}

func newStartChainFixture(t *testing.T) *startChainFixture {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	f := &startChainFixture{s: s, pa: t.TempDir(), global: t.TempDir()}
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: s.hostName, Name: "pa", Driver: "dir", Target: f.pa, Project: "a", State: "active"},
		{HostName: s.hostName, Name: "g", Driver: "dir", Target: f.global, State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, p); err != nil {
			t.Fatal(err)
		}
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"pa": {Driver: "dir", Target: f.pa}, "g": {Driver: "dir", Target: f.global}})
	f.bDisk = filepath.Join(f.global, "bvm-root.qcow2")
	if err := qcow2.Create(f.bDisk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f.insertVM(t, "bvm", "b", f.bDisk, "g", "")
	return f
}

func (f *startChainFixture) insertVM(t *testing.T, name, project, disk, pool, image string) *corrosion.VMRecord {
	t.Helper()
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Project: project, Cpu: 1, MemoryMib: 256, Image: image})
	storage := "dir"
	if pool == "" {
		storage = "local"
	}
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: name, HostName: f.s.hostName, State: "stopped", Project: project, Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: f.s.hostName, Path: disk, SizeBytes: 1 << 20,
			StorageType: storage, StorageVolume: pool, BackingImage: image}}); err != nil {
		t.Fatal(err)
	}
	return vmRecord(t, f.s, name)
}

// mainEraVM records project a's VM whose root disk in dir is an overlay
// naming its image by the bare name "ubuntu", as main's pool drivers wrote it.
func (f *startChainFixture) mainEraVM(t *testing.T, name, dir, pool string) *corrosion.VMRecord {
	t.Helper()
	disk := filepath.Join(dir, name+"-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, "ubuntu", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if info, err := qcow2.Info(disk); err != nil || info.BackingFile != "ubuntu" {
		t.Fatalf("the main-era disk names %q (%v), want the bare name ubuntu", info.BackingFile, err)
	}
	return f.insertVM(t, name, "a", disk, pool, "ubuntu")
}

func startRefused(t *testing.T, s *Server, vm *corrosion.VMRecord, what string) {
	t.Helper()
	err := s.verifyImageBasesForStart(context.Background(), vm)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "backing chain") {
		t.Fatalf("%s: got %v, want the start refused for its backing chain", what, err)
	}
}

func startAllowed(t *testing.T, s *Server, vm *corrosion.VMRecord, what string) {
	t.Helper()
	if err := s.verifyImageBasesForStart(context.Background(), vm); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// A main-era pool root disk whose image sits beside it, intact, starts — in
// a pool of its own and in the default pool on <data_dir>/disks alike.
func TestStart_AnIntactMainEraChainStarts(t *testing.T) {
	f := newStartChainFixture(t)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	if err := qcow2.Create(filepath.Join(f.pa, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	startAllowed(t, f.s, vm, "a main-era pool disk on its image")

	disks := filepath.Join(f.s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	vm2 := f.mainEraVM(t, "app", disks, "")
	if err := qcow2.Create(filepath.Join(disks, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	startAllowed(t, f.s, vm2, "a main-era disk in <data_dir>/disks on its image")
}

// Its base missing, the start is refused, saying so.
func TestStart_AMainEraDiskWithItsBaseMissingIsRefused(t *testing.T) {
	f := newStartChainFixture(t)
	startRefused(t, f.s, f.mainEraVM(t, "web", f.pa, "pa"), "a disk whose base is missing")
}

// The base missing, a's operator uploads a file under its name into the
// pool. The upload is a's own content and may be the base; but its header is
// the operator's to write, and one naming b's disk in a pool every project
// uses, or a host file, refuses the start.
func TestStart_AnUploadUnderAMissingBasesNameCannotNameAnotherProjectsDisk(t *testing.T) {
	ctx := context.Background()
	for name, backing := range map[string]func(f *startChainFixture, t *testing.T) (string, string){
		"b's disk in a global pool": func(f *startChainFixture, _ *testing.T) (string, string) { return f.bDisk, "qcow2" },
		"a host file": func(_ *startChainFixture, t *testing.T) (string, string) {
			p := filepath.Join(t.TempDir(), "shadow")
			if err := os.WriteFile(p, []byte("root:x:0:0"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p, "raw"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newStartChainFixture(t)
			vm := f.mainEraVM(t, "web", f.pa, "pa")
			up := filepath.Join(f.pa, "ubuntu")
			target, format := backing(f, t)
			if err := qcow2.CreateWithBackingFormat(up, target, format, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			if err := f.s.recordPoolUpload(ctx, "pa", "a", "alice@local", up); err != nil {
				t.Fatal(err)
			}
			startRefused(t, f.s, vm, "a disk on an upload naming "+name)
		})
	}

	// An upload that names nothing is a's own content, and starts.
	f := newStartChainFixture(t)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	up := filepath.Join(f.pa, "ubuntu")
	if err := qcow2.Create(up, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.s.recordPoolUpload(ctx, "pa", "a", "alice@local", up); err != nil {
		t.Fatal(err)
	}
	startAllowed(t, f.s, vm, "a disk on a standalone upload of its own project")
}

// In <data_dir>/disks, which holds every project's disks, a file beside the
// disk is a main-era base only if no other project's VM disk is that file.
func TestStart_AMainEraBaseIsNeverAnotherProjectsDisk(t *testing.T) {
	f := newStartChainFixture(t)
	disks := filepath.Join(f.s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	vm := f.mainEraVM(t, "app", disks, "")
	other := filepath.Join(disks, "ubuntu")
	if err := qcow2.Create(other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f.insertVM(t, "bvm2", "b", other, "", "")
	startRefused(t, f.s, vm, "a disk whose bare-named base is project b's disk")
}

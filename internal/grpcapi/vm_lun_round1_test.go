package grpcapi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Fix round 1 of fix/iscsi-one-disk-per-lun: the review's I-4, I-5 and M-1.

// overwrite is a one-shot acknowledgement for the create that carries it,
// never a standing permission: the stored spec — what a rebuild or a rolling
// recreate re-creates from — does not keep it.
//
// Mutation: drop the clear before the spec is stored — this goes red.
func TestCreateVM_ISCSI_OverwriteIsNotPersisted(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	d.lun("0", 64<<20)
	if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", true)); err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := vmRecord(t, s, "a")
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	for _, disk := range spec.Disks {
		if disk.Overwrite {
			t.Errorf("stored spec keeps overwrite on disk %q: every later rebuild would re-image the LUN", disk.Name)
		}
	}
	if strings.Contains(rec.Spec, "overwrite") {
		t.Errorf("stored spec mentions overwrite: %s", rec.Spec)
	}
}

// A LUN a linked clone reads from — the base of its overlay — is in use, even
// once the clone's source is gone (deleted with --keep-disks): a new disk on
// it would write under every clone's overlay.
//
// Mutation: match only the disk path in the in-use query — this goes red.
func TestCreateVM_ISCSI_ALinkedCloneBaseHoldsItsLUN(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	dev := mustLUNDevice(t, "10.0.0.1", "0")
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "clone", HostName: s.hostName, State: "stopped", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: s.hostName,
			Path: "/var/lib/litevirt/disks/clone-root.qcow2", BackingDisk: dev,
			SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "clone"`) {
		t.Fatalf("a disk on a linked clone's base LUN: got %v, want FailedPrecondition naming VM \"clone\"", err)
	}
	requireNoVM(t, s, "b")
}

func mustLUNDevice(t *testing.T, portal, lun string) string {
	t.Helper()
	_, dev, ok := storage.FixedDevice(storage.Config{Driver: "iscsi", Source: lunTestTarget,
		Options: map[string]string{"portal": portal, "lun": lun}})
	if !ok {
		t.Fatal("not a fixed device")
	}
	return dev
}

// The blank probe looks past the first and last MiB: at the first-partition
// offsets, where a filesystem whose partition table was wiped still starts,
// and across the device, where headerless data lives.
//
// Mutation: probe only the edges — this goes red.
func TestCreateVM_ISCSI_BlankProbeLooksPastTheEdges(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
		off  int64
	}{
		// An ext superblock magic of a filesystem at 1 MiB with no MBR.
		{"a filesystem at 1 MiB", 64 << 20, 1<<20 + 1080},
		// Headerless data in the middle of a 3 GiB LUN.
		{"data mid-device", 3 << 30, 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunImageServer(t)
			d := newLUNDisks(t)
			dev := d.lun("0", tc.size)
			f, err := os.OpenFile(d.files[dev], os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte{0x53, 0xef}, tc.off); err != nil {
				t.Fatal(err)
			}
			f.Close()
			_, err = s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "overwrite") {
				t.Fatalf("image onto a LUN with data at %d: got %v, want FailedPrecondition naming overwrite", tc.off, err)
			}
			if len(d.writes) != 0 {
				t.Errorf("wrote %v over a LUN holding data", d.writes)
			}
		})
	}
}

// A rebuild of an image-root iscsi VM keeps its LUN exactly as it is: the
// rebuilt VM takes over its own LUN, nothing is written, and no overwrite is
// needed for a LUN that holds the VM's own disk.
//
// Mutation: drop the replaced-VM takeover — the rebuild is refused (the LUN
// is not blank) and this goes red.
func TestRebuildVM_ISCSI_KeepsTheLUNAsItIs(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	// The guest has since written its disk.
	f, err := os.OpenFile(d.files[dev], os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("GUEST-DATA"), 4096); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "a"}); err != nil {
		t.Fatalf("rebuild of an image-root iscsi VM: %v", err)
	}
	if len(d.writes) != 1 {
		t.Errorf("writes = %v: the rebuild wrote over the VM's own LUN", d.writes)
	}
	b := make([]byte, 10)
	g, _ := os.Open(d.files[dev])
	_, _ = g.ReadAt(b, 4096)
	g.Close()
	if string(b) != "GUEST-DATA" {
		t.Errorf("the rebuild changed the LUN: %q", b)
	}
	vmExists(t, s, "a", "after the rebuild")
}

// A rebuild that the create would refuse for its LUN — here one VM of a pair
// an older build put on one LUN — is refused BEFORE the teardown: the VM, its
// domain and its row are left as they were.
//
// Mutation: drop the LUN preflight — the VM is torn down, then its create is
// refused, and this goes red.
func TestRebuildVM_ISCSI_LUNRefusalComesBeforeTheTeardown(t *testing.T) {
	s := lunImageServer(t)
	ctx := adminCtx()
	dev := mustLUNDevice(t, "10.0.0.1", "0")
	spec := &pb.VMSpec{Name: "a", Cpu: 1, MemoryMib: 256, Image: "cirros", Placement: &pb.PlacementSpec{Host: s.hostName},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G", Storage: "lun0"}}}
	raw, _ := json.Marshal(spec)
	for _, vm := range []string{"a", "other"} {
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: vm, HostName: s.hostName, State: "stopped", Spec: string(raw)},
			nil, []corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: s.hostName, Path: dev,
				SizeBytes: 1 << 30, StorageType: "iscsi", StorageVolume: "lun0", TargetDev: "vda"}}); err != nil {
			t.Fatalf("InsertVM %s: %v", vm, err)
		}
	}
	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "other"`) ||
		!strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rebuild of one VM of a shared pair: got %v, want FailedPrecondition naming VM \"other\", nothing changed", err)
	}
	vmExists(t, s, "a", "after the refused rebuild")
}

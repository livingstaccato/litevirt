package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// lunDisks stands in for the LUNs' block devices: each device path the iscsi
// pools hand out is a file of the given size, and "qemu-img convert" writes a
// marker at its start.
type lunDisks struct {
	t      *testing.T
	files  map[string]string // device → file
	writes []string          // "image → device", in order
}

const lunImageMarker = "IMAGE-ON-THE-LUN"

func newLUNDisks(t *testing.T) *lunDisks {
	t.Helper()
	d := &lunDisks{t: t, files: map[string]string{}}
	prevOpen, prevWrite := openLUNDevice, writeImageToDevice
	t.Cleanup(func() { openLUNDevice, writeImageToDevice = prevOpen, prevWrite })
	openLUNDevice = func(path string) (*os.File, error) {
		f, ok := d.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return os.Open(f)
	}
	writeImageToDevice = func(_ context.Context, image, device string) error {
		d.writes = append(d.writes, image+" → "+device)
		f, err := os.OpenFile(d.files[device], os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteAt([]byte(lunImageMarker), 0)
		return err
	}
	return d
}

// lun makes LUN n of the test target (portal 10.0.0.1) a size-byte device.
func (d *lunDisks) lun(n string, size int64) string {
	d.t.Helper()
	_, dev, _ := storage.FixedDevice(storage.Config{Driver: "iscsi", Source: lunTestTarget,
		Options: map[string]string{"portal": "10.0.0.1", "lun": n}})
	f := filepath.Join(d.t.TempDir(), "lun"+n)
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Truncate(f, size); err != nil {
		d.t.Fatal(err)
	}
	d.files[dev] = f
	return dev
}

func (d *lunDisks) head(dev string) string {
	d.t.Helper()
	b := make([]byte, len(lunImageMarker))
	f, err := os.Open(d.files[dev])
	if err != nil {
		d.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.ReadAt(b, 0); err != nil {
		d.t.Fatal(err)
	}
	return string(b)
}

// lunImageServer is lunTestServer with a 32 MiB image "cirros" in the store.
func lunImageServer(t *testing.T) *Server {
	t.Helper()
	s := lunTestServer(t)
	if err := qcow2.Create(s.images.ImagePath("cirros"), 32<<20, nil); err != nil {
		t.Fatalf("image: %v", err)
	}
	return s
}

func lunImageVM(name, pool string, overwrite bool) *pb.CreateVMRequest {
	return &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Image: "cirros", Placement: &pb.PlacementSpec{Host: "test-host"},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G", Storage: pool, Overwrite: overwrite}},
	}}
}

// A root disk from an image on an iscsi pool IS the image: it is written onto
// the (blank, large enough) LUN before the VM is defined — never a blank LUN
// booting to the firmware shell.
//
// Mutation: skip the write in createVM — the LUN stays blank and this goes red.
func TestCreateVM_ISCSI_RootFromImageWritesTheImage(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if want := s.images.ImagePath("cirros") + " → " + dev; len(d.writes) != 1 || d.writes[0] != want {
		t.Fatalf("writes = %v, want [%s]", d.writes, want)
	}
	if got := d.head(dev); got != lunImageMarker {
		t.Errorf("LUN starts %q, want the image", got)
	}
}

// A LUN smaller than the image is refused with both sizes, before anything is
// written or the VM is recorded.
//
// Mutation: drop the size check — the image is written onto a LUN it does
// not fit and this goes red.
func TestCreateVM_ISCSI_RootFromImageRefusesASmallLUN(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	d.lun("0", 16<<20)
	_, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "16777216") ||
		!strings.Contains(err.Error(), "33554432") {
		t.Fatalf("image larger than the LUN: got %v, want FailedPrecondition with both sizes", err)
	}
	if len(d.writes) != 0 {
		t.Errorf("wrote %v onto a LUN too small for the image", d.writes)
	}
	requireNoVM(t, s, "a")
}

// A LUN that is not blank — a partition table, a filesystem, an earlier
// disk — is not written unless the disk says overwrite.
//
// Mutation: drop the blank check — the MBR'd LUN is overwritten without
// overwrite and this goes red.
func TestCreateVM_ISCSI_RootFromImageNeedsOverwriteForANonBlankLUN(t *testing.T) {
	for _, at := range []struct {
		name string
		off  func(size int64) int64
	}{
		{"an MBR", func(int64) int64 { return 510 }},
		{"a GPT backup header", func(size int64) int64 { return size - 512 }},
	} {
		t.Run(at.name, func(t *testing.T) {
			s := lunImageServer(t)
			d := newLUNDisks(t)
			const size = 64 << 20
			dev := d.lun("0", size)
			f, err := os.OpenFile(d.files[dev], os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte{0x55, 0xaa}, at.off(size)); err != nil {
				t.Fatal(err)
			}
			f.Close()

			_, err = s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "overwrite") {
				t.Fatalf("image onto a LUN holding data: got %v, want FailedPrecondition naming overwrite", err)
			}
			if len(d.writes) != 0 {
				t.Fatalf("wrote %v over a LUN holding data", d.writes)
			}
			requireNoVM(t, s, "a")

			if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", true)); err != nil {
				t.Fatalf("with overwrite: %v", err)
			}
			if got := d.head(dev); got != lunImageMarker {
				t.Errorf("with overwrite the LUN starts %q, want the image", got)
			}
		})
	}
}

// A LUN another VM's disk is is never written, overwrite or not: the in-use
// refusal comes first.
func TestCreateVM_ISCSI_RootFromImageNeverWritesALUNInUse(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	d.lun("0", 64<<20)
	if _, err := s.CreateVM(adminCtx(), lunVM("holder", "lun0")); err != nil {
		t.Fatalf("holder: %v", err)
	}
	_, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0b", true))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "holder"`) {
		t.Fatalf("image onto a LUN in use: got %v, want the in-use refusal", err)
	}
	if len(d.writes) != 0 {
		t.Errorf("wrote %v onto a LUN in use", d.writes)
	}
}

// A data disk on an iscsi pool is the LUN as it is: no image, no write.
func TestCreateVM_ISCSI_DataDiskIsNotWritten(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	d.lun("1", 64<<20)
	req := lunImageVM("a", "", false)
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1G"}, {Name: "data", Size: "1G", Storage: "lun1"}}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(d.writes) != 0 {
		t.Errorf("a data disk's LUN was written: %v", d.writes)
	}
}

package grpcapi

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// seedCreateRequest is a create of a VM from an image, which makes it a
// cloud-init seed; userData "" takes the auto-generated seed's branch.
func seedCreateRequest(t *testing.T, s *Server, name, userData string) *pb.CreateVMRequest {
	t.Helper()
	img := filepath.Join(s.dataDir, "images", "ubuntu.qcow2")
	if _, err := os.Stat(img); err != nil {
		if err := qcow2.Create(img, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	req := disklessCreateRequest(name)
	req.Spec.Network = nil
	req.Spec.Image = "ubuntu"
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
	if userData != "" {
		req.Spec.CloudInit = &pb.CloudInitSpec{Userdata: userData}
	}
	return req
}

// Lab 2 run b, finding 4: an `lv run` whose domain would not start (qemu
// refused its disk) left /var/lib/litevirt/cloudinit/<vm>.iso behind — the
// seed holds the user-data (passwords, keys). A create that fails after it
// made the seed removes that seed, as it removes the disks it made. Another
// VM's seed is never touched, and a create that succeeds keeps its own.
//
// Mutation: drop the seed removal from the create's cleanup — both failing
// subtests go red. Remove the seed on success too — the success check goes red.
func TestCreateVM_AFailedStartRemovesTheSeedItMade(t *testing.T) {
	for _, tc := range []struct{ name, userData string }{
		{"user-data", "#cloud-config\npassword: hunter2\n"},
		{"auto", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageGenisoimage(t)
			s, fake, _ := isoServer(t)
			other := lv.CloudInitISOPath(s.dataDir, "other")
			if err := os.MkdirAll(filepath.Dir(other), 0o711); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(other, []byte("another VM's seed"), 0o600); err != nil {
				t.Fatal(err)
			}

			var seedAtStart bool
			seed := lv.CloudInitISOPath(s.dataDir, "w")
			fake.FailStartDomain = func(string) error {
				_, err := os.Stat(seed)
				seedAtStart = err == nil
				return errors.New("qemu: Could not open disk: Permission denied")
			}
			if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", tc.userData)); err == nil {
				t.Fatal("the create was meant to fail at its domain start")
			}
			if !seedAtStart {
				t.Fatal("setup: the create made no seed before its start, so this proves nothing")
			}
			if _, err := os.Lstat(seed); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the failed create left its cloud-init seed %s (err=%v)", seed, err)
			}
			if _, err := os.Stat(other); err != nil {
				t.Errorf("another VM's seed was removed: %v", err)
			}

			fake.FailStartDomain = nil
			if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w2", tc.userData)); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			if _, err := os.Stat(lv.CloudInitISOPath(s.dataDir, "w2")); err != nil {
				t.Errorf("a create that succeeded lost its seed: %v", err)
			}
		})
	}
}

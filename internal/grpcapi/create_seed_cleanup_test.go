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

// The seed a failed create removes is the file it placed, not whatever is at
// the name by then: a concurrent create of the same name may have placed its
// own seed there (review M6), and that one is not this create's to remove.
//
// Mutation: remove by path alone — the other create's seed goes, red.
func TestCreateVM_AFailedCreateLeavesASeedItDidNotPlace(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	seed := lv.CloudInitISOPath(s.dataDir, "w")
	fake.FailStartDomain = func(string) error {
		// Another create of the name replaces the seed meanwhile.
		if err := os.Remove(seed); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(seed, []byte("another create's seed"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("start failed")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\n")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if b, err := os.ReadFile(seed); err != nil || string(b) != "another create's seed" {
		t.Errorf("the failed create removed a seed it did not place: %q %v", b, err)
	}
}

// takeFreedInode makes files in p's directory until one is given the inode
// of old, a file just removed, and renames that one to p: a new file at p
// that reads, by device and inode, as the removed one. It holds each file the
// filesystem numbered otherwise, so the next takes a different free inode.
// It reports false when no file took the inode in tries attempts: the
// filesystem does not reuse it, or something still holds it open.
func takeFreedInode(t *testing.T, p string, old os.FileInfo, content string, tries int) bool {
	t.Helper()
	var held []string
	defer func() {
		for _, h := range held {
			os.Remove(h)
		}
	}()
	for i := 0; i < tries; i++ {
		f, err := os.CreateTemp(filepath.Dir(p), ".reuse-*")
		if err != nil {
			t.Fatal(err)
		}
		_, werr := f.WriteString(content)
		fi, serr := f.Stat()
		if cerr := f.Close(); werr != nil || serr != nil || cerr != nil {
			t.Fatal(werr, serr, cerr)
		}
		if os.SameFile(fi, old) {
			if err := os.Rename(f.Name(), p); err != nil {
				t.Fatal(err)
			}
			return true
		}
		held = append(held, f.Name())
	}
	return false
}

// The same as TestCreateVM_AFailedCreateLeavesASeedItDidNotPlace, with the
// inode reuse that test meets by chance forced: the other create's seed is
// given the very inode of the seed this create placed, so it reads the same by
// device and inode. A device and inode read when the seed was placed tells
// the two apart only while that inode cannot be reused, so the create holds
// its seed open until it returns; the inode stays its file's, and the other
// seed can never take it.
//
// Mutation: close the seed right after it is pinned — the other seed takes
// the inode, and the failed create removes it, red.
func TestCreateVM_AFailedCreateLeavesASeedOnTheReusedInode(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	seed := lv.CloudInitISOPath(s.dataDir, "w")
	if err := os.MkdirAll(filepath.Dir(seed), 0o711); err != nil {
		t.Fatal(err)
	}

	// Control: a file nothing holds open has its inode taken here.
	ctl := filepath.Join(filepath.Dir(seed), "control")
	if err := os.WriteFile(ctl, []byte("control"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctlFi, err := os.Stat(ctl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if !takeFreedInode(t, ctl, ctlFi, "control", 1024) {
		t.Skip("this filesystem does not reuse a freed inode, so it cannot fool an inode comparison")
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}

	var reused, replaced bool
	fake.FailStartDomain = func(string) error {
		old, err := os.Stat(seed)
		if err != nil {
			t.Fatal(err)
		}
		replaced = true
		if err := os.Remove(seed); err != nil {
			t.Fatal(err)
		}
		reused = takeFreedInode(t, seed, old, "another create's seed", 1024)
		if !reused {
			if err := os.WriteFile(seed, []byte("another create's seed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return errors.New("start failed")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\n")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if !replaced {
		t.Fatal("setup: the create never reached its start, so no seed was replaced")
	}
	t.Logf("the other seed took the placed seed's inode: %v", reused)
	if b, err := os.ReadFile(seed); err != nil || string(b) != "another create's seed" {
		t.Errorf("the failed create removed a seed it did not place (it had the placed seed's inode: %v): %q %v", reused, b, err)
	}
}

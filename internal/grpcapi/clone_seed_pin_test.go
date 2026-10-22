package grpcapi

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// seedCloudInitCloneSource records a template whose spec carries cloud-init,
// so a clone of it writes its own seed.
func seedCloudInitCloneSource(t *testing.T, s *Server, name string) {
	t.Helper()
	srcDisk := s.images.DiskPath(name, "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 2, MemoryMib: 2048,
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\n{}\n"},
	})
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: name, HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func cloudInitCloneServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	stageGenisoimage(t)
	s := cloneTargetServer(t)
	seedCloudInitCloneSource(t, s, "citpl")
	return s, s.virt.(*libvirtfake.Fake)
}

// A clone rolled back after its define removes the seed it wrote only while
// the file at the seed's path is still that one. Here another's seed replaces
// it, given the clone's seed's very inode where the filesystem allows it, so
// it reads the same by device and inode. Before, the rollback removed the
// path whatever was there.
//
// Mutation: release the seed's pin right after pinning — the other seed takes
// the inode, and the rolled-back clone removes it, red. (With no identity
// check at all, as before, it is red whatever the inode.)
func TestCloneVM_ARolledBackCloneLeavesASeedItDidNotWrite(t *testing.T) {
	s, fake := cloudInitCloneServer(t)
	const target = "cseed"
	iso := lv.CloudInitISOPath(s.dataDir, target)
	requireInodeReuse(t, filepath.Join(filepath.Dir(iso), "reuse-control"))

	var reused, replaced bool
	fake.FailStartDomain = func(string) error {
		replaced = true
		reused = replaceOnItsInode(t, iso, "another's seed")
		return errors.New("start failed")
	}
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "citpl", Target: target, Start: true}); err == nil {
		t.Fatal("the clone was meant to fail")
	}
	if !replaced {
		t.Fatal("setup: the clone never reached its start, so no seed was replaced")
	}
	t.Logf("the other seed took the clone's seed's inode: %v", reused)
	if b, err := os.ReadFile(iso); err != nil || string(b) != "another's seed" {
		t.Errorf("the rolled-back clone removed a seed it did not write (it had the seed's inode: %v): %q %v", reused, b, err)
	}
}

// The plain case: a clone that fails after writing its seed removes it,
// whether it fails at the start (rolled back) or before its define.
func TestCloneVM_AFailedCloneRemovesItsOwnSeed(t *testing.T) {
	for _, at := range []string{"start", "define"} {
		t.Run(at, func(t *testing.T) {
			s, fake := cloudInitCloneServer(t)
			target := "cown-" + at
			iso := lv.CloudInitISOPath(s.dataDir, target)
			fail := func(string) error {
				if _, err := os.Stat(iso); err != nil {
					t.Errorf("setup: the seed is not there at the %s: %v", at, err)
				}
				return errors.New(at + " failed")
			}
			if at == "start" {
				fake.FailStartDomain = fail
			} else {
				fake.FailDefineDomain = fail
			}
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "citpl", Target: target, Start: true}); err == nil {
				t.Fatal("the clone was meant to fail")
			}
			if _, err := os.Lstat(iso); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a failed clone left the seed it wrote: %v", err)
			}
		})
	}
}

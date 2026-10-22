package grpcapi

import (
	"errors"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// pinFails makes pinning fail for the paths want names, as an open refused by
// the fd limit or the file's mode would.
func pinFails(s *Server, want ...string) {
	s.pinFault = func(p string) error {
		for _, w := range want {
			if p == w {
				return errors.New("too many open files")
			}
		}
		return nil
	}
}

// A disk or seed a failed create could not hold open is left (it cannot be
// told from another file at the path), and the create's error names it and
// why: the operator sees it there, not only in the daemon log, and knows what
// a retry of the name will meet.
//
// Mutation: drop withLeftovers from the create's failure — the error names
// neither, red.
func TestCreateVM_AFailedCreateNamesWhatItCouldNotHoldAndLeft(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "dleft"
	disk := s.images.DiskPath(name, "root")
	seed := lv.CloudInitISOPath(s.dataDir, name)
	pinFails(s, disk, seed)
	fake.FailStartDomain = func(string) error { return errors.New("start failed") }

	_, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, ""))
	if err == nil {
		t.Fatal("the create was meant to fail")
	}
	msg := err.Error()
	for _, p := range []string{disk, seed} {
		if _, serr := os.Stat(p); serr != nil {
			t.Errorf("%s was removed though it could not be held open: %v", p, serr)
		}
		if !strings.Contains(msg, p) {
			t.Errorf("the create's error does not name what it left, %s: %v", p, err)
		}
	}
	if !strings.Contains(msg, "start failed") || !strings.Contains(msg, "could not be held open") {
		t.Errorf("the create's error = %v, want its cause and why each file was left", err)
	}
}

// The same for a clone: a copy and a seed it could not hold open are left and
// named in its error.
//
// Mutation: drop withLeftovers from the clone's return — red.
func TestCloneVM_AFailedCloneNamesWhatItCouldNotHoldAndLeft(t *testing.T) {
	s, fake := cloudInitCloneServer(t)
	const target = "cleft"
	disk := s.images.DiskPath(target, "root")
	seed := lv.CloudInitISOPath(s.dataDir, target)
	pinFails(s, disk, seed)
	fake.FailStartDomain = func(string) error { return errors.New("start failed") }

	_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "citpl", Target: target, Start: true})
	if err == nil {
		t.Fatal("the clone was meant to fail")
	}
	for _, p := range []string{disk, seed} {
		if _, serr := os.Stat(p); serr != nil {
			t.Errorf("%s was removed though it could not be held open: %v", p, serr)
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("the clone's error does not name what it left, %s: %v", p, err)
		}
	}
}

// A failed create or clone that leaves nothing says nothing more.
func TestCloneVM_AFailedCloneThatLeavesNothingSaysSo(t *testing.T) {
	s := cloneTargetServer(t)
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error { return errors.New("define failed") }
	_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "cnone"})
	if err == nil || strings.Contains(err.Error(), "left what it made") {
		t.Fatalf("clone error = %v, want the define's failure and no leftovers", err)
	}
}

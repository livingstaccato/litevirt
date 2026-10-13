package grpcapi

import (
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// Lab 2 O-1: `lv start` of a stopped VM on an NFS pool whose server had
// stopped answering did not return, and held the VM lock, so a stop queued
// behind it. A stat of the disk and of its overlay was answered (the client
// caches attributes); the start's look for a set-aside overlay lists the
// disk's directory, which only the server answers, and was not bounded.
//
// Mutation "SetAsideEvidence unbounded" (repointDanglingPITDefinition calls
// pitoverlay.SetAsideEvidence) — the start hangs: red.
func TestStart_AVMWhoseOrphanLookDoesNotAnswerIsRefused(t *testing.T) {
	f, mnt, _ := deadPoolVM(t)
	release := make(chan struct{})
	t.Cleanup(pitoverlay.SetGlobForTest(func(pattern string) ([]string, error) {
		if pathWithin(mnt, pattern) {
			<-release
		}
		return filepath.Glob(pattern)
	}))
	t.Cleanup(func() { close(release) })
	t0 := time.Now()
	err := within(t, 10*time.Second, "a start of a VM on the dead pool", func() error {
		_, err := f.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "nvm"})
		return err
	})
	wantNoAnswer(t, "start", err)
	if took := time.Since(t0); took > 3*time.Second {
		t.Fatalf("the refusal took %v", took)
	}
	within(t, 3*time.Second, "a stop of the VM after its refused start", func() error {
		_, err := f.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "nvm", Force: true})
		return err
	})
}

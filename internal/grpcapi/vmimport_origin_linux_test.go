package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// setOriginForTest writes an import origin on p as the import does, or skips
// the test where the filesystem holds no user xattrs.
func setOriginForTest(t *testing.T, p, origin string) {
	t.Helper()
	if err := unix.Lsetxattr(p, "user.litevirt.import-origin", []byte(origin), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("no user xattrs on %s: %v", filepath.Dir(p), err)
		}
		t.Fatal(err)
	}
}

// A disk this host's import wrote, under an import that is no longer running
// here (the daemon restarted mid-import), is a leftover the moment the
// re-import comes: its own siblings, left by the same crash, do not hold it.
func TestImportVM_ALeftoverOfADeadImportIsMovedAsideAtOnce(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	if err := os.WriteFile(dst, []byte("crashed"), 0o600); err != nil {
		t.Fatal(err)
	}
	sib := filepath.Join(filepath.Dir(dst), "web-data.qcow2")
	if err := os.WriteFile(sib, []byte("crashed too"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dst, sib} {
		setOriginForTest(t, p, "test-host/a-daemon-gone/imp-1")
	}
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "web", false)}}); err != nil {
		t.Fatalf("a re-import right after a crash: %v", err)
	}
	aside, _ := filepath.Glob(dst + ".orphan-*")
	if len(aside) != 1 {
		t.Fatalf("leftover kept as %v, want one file beside the disk", aside)
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != "crashed" {
		t.Fatalf("the leftover kept aside holds %q", b)
	}
}

// One whose origin is another host's import, or a running import here, is
// judged as before: fresh, so refused.
func TestImportVM_AFreshFileOfALiveOriginIsNotAnOrphan(t *testing.T) {
	for _, origin := range []string{"other-host/its-daemon/imp-1", "test-host/" + importDaemonInstance + "/still-running"} {
		t.Run(origin, func(t *testing.T) {
			s, dst := orphanFixture(t, "web")
			if err := os.WriteFile(dst, []byte("live"), 0o600); err != nil {
				t.Fatal(err)
			}
			setOriginForTest(t, dst, origin)
			release, err := s.claimImportNameAs("web-other", "still-running")
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			refusedAndUntouched(t, s, "web", dst, "live")
		})
	}
	_ = context.Background
	_ = time.Now
}

// An import's own disks, placed a moment ago, are not a flow that holds its
// next disk's leftover back.
func TestImportVM_AnImportsOwnFreshDisksDoNotHoldItsNextDisk(t *testing.T) {
	s, _ := orphanFixture(t, "web")
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(poolDir, "web-disk1.qcow2")
	plantOld(t, leftover, "leftover")
	frame := smallImportFrame(t, "web", false)
	second := t.TempDir() + "/disk1.raw"
	if err := writeFileHelper(second, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	frame.Chunk = append(frame.Chunk, []byte("scsi1: local-lvm:web-disk-1,size=1M\n")...)
	frame.DiskMap["scsi1"] = second
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{frame}}); err != nil {
		t.Fatalf("a two-disk import over a leftover at its second disk's name: %v", err)
	}
	if aside, _ := filepath.Glob(leftover + ".orphan-*"); len(aside) != 1 {
		t.Fatalf("leftover kept as %v", aside)
	}
}

package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// identities stats each of paths, which must be there.
func identities(t *testing.T, paths ...string) []os.FileInfo {
	t.Helper()
	var fis []os.FileInfo
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("setup: %v", err)
			continue
		}
		fis = append(fis, fi)
	}
	return fis
}

// stillHeld returns the names of those files (identities) this process still
// holds open once their name is gone: on NFS each is a .nfsXXXX file, taking
// its full size, until the descriptor closes. By identity, not by name: a
// descriptor's name is the one it was opened by.
func stillHeld(t *testing.T, files []os.FileInfo) []string {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, e := range ents {
		fi, err := os.Stat(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if os.SameFile(fi, f) {
				held = append(held, f.Name())
			}
		}
	}
	return held
}

func requireProcFD(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/self/fd")
	}
}

// A failed create releases each file's pin as soon as it has removed the
// file, not when the create returns: the pin protects nothing once the file
// is gone, and on NFS the removed file lingers (.nfsXXXX) while it is held.
//
// Mutation: drop the release after each removal — the disk and seed are
// still held once the cleanup is done, red.
func TestCreateVM_AFailedCreateReleasesEachPinOnceItsFileIsRemoved(t *testing.T) {
	requireProcFD(t)
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "drel"
	disk := s.images.DiskPath(name, "root")
	seed := lv.CloudInitISOPath(s.dataDir, name)
	var made []os.FileInfo
	fake.FailStartDomain = func(string) error {
		made = identities(t, disk, seed)
		return errors.New("start failed")
	}
	ran := false
	s.cleanedUpHook = func() {
		ran = true
		if held := stillHeld(t, made); len(held) > 0 {
			t.Errorf("the cleanup removed %v and still holds them open", held)
		}
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if !ran {
		t.Fatal("setup: the create's cleanup never ran")
	}
	for _, p := range []string{disk, seed} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("the failed create left %s: %v", p, err)
		}
	}
}

// The same for a clone's copy and seed.
//
// Mutation: drop the release after each removal in the clone — red.
func TestCloneVM_AFailedCloneReleasesEachPinOnceItsFileIsRemoved(t *testing.T) {
	requireProcFD(t)
	s, fake := cloudInitCloneServer(t)
	const target = "crel"
	disk := s.images.DiskPath(target, "root")
	seed := lv.CloudInitISOPath(s.dataDir, target)
	var made []os.FileInfo
	fake.FailStartDomain = func(string) error {
		made = identities(t, disk, seed)
		return errors.New("start failed")
	}
	ran := false
	s.cleanedUpHook = func() {
		ran = true
		if held := stillHeld(t, made); len(held) > 0 {
			t.Errorf("the cleanup removed %v and still holds them open", held)
		}
	}
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "citpl", Target: target, Start: true}); err == nil {
		t.Fatal("the clone was meant to fail")
	}
	if !ran {
		t.Fatal("setup: the clone's cleanup never ran")
	}
}

// The same for a cold-copy receive's take-back: the copy it took back is not
// held through the directory sync that follows, which can stall.
//
// Mutation: drop the release after the take-back's removal — red.
func TestReceiveMigrationDisk_ATakeBackReleasesItsPinOnceTheCopyIsRemoved(t *testing.T) {
	requireProcFD(t)
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("the VM's disk"))
	up := &captureDiskUp{size: int64(len("the VM's disk"))}
	if err := f.src.streamColdDisk(adminCtx(), &captureDiskClient{up: up}, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}
	sctx, giveUp := context.WithCancel(f.peer)
	defer giveUp()
	var placed []os.FileInfo
	f.dst.SetColdDiskPlacedHookForTest(func() {
		placed = identities(t, f.path)
		giveUp()
	})
	ran := false
	f.dst.cleanedUpHook = func() {
		ran = true
		if held := stillHeld(t, placed); len(held) > 0 {
			t.Errorf("the take-back removed %v and still holds it open", held)
		}
	}
	err := f.dst.ReceiveMigrationDisk(&diskRecvStream{ctx: sctx, frames: up.frames})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("receive whose source gave up = %v, want Canceled", err)
	}
	if !ran {
		t.Fatal("setup: the take-back never removed the copy")
	}
}

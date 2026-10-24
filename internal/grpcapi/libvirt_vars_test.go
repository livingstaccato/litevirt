package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// staleVars plants an earlier VM's libvirt-managed vars file for name under a
// libvirt nvram dir of s's own, and has fake note whether it is still there
// when the domain is defined (the moment libvirt's first start would read it).
func staleVars(t *testing.T, s *Server, fake *libvirtfake.Fake, name string) (path string, presentAtDefine *bool) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "libvirt-nvram")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.SetLibvirtNvramDir(dir)
	path = s.libvirtVarsPath(name)
	if err := os.WriteFile(path, []byte("the earlier VM's vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := new(bool)
	fake.FillDefine = func(x string) string {
		if _, err := os.Lstat(path); err == nil {
			*seen = true
		}
		return x
	}
	return path, seen
}

// wantSetAside fails unless the file was gone at the define, its bytes are in
// a set-aside copy, and nothing is at the path for the new VM's first boot.
func wantSetAside(t *testing.T, path string, presentAtDefine *bool) {
	t.Helper()
	if *presentAtDefine {
		t.Error("the new domain was defined with an earlier VM's UEFI vars still at its path")
	}
	kept, _ := filepath.Glob(path + ".superseded-*")
	if len(kept) != 1 {
		t.Fatalf("set-aside copies = %v, want one", kept)
	}
	if b, _ := os.ReadFile(kept[0]); string(b) != "the earlier VM's vars" {
		t.Errorf("the set-aside copy holds %q", b)
	}
}

// Every definer of a new same-name domain sets an earlier VM's libvirt vars
// aside before the define, not just CreateVM.
//
// Mutation: drop setAsideStaleLibvirtVars from the definer; its test goes red.
func TestClone_SetsAsideAnEarlierVMsUEFIVars(t *testing.T) {
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.images = image.NewStore(s.dataDir)
	seedCloneSource(t, s, "tpl", "", "")
	path, seen := staleVars(t, s, fake, "clone1")
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "clone1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	wantSetAside(t, path, seen)
}

func TestImportVM_SetsAsideAnEarlierVMsUEFIVars(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	path, seen := staleVars(t, s, s.virt.(*libvirtfake.Fake), "imp-uefi")
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-uefi", false)}}); err != nil {
		t.Fatalf("ImportVM: %v", err)
	}
	wantSetAside(t, path, seen)
}

func TestRestoreLive_AutoStart_SetsAsideAnEarlierVMsUEFIVars(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	path, seen := staleVars(t, s, fake, "vm1")
	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 2048,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(specJSON))
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()
	wantSetAside(t, path, seen)
	cancel()
	<-done
}

func TestPromoteReplica_SetsAsideAnEarlierVMsUEFIVars(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local",
		}},
	); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	path, seen := staleVars(t, s, fake, "vm1-promoted")
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	wantSetAside(t, path, seen)
}

// The set-aside never touches the name-keyed Secure Boot / vTPM path, which is
// the firmware store's and under its move guard.
//
// Mutation: drop the name-keyed check in setAsideStaleVars; the file is renamed.
func TestSetAsideStaleVars_NeverTouchesTheNameKeyedFirmwarePath(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	named := s.fw().NvramPath("sb1")
	if err := os.MkdirAll(filepath.Dir(named), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(named, []byte("secure boot vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	if to, err := s.setAsideStaleVars("sb1", named); err != nil || to != "" {
		t.Fatalf("setAsideStaleVars(name-keyed) = %q, %v; want nothing done", to, err)
	}
	if b, err := os.ReadFile(named); err != nil || string(b) != "secure boot vars" {
		t.Fatalf("the name-keyed vars = %q, %v; want them where they were", b, err)
	}
}

// The source removes its vars only when every guard holds. Each case keeps the
// file; the last removes it.
//
// Mutations: delete the "domain still defined" guard, the "row names this
// host" guard, or the hash comparison — the matching case goes red.
func TestRemoveMigratedSourceVars_Guards(t *testing.T) {
	setup := func(t *testing.T, host string) (*Server, *libvirtfake.Fake, string) {
		t.Helper()
		s := testServer(t)
		s.dataDir = t.TempDir()
		fake := libvirtfake.New()
		s.virt = fake
		dir := t.TempDir()
		s.SetLibvirtNvramDir(dir)
		spec, _ := json.Marshal(&pb.VMSpec{Name: "v1", Cpu: 1, MemoryMib: 256})
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: "v1", HostName: host, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		p := s.libvirtVarsPath("v1")
		if err := os.WriteFile(p, []byte("vars"), 0o600); err != nil {
			t.Fatal(err)
		}
		return s, fake, p
	}
	kept := func(t *testing.T, p string) {
		t.Helper()
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the vars were removed: %v", err)
		}
	}
	t.Run("domain still on the source", func(t *testing.T) {
		s, fake, p := setup(t, "elsewhere")
		fake.SetState("v1", "running")
		s.removeMigratedSourceVars(context.Background(), "v1", "")
		kept(t, p)
	})
	t.Run("row names this host", func(t *testing.T) {
		s, _, p := setup(t, "test-host")
		s.hostName = "test-host"
		s.removeMigratedSourceVars(context.Background(), "v1", "")
		kept(t, p)
	})
	t.Run("not the copy the target confirmed", func(t *testing.T) {
		s, _, p := setup(t, "elsewhere")
		s.removeMigratedSourceVars(context.Background(), "v1", varsSHA256([]byte("other bytes")))
		kept(t, p)
	})
	t.Run("all guards hold", func(t *testing.T) {
		s, _, p := setup(t, "elsewhere")
		s.removeMigratedSourceVars(context.Background(), "v1", varsSHA256([]byte("vars")))
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("the vars were kept (stat: %v)", err)
		}
	})
}

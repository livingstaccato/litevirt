package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/vfio"
)

const restoreGPU = "0000:41:00.0"

func seedRestoreGPU(t *testing.T, s *Server) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(context.Background(), s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: restoreGPU, Type: "gpu", VendorID: "10de", IOMMUGroup: soloIOMMUGroup(restoreGPU),
	}); err != nil {
		t.Fatalf("seed PCI device: %v", err)
	}
}

func gpuSpecRepo(t *testing.T, dev *pb.DeviceSpec) (string, string) {
	t.Helper()
	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 2048, Machine: "q35",
		Devices: []*pb.DeviceSpec{dev},
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	return seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(specJSON))
}

// restoreLiveBounded runs RestoreLive to its return, bounded: a restore that is
// not refused keeps its stream open until the caller goes away.
func restoreLiveBounded(s *Server, req *pb.RestoreLiveRequest) error {
	ctx, cancel := context.WithTimeout(adminCtx(), 20*time.Second)
	defer cancel()
	return s.RestoreLive(req, &restoreLiveStream{ctx: ctx})
}

func pciOwner(t *testing.T, s *Server, addr string) string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(context.Background(), s.db, s.hostName, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	return ""
}

// --without-devices restores a GPU VM onto a host without that GPU as a
// managed VM: started without the devices, which are removed from its stored
// spec (so inspect, placement and migrate agree with the domain), with a
// progress line and a degraded audit row saying what was not attached.
//
// Mutation: ignore WithoutDevices — the restore is refused for the missing
// GPU: red.
func TestRestoreLive_AutoStart_WithoutDevicesStartsWithoutThem(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	defer vfio.SetFS(newPCIBindFakeFS())()
	repoDir, ts := gpuSpecRepo(t, &pb.DeviceSpec{Type: "gpu", Vendor: "10de"}) // no GPU on host-a

	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true, WithoutDevices: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer func() { cancel(); <-done }()
	if !sawPhase(stream, pb.RestoreLiveProgress_STARTED) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("restore --without-devices did not start vm1: %v", err)
		default:
			t.Fatal("restore --without-devices did not start vm1")
		}
	}
	if got := lv.HostdevSourcePCIAddresses(fake.DefinedXML("vm1")); len(got) != 0 {
		t.Errorf("restored domain hostdevs = %v, want none", got)
	}
	ctx := context.Background()
	if got := loadStoredSpec(t, s, "vm1"); len(got.Devices) != 0 {
		t.Errorf("stored spec still lists devices %v: the row claims a GPU the guest does not have", got.Devices)
	}
	if intents, _ := corrosion.ListVMPCIIntents(ctx, s.db, "vm1"); len(intents) != 0 {
		t.Errorf("vm_pci_intent = %+v, want none", intents)
	}
	var said bool
	stream.mu.Lock()
	for _, p := range stream.out {
		if strings.Contains(p.Status, "--without-devices") && strings.Contains(p.Status, "type=gpu") {
			said = true
		}
	}
	stream.mu.Unlock()
	if !said {
		t.Error("no progress line names the devices not attached")
	}
	rows, _ := s.db.Query(ctx, `SELECT detail, result FROM audit_log WHERE action = 'vm.devices_dropped' AND target = 'vm1'`)
	if len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "type=gpu") || rows[0].String("result") != "degraded" {
		t.Errorf("audit rows %v, want one degraded vm.devices_dropped naming the GPU", rows)
	}
}

// Without --without-devices, the refusal for a device this host cannot
// provide names the flag that gets the managed restore back.
func TestRestoreLive_AutoStart_RefusalNamesWithoutDevices(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()
	defer vfio.SetFS(newPCIBindFakeFS())()
	repoDir, ts := gpuSpecRepo(t, &pb.DeviceSpec{Type: "gpu", Vendor: "10de"})

	err := restoreLiveBounded(s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	})
	if err == nil || !strings.Contains(status.Convert(err).Message(), "--without-devices") {
		t.Fatalf("restore = %v, want a refusal naming --without-devices", err)
	}
}

// --without-devices asks for an auto-started VM; without --auto-start there is
// none, so it is refused rather than ignored.
func TestRestoreLive_WithoutDevicesNeedsAutoStart(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	repoDir, ts := gpuSpecRepo(t, &pb.DeviceSpec{Type: "gpu"})
	err := restoreLiveBounded(s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), WithoutDevices: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("restore --without-devices without --auto-start = %v, want InvalidArgument", err)
	}
}

// A restore that allocated the backed-up VM's GPU and then fails before its
// domain runs gives the GPU back at once: owner cleared and off vfio-pci. It
// used to stay owned by a VM with no row, bound, until the stranded-ownership
// sweep's age ran out, and no other VM could take it meanwhile.
//
// Mutation: drop the release on a failed restore: red.
func TestRestoreLive_AutoStart_AFailedRestoreReleasesTheDevices(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(f *libvirtfake.Fake)
	}{
		{"define", func(f *libvirtfake.Fake) { f.FailDefineDomain = func(string) error { return errors.New("boom") } }},
		{"start", func(f *libvirtfake.Fake) { f.FailStartDomain = func(string) error { return errors.New("boom") } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.hostName = "host-a"
			s.dataDir = t.TempDir()
			fake := libvirtfake.New()
			tc.fail(fake)
			s.virt = fake
			fs := newPCIUnbindRecordingFS()
			fs.setHostDriver(restoreGPU, "nvidia")
			defer vfio.SetFS(fs)()
			seedRestoreGPU(t, s)
			repoDir, ts := gpuSpecRepo(t, &pb.DeviceSpec{Address: restoreGPU})

			err := restoreLiveBounded(s, &pb.RestoreLiveRequest{
				RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
				TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
			})
			if err == nil {
				t.Fatal("the restore succeeded; the injected failure did not fire")
			}
			if o := pciOwner(t, s, restoreGPU); o != "" || fs.isBound(restoreGPU) {
				t.Fatalf("after the failed restore (%v): owner=%q bound=%v, want released and unbound", err, o, fs.isBound(restoreGPU))
			}
		})
	}
}

// CreateVM's first boot failing gives its devices back the same way.
//
// Mutation: drop the release on a failed create: red.
func TestCreateVM_AFailedStartReleasesTheDevices(t *testing.T) {
	s := testServerR2(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	fake.FailStartDomain = func(string) error { return errors.New("boom") }
	s.virt = fake
	ctx := adminCtx()
	fs := newPCIUnbindRecordingFS()
	fs.setHostDriver(restoreGPU, "nvidia")
	defer vfio.SetFS(fs)()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: restoreGPU, Type: "gpu", VendorID: "10de", IOMMUGroup: soloIOMMUGroup(restoreGPU),
	}); err != nil {
		t.Fatalf("seed PCI device: %v", err)
	}
	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: "test-host"},
		Devices:   []*pb.DeviceSpec{{Address: restoreGPU}},
	}})
	if err == nil {
		t.Fatal("CreateVM succeeded; the injected start failure did not fire")
	}
	if o := pciOwner(t, s, restoreGPU); o != "" || fs.isBound(restoreGPU) {
		t.Fatalf("after the failed create (%v): owner=%q bound=%v, want released and unbound", err, o, fs.isBound(restoreGPU))
	}
}

// A fence that refuses the restore's commit after its domain started gives
// the devices back only once that domain is destroyed: a guest whose destroy
// failed may still hold them, and keeps them.
//
// Mutation: clear pciHeld on the fence branch whether or not the destroy
// succeeded: red (destroy-failed).
func TestRestoreLive_AutoStart_FenceRefusalReleasesOnlyADestroyedDomainsDevices(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failDestroy bool
		wantOwner   string
		wantBound   bool
	}{
		{"destroyed", false, "", false},
		{"destroy-failed", true, "vm1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.hostName = "host-a"
			s.dataDir = t.TempDir()
			ctx := context.Background()
			fake := libvirtfake.New()
			if tc.failDestroy {
				fake.FailDestroyDomain = func(string) error { return errors.New("destroy boom") }
			}
			s.virt = fake
			s.enfProjectAuthority.Store(true)
			s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.ProjectAuthorityV1: true}})
			authorityHost(t, s, "_default")
			fs := newPCIUnbindRecordingFS()
			fs.setHostDriver(restoreGPU, "nvidia")
			defer vfio.SetFS(fs)()
			seedRestoreGPU(t, s)
			s.commitFenceHook = func(op string) {
				if op != "RestoreLive" {
					return
				}
				if _, applied, err := corrosion.TakeoverProjectAuthority(ctx, s.db, "_default", "usurper", "planned", "", 1); err != nil || !applied {
					t.Errorf("takeover: applied=%v err=%v", applied, err)
				}
			}
			repoDir, ts := gpuSpecRepo(t, &pb.DeviceSpec{Address: restoreGPU})
			err := restoreLiveBounded(s, &pb.RestoreLiveRequest{
				RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
				TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
			})
			if err == nil {
				t.Fatal("restore succeeded; the fence did not refuse")
			}
			if o, b := pciOwner(t, s, restoreGPU), fs.isBound(restoreGPU); o != tc.wantOwner || b != tc.wantBound {
				t.Fatalf("err=%v: owner=%q bound=%v, want owner=%q bound=%v", err, o, b, tc.wantOwner, tc.wantBound)
			}
		})
	}
}

package grpcapi

import (
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// hangingUnbindFS blocks the vfio-pci unbind write for one address until gate is
// closed: the kernel's behaviour while a process (a QEMU that has not exited, or
// anything else) still holds the vfio device fd open.
type hangingUnbindFS struct {
	*pciUnbindRecordingFS
	addr    string
	gate    chan struct{}
	entered chan struct{}
}

func (f *hangingUnbindFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	a := strings.TrimSpace(string(data))
	if strings.HasSuffix(path, "/driver/unbind") && (a == f.addr || f.addr == "*") && f.isBound(a) {
		f.entered <- struct{}{}
		<-f.gate
	}
	return f.pciUnbindRecordingFS.WriteFile(path, data, perm)
}

// TestDetachPCI_ABlockedUnbindDoesNotWedgeTheDaemon: a detach whose vfio-pci
// unbind the kernel blocks held the VM lock for as long as the holder kept the
// fd, so every later operation on the VM queued behind it. The detach must come
// back within the bounded wait, keep the device owned (fail closed), and leave
// the VM usable: a retry fails at once while the write is stuck, and converges
// once the holder lets go.
func TestDetachPCI_ABlockedUnbindDoesNotWedgeTheDaemon(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	inner := newPCIUnbindRecordingFS()
	inner.setHostDriver(addr, "igbvf")
	fs := &hangingUnbindFS{pciUnbindRecordingFS: inner, addr: addr, gate: make(chan struct{}), entered: make(chan struct{}, 4)}
	defer vfio.SetFS(fs)()
	released := false
	release := func() {
		if !released {
			released = true
			close(fs.gate)
		}
	}
	t.Cleanup(release)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer vfio.SetUnbindTimeout(200 * time.Millisecond)()

	start := time.Now()
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if err == nil {
		t.Fatal("detach reported success while the unbind was still blocked")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("detach took %v with a 200ms unbind bound", took)
	}
	<-fs.entered
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("owner = %q after a blocked unbind, want vm1 (fail closed)", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("device reads unbound while its unbind is still blocked")
	}

	// The VM lock is free, and a retry fails fast instead of queueing a second
	// write behind the first.
	unlocked := make(chan struct{})
	go func() { s.lockVM("vm1")(); close(unlocked) }()
	select {
	case <-unlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("the VM lock is still held after the detach returned")
	}
	defer vfio.SetUnbindTimeout(time.Hour)()
	start = time.Now()
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err == nil ||
		!strings.Contains(err.Error(), "blocked") {
		t.Fatalf("retry while the write is stuck = %v, want a fast 'blocked' error", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("retry took %v; it must fail fast", took)
	}
	select {
	case <-fs.entered:
		t.Fatal("the retry started a second unbind write")
	default:
	}

	// The holder lets go: the stuck write lands and a retry releases the device.
	release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("detach after the holder let go: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("owner = %q after the release, want none", o)
	}
	if inner.hostDriver(addr) != "igbvf" {
		t.Fatalf("host driver = %q, want igbvf", inner.hostDriver(addr))
	}
}

// TestReleaseDevices_StopsAtTheFirstBlockedUnbind (review M1): the release is
// all-or-nothing, so once one device's unbind is blocked there is no point
// unbinding the rest — and each would cost another bounded wait under the VM
// lock. The release must stop at the first, with one write in the kernel.
func TestReleaseDevices_StopsAtTheFirstBlockedUnbind(t *testing.T) {
	s := hotplugDiskServer(t)
	inner := newPCIUnbindRecordingFS()
	fs := &hangingUnbindFS{pciUnbindRecordingFS: inner, addr: "*", gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	defer vfio.SetFS(fs)()
	t.Cleanup(func() {
		close(fs.gate)
		// Let the stuck writes land, so no later test finds these addresses busy.
		deadline := time.Now().Add(5 * time.Second)
		for len(vfio.StuckUnbinds()) > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	})
	ctx := adminCtx()
	for _, a := range []string{"0000:50:00.0", "0000:51:00.0", "0000:52:00.0"} {
		seedPCIGPU(t, s, a, -1)
		if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", a, "vm1"); err != nil {
			t.Fatalf("assign: %v", err)
		}
		inner.setBound(a)
	}
	defer vfio.SetUnbindTimeout(150 * time.Millisecond)()

	if err := s.releaseDevices(ctx, "vm1"); err == nil {
		t.Fatal("releaseDevices succeeded with every unbind blocked")
	}
	if got := len(fs.entered); got != 1 {
		t.Fatalf("%d unbind writes reached the kernel, want 1 (stop at the first blocked one)", got)
	}
	for _, a := range []string{"0000:50:00.0", "0000:51:00.0", "0000:52:00.0"} {
		if o := pciOwnerOf(t, ctx, s, a); o != "vm1" {
			t.Fatalf("%s owner = %q, want vm1", a, o)
		}
	}
}

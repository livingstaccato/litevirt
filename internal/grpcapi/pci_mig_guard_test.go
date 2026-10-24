package grpcapi

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// migFakeSMI installs a fake nvidia-smi that answers --query-gpu with gpus
// (CSV rows) and `mig -lgi` with lgi, exiting lgiRC; any other call fails.
// It returns the path of the log of its calls.
func migFakeSMI(t *testing.T, gpus, lgi string, lgiRC int) string {
	t.Helper()
	body := "case \"$1\" in\n" +
		"--query-gpu*) cat <<'EOF'\n" + gpus + "EOF\n;;\n" +
		"mig) cat <<'EOF'\n" + lgi + "EOF\nexit " + strconv.Itoa(lgiRC) + "\n;;\n" +
		"*) exit 1;;\nesac\n"
	return migFakeSMIScript(t, body)
}

func migFakeSMIScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	bin := filepath.Join(dir, "nvidia-smi")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$*\" >> "+log+"\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pci.SetNvidiaSMI(bin))
	return log
}

// lgiTwoOnGPU0 is `nvidia-smi mig -lgi` with two GPU instances on GPU 0.
const lgiTwoOnGPU0 = `+-------------------------------------------------------+
| GPU instances:                                        |
| GPU   Name          Profile  Instance   Placement     |
|                       ID       ID       Start:Size    |
|=======================================================|
|   0  MIG 3g.20gb       9        1          4:4     |
+-------------------------------------------------------+
|   0  MIG 3g.20gb       9        2          0:4     |
+-------------------------------------------------------+
`

const noGIs = "No GPU instances found: Not Found\n"

// migScenarios are the MIG states of the GPU at 0000:41:00.0 (nvidia-smi
// index 0), each with whether a passthrough of it must be refused.
var migScenarios = []struct {
	name    string
	setup   func(t *testing.T)
	refused string // a substring of the refusal; "" = allowed
}{
	{"mig-enabled", func(t *testing.T) {
		migFakeSMI(t, "0, 00000000:41:00.0, Enabled, Enabled, NVIDIA A100\n", noGIs, 6)
	}, "MIG mode is on"},
	{"pending-enable", func(t *testing.T) {
		migFakeSMI(t, "0, 00000000:41:00.0, Disabled, Enabled, NVIDIA A100\n", noGIs, 6)
	}, "pending Enabled"},
	{"instances", func(t *testing.T) {
		migFakeSMI(t, "0, 00000000:41:00.0, Disabled, Disabled, NVIDIA A100\n", lgiTwoOnGPU0, 0)
	}, "2 MIG GPU instance(s)"},
	{"nvidia-smi-fails", func(t *testing.T) {
		migFakeSMIScript(t, "echo 'Failed to initialize NVML: Driver/library version mismatch'\nexit 18\n")
	}, "Driver/library version mismatch"},
	{"disabled-no-instances", func(t *testing.T) {
		migFakeSMI(t, "0, 00000000:41:00.0, Disabled, Disabled, NVIDIA A100\n", noGIs, 6)
	}, ""},
	{"no-nvidia-smi", func(t *testing.T) {
		t.Cleanup(pci.SetNvidiaSMI(filepath.Join(t.TempDir(), "nvidia-smi")))
	}, ""},
}

// A GPU MIG holds is never bound to vfio-pci: the acquire refuses it with
// FailedPrecondition before claiming or binding anything, and gives back what
// the caller claimed for the attempt. Once MIG is off with no instance (or
// there is no NVIDIA driver at all) it is bound as any device is.
func TestAcquireDeviceLeases_NeverBindsAGPUThatMIGHolds(t *testing.T) {
	for _, sc := range migScenarios {
		t.Run(sc.name, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			fs := newPCIBindFakeFS()
			defer vfio.SetFS(fs)()
			ctx := adminCtx()
			seedPCIGPU(t, s, "0000:41:00.0", -1)
			// A device the caller claimed for this attempt beforehand (an SR-IOV VF).
			seedPCIGPU(t, s, "0000:42:00.0", -1)
			if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, "test-host", "0000:42:00.0", "vm1"); err != nil || !ok {
				t.Fatalf("pre-claim: %v %v", ok, err)
			}
			sc.setup(t)

			finish, _, err := s.acquireDeviceLeases(ctx, "vm1", []ResolvedMember{{Address: "0000:41:00.0"}}, deviceLeaseStageBound, []string{"0000:42:00.0"})
			if sc.refused == "" {
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				finish()
				if fs.binds != 1 || pciOwnerOf(t, ctx, s, "0000:41:00.0") != "vm1" {
					t.Fatalf("binds = %d, owner = %q; want the GPU bound and owned by vm1", fs.binds, pciOwnerOf(t, ctx, s, "0000:41:00.0"))
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), sc.refused) ||
				!strings.Contains(err.Error(), "0000:41:00.0") {
				t.Fatalf("acquire = %v; want FailedPrecondition naming the GPU and %q", err, sc.refused)
			}
			if fs.binds != 0 {
				t.Fatalf("a refused GPU was bound to vfio-pci (%d binds)", fs.binds)
			}
			if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
				t.Fatalf("a refused GPU is owned by %q", o)
			}
			if o := pciOwnerOf(t, ctx, s, "0000:42:00.0"); o != "" {
				t.Fatalf("the caller's pre-claim was not given back: owned by %q", o)
			}
		})
	}
}

// The refusal names the fix: destroy the instances, then disable MIG.
func TestAcquireDeviceLeases_MIGRefusalNamesTheReclaim(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	defer vfio.SetFS(newPCIBindFakeFS())()
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	migFakeSMI(t, "3, 00000000:41:00.0, Enabled, Enabled, NVIDIA A100\n", strings.ReplaceAll(lgiTwoOnGPU0, "|   0  MIG", "|   3  MIG"), 0)
	_, _, err := s.acquireDeviceLeases(adminCtx(), "vm1", []ResolvedMember{{Address: "0000:41:00.0"}}, deviceLeaseStageBound, nil)
	for _, want := range []string{"lv host mig destroy 3", "lv host mig disable 3", "2 MIG GPU instance(s)", "test-host"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %v does not say %q", err, want)
		}
	}
}

// Only NVIDIA GPUs are checked: with an nvidia-smi that fails every call, a
// device of another vendor is bound, and nvidia-smi is never run.
func TestAcquireDeviceLeases_NonNVIDIADeviceIsNotChecked(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:43:00.0", Type: "gpu", VendorID: "1002", IOMMUGroup: soloIOMMUGroup("0000:43:00.0"),
	}); err != nil {
		t.Fatal(err)
	}
	log := migFakeSMIScript(t, "exit 1\n")
	finish, _, err := s.acquireDeviceLeases(ctx, "vm1", []ResolvedMember{{Address: "0000:43:00.0"}}, deviceLeaseStageBound, nil)
	if err != nil {
		t.Fatalf("acquire of an AMD GPU: %v", err)
	}
	finish()
	if fs.binds != 1 {
		t.Fatalf("binds = %d, want 1", fs.binds)
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("nvidia-smi ran for a device that is not an NVIDIA GPU")
	}
}

// A running attach by address of a GPU MIG holds fails with the refusal and
// leaves nothing behind: no intent, no owner, no bind, no barrier.
func TestAttachDevice_RunningPCIRefusesAGPUThatMIGHolds(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	migFakeSMI(t, "0, 00000000:41:00.0, Enabled, Enabled, NVIDIA A100\n", noGIs, 6)

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: "0000:41:00.0"}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "MIG") {
		t.Fatalf("attach = %v; want the MIG refusal", err)
	}
	if fs.binds != 0 {
		t.Fatalf("%d vfio binds", fs.binds)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("GPU owned by %q", o)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent survived the refusal: %+v", in)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared: %q", vm.ActiveOperationID)
	}
}

// A type selector does not pick a GPU MIG holds when another is free; with
// none other free it says why the held one was skipped.
func TestAttachDevice_TypeSelectorSkipsAGPUThatMIGHolds(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	migFakeSMI(t, "0, 00000000:41:00.0, Enabled, Enabled, NVIDIA A100\n1, 00000000:42:00.0, Disabled, Disabled, NVIDIA A100\n", noGIs, 6)

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"}})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "MIG mode is on") {
		t.Fatalf("attach with only a MIG GPU free = %v; want ResourceExhausted saying why it was skipped", err)
	}

	seedPCIGPU(t, s, "0000:42:00.0", -1)
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"}}); err != nil {
		t.Fatalf("attach with a free non-MIG GPU: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:41:00.0"); o != "" {
		t.Fatalf("the MIG GPU was taken by %q", o)
	}
	if o := pciOwnerOf(t, ctx, s, "0000:42:00.0"); o != "vm1" {
		t.Fatalf("the free GPU is owned by %q, want vm1", o)
	}
}

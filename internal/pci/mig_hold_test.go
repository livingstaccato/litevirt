package pci

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// migSMI installs a fake nvidia-smi that answers --query-gpu with gpus (CSV
// rows) and `mig -lgi` with lgi, exiting lgiRC.
func migSMI(t *testing.T, gpus, lgi string, lgiRC int) string {
	t.Helper()
	body := "case \"$1\" in\n" +
		"--query-gpu*) cat <<'EOF'\n" + gpus + "EOF\n;;\n" +
		"mig) cat <<'EOF'\n" + lgi + "EOF\nexit " + strconv.Itoa(lgiRC) + "\n;;\n" +
		"esac\n"
	return fakeSMI(t, body)
}

const gpuAddr = "0000:36:00.0"

func hold(t *testing.T, vendor, driver string) error {
	t.Helper()
	return ReadMIGState().Hold(gpuAddr, vendor, driver)
}

func wantBusy(t *testing.T, err error, instances int) {
	t.Helper()
	var busy *MIGBusyError
	if !errors.As(err, &busy) {
		t.Fatalf("Hold = %v, want a *MIGBusyError", err)
	}
	if busy.Instances != instances || busy.Address != gpuAddr || busy.Index != 0 {
		t.Fatalf("busy = %+v, want GPU %s index 0 with %d instance(s)", busy, gpuAddr, instances)
	}
	for _, s := range []string{gpuAddr, "lv host mig destroy 0", "lv host mig disable 0"} {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("refusal %q does not name %q", err, s)
		}
	}
}

func TestMIGHold_MIGEnabledIsRefused(t *testing.T) {
	migSMI(t, "0, 00000000:36:00.0, Enabled, Enabled, NVIDIA A100\n", "No GPU instances found: Not Found\n", 6)
	wantBusy(t, hold(t, "10de", "nvidia"), 0)
}

func TestMIGHold_PendingEnableIsRefused(t *testing.T) {
	migSMI(t, "0, 00000000:36:00.0, Disabled, Enabled, NVIDIA A100\n", "No GPU instances found: Not Found\n", 6)
	err := hold(t, "10de", "nvidia")
	wantBusy(t, err, 0)
	if !strings.Contains(err.Error(), "pending Enabled") {
		t.Fatalf("refusal %q does not say the mode is pending", err)
	}
}

func TestMIGHold_InstancesAreRefused(t *testing.T) {
	// Instances counted on their own, whatever the mode reads: a GPU holding
	// one is refused even if the mode query says Disabled.
	migSMI(t, "0, 00000000:36:00.0, Disabled, Disabled, NVIDIA A100\n", lgiOutput, 0)
	err := hold(t, "10de", "nvidia")
	wantBusy(t, err, 2)
	if !strings.Contains(err.Error(), "2 MIG GPU instance(s)") {
		t.Fatalf("refusal %q does not count the instances", err)
	}
}

func TestMIGHold_InstancesOnAnotherGPUDoNotCount(t *testing.T) {
	migSMI(t, "0, 00000000:36:00.0, Disabled, Disabled, NVIDIA A100\n1, 00000000:37:00.0, Enabled, Enabled, NVIDIA A100\n",
		strings.ReplaceAll(lgiOutput, "|   0  MIG", "|   1  MIG"), 0)
	if err := hold(t, "10de", "nvidia"); err != nil {
		t.Fatalf("GPU 0 has no instance and MIG off, Hold = %v", err)
	}
}

func TestMIGHold_DisabledWithNoInstancesIsAllowed(t *testing.T) {
	for _, lgi := range []string{"No GPU instances found: Not Found\n", "No MIG-enabled devices found.\n"} {
		migSMI(t, "0, 00000000:36:00.0, Disabled, Disabled, NVIDIA A100\n", lgi, 6)
		if err := hold(t, "10de", "nvidia"); err != nil {
			t.Fatalf("lgi %q: Hold = %v, want nil", lgi, err)
		}
	}
}

func TestMIGHold_NotMIGCapableIsAllowed(t *testing.T) {
	log := migSMI(t, "0, 00000000:36:00.0, [N/A], [N/A], NVIDIA L4\n", "", 9)
	if err := hold(t, "10de", "nvidia"); err != nil {
		t.Fatalf("Hold = %v, want nil", err)
	}
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "mig") {
			t.Fatalf("instances listed on a host with no MIG-capable GPU: %v", calls(t, log))
		}
	}
}

func TestMIGHold_NoNvidiaSMIIsAllowed(t *testing.T) {
	defer SetNvidiaSMI(filepath.Join(t.TempDir(), "nvidia-smi"))()
	if err := hold(t, "10de", "nvidia"); err != nil {
		t.Fatalf("Hold = %v, want nil with no nvidia-smi", err)
	}
	defer SetNvidiaSMI("litevirt-no-such-nvidia-smi")()
	if err := hold(t, "10de", ""); err != nil {
		t.Fatalf("Hold = %v, want nil with no nvidia-smi on PATH", err)
	}
}

func TestMIGHold_NvidiaSMIFailureIsRefused(t *testing.T) {
	fakeSMI(t, "echo 'Unable to determine the device handle for GPU0000:36:00.0: Unknown Error'\nexit 15\n")
	err := hold(t, "10de", "nvidia")
	var busy *MIGBusyError
	if err == nil || errors.As(err, &busy) || !strings.Contains(err.Error(), "Unknown Error") {
		t.Fatalf("Hold = %v, want the nvidia-smi failure", err)
	}
}

func TestMIGHold_InstanceListFailureIsRefused(t *testing.T) {
	migSMI(t, "0, 00000000:36:00.0, Disabled, Disabled, NVIDIA A100\n", "Insufficient Permissions\n", 4)
	if err := hold(t, "10de", "nvidia"); err == nil || !strings.Contains(err.Error(), "Insufficient Permissions") {
		t.Fatalf("Hold = %v, want the -lgi failure", err)
	}
}

func TestMIGHold_UnlistedGPUOnNvidiaDriverIsRefused(t *testing.T) {
	migSMI(t, "0, 00000000:37:00.0, Disabled, Disabled, NVIDIA A100\n", "No GPU instances found\n", 6)
	if err := hold(t, "10de", "nvidia"); err == nil {
		t.Fatal("a GPU the nvidia driver holds but nvidia-smi does not list must be refused")
	}
	if err := hold(t, "10de", ""); err != nil {
		t.Fatalf("a GPU on no driver cannot be in MIG use, Hold = %v", err)
	}
}

func TestMIGHold_OnlyNVIDIAOffVFIOIsChecked(t *testing.T) {
	log := fakeSMI(t, "exit 1\n")
	if err := hold(t, "8086", "ixgbe"); err != nil {
		t.Fatalf("non-NVIDIA device: Hold = %v", err)
	}
	if err := hold(t, "1002", "amdgpu"); err != nil {
		t.Fatalf("non-NVIDIA GPU: Hold = %v", err)
	}
	if err := ReadMIGState().Hold(gpuAddr, "10de", "vfio-pci"); err != nil {
		t.Fatalf("GPU already on vfio-pci is not rebound: Hold = %v", err)
	}
	if c := calls(t, log); len(c) != 0 {
		t.Fatalf("nvidia-smi ran for a device that is not checked: %v", c)
	}
	// The same failing nvidia-smi refuses an NVIDIA GPU, so the checks above
	// pass because the device was skipped, not because nvidia-smi said yes.
	if err := hold(t, "0x10DE", "nvidia"); err == nil {
		t.Fatal("an NVIDIA GPU with a failing nvidia-smi must be refused")
	}
}

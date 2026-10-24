package pci

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The outputs below are copied from NVIDIA's MIG user guide, "Getting Started
// with MIG" (docs.nvidia.com/datacenter/tesla/mig-user-guide). No NVIDIA GPU
// is available to the tests, so this is the only check of the format.

const lgiOutput = `+-------------------------------------------------------+
| GPU instances:                                        |
| GPU   Name          Profile  Instance   Placement     |
|                       ID       ID       Start:Size    |
|=======================================================|
|   0  MIG 3g.20gb       9        1          4:4     |
+-------------------------------------------------------+
|   0  MIG 3g.20gb       9        2          0:4     |
+-------------------------------------------------------+
`

const cgiOutput = `Successfully created GPU instance ID  2 on GPU  0 using profile MIG 3g.20gb (ID  9)
Successfully created compute instance ID  0 on GPU  0 GPU instance ID  2 using profile MIG 3g.20gb (ID  2)
`

// fakeSMI installs a fake nvidia-smi that logs its arguments, one call per
// line, and answers from the script body. It returns the log path.
func fakeSMI(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	bin := filepath.Join(dir, "nvidia-smi")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" + body
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := nvidiaSMI
	nvidiaSMI = bin
	t.Cleanup(func() { nvidiaSMI = old })
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestListMIGInstances_ParsesTheLGITable(t *testing.T) {
	fakeSMI(t, "cat <<'EOF'\n"+lgiOutput+"EOF\n")
	got, err := ListMIGInstances()
	if err != nil {
		t.Fatal(err)
	}
	want := []MIGInstance{
		{GPUIndex: 0, InstanceID: 1, Profile: "3g.20gb", ProfileID: 9, Placement: "4:4"},
		{GPUIndex: 0, InstanceID: 2, Profile: "3g.20gb", ProfileID: 9, Placement: "0:4"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instances = %+v, want %+v", got, want)
	}
}

func TestListMIGInstances_NoneFoundIsEmptyNotAnError(t *testing.T) {
	fakeSMI(t, "echo 'No GPU instances found: Not Found'\nexit 6\n")
	got, err := ListMIGInstances()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v; want none, nil", got, err)
	}
}

func TestListMIGInstances_OtherFailureIsAnError(t *testing.T) {
	fakeSMI(t, "echo 'Insufficient Permissions'\nexit 4\n")
	if _, err := ListMIGInstances(); err == nil || !strings.Contains(err.Error(), "Insufficient Permissions") {
		t.Fatalf("err = %v, want nvidia-smi's message", err)
	}
}

func TestListMIGGPUs_ParsesQueryGPU(t *testing.T) {
	log := fakeSMI(t, `cat <<'EOF'
0, 00000000:36:00.0, Enabled, Enabled, NVIDIA A100-SXM4-40GB
1, 00000000:37:00.0, Disabled, Enabled, NVIDIA A100-SXM4-40GB
2, 00000000:81:00.0, [N/A], [N/A], NVIDIA GeForce RTX 3090
EOF
`)
	got, err := ListMIGGPUs()
	if err != nil {
		t.Fatal(err)
	}
	want := []MIGGPU{
		{Index: 0, BusID: "00000000:36:00.0", Name: "NVIDIA A100-SXM4-40GB", Current: "Enabled", Pending: "Enabled"},
		{Index: 1, BusID: "00000000:37:00.0", Name: "NVIDIA A100-SXM4-40GB", Current: "Disabled", Pending: "Enabled"},
		{Index: 2, BusID: "00000000:81:00.0", Name: "NVIDIA GeForce RTX 3090", Current: "[N/A]", Pending: "[N/A]"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gpus = %+v, want %+v", got, want)
	}
	if !got[0].MIGCapable() || !got[1].MIGCapable() || got[2].MIGCapable() {
		t.Fatalf("MIGCapable wrong: %+v", got)
	}
	if c := calls(t, log); len(c) != 1 || c[0] != "--query-gpu=index,pci.bus_id,mig.mode.current,mig.mode.pending,name --format=csv,noheader" {
		t.Fatalf("calls = %q", c)
	}
}

func TestCreateMIGInstance_CreatesGIAndCIInOneCall(t *testing.T) {
	log := fakeSMI(t, "cat <<'EOF'\n"+cgiOutput+"EOF\n")
	in, err := CreateMIGInstance("0", "3g.20gb")
	if err != nil {
		t.Fatal(err)
	}
	want := MIGInstance{GPUIndex: 0, InstanceID: 2, Profile: "3g.20gb", ProfileID: 9}
	if *in != want {
		t.Fatalf("instance = %+v, want %+v", *in, want)
	}
	if c := calls(t, log); len(c) != 1 || c[0] != "mig -i 0 -cgi 3g.20gb -C" {
		t.Fatalf("calls = %q, want one -cgi ... -C", c)
	}
}

func TestCreateMIGInstance_UnreportedCreateIsAnError(t *testing.T) {
	fakeSMI(t, "echo 'Unable to create a GPU instance on GPU  0 using profile 3g.20gb: Insufficient Resources'\n")
	if _, err := CreateMIGInstance("0", "3g.20gb"); err == nil {
		t.Fatal("an output with no created GPU instance must fail")
	}
}

func TestDestroyMIGInstance_ComputeInstancesFirst(t *testing.T) {
	log := fakeSMI(t, "exit 0\n")
	if err := DestroyMIGInstance("0", 2); err != nil {
		t.Fatal(err)
	}
	want := []string{"mig -i 0 -gi 2 -dci", "mig -i 0 -gi 2 -dgi"}
	if c := calls(t, log); !reflect.DeepEqual(c, want) {
		t.Fatalf("calls = %q, want %q", c, want)
	}
}

func TestDestroyMIGInstance_ReportsBothFailures(t *testing.T) {
	fakeSMI(t, `case "$*" in
*-dci*) echo 'In use by another client'; exit 1 ;;
*-dgi*) echo 'Unable to destroy GPU instance ID  2: In use by another client'; exit 1 ;;
esac
`)
	err := DestroyMIGInstance("0", 2)
	if err == nil || !strings.Contains(err.Error(), "Unable to destroy GPU instance") ||
		!strings.Contains(err.Error(), "compute instances first: In use by another client") {
		t.Fatalf("err = %v, want both nvidia-smi messages", err)
	}
}

func TestEnableDisableMIG_Args(t *testing.T) {
	log := fakeSMI(t, "echo 'Enabled MIG Mode for GPU 00000000:36:00.0'\necho 'All done.'\n")
	out, err := EnableMIG("00000000:36:00.0")
	if err != nil || !strings.Contains(out, "Enabled MIG Mode") {
		t.Fatalf("enable: %q, %v", out, err)
	}
	if _, err := DisableMIG("0"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-i 00000000:36:00.0 -mig 1", "-i 0 -mig 0"}
	if c := calls(t, log); !reflect.DeepEqual(c, want) {
		t.Fatalf("calls = %q, want %q", c, want)
	}
}

// A GPU or profile that nvidia-smi could read as a flag never reaches it.
func TestMIG_RefusesFlagLikeArguments(t *testing.T) {
	log := fakeSMI(t, "exit 0\n")
	for _, f := range []func() error{
		func() error { _, err := EnableMIG("-r"); return err },
		func() error { _, err := DisableMIG(""); return err },
		func() error { _, err := CreateMIGInstance("0", "--gpu-reset"); return err },
		func() error { _, err := CreateMIGInstance("0 1", "3g.20gb"); return err },
		func() error { return DestroyMIGInstance("-i", 1) },
		func() error { return DestroyMIGInstance("0", -1) },
	} {
		if err := f(); err == nil {
			t.Error("a flag-like argument was accepted")
		}
	}
	if c := calls(t, log); c != nil {
		t.Fatalf("nvidia-smi ran: %q", c)
	}
}

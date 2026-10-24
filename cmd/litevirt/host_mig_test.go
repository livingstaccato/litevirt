package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNvidiaSMIOnPath puts a fake nvidia-smi first on PATH. Its answers are
// the formats in NVIDIA's MIG user guide; there is no GPU to check them on.
func fakeNvidiaSMIOnPath(t *testing.T, anyEnabled bool) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	mode := "Disabled, Disabled"
	if anyEnabled {
		mode = "Enabled, Enabled"
	}
	script := `#!/bin/sh
echo "$*" >> ` + log + `
case "$*" in
--query-gpu*)
  echo "0, 00000000:36:00.0, ` + mode + `, NVIDIA A100-SXM4-40GB"
  echo "1, 00000000:37:00.0, Disabled, Enabled, NVIDIA A100-SXM4-40GB"
  echo "2, 00000000:81:00.0, [N/A], [N/A], NVIDIA GeForce RTX 3090" ;;
"mig -lgi")
  echo "|   0  MIG 3g.20gb       9        1          4:4     |" ;;
*-cgi*)
  echo "Successfully created GPU instance ID  2 on GPU  0 using profile MIG 3g.20gb (ID  9)"
  echo "Successfully created compute instance ID  0 on GPU  0 GPU instance ID  2 using profile MIG 3g.20gb (ID  2)" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "nvidia-smi"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func runHostMIG(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newHostCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"mig"}, args...))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("lv host mig %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func TestHostMIGLs_ShowsModesPendingAndInstances(t *testing.T) {
	fakeNvidiaSMIOnPath(t, true)
	out := runHostMIG(t, "ls")
	for _, want := range []string{
		"0    00000000:36:00.0  NVIDIA A100-SXM4-40GB    Enabled",
		"Disabled     Enabled (needs GPU reset)",
		"NVIDIA GeForce RTX 3090  unsupported",
		"GPU  INSTANCE  PROFILE  PROFILE ID  PLACEMENT",
		"0    1         3g.20gb  9           4:4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// With no GPU in MIG mode there is nothing to list, and -lgi would only fail.
func TestHostMIGLs_NoInstanceQueryWithoutMIGMode(t *testing.T) {
	log := fakeNvidiaSMIOnPath(t, false)
	out := runHostMIG(t, "ls")
	if strings.Contains(out, "INSTANCE") {
		t.Errorf("instance table printed with no GPU in MIG mode:\n%s", out)
	}
	b, _ := os.ReadFile(log)
	if strings.Contains(string(b), "-lgi") {
		t.Errorf("-lgi ran with no GPU in MIG mode: %q", b)
	}
}

func TestHostMIGCreate_ReportsTheInstance(t *testing.T) {
	fakeNvidiaSMIOnPath(t, true)
	out := runHostMIG(t, "create", "0", "3g.20gb")
	if !strings.Contains(out, "Created MIG instance 2 (3g.20gb) on GPU 0") {
		t.Fatalf("create output = %q", out)
	}
}

func TestHostMIGDestroy_RefusesANonNumericID(t *testing.T) {
	fakeNvidiaSMIOnPath(t, true)
	cmd := newHostCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"mig", "destroy", "0", "two"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a non-numeric instance id was accepted")
	}
}

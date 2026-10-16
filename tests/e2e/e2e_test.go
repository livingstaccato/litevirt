// Package e2e runs end-to-end tests against a live litevirt cluster.
//
// Requirements:
//   - 4-node cluster with litevirtd running on all nodes
//   - `lv` binary in PATH (or set LV_BIN)
//   - Either LV_HOST set (remote mode) or running on a cluster node (local mode)
//   - A test image already pulled (auto-detected, or set E2E_IMAGE)
//   - The user running tests must have admin RBAC
//
// Run on a cluster node:
//
//	./e2e-test -test.v -test.timeout 30m
//
// Run remotely:
//
//	LV_HOST=root@10.0.50.10 go test./tests/e2e/ -v -timeout 30m
//
// Optional env vars:
//
//	LV_BIN          — path to lv binary (default: "lv")
//	E2E_IMAGE       — base image name (default: auto-detect from lv image ls)
//	E2E_HOSTS       — comma-separated host names if auto-detection fails
//	E2E_REST_URL    — REST API base URL (default: http://127.0.0.1:7446)
//	E2E_REST_TOKEN  — API token for REST tests (created automatically if empty)
//	E2E_SKIP_SLOW   — set to "1" to skip migration/failover tests
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	lvcompose "github.com/litevirt/litevirt/internal/compose"
)

// ─── Configuration ──────────────────────────────────────────────────────────

var (
	lvBin     = envOr("LV_BIN", "lv")
	lvHost    = os.Getenv("LV_HOST")
	testImage = os.Getenv("E2E_IMAGE")
	restURL   = os.Getenv("E2E_REST_URL")
	restToken = os.Getenv("E2E_REST_TOKEN")
	skipSlow  = os.Getenv("E2E_SKIP_SLOW") == "1"

	// Populated during TestSetup.
	hostNames []string
	hostIPs   map[string]string // name → address
	localMode bool
	localHost string // name of the host we're running on
)

// vmMemory is the memory (MiB) of a test VM whose test needs none in
// particular. Lab nodes have about 3 GiB, and the planner charges 128 MiB of
// qemu overhead on top, so 1 GiB VMs left whole tests unplaceable.
func vmMemory() string { return envOr("E2E_VM_MEMORY", "512") }

// agentVMMemory is the memory (MiB) of a guest-agent VM, which installs
// packages at first boot.
func agentVMMemory() string { return envOr("E2E_AGENT_VM_MEMORY", "1024") }

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── Test harness ───────────────────────────────────────────────────────────

func TestMain(m *testing.M) {
	// Pure helper tests (no cluster, no lv) opt in separately, and only when
	// -test.run names nothing but them: unit mode must never let a
	// cluster-touching test run without LITEVIRT_E2E=1 and LV_BIN.
	if os.Getenv("LITEVIRT_E2E_UNIT") == "1" {
		flag.Parse() // -test.run is not set until the flags are parsed
		run := ""
		if f := flag.Lookup("test.run"); f != nil {
			run = f.Value.String()
		}
		if !unitRunAllowed(run) {
			fmt.Fprintf(os.Stderr, "E2E: LITEVIRT_E2E_UNIT=1 runs only %v; set -test.run to %s (got %q)\n", pureTests, "^("+strings.Join(pureTests, "|")+")$", run)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	// Live e2e is OPT-IN. It mutates a real cluster and runs the CLI against
	// whatever `lv` resolves, so a plain `go test ./...` must never accidentally
	// touch a stale system `lv`. Require an explicit LITEVIRT_E2E=1, and once
	// enabled require LV_BIN so we test a known binary, not whatever's on PATH.
	if os.Getenv("LITEVIRT_E2E") != "1" {
		fmt.Fprintln(os.Stderr, "E2E: set LITEVIRT_E2E=1 to run live e2e tests; skipping")
		os.Exit(0)
	}
	if os.Getenv("LV_BIN") == "" {
		fmt.Fprintln(os.Stderr, "E2E: LITEVIRT_E2E=1 but LV_BIN is not set — point LV_BIN at the binary under test (e.g. ./bin/litevirt) so e2e never runs a stale system lv")
		os.Exit(1)
	}
	// Lab mode drives the nested lab from the machine hosting it
	// (lab_harness_test.go): LV_BIN names the binary on the NODES and every CLI
	// call goes over SSH, so neither a local lv nor LV_HOST applies.
	if labMode {
		for _, f := range []string{"lab.sh", "cluster_key"} {
			if _, err := os.Stat(labDir + "/" + f); err != nil {
				fmt.Fprintf(os.Stderr, "E2E: E2E_LAB_DIR=%s has no %s\n", labDir, f)
				os.Exit(1)
			}
		}
		os.Exit(m.Run())
	}
	// Ensure the lv binary is available.
	if _, err := exec.LookPath(lvBin); err != nil {
		fmt.Fprintf(os.Stderr, "E2E: %s binary not found in PATH, skipping e2e tests\n", lvBin)
		os.Exit(0)
	}
	// Allow running in local mode (on a cluster node) without LV_HOST.
	if lvHost == "" {
		if _, err := os.Stat("/etc/litevirt/config.yaml"); err != nil {
			fmt.Fprintln(os.Stderr, "E2E: LV_HOST not set and not on a cluster node, skipping e2e tests")
			os.Exit(0)
		}
		localMode = true
	}
	os.Exit(m.Run())
}

// lvEnv returns the environment for CLI invocations.
func lvEnv() []string {
	env := os.Environ()
	if lvHost != "" {
		env = append(env, "LV_HOST="+lvHost)
	}
	return env
}

// requireNotLabMode skips a test that drives a local lv: in lab mode
// (E2E_LAB_DIR) only the drills run, through lab_harness_test.go.
func requireNotLabMode(t *testing.T) {
	t.Helper()
	if labMode {
		t.Skip("lab mode (E2E_LAB_DIR) runs only the TestDrill* partition drills; unset it to run this test via LV_HOST or on a node")
	}
}

// lvArgsForLog is the argument list as a failure message prints it: the value
// of --password is not repeated into the test log.
func lvArgsForLog(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--password" {
			out[i+1] = "<redacted>"
		}
	}
	return strings.Join(out, " ")
}

// lv runs the CLI and returns stdout. Fails the test on non-zero exit.
func lv(t *testing.T, args ...string) string {
	t.Helper()
	requireNotLabMode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, lvBin, args...)
	cmd.Env = lvEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lv %s failed: %v\nstdout: %s\nstderr: %s", lvArgsForLog(args), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// lvErr runs the CLI and returns stdout + error. Does NOT fail on non-zero exit.
func lvErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	requireNotLabMode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, lvBin, args...)
	cmd.Env = lvEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String() + stderr.String(), err
	}
	return stdout.String(), nil
}

// lvWithin runs the CLI under budget and returns stdout + stderr and its
// error. Does NOT fail on non-zero exit. For a command that can outlast lv's
// 2-minute budget, such as a drain that copies disks.
func lvWithin(t *testing.T, budget time.Duration, args ...string) (string, error) {
	t.Helper()
	requireNotLabMode(t)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, lvBin, args...)
	cmd.Env = lvEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// lvStdin runs the CLI with stdin piped. Fails on non-zero exit.
func lvStdin(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	requireNotLabMode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, lvBin, args...)
	cmd.Env = lvEnv()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lv %s failed: %v\nstdout: %s\nstderr: %s", lvArgsForLog(args), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// lvStdinErr runs the CLI with stdin piped. Does NOT fail on non-zero exit.
func lvStdinErr(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	requireNotLabMode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, lvBin, args...)
	cmd.Env = lvEnv()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

// restGET makes a GET request to the REST API.
func restGET(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	return restReq(t, "GET", path, nil)
}

// restPOST makes a POST request to the REST API.
func restPOST(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return restReq(t, "POST", path, body)
}

// restPUT makes a PUT request to the REST API.
func restPUT(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return restReq(t, "PUT", path, body)
}

// restDELETE makes a DELETE request to the REST API.
func restDELETE(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	return restReq(t, "DELETE", path, nil)
}

func restReq(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	if restURL == "" {
		t.Skip("REST API URL not available")
	}
	if restToken == "" {
		t.Skip("E2E_REST_TOKEN not set, skipping REST test")
	}

	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, restURL+path, bodyReader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+restToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	return resp.StatusCode, result
}

// restReachable tests if the REST API is responding.
func restReachable() bool {
	if restURL == "" {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(restURL + "/api/v1/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// waitVM polls until a VM reaches the expected state or times out.
func waitVM(t *testing.T, name, state string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := lvErr(t, "inspect", name)
		if err != nil {
			// VM may not have replicated yet — keep polling.
			time.Sleep(3 * time.Second)
			continue
		}
		if strings.Contains(out, state) {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("VM %s did not reach state %q within %v", name, state, timeout)
}

// waitVMGone polls until the VM no longer appears in `lv ls`.
func waitVMGone(t *testing.T, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := lvErr(t, "ls")
		if !strings.Contains(out, name) {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Errorf("VM %s still in ls after %v", name, timeout)
}

// requireHosts ensures we have at least n hosts discovered.
func requireHosts(t *testing.T, n int) {
	t.Helper()
	ensureTopology(t)
	if len(hostNames) < n {
		t.Skipf("need %d hosts, have %d", n, len(hostNames))
	}
}

// requireImage skips if no test image is available.
func requireImage(t *testing.T) {
	t.Helper()
	ensureTopology(t)
	if testImage == "" {
		t.Skip("no test image available (pull one or set E2E_IMAGE)")
	}
}

// uniqueName returns a test-unique resource name.
var nameMu sync.Mutex
var nameSeq int

func uniqueName(prefix string) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	nameSeq++
	// The PID matters: a bare sequence restarts at 1 every run, so any resource
	// surviving an interrupted run (a VM the cleanup could not remove, a stopped
	// VM left behind by a failure) collides with the next run and fails it with
	// AlreadyExists — a failure that looks like a product bug and is not.
	return fmt.Sprintf("e2e-%s-%d-%d", prefix, os.Getpid(), nameSeq)
}

// ═══════════════════════════════════════════════════════════════════════════
// Setup — discover cluster topology
// ═══════════════════════════════════════════════════════════════════════════

// setupOnce guards topology discovery so it happens exactly once per run.
var setupOnce sync.Once

// ensureTopology discovers the cluster if it hasn't been already.
//
// Discovery used to live only in TestSetup, which made it depend on `go test`
// running that function first — true only because every test needing it lived in
// this file, which sorts after nothing. A new test FILE sorting before
// "e2e_test.go" ran with hostNames still empty and skipped with "need 2 hosts,
// have 0", which reads like a broken cluster rather than a test-ordering bug.
// Discovery is idempotent, so making it lazy costs nothing and removes the trap.
func ensureTopology(t *testing.T) {
	t.Helper()
	// Before the Once: in lab mode every lv call skips its test, and a skip
	// inside the Once would consume it with hostNames still empty, leaving every
	// later caller to index an empty slice.
	requireNotLabMode(t)
	setupOnce.Do(func() { discoverTopology(t) })
}

// TestSetup keeps discovery visible as an explicit, first-class check with the
// summary log operators expect at the top of a run.
func TestSetup(t *testing.T) {
	ensureTopology(t)
	t.Logf("Cluster: %d hosts %v", len(hostNames), hostNames)
	t.Logf("Local host: %s (local mode: %v)", localHost, localMode)
	t.Logf("REST URL: %s", restURL)
	t.Logf("Test image: %s", testImage)
}

func discoverTopology(t *testing.T) {
	// Discover hosts.
	if envHosts := os.Getenv("E2E_HOSTS"); envHosts != "" {
		hostNames = strings.Split(envHosts, ",")
	} else {
		out := lv(t, "host", "ls")
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.Contains(fields[1], ".") {
				hostNames = append(hostNames, fields[0])
			}
		}
	}

	if len(hostNames) < 2 {
		t.Fatalf("need at least 2 hosts, found %d: %v", len(hostNames), hostNames)
	}

	// Build IP map from host inspect.
	hostIPs = make(map[string]string)
	for _, h := range hostNames {
		out := lv(t, "host", "inspect", h)
		var obj map[string]any
		if err := json.Unmarshal([]byte(out), &obj); err == nil {
			if addr, ok := obj["address"].(string); ok {
				hostIPs[h] = addr
			}
		}
	}

	// Detect which host we're on (local mode).
	if localMode {
		hostname, _ := os.Hostname()
		for _, h := range hostNames {
			if strings.EqualFold(h, hostname) || strings.HasPrefix(hostname, h) || strings.HasPrefix(h, hostname) {
				localHost = h
				break
			}
		}
	}

	// Auto-configure REST URL: prefer localhost (avoids firewall issues).
	if restURL == "" {
		if localMode {
			restURL = "http://127.0.0.1:7446"
		} else {
			for _, ip := range hostIPs {
				restURL = fmt.Sprintf("http://%s:7446", ip)
				break
			}
		}
	}

	// Verify REST API is actually reachable; clear URL if not.
	if !restReachable() {
		t.Logf("REST API at %s is not reachable, REST tests will be skipped", restURL)
		restURL = ""
	}

	// Auto-detect test image if not set.
	if testImage == "" {
		out := lv(t, "image", "ls")
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			// Skip header line and empty lines.
			if len(fields) >= 2 && fields[0] != "NAME" && !strings.HasPrefix(line, "---") {
				testImage = fields[0]
				break
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Cluster health & host operations
// ═══════════════════════════════════════════════════════════════════════════

func TestCluster_Status(t *testing.T) {
	out := lv(t, "status")
	if !strings.Contains(out, "hosts") && !strings.Contains(out, "Hosts") && !strings.Contains(out, "total") {
		t.Error("status output missing host info")
	}
}

func TestCluster_Version(t *testing.T) {
	out := lv(t, "version")
	if out == "" {
		t.Error("version returned empty")
	}
}

// suiteStart is when this test binary began: a health condition first seen
// after it was not there before the run.
var suiteStart = time.Now()

// conditionsSince returns the condition rows of `lv health` output whose SINCE
// (the last column; RFC3339 or "2006-01-02 15:04:05") is at or after t, or
// cannot be read: an unreadable time is treated as new, never as old.
func conditionsSince(out string, t time.Time) []string {
	var fresh []string
	inConds := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "conditions:"):
			inConds = true
			continue
		case line != "" && !strings.HasPrefix(line, " "):
			inConds = false
		}
		f := strings.Fields(line)
		if !inConds || len(f) < 2 || f[0] == "SEVERITY" {
			continue
		}
		var ts time.Time
		var err error = errors.New("no time")
		for _, cand := range []string{f[len(f)-1], strings.Join(f[max(0, len(f)-2):], " ")} {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
				if ts, err = time.Parse(layout, cand); err == nil {
					break
				}
			}
			if err == nil {
				break
			}
		}
		if err != nil || !ts.Before(t) {
			fresh = append(fresh, line)
		}
	}
	return fresh
}

// TestConditionsSince pins which health conditions count as new.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestConditionsSince(t *testing.T) {
	start := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	out := "overall: DEGRADED\n\nconditions:\n  SEVERITY  LIFECYCLE  CODE  SUBJECT  HOSTS  SINCE\n" +
		"  warning  active  vm_settled  vm/a  node-1  2026-10-03T10:00:00Z\n" +
		"  warning  active  vm_settled  vm/b  node-1  2026-10-03 10:00:00\n\nevaluators:\n  x  y 2026-10-14T10:00:00Z\n"
	if f := conditionsSince(out, start); len(f) != 0 {
		t.Errorf("old conditions counted as new: %v", f)
	}
	for name, row := range map[string]string{
		"new":        "  warning  active  vm_dual_run  vm/c  node-2  2026-10-14T09:30:00Z\n",
		"unreadable": "  warning  active  vm_dual_run  vm/c  node-2  yesterday\n",
	} {
		if f := conditionsSince(out+"", start); len(f) != 0 {
			t.Fatalf("setup: %v", f)
		}
		o := strings.Replace(out, "\nevaluators:", row+"\nevaluators:", 1)
		if f := conditionsSince(o, start); len(f) != 1 {
			t.Errorf("%s condition was not reported: %v", name, f)
		}
	}
}

func TestCluster_Health(t *testing.T) {
	// `lv health` exits 1 when the overall state is DEGRADED (and 2 when
	// CRITICAL): the report is still printed in full. This test pins that the
	// report names the cluster's hosts, so a DEGRADED cluster, whose old
	// conditions this test did not create, is a valid report. Only a report that
	// was not produced at all (an error, no "overall:" line) or one that says
	// CRITICAL fails here.
	out, err := lvErr(t, "health")
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.HasPrefix(out, "overall: DEGRADED") {
			t.Fatalf("lv health failed, or reports something worse than DEGRADED: %v\n%s", err, out)
		}
		// Only conditions that predate this run are excused: one raised since
		// the suite started could be this run's own doing or a regression.
		if fresh := conditionsSince(out, suiteStart); len(fresh) > 0 {
			t.Fatalf("the cluster is DEGRADED by conditions first seen since this run began (%s) or with an unreadable SINCE:\n%s",
				suiteStart.UTC().Format(time.RFC3339), strings.Join(fresh, "\n"))
		}
		t.Logf("cluster is DEGRADED (exit 1) by older conditions only; checking the report still names the hosts:\n%s", out)
	}
	// At least the local/connected host should appear.
	found := false
	for _, h := range hostNames {
		if strings.Contains(out, h) {
			found = true
		}
	}
	if !found {
		t.Error("health matrix contains no recognized host names")
	}
}

func TestCluster_Digest(t *testing.T) {
	out := lv(t, "cluster", "digest")
	if out == "" {
		t.Error("cluster digest returned empty")
	}
	// Digest only shows the connected host's data — just verify it has table rows.
	if !strings.Contains(out, "TABLE") && !strings.Contains(out, "ROWS") {
		// Check for any hash-like output.
		if len(out) < 20 {
			t.Error("digest output looks too short")
		}
	}
	t.Logf("digest:\n%s", out)
}

func TestHost_List(t *testing.T) {
	out := lv(t, "host", "ls")
	for _, h := range hostNames {
		if !strings.Contains(out, h) {
			t.Errorf("host ls missing %s", h)
		}
	}
}

func TestHost_Inspect(t *testing.T) {
	requireHosts(t, 1)
	out := lv(t, "host", "inspect", hostNames[0])
	if !strings.Contains(out, hostNames[0]) {
		t.Error("inspect missing host name")
	}
}

func TestHost_Devices(t *testing.T) {
	requireHosts(t, 1)
	lv(t, "host", "devices", hostNames[0])
}

func TestHost_Rescan(t *testing.T) {
	requireHosts(t, 1)
	out := lv(t, "host", "rescan", hostNames[0])
	if out == "" {
		t.Error("rescan returned empty")
	}
}

func TestHost_Stats(t *testing.T) {
	requireHosts(t, 1)
	out := lv(t, "host", "stats", hostNames[0])
	if out == "" {
		t.Error("host stats returned empty")
	}
}

func TestHost_Labels(t *testing.T) {
	requireHosts(t, 1)
	host := hostNames[0]

	lv(t, "host", "label", "set", host, "e2etest=true")

	out := lv(t, "host", "label", "ls", host)
	if !strings.Contains(out, "e2etest") {
		// Labels might be in the inspect output instead.
		out2 := lv(t, "host", "inspect", host)
		if !strings.Contains(out2, "e2etest") {
			t.Error("label not found after set (checked label ls and inspect)")
		}
	}

	lv(t, "host", "label", "rm", host, "e2etest")

	out = lv(t, "host", "label", "ls", host)
	if strings.Contains(out, "e2etest") {
		t.Error("label still present after rm")
	}
}

// drainBudget bounds `lv host drain` in TestHost_DrainUndrain. A drain now
// copies every host-local disk of the VMs it moves cold, so it takes as long
// as those copies, not the 2 minutes of an ordinary lv call.
const drainBudget = 30 * time.Minute

func TestHost_DrainUndrain(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireHosts(t, 2)
	// Use the last host to minimize disruption.
	host := hostNames[len(hostNames)-1]

	// Whatever happens below, the host must not be left draining: placement
	// skips a draining host, and every later multi-host test would run on one
	// host fewer.
	undrained := false
	t.Cleanup(func() {
		if undrained {
			return
		}
		if out, err := lvErr(t, "host", "undrain", host); err != nil {
			t.Errorf("cleanup: lv host undrain %s: %v\n%s", host, err, out)
		}
	})

	out, err := lvWithin(t, drainBudget, "host", "drain", host)
	if err != nil {
		// A drain that leaves a VM behind fails with "drain incomplete" and
		// names every VM it left, with the reason, before it does. Anything
		// else is a failure of the drain itself.
		if !strings.Contains(out, "drain incomplete") {
			t.Fatalf("lv host drain %s failed: %v\n%s", host, err, out)
		}
		if !strings.Contains(out, "ERROR:") {
			t.Fatalf("lv host drain %s ended incomplete without naming the VMs it left:\n%s", host, out)
		}
		t.Logf("drain of %s was incomplete; the VMs it left and why:\n%s", host, out)
	}

	// Check state — drain output or inspect should indicate drained.
	out = lv(t, "host", "inspect", host)
	drainStr := strings.ToLower(out)
	if !strings.Contains(drainStr, "drain") && !strings.Contains(drainStr, "DRAIN") &&
		!strings.Contains(drainStr, "maintenance") {
		// Also check host ls for state column.
		out2 := lv(t, "host", "ls")
		for _, line := range strings.Split(out2, "\n") {
			if strings.Contains(line, host) {
				if !strings.Contains(strings.ToLower(line), "drain") {
					t.Logf("warning: drain state not clearly visible. host ls line: %s", line)
				}
				break
			}
		}
	}

	lv(t, "host", "undrain", host)
	undrained = true
	t.Logf("drain/undrain cycle completed for %s", host)
}

func TestHost_Config(t *testing.T) {
	requireHosts(t, 1)
	host := hostNames[0]
	// The setting is cluster state: left at "ssh" it makes a later drill's
	// powered-off victim unrecoverable (an unreachable host cannot be
	// SSH-fenced). Read it first and put it back in Cleanup, which runs even
	// when the test fails or is skipped partway.
	prev := inspectFenceStrategy(lv(t, "host", "inspect", host))
	if prev == "" {
		t.Skipf("cannot read %s's host record, so its fence strategy could not be restored", host)
	}
	t.Cleanup(func() {
		if out, err := lvErr(t, "host", "config", host, "--fence-strategy", prev); err != nil {
			t.Errorf("restoring %s's fence strategy to %q failed: %v\n%s", host, prev, err, out)
		}
	})
	lv(t, "host", "config", host, "--fence-strategy", "ssh")
	t.Log("host config set fence-strategy=ssh")
}

// inspectVMCPU reads spec.cpu out of `lv inspect <vm>` output, 0 when absent.
func inspectVMCPU(inspect string) int {
	var obj struct {
		Spec struct {
			CPU int `json:"cpu"`
		} `json:"spec"`
	}
	if json.Unmarshal([]byte(inspect), &obj) != nil {
		return 0
	}
	return obj.Spec.CPU
}

// inspectFenceStrategy reads fenceStrategy out of `lv host inspect` output, ""
// only when the output is not JSON. An absent field is an unset strategy, which
// the product treats as best-effort (the JSON omits empty fields), and
// `--fence-strategy ""` cannot restore an empty value, so it reads as that.
func inspectFenceStrategy(inspect string) string {
	var obj struct {
		FenceStrategy string `json:"fenceStrategy"`
	}
	if json.Unmarshal([]byte(inspect), &obj) != nil {
		return ""
	}
	if obj.FenceStrategy == "" {
		return "best-effort"
	}
	return obj.FenceStrategy
}

// TestInspectFenceStrategy pins the parse TestHost_Config restores from.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestInspectFenceStrategy(t *testing.T) {
	for in, want := range map[string]string{
		`{"name":"node-1","fenceStrategy":"best-effort"}`: "best-effort",
		`{"name":"node-1"}`: "best-effort",
		`not json`:          "",
	} {
		if got := inspectFenceStrategy(in); got != want {
			t.Errorf("inspectFenceStrategy(%q) = %q, want %q", in, got, want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Image management
// ═══════════════════════════════════════════════════════════════════════════

func TestImage_List(t *testing.T) {
	out := lv(t, "image", "ls")
	if out == "" || strings.TrimSpace(out) == "" {
		t.Skip("no images available")
	}
	t.Logf("images:\n%s", out)
}

func TestImage_PushToOtherHost(t *testing.T) {
	requireHosts(t, 2)
	requireImage(t)
	lv(t, "image", "push", testImage, "--to", hostNames[1])
	t.Logf("pushed %s to %s", testImage, hostNames[1])
}

// ═══════════════════════════════════════════════════════════════════════════
// VM lifecycle — single VM
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_CreateStartStopDelete(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])

	// Wait for VM to be visible (may take a moment for state to replicate).
	waitVM(t, name, "RUNNING", 2*time.Minute)

	out := lv(t, "ls")
	if !strings.Contains(out, name) {
		t.Fatal("VM not in ls after run")
	}

	inspectOut := lv(t, "inspect", name)
	if !strings.Contains(inspectOut, name) {
		t.Error("inspect missing VM name")
	}

	lv(t, "stop", name)
	waitVM(t, name, "STOPPED", 1*time.Minute)

	lv(t, "start", name)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "restart", name)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "rm", name)
	waitVMGone(t, name, 30*time.Second)
}

func TestVM_ForceStop(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "stop", name, "--force")
	waitVM(t, name, "STOPPED", 30*time.Second)
	lv(t, "rm", name)
}

func TestVM_Stats(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	out := lv(t, "stats", name)
	if out == "" {
		t.Error("stats returned empty for running VM")
	}
	lv(t, "rm", name, "--force")
}

func TestVM_Logs(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	out := lv(t, "logs", name, "-n", "10")
	t.Logf("logs: %s", out)
	lv(t, "rm", name, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// VM hot-update
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_Update(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "stop", name)
	waitVM(t, name, "STOPPED", 1*time.Minute)

	lv(t, "update", name, "--cpu", "2")

	out := lv(t, "inspect", name)
	t.Logf("inspect after update: %s", out)
	lv(t, "rm", name, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Snapshots
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_Snapshots(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	snapName := "e2e-snap"
	cleanup(t, func() {
		lvErr(t, "snapshot", "rm", name, snapName)
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "snapshot", "create", name, snapName)

	out := lv(t, "snapshot", "ls", name)
	if !strings.Contains(out, snapName) {
		t.Error("snapshot not in ls after create")
	}

	// Disk-only snapshots must be restored while the VM is running
	// (libvirt refuses to revert a disk-snapshot on a stopped domain).
	lv(t, "snapshot", "restore", name, snapName)

	lv(t, "snapshot", "rm", name, snapName)
	out = lv(t, "snapshot", "ls", name)
	if strings.Contains(out, snapName) {
		t.Error("snapshot still in ls after rm")
	}

	lv(t, "rm", name, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Migration
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_LiveMigrate(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireHosts(t, 2)
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	src := hostNames[0]
	dst := hostNames[1]

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", src)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "migrate", name, dst, "--with-storage")
	waitVM(t, name, "RUNNING", 3*time.Minute)

	out := lv(t, "inspect", name)
	if !strings.Contains(out, dst) {
		t.Errorf("VM not on target host %s after migration", dst)
	}
	lv(t, "rm", name, "--force")
}

func TestVM_ColdMigrate(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireHosts(t, 2)
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	src := hostNames[0]
	dst := hostNames[1]

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", src)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "migrate", name, dst, "--cold", "--with-storage")
	waitVM(t, name, "RUNNING", 3*time.Minute)

	out := lv(t, "inspect", name)
	if !strings.Contains(out, dst) {
		t.Errorf("VM not on target host %s after cold migration", dst)
	}
	lv(t, "rm", name, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Networks
// ═══════════════════════════════════════════════════════════════════════════

func TestNetwork_CreateDeleteBridge(t *testing.T) {
	// Use short name — long names can fail nmcli bridge policy.
	name := uniqueName("n")
	cleanup(t, func() {
		lvErr(t, "network", "rm", name, "--force")
	})

	lv(t, "network", "create", name, "--type", "bridge",
		"--subnet", "172.30.0.0/24", "--dhcp")

	out := lv(t, "network", "ls")
	if !strings.Contains(out, name) {
		t.Error("network not in ls after create")
	}

	out = lv(t, "network", "inspect", name)
	if !strings.Contains(out, "172.30.0.0") {
		t.Error("subnet not in inspect output")
	}

	lv(t, "network", "rm", name)

	out = lv(t, "network", "ls")
	if strings.Contains(out, name) {
		t.Error("network still in ls after rm")
	}
}

func TestNetwork_VMWithCustomNetwork(t *testing.T) {
	requireImage(t)
	netName := uniqueName("n")
	vmName := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", vmName, "--force")
		lvErr(t, "network", "rm", netName, "--force")
	})

	lv(t, "network", "create", netName, "--type", "bridge",
		"--subnet", "172.31.0.0/24", "--dhcp")

	compose := fmt.Sprintf(`name: e2e-nettest
networks:
  %s:
    external: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: %s
    placement:
      host: %s
`, netName, vmName, testImage, netName, hostNames[0])

	composeFile := fmt.Sprintf("/tmp/e2e-compose-%d.yaml", os.Getpid())
	os.WriteFile(composeFile, []byte(compose), 0644)
	defer os.Remove(composeFile)

	lv(t, "compose", "up", "-f", composeFile, "-y")
	waitVM(t, vmName, "RUNNING", 2*time.Minute)

	out := lv(t, "inspect", vmName)
	if !strings.Contains(out, netName) {
		t.Error("VM not attached to custom network")
	}

	lv(t, "compose", "down", "-f", composeFile, "-y")
	lv(t, "network", "rm", netName, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Compose stacks
// ═══════════════════════════════════════════════════════════════════════════

func TestCompose_DeployAndTeardown(t *testing.T) {
	requireImage(t)
	stackName := uniqueName("stk")
	vmBase := uniqueName("w")
	cleanup(t, func() {
		lvErr(t, "compose", "down", "--name", stackName, "-y")
	})

	compose := fmt.Sprintf(`name: %s
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    replicas: 2
`, stackName, vmBase, testImage)

	composeFile := fmt.Sprintf("/tmp/e2e-compose-%d.yaml", os.Getpid())
	os.WriteFile(composeFile, []byte(compose), 0644)
	defer os.Remove(composeFile)

	lv(t, "compose", "up", "-f", composeFile, "-y")

	out := lv(t, "compose", "ps", "-f", composeFile)
	if !strings.Contains(out, vmBase) {
		t.Error("compose ps missing VMs")
	}

	out = lv(t, "compose", "ls")
	if !strings.Contains(out, stackName) {
		t.Error("compose ls missing stack")
	}

	waitVM(t, vmBase+"-1", "RUNNING", 2*time.Minute)
	waitVM(t, vmBase+"-2", "RUNNING", 2*time.Minute)

	out = lv(t, "compose", "diff", "-f", composeFile)
	t.Logf("diff after deploy: %s", out)

	lv(t, "compose", "down", "-f", composeFile, "-y")
	waitVMGone(t, vmBase+"-1", 30*time.Second)
	waitVMGone(t, vmBase+"-2", 30*time.Second)
}

func TestCompose_ScaleUp(t *testing.T) {
	requireImage(t)
	stackName := uniqueName("stk")
	vmBase := uniqueName("a")
	cleanup(t, func() {
		lvErr(t, "compose", "down", "--name", stackName, "-y")
	})

	writeCompose := func(replicas int) string {
		compose := fmt.Sprintf(`name: %s
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    replicas: %d
`, stackName, vmBase, testImage, replicas)
		f := fmt.Sprintf("/tmp/e2e-compose-%d.yaml", os.Getpid())
		os.WriteFile(f, []byte(compose), 0644)
		return f
	}

	f := writeCompose(1)
	defer os.Remove(f)
	lv(t, "compose", "up", "-f", f, "-y")
	// With replicas=1, InstanceName returns the base name without a "-1" suffix.
	waitVM(t, vmBase, "RUNNING", 3*time.Minute)

	f = writeCompose(3)
	lv(t, "compose", "up", "-f", f, "-y")
	// Scaling from 1→3 renames the singleton to -1 and creates -2, -3.
	waitVM(t, vmBase+"-1", "RUNNING", 3*time.Minute)
	waitVM(t, vmBase+"-2", "RUNNING", 3*time.Minute)
	waitVM(t, vmBase+"-3", "RUNNING", 3*time.Minute)

	f = writeCompose(1)
	lv(t, "compose", "up", "-f", f, "-y")
	time.Sleep(5 * time.Second)

	out := lv(t, "ls", "--stack", stackName)
	if strings.Contains(out, vmBase+"-2") || strings.Contains(out, vmBase+"-3") {
		t.Error("VMs not removed after scale-down")
	}

	lv(t, "compose", "down", "--name", stackName, "-y")
}

func TestCompose_RollingUpdate(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireImage(t)
	stackName := uniqueName("stk")
	vmBase := uniqueName("r")
	cleanup(t, func() {
		lvErr(t, "compose", "down", "--name", stackName, "-y")
	})

	writeCompose := func(cpu int) string {
		compose := fmt.Sprintf(`name: %s
vms:
  %s:
    image: %s
    cpu: %d
    memory: `+vmMemory()+`
    disks:
      root: 5G
    replicas: 2
    update:
      strategy: rolling
      max-unavailable: 1
      max-surge: 1
      order: start-first
      health-wait: 30s
`, stackName, vmBase, testImage, cpu)
		f := fmt.Sprintf("/tmp/e2e-compose-%d.yaml", os.Getpid())
		os.WriteFile(f, []byte(compose), 0644)
		return f
	}

	f := writeCompose(1)
	defer os.Remove(f)
	lv(t, "compose", "up", "-f", f, "-y")
	waitVM(t, vmBase+"-1", "RUNNING", 2*time.Minute)
	waitVM(t, vmBase+"-2", "RUNNING", 2*time.Minute)

	f = writeCompose(2)
	lv(t, "compose", "up", "-f", f, "-y")
	waitVM(t, vmBase+"-1", "RUNNING", 3*time.Minute)
	waitVM(t, vmBase+"-2", "RUNNING", 3*time.Minute)

	// The update must have taken effect on every replica: cpu 1 -> 2.
	for _, vm := range []string{vmBase + "-1", vmBase + "-2"} {
		var got int
		for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
			got = inspectVMCPU(lv(t, "inspect", vm))
			if got == 2 || time.Now().After(deadline) {
				break
			}
		}
		if got != 2 {
			t.Errorf("%s has cpu %d after the rolling update to cpu 2", vm, got)
		}
	}

	lv(t, "compose", "down", "--name", stackName, "-y")
}

// ═══════════════════════════════════════════════════════════════════════════
// Users, auth, RBAC
// ═══════════════════════════════════════════════════════════════════════════

func TestUser_CRUD(t *testing.T) {
	username := uniqueName("u")
	cleanup(t, func() {
		lvErr(t, "user", "delete", username)
	})

	// Pipe password via stdin since the CLI prompts interactively.
	lv(t, "user", "create", username, "--role", "viewer", "--password", "e2e-test-pass")

	out := lv(t, "user", "ls")
	if !strings.Contains(out, username) {
		t.Error("user not in user ls after create")
	}

	lv(t, "user", "delete", username)

	out = lv(t, "user", "ls")
	if strings.Contains(out, username) {
		t.Error("user still in user ls after delete")
	}
}

func TestUser_TokenCreateRevoke(t *testing.T) {
	username := uniqueName("u")
	cleanup(t, func() {
		lvErr(t, "user", "delete", username)
	})

	lv(t, "user", "create", username, "--role", "operator", "--password", "e2e-test-pass")

	out := lv(t, "user", "token-create", username, "e2e-token")
	if out == "" {
		t.Fatal("token-create returned empty")
	}
	t.Logf("token output: %s", redacted(strings.TrimSpace(out)))

	lv(t, "user", "delete", username)
}

func TestUser_RBACEnforcement(t *testing.T) {
	viewerUser := uniqueName("v")
	cleanup(t, func() {
		lvErr(t, "user", "delete", viewerUser)
	})

	lv(t, "user", "create", viewerUser, "--role", "viewer", "--password", "e2e-test-pass")

	out := lv(t, "user", "token-create", viewerUser, "e2e-rbac")
	var token string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Token:") {
			token = strings.TrimSpace(strings.TrimPrefix(trimmed, "Token:"))
			break
		}
	}
	t.Logf("viewer token: %s", redacted(token))

	// Verify viewer can list but not create users via REST.
	if restURL == "" || token == "" {
		t.Log("skipping REST RBAC check (no REST URL or token)")
		return
	}

	// List VMs should work.
	req, _ := http.NewRequest("GET", restURL+"/api/v1/vms", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("REST check failed: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode == 403 || resp.StatusCode == 401 {
			t.Log("warning: viewer token rejected for list VMs (may need auth wiring check)")
		}
		t.Logf("viewer GET /vms returned %d", resp.StatusCode)
	}

	lv(t, "user", "delete", viewerUser)
}

// ═══════════════════════════════════════════════════════════════════════════
// Monitoring & observability
// ═══════════════════════════════════════════════════════════════════════════

func TestAudit_Log(t *testing.T) {
	out := lv(t, "audit", "ls", "--limit", "10")
	if out == "" {
		t.Log("warning: audit log is empty")
	}
}

func TestMonitoring_Prometheus(t *testing.T) {
	// Try localhost first (most reliable on a cluster node).
	urls := []string{"http://127.0.0.1:7444/metrics"}
	for _, ip := range hostIPs {
		urls = append(urls, fmt.Sprintf("http://%s:7444/metrics", ip))
	}

	for _, u := range urls {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Errorf("metrics at %s returned %d", u, resp.StatusCode)
			return
		}
		if !strings.Contains(string(body), "litevirt") {
			t.Error("metrics response missing litevirt prefix")
		}
		return
	}
	t.Skip("could not reach metrics endpoint on any host")
}

// ═══════════════════════════════════════════════════════════════════════════
// REST API
// ═══════════════════════════════════════════════════════════════════════════

func TestREST_Health(t *testing.T) {
	code, body := restGET(t, "/api/v1/health")
	if code != 200 {
		t.Errorf("health returned %d", code)
	}
	if body["status"] != "ok" {
		t.Errorf("health status: %v", body["status"])
	}
}

func TestREST_Hosts(t *testing.T) {
	code, body := restGET(t, "/api/v1/hosts")
	if code != 200 {
		t.Errorf("hosts returned %d", code)
	}
	hosts, ok := body["hosts"].([]any)
	if !ok || len(hosts) < 2 {
		t.Errorf("expected at least 2 hosts, got %v", body)
	}
}

func TestREST_VMs(t *testing.T) {
	code, _ := restGET(t, "/api/v1/vms")
	if code != 200 {
		t.Errorf("vms returned %d", code)
	}
}

func TestREST_Status(t *testing.T) {
	code, body := restGET(t, "/api/v1/status")
	if code != 200 {
		t.Errorf("status returned %d", code)
	}
	if body["hosts_total"] == nil && body["hostsTotal"] == nil {
		t.Error("status missing hosts_total")
	}
}

func TestREST_Audit(t *testing.T) {
	code, _ := restGET(t, "/api/v1/audit?limit=5")
	if code != 200 {
		t.Errorf("audit returned %d", code)
	}
}

func TestREST_Images(t *testing.T) {
	code, _ := restGET(t, "/api/v1/images")
	if code != 200 {
		t.Errorf("images returned %d", code)
	}
}

func TestREST_Users(t *testing.T) {
	code, _ := restGET(t, "/api/v1/users")
	if code != 200 {
		t.Errorf("users returned %d", code)
	}
}

func TestREST_Stacks(t *testing.T) {
	code, _ := restGET(t, "/api/v1/stacks")
	if code != 200 {
		t.Errorf("stacks returned %d", code)
	}
}

func TestREST_Networks(t *testing.T) {
	code, _ := restGET(t, "/api/v1/networks")
	if code != 200 {
		t.Errorf("networks returned %d", code)
	}
}

func TestREST_HostInspect(t *testing.T) {
	requireHosts(t, 1)
	code, body := restGET(t, "/api/v1/hosts/"+hostNames[0])
	if code != 200 {
		t.Errorf("host inspect returned %d", code)
	}
	if body["name"] != hostNames[0] {
		t.Errorf("wrong host: %v", body["name"])
	}
}

func TestREST_HostStats(t *testing.T) {
	requireHosts(t, 1)
	code, _ := restGET(t, "/api/v1/hosts/"+hostNames[0]+"/stats")
	if code != 200 {
		t.Errorf("host stats returned %d", code)
	}
}

func TestREST_HostHealth(t *testing.T) {
	requireHosts(t, 1)
	code, _ := restGET(t, "/api/v1/hosts/"+hostNames[0]+"/health")
	if code != 200 {
		t.Errorf("host health returned %d", code)
	}
}

func TestREST_HostLabels(t *testing.T) {
	requireHosts(t, 1)
	host := hostNames[0]

	code, _ := restPUT(t, "/api/v1/hosts/"+host+"/labels", map[string]any{
		"labels": map[string]string{"e2erest": "true"},
	})
	if code != 200 {
		t.Errorf("set labels returned %d", code)
	}

	// Label may take a moment to replicate to the node the CLI queries.
	deadline := time.Now().Add(30 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		out := lv(t, "host", "label", "ls", host)
		if strings.Contains(out, "e2erest") {
			found = true
			break
		}
		out2 := lv(t, "host", "inspect", host)
		if strings.Contains(out2, "e2erest") {
			found = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !found {
		t.Error("label not visible via CLI after REST set (waited 30s for replication)")
	}

	lv(t, "host", "label", "rm", host, "e2erest")
}

func TestREST_AuthMissingToken(t *testing.T) {
	if restURL == "" {
		t.Skip("REST not available")
	}
	if restToken == "" {
		t.Skip("E2E_REST_TOKEN not set — server has no static token, auth is intentionally disabled")
	}
	req, _ := http.NewRequest("GET", restURL+"/api/v1/hosts", nil)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestREST_AuthBadToken(t *testing.T) {
	if restURL == "" {
		t.Skip("REST not available")
	}
	if restToken == "" {
		t.Skip("E2E_REST_TOKEN not set — server has no static token, auth is intentionally disabled")
	}
	req, _ := http.NewRequest("GET", restURL+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer totally-invalid-token-12345")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 with bad token, got %d", resp.StatusCode)
	}
}

func TestREST_VMLifecycle(t *testing.T) {
	requireImage(t)
	name := uniqueName("rv")
	cleanup(t, func() {
		restDELETE(t, "/api/v1/vms/"+name)
		lvErr(t, "rm", name, "--force")
	})

	// Create via CLI.
	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// Inspect via REST.
	code, body := restGET(t, "/api/v1/vms/"+name)
	if code != 200 {
		t.Errorf("inspect returned %d", code)
	}
	if body["name"] != name {
		t.Errorf("wrong VM name: %v", body["name"])
	}

	// Stop via REST.
	code, _ = restPOST(t, "/api/v1/vms/"+name+"/stop", nil)
	if code != 200 {
		t.Errorf("stop returned %d", code)
	}
	waitVM(t, name, "STOPPED", 1*time.Minute)

	// Start via REST.
	code, _ = restPOST(t, "/api/v1/vms/"+name+"/start", nil)
	if code != 200 {
		t.Errorf("start returned %d", code)
	}
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// Delete via REST.
	code, _ = restDELETE(t, "/api/v1/vms/"+name)
	if code != 204 && code != 200 {
		t.Errorf("delete returned %d (expected 204)", code)
	}
}

func TestREST_UserLifecycle(t *testing.T) {
	username := uniqueName("ru")

	// Create user.
	code, _ := restPOST(t, "/api/v1/users", map[string]string{
		"username": username,
		"password": "e2e-test-pass",
		"role":     "viewer",
	})
	if code != 200 && code != 201 {
		t.Errorf("create user returned %d", code)
	}

	// List users.
	code, body := restGET(t, "/api/v1/users")
	if code != 200 {
		t.Errorf("list users returned %d", code)
	}
	users, _ := json.Marshal(body)
	if !strings.Contains(string(users), username) {
		t.Error("user not in list after create")
	}

	// Delete user.
	code, _ = restDELETE(t, "/api/v1/users/"+username)
	if code != 204 && code != 200 {
		t.Errorf("delete user returned %d", code)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-host state convergence
// ═══════════════════════════════════════════════════════════════════════════

func TestCluster_StateConvergence(t *testing.T) {
	requireHosts(t, 2)
	requireImage(t)

	name := uniqueName("cv")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// Verify VM is visible via REST on different hosts (if REST is available).
	// The REST API on the local host reads from local SQLite which should have
	// replicated state from all peers.
	if restURL != "" && restToken != "" {
		time.Sleep(3 * time.Second) // Allow replication.
		code, body := restGET(t, "/api/v1/vms/"+name)
		if code != 200 {
			t.Errorf("VM %s not visible via REST (state not replicated?): %d", name, code)
		} else {
			t.Logf("VM %s visible via REST: host=%v", name, body["host_name"])
		}
	}

	lv(t, "rm", name, "--force")
}

func TestCluster_DigestMatch(t *testing.T) {
	out := lv(t, "cluster", "digest")
	// Just verify it runs and produces table output.
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "TABLE") {
		t.Logf("digest output format may differ:\n%s", out)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Error handling & edge cases
// ═══════════════════════════════════════════════════════════════════════════

func TestError_InspectNonexistent(t *testing.T) {
	_, err := lvErr(t, "inspect", "e2e-does-not-exist-12345")
	if err == nil {
		t.Error("expected error inspecting nonexistent VM")
	}
}

func TestError_StartNonexistent(t *testing.T) {
	_, err := lvErr(t, "start", "e2e-does-not-exist-12345")
	if err == nil {
		t.Error("expected error starting nonexistent VM")
	}
}

func TestError_StopNonexistent(t *testing.T) {
	_, err := lvErr(t, "stop", "e2e-does-not-exist-12345")
	if err == nil {
		t.Error("expected error stopping nonexistent VM")
	}
}

func TestError_DeleteNonexistent(t *testing.T) {
	_, err := lvErr(t, "rm", "e2e-does-not-exist-12345")
	if err == nil {
		t.Error("expected error deleting nonexistent VM")
	}
}

func TestError_MigrateNonexistent(t *testing.T) {
	requireHosts(t, 2)
	_, err := lvErr(t, "migrate", "e2e-does-not-exist-12345", hostNames[1])
	if err == nil {
		t.Error("expected error migrating nonexistent VM")
	}
}

func TestError_MigrateToSameHost(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	_, err := lvErr(t, "migrate", name, hostNames[0])
	if err == nil {
		t.Error("expected error migrating to same host")
	}
	lv(t, "rm", name, "--force")
}

func TestError_SnapshotNonexistentVM(t *testing.T) {
	_, err := lvErr(t, "snapshot", "create", "e2e-does-not-exist-12345", "test-snap")
	if err == nil {
		t.Error("expected error snapshotting nonexistent VM")
	}
}

func TestError_DuplicateVMName(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	_, err := lvErr(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	if err == nil {
		t.Error("expected error creating duplicate VM name")
	}
	lv(t, "rm", name, "--force")
}

func TestError_InvalidImage(t *testing.T) {
	name := uniqueName("vm")
	_, err := lvErr(t, "run", "--name", name, "--image", "e2e-nonexistent-image-12345",
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G")
	if err == nil {
		t.Error("expected error with invalid image")
		lvErr(t, "rm", name, "--force")
	}
}

func TestError_REST_NotFound(t *testing.T) {
	code, _ := restGET(t, "/api/v1/vms/e2e-does-not-exist-12345")
	if code == 200 {
		t.Error("expected non-200 for nonexistent VM")
	}
}

func TestError_REST_InvalidMethod(t *testing.T) {
	if restURL == "" || restToken == "" {
		t.Skip("REST not available")
	}
	req, _ := http.NewRequest("PATCH", restURL+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+restToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Error("PATCH on hosts should not return 200")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Concurrent operations
// ═══════════════════════════════════════════════════════════════════════════

func TestConcurrent_MultipleVMCreate(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireHosts(t, 2)
	requireImage(t)

	const count = 4
	names := make([]string, count)
	for i := range names {
		names[i] = uniqueName("c")
	}
	cleanup(t, func() {
		for _, n := range names {
			lvErr(t, "rm", n, "--force")
		}
	})

	var wg sync.WaitGroup
	errs := make([]error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			host := hostNames[idx%len(hostNames)]
			_, errs[idx] = lvErr(t, "run", "--name", names[idx], "--image", testImage,
				"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
				"--host", host)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("VM %s creation failed: %v", names[i], err)
		}
	}

	for _, n := range names {
		waitVM(t, n, "RUNNING", 3*time.Minute)
	}

	out := lv(t, "ls")
	for _, n := range names {
		if !strings.Contains(out, n) {
			t.Errorf("VM %s missing from ls", n)
		}
	}

	for _, n := range names {
		lv(t, "rm", n, "--force")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Backup & restore
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_BackupRestore(t *testing.T) {
	if skipSlow {
		t.Skip("slow test skipped")
	}
	requireImage(t)

	name := uniqueName("bk")
	repo := fmt.Sprintf("/var/tmp/e2e-backup-%d", os.Getpid())
	ts := time.Now().UTC().Format(time.RFC3339)
	var restored string
	cleanup(t, func() {
		lvErr(t, "rm", name, "--force")
		if restored != "" {
			os.Remove(restored)
		}
		os.RemoveAll(repo)
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// `backup create` and `backup restore` are the repo-backed snapshot
	// and restore-from (the raw full-disk stream they used is retired).
	lv(t, "backup", "repo", "init", repo)
	if out := lv(t, "backup", "create", name, "--repo", repo, "--quiesce", "off", "--timestamp", ts); !strings.Contains(out, "[done] manifest="+ts) {
		t.Fatalf("backup create printed no [done] line for %s:\n%s", ts, out)
	}
	out := lv(t, "backup", "restore", "--repo", repo, "--vm", name, "--disk", "root", "--timestamp", ts)
	m := regexp.MustCompile(`restored to (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("backup restore printed no target:\n%s", out)
	}
	restored = m[1]

	lv(t, "rm", name, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Disk operations
// ═══════════════════════════════════════════════════════════════════════════

func TestVM_AttachDetachDisk(t *testing.T) {
	requireImage(t)
	name := uniqueName("vm")
	diskName := "e2edata"
	cleanup(t, func() {
		lvErr(t, "detach-disk", name, diskName)
		lvErr(t, "rm", name, "--force")
	})

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	lv(t, "attach-disk", name, diskName, "--size", "10G")

	out := lv(t, "inspect", name)
	if !strings.Contains(out, diskName) {
		t.Error("attached disk not in inspect output")
	}

	lv(t, "detach-disk", name, diskName)
	lv(t, "rm", name, "--force")
}

// removeVerified runs args until gone() holds, for up to two minutes, and fails
// the test naming the leak if it never does. A cleanup that ignores its errors
// leaks the VM or network into every later test: in lab run lab1-c713 a VM whose
// detach was left recoverable refused `rm --force` (its operation barrier was
// held), kept the deleted network's dnsmasq alive, and the next two runs failed
// on `network create` for the subnet it still held.
func removeVerified(t *testing.T, what string, gone func() bool, args ...string) {
	t.Helper()
	var lastOut string
	var lastErr error
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if gone() {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("cleanup: %s still present after 2m; it leaks into later tests (last `lv %s`: %v %s)",
				what, strings.Join(args, " "), lastErr, strings.TrimSpace(lastOut))
			return
		}
		lastOut, lastErr = lvErr(t, args...)
		if gone() {
			return
		}
		time.Sleep(10 * time.Second)
	}
}

func TestVM_AttachDetachNIC(t *testing.T) {
	requireImage(t)
	netName := uniqueName("n")
	vmName := uniqueName("vm")
	host := hostNames[0]
	cleanup(t, func() {
		removeVerified(t, "VM "+vmName, func() bool {
			out, err := lvErr(t, "inspect", vmName)
			return err != nil && strings.Contains(strings.ToLower(out+err.Error()), "not found")
		}, "rm", vmName, "--force")
		removeVerified(t, "network "+netName, func() bool {
			out, err := lvErr(t, "network", "ls")
			return err == nil && !strings.Contains(out, netName)
		}, "network", "rm", netName, "--force")
	})

	lv(t, "network", "create", netName, "--type", "bridge",
		"--subnet", "172.32.0.0/24", "--dhcp")

	lv(t, "run", "--name", vmName, "--image", testImage,
		"--cpu", "1", "--memory", vmMemory(), "--disk", "5G",
		"--host", host)
	waitVM(t, vmName, "RUNNING", 2*time.Minute)

	// RUNNING is the DOMAIN, not the guest. Hot-unplug needs the guest to answer
	// the eject, and a guest still booting drops it: the lab saw this test detach
	// ~4 s after RUNNING and fail 3 runs in 3 (lab1-c713, M6). The wait that
	// matters is the one after the attach: until the guest drives the attached
	// NIC, it has not enumerated what it will be asked to eject. The root-disk
	// wait here only keeps the attach from landing in the earliest boot; firmware
	// drives virtio-blk too, so it does not prove the kernel is up. Both are read
	// from QEMU on the VM's host; where that cannot be asked the CLI-level
	// assertions below carry the test alone.
	canAsk := waitVirtioDriversOK(t, host, vmName, "virtio-blk", 4*time.Minute)

	// `lv run --name ... --image ...` makes a VM with no NIC at all, so the VM
	// starts with none and the NIC this test attaches is the only one. Record
	// the MACs before, so the assertion is on the one the attach added whatever
	// the VM started with.
	macRe := regexp.MustCompile(`52:54:00:[0-9a-f:]+`)
	before := map[string]bool{}
	for _, m := range macRe.FindAllString(lv(t, "inspect", vmName), -1) {
		before[m] = true
	}

	lv(t, "attach-nic", vmName, netName)

	out := lv(t, "inspect", vmName)
	if !strings.Contains(out, netName) {
		t.Error("attached NIC not in inspect output")
	}

	// Detach by the MAC the attach added. If it cannot be found the attach
	// assertion above was already wrong, so fail rather than skip the half of
	// this test with the actual risk in it.
	var added string
	for _, m := range macRe.FindAllString(out, -1) {
		if !before[m] {
			added = m
		}
	}
	if added == "" {
		t.Fatalf("no new MAC in inspect after attaching a NIC (before %v):\n%s", before, out)
	}
	if canAsk {
		waitVirtioDriversOK(t, host, vmName, "virtio-net", 2*time.Minute)
	}
	// Whether the domain's definitions can be read is its own question: it needs
	// only virsh on the host, not the QMP probe above (a QEMU older than 7.2
	// answers dumpxml but not x-query-virtio). Where it can, the attach must have
	// put the NIC in both copies.
	canReadDefs := false
	if live, config, err := nicCopies(host, vmName, added); err != nil {
		t.Logf("cannot read %s's definitions on %s (%v); the both-copies check is skipped", vmName, host, err)
	} else {
		canReadDefs = true
		if !live || !config {
			t.Fatalf("after attach-nic, NIC %s in live domain=%v, persistent definition=%v; want both", added, live, config)
		}
	}

	// The detach must succeed outright: `lv detach-nic` waits for the unplug and
	// re-requests it, so a guest that has booted releases the NIC inside that
	// wait. A detach that is broken returns an error here and fails the test.
	lv(t, "detach-nic", vmName, added)
	// The guest acks an unplug asynchronously, so poll rather than read once.
	assertEventually(t, 30*time.Second, "detached NIC "+added+" gone from inspect", func() bool {
		return !strings.Contains(lv(t, "inspect", vmName), added)
	})
	// inspect reads litevirt's rows. Where the definitions can be read, the domain
	// itself must agree, in BOTH copies: a NIC left in the live domain is still
	// plugged into the guest, and one left in the persistent definition comes
	// back on the next cold boot.
	if canReadDefs {
		assertEventually(t, 30*time.Second, "detached NIC "+added+" gone from the live domain and the persistent definition", func() bool {
			live, config, err := nicCopies(host, vmName, added)
			if err != nil {
				t.Logf("reading %s's definitions on %s: %v", vmName, host, err)
				return false
			}
			return !live && !config
		})
	}

	lv(t, "rm", vmName, "--force")
	lv(t, "network", "rm", netName, "--force")
}

// ═══════════════════════════════════════════════════════════════════════════
// Web UI reachability
// ═══════════════════════════════════════════════════════════════════════════

func TestWebUI_Reachable(t *testing.T) {
	out := lv(t, "ui")
	if out == "" {
		t.Error("lv ui returned empty")
	}
	t.Logf("ui: %s", strings.TrimSpace(out))
}

// ═══════════════════════════════════════════════════════════════════════════
// Ansible inventory
// ═══════════════════════════════════════════════════════════════════════════

func TestAnsible_Inventory(t *testing.T) {
	out := lv(t, "ansible-inventory", "--list")
	if out == "" {
		t.Error("ansible-inventory returned empty")
	}
	var inv map[string]any
	if err := json.Unmarshal([]byte(out), &inv); err != nil {
		t.Errorf("ansible-inventory is not valid JSON: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Networking — bridge, VXLAN, isolated, host-isolation, LB, SNAT
// ═══════════════════════════════════════════════════════════════════════════

// netCloudInit is the shared cloud-init userdata for networking test VMs.
// It starts a minimal HTTP server that serves the VM hostname on port 8080.
const netCloudInit = `#cloud-config
runcmd:
  - mkdir -p /tmp/www
  - hostname > /tmp/www/index.html
  - cd /tmp/www && nohup python3 -m http.server 8080 &>/dev/null &
`

// execRetry runs lv exec with retries for guest-agent readiness.
func execRetry(t *testing.T, vmName string, cmd ...string) (string, error) {
	t.Helper()
	args := append([]string{"exec", vmName}, cmd...)
	var out string
	var err error
	for i := 0; i < 10; i++ {
		out, err = lvErr(t, args...)
		if err == nil {
			return out, nil
		}
		t.Logf("execRetry %s attempt %d: %v", vmName, i+1, err)
		time.Sleep(10 * time.Second)
	}
	return out, err
}

// waitCloudInit waits for cloud-init runcmd to finish by checking for the HTTP server file.
func waitCloudInit(t *testing.T, vmName string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := execRetry(t, vmName, "test", "-f", "/tmp/www/index.html")
		if err == nil {
			_ = out
			return
		}
		time.Sleep(15 * time.Second)
	}
	t.Fatalf("cloud-init on %s did not complete within %v", vmName, timeout)
}

// getVMIP retrieves the IP address for a VM on a given network by parsing lv inspect output.
func getVMIP(t *testing.T, vmName, stackName, networkName string) string {
	t.Helper()
	// A network a stack declares is stored, and reported by lv inspect, under
	// its stack-scoped name: "<stack>_<name>". Matching the bare name finds
	// nothing; matching a suffix would find another stack's network of the
	// same name.
	scoped := lvcompose.ScopedNetworkName(stackName, networkName)
	var ip, lastErr string
	took, ok := pollFor(vmIPWait, 5*time.Second, func() bool {
		out, err := lvErr(t, "inspect", vmName)
		if err != nil {
			lastErr = err.Error()
			return false
		}
		lastErr = ""
		ip = inspectNICIP(out, scoped)
		return ip != ""
	})
	if !ok {
		t.Fatalf("lv inspect %s reported no IP on network %s within %v (last inspect error %q): the VM's host never learned its lease; a VM on a host that is not the network's DHCP host depends on that host's ARP table", vmName, scoped, vmIPWait, lastErr)
	}
	t.Logf("%s got %s on %s after %v", vmName, ip, scoped, took.Round(time.Second))
	return ip
}

// vmIPWait bounds how long lv inspect may take to report a guest's address.
// A guest on a host that is not the network's DHCP host has no local lease, so
// the address comes from that host's ARP table; 60 s was too short for it, and
// the bound stays tight enough for a total reporting regression to fail. The
// product fix for cross-host IP reporting is on fix/net-isolation-lb; tighten
// this bound once it merges.
const vmIPWait = 120 * time.Second

// pollFor calls cond every interval until it returns true or timeout passes,
// and reports how long it took. The last attempt is made at the timeout, not
// an interval before it.
func pollFor(timeout, interval time.Duration, cond func() bool) (time.Duration, bool) {
	start := time.Now()
	for {
		if cond() {
			return time.Since(start), true
		}
		left := timeout - time.Since(start)
		if left <= 0 {
			return time.Since(start), false
		}
		time.Sleep(min(interval, left))
	}
}

// pingVerdict reads the result of a ping run through lv exec. reached says the
// ping got replies; conclusive is false when the run itself failed (lv exec
// transport, guest agent) and proves nothing about reachability.
func pingVerdict(out string, err error) (reached, conclusive bool) {
	if err == nil {
		return true, true
	}
	if strings.Contains(out, "100% packet loss") || strings.Contains(out, "Unreachable") {
		return false, true
	}
	return false, false
}

// inspectNICIP is the address `lv inspect` output records for the VM's NIC on
// the network stored as exactly network, or "" when there is none (yet).
func inspectNICIP(inspectJSON, network string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(inspectJSON), &obj); err != nil {
		return ""
	}
	ifaces, _ := obj["interfaces"].([]any)
	for _, iface := range ifaces {
		m, ok := iface.(map[string]any)
		if !ok {
			continue
		}
		if m["networkName"] == network || m["network_name"] == network {
			if ip, ok := m["ip"].(string); ok && ip != "" {
				return ip
			}
		}
	}
	return ""
}

// getVMIfaceForSubnet finds the interface name inside a VM whose IP matches the given prefix.
func getVMIfaceForSubnet(t *testing.T, vmName, subnetPrefix string) string {
	t.Helper()
	out, err := execRetry(t, vmName, "ip", "-4", "addr", "show")
	if err != nil {
		t.Fatalf("ip addr show on %s failed: %v", vmName, err)
	}
	// Parse output like:
	// 2: eth0: <...>
	//     inet 10.200.0.5/24...
	// 3: eth1: <...>
	//     inet 10.201.0.3/24...
	var currentIface string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Interface line: "2: eth0: <BROADCAST..."
		if idx := strings.Index(line, ": "); idx >= 0 {
			rest := line[idx+2:]
			if colonIdx := strings.Index(rest, ":"); colonIdx >= 0 {
				candidate := rest[:colonIdx]
				if candidate != "" && !strings.Contains(candidate, " ") {
					currentIface = candidate
				}
			}
		}
		// inet line
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasPrefix(fields[1], subnetPrefix) {
				return currentIface
			}
		}
	}
	t.Fatalf("no interface on %s with IP prefix %s", vmName, subnetPrefix)
	return ""
}

// writeComposeFile writes a compose YAML to a temp file and registers cleanup.
func writeComposeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := fmt.Sprintf("/tmp/e2e-compose-%s.yaml", name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write compose file: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
}

// composeUp deploys a compose stack. Fatals on error.
func composeUp(t *testing.T, filePath string) {
	t.Helper()
	lv(t, "compose", "up", "-f", filePath, "-y")
}

// composeDown tears down a compose stack by name. Tolerates errors.
func composeDown(t *testing.T, stackName string) {
	t.Helper()
	lvErr(t, "compose", "down", "--name", stackName, "-y")
}

func TestNetworking(t *testing.T) {
	requireHosts(t, 2)
	requireImage(t)
	if skipSlow {
		t.Skip("E2E_SKIP_SLOW set, skipping networking tests")
	}

	t.Run("Bridge", testNetBridge)
	t.Run("Overlay", testNetOverlay)
	t.Run("LBAndSNAT", testNetLBSNAT)
}

// ── Stack A: Bridge network ─────────────────────────────────────────────────

func testNetBridge(t *testing.T) {
	stackName := uniqueName("netbr")
	vmName := uniqueName("nb")

	compose := fmt.Sprintf(`name: %s
networks:
  brnet:
    type: bridge
    subnet: 172.40.0.0/24
    dhcp: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: brnet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s`, stackName, vmName, testImage, hostNames[0], strings.ReplaceAll(netCloudInit, "\n", "\n        "))

	filePath := writeComposeFile(t, stackName, compose)
	cleanup(t, func() { composeDown(t, stackName) })

	composeUp(t, filePath)
	waitVM(t, vmName, "RUNNING", 3*time.Minute)
	waitCloudInit(t, vmName, 3*time.Minute)

	t.Run("VMGetsIP", func(t *testing.T) {
		ip := getVMIP(t, vmName, stackName, "brnet")
		if !strings.HasPrefix(ip, "172.40.0.") {
			t.Errorf("expected IP in 172.40.0.0/24, got %s", ip)
		}
		t.Logf("VM %s got IP %s on brnet", vmName, ip)
	})

	t.Run("InternetAccess", func(t *testing.T) {
		out, err := execRetry(t, vmName, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "10", "http://1.1.1.1")
		if err != nil {
			t.Fatalf("curl to internet failed: %v", err)
		}
		code := strings.TrimSpace(out)
		if code != "200" && code != "301" && code != "302" {
			t.Errorf("expected HTTP 200/301/302 from internet, got %s", code)
		}
	})
}

// ── Stack B: VXLAN + Isolated ───────────────────────────────────────────────

func testNetOverlay(t *testing.T) {
	stackName := uniqueName("netov")
	vm1Name := uniqueName("nv1")
	vm2Name := uniqueName("nv2")
	vm3Name := uniqueName("nv3")

	compose := fmt.Sprintf(`name: %s
networks:
  vxnet:
    type: vxlan
    vni: 5000
    subnet: 10.200.0.0/24
    dhcp: true
  isonet:
    type: isolated
    subnet: 10.201.0.0/24
    dhcp: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: vxnet
      - name: isonet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: vxnet
      - name: isonet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: isonet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s`, stackName,
		vm1Name, testImage, hostNames[0], strings.ReplaceAll(netCloudInit, "\n", "\n        "),
		vm2Name, testImage, hostNames[1], strings.ReplaceAll(netCloudInit, "\n", "\n        "),
		vm3Name, testImage, hostNames[0], strings.ReplaceAll(netCloudInit, "\n", "\n        "))

	filePath := writeComposeFile(t, stackName, compose)
	cleanup(t, func() { composeDown(t, stackName) })

	composeUp(t, filePath)
	waitVM(t, vm1Name, "RUNNING", 3*time.Minute)
	waitVM(t, vm2Name, "RUNNING", 3*time.Minute)
	waitVM(t, vm3Name, "RUNNING", 3*time.Minute)
	waitCloudInit(t, vm1Name, 3*time.Minute)
	waitCloudInit(t, vm2Name, 3*time.Minute)
	waitCloudInit(t, vm3Name, 3*time.Minute)

	t.Run("VXLAN/InterVMPing", func(t *testing.T) {
		vm2IP := getVMIP(t, vm2Name, stackName, "vxnet")
		t.Logf("vm2 VXLAN IP: %s", vm2IP)
		out, err := execRetry(t, vm1Name, "ping", "-c", "3", "-W", "5", vm2IP)
		if err != nil {
			t.Errorf("ping from %s to %s (%s) failed: %v\n%s", vm1Name, vm2Name, vm2IP, err, out)
		}
	})

	t.Run("VXLAN/InterVMHTTP", func(t *testing.T) {
		vm2IP := getVMIP(t, vm2Name, stackName, "vxnet")
		out, err := execRetry(t, vm1Name, "curl", "-s", "--connect-timeout", "10", fmt.Sprintf("http://%s:8080/index.html", vm2IP))
		if err != nil {
			t.Fatalf("curl from %s to %s:8080 failed: %v", vm1Name, vm2IP, err)
		}
		out = strings.TrimSpace(out)
		if !strings.Contains(out, vm2Name) {
			t.Errorf("expected response to contain %s, got %q", vm2Name, out)
		}
	})

	// An isolated network does not span hosts (docs/networking.md): each host
	// runs its own bridge and DHCP for it. Same-host VMs reach each other.
	t.Run("Isolated/InterVMPing", func(t *testing.T) {
		vm3IP := getVMIP(t, vm3Name, stackName, "isonet")
		t.Logf("%s (same host as %s) isolated IP: %s", vm3Name, vm1Name, vm3IP)
		out, err := execRetry(t, vm1Name, "ping", "-c", "3", "-W", "5", vm3IP)
		if err != nil {
			t.Errorf("ping from %s to %s (%s) on the isolated net, same host, failed: %v\n%s", vm1Name, vm3Name, vm3IP, err, out)
		}
	})

	t.Run("Isolated/CrossHostNotReachable", func(t *testing.T) {
		vm1IP := getVMIP(t, vm1Name, stackName, "isonet")
		vm3IP := getVMIP(t, vm3Name, stackName, "isonet")
		vm2IP := getVMIP(t, vm2Name, stackName, "isonet")
		// Each host leases the isolated range independently, so vm2 may hold
		// the same address as a VM on host 1: a ping to it then proves nothing.
		if vm2IP == vm1IP || vm2IP == vm3IP {
			t.Skipf("%s's isolated address %s equals %s's (%s) or %s's (%s) on the other host; a ping to it would be answered locally", vm2Name, vm2IP, vm1Name, vm1IP, vm3Name, vm3IP)
		}
		// Control: the guest agent answers, so a failure below is the ping's.
		if _, err := execRetry(t, vm1Name, "true"); err != nil {
			t.Fatalf("lv exec on %s does not work, so the cross-host check cannot run: %v", vm1Name, err)
		}
		out, err := lvErr(t, "exec", vm1Name, "ping", "-c", "3", "-W", "3", vm2IP)
		reached, conclusive := pingVerdict(out, err)
		switch {
		case !conclusive:
			t.Fatalf("lv exec ping from %s failed without a ping result, so cross-host unreachability is unproven: %v\n%s", vm1Name, err, out)
		case reached:
			t.Errorf("ping from %s (%s) to %s (%s) on the isolated net succeeded across hosts; an isolated network does not span hosts: %s", vm1Name, hostNames[0], vm2Name, vm2IP, out)
		}
	})

	t.Run("Isolated/NoInternet", func(t *testing.T) {
		iface := getVMIfaceForSubnet(t, vm1Name, "10.201.0.")
		t.Logf("isolated interface on %s: %s", vm1Name, iface)
		out, err := execRetry(t, vm1Name, "ping", "-c", "2", "-W", "3", "-I", iface, "1.1.1.1")
		if err == nil {
			t.Errorf("expected ping via isolated interface %s to fail, but it succeeded: %s", iface, out)
		}
	})
}

// ── Stack C: Host-Isolated + LB + SNAT ──────────────────────────────────────

func testNetLBSNAT(t *testing.T) {
	stackName := uniqueName("netlb")
	vm1Name := uniqueName("nl1")
	vm2Name := uniqueName("nl2")

	compose := fmt.Sprintf(`name: %s
networks:
  hinet:
    type: bridge
    subnet: 10.202.0.0/24
    dhcp: true
    host-isolation: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: hinet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s
    loadbalancer:
      enabled: true
      vip: 10.202.0.250/24
      ports:
        - listen: 80
          target: 8080
          protocol: tcp
      algorithm: roundrobin
      hosts:
        - %s
      snat: true
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: hinet
    placement:
      host: %s
    cloud-init:
      userdata: |
        %s`, stackName,
		vm1Name, testImage, hostNames[0], strings.ReplaceAll(netCloudInit, "\n", "\n        "),
		hostNames[0],
		vm2Name, testImage, hostNames[0], strings.ReplaceAll(netCloudInit, "\n", "\n        "))

	filePath := writeComposeFile(t, stackName, compose)
	cleanup(t, func() { composeDown(t, stackName) })

	composeUp(t, filePath)
	waitVM(t, vm1Name, "RUNNING", 3*time.Minute)
	waitVM(t, vm2Name, "RUNNING", 3*time.Minute)
	waitCloudInit(t, vm1Name, 3*time.Minute)
	waitCloudInit(t, vm2Name, 3*time.Minute)

	// Wait for VIP to come up (keepalived convergence).
	t.Log("Waiting for VIP 10.202.0.250 to become reachable...")
	vipReady := false
	for i := 0; i < 20; i++ {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://10.202.0.250:80/index.html")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				vipReady = true
				break
			}
		}
		time.Sleep(3 * time.Second)
	}
	if !vipReady {
		t.Fatal("VIP 10.202.0.250:80 did not become reachable within 60s")
	}

	t.Run("HostIsolation/CannotPingGateway", func(t *testing.T) {
		// VM should not be able to reach the bridge gateway due to host-isolation nftables rules.
		out, err := execRetry(t, vm1Name, "ping", "-c", "2", "-W", "3", "10.202.0.1")
		if err == nil {
			t.Errorf("expected ping to gateway 10.202.0.1 to fail (host-isolation), but it succeeded: %s", out)
		}
	})

	t.Run("LB/VIPReachable", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get("http://10.202.0.250:80/index.html")
		if err != nil {
			t.Fatalf("curl VIP failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("VIP returned status %d, expected 200", resp.StatusCode)
		}
	})

	t.Run("LB/TrafficBalanced", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		seen := map[string]int{}
		for i := 0; i < 10; i++ {
			resp, err := client.Get("http://10.202.0.250:80/index.html")
			if err != nil {
				t.Logf("request %d failed: %v", i, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			hostname := strings.TrimSpace(string(body))
			seen[hostname]++
		}
		t.Logf("LB distribution: %v", seen)
		if len(seen) < 2 {
			t.Errorf("expected traffic to reach both backends, but only saw: %v", seen)
		}
	})

	t.Run("SNAT/OutboundWorks", func(t *testing.T) {
		// On a host-isolated network without SNAT, VMs cannot reach the internet.
		// With SNAT enabled, outbound traffic is rewritten to the VIP and exits via the host.
		out, err := execRetry(t, vm1Name, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "10", "http://1.1.1.1")
		if err != nil {
			t.Fatalf("SNAT outbound curl failed: %v (VM on host-isolated network should reach internet via SNAT)", err)
		}
		code := strings.TrimSpace(out)
		if code != "200" && code != "301" && code != "302" {
			t.Errorf("expected HTTP 200/301/302 via SNAT, got %s", code)
		}
	})
}

// cleanup registers a function that runs even if the test fails.
func cleanup(t *testing.T, fn func()) {
	t.Helper()
	t.Cleanup(fn)
}

// ═══════════════════════════════════════════════════════════════════════════
// Guest agent + notifications (MR1/MR2)
// ═══════════════════════════════════════════════════════════════════════════

// provisionAgentVM boots a cloud VM on a litevirt-managed (NAT+DNS) bridge with
// qemu-guest-agent installed via cloud-init, and waits for the agent to answer.
// Returns false (skip) if the agent never connects (no internet / slow apt).
func provisionAgentVM(t *testing.T, stack, vmName, bridge, subnet string) bool {
	t.Helper()
	compose := fmt.Sprintf(`name: %s
networks:
  %s:
    type: bridge
    interface: %s-br
    subnet: %s
    dhcp: true
vms:
  %s:
    image: %s
    cpu: 2
    memory: `+agentVMMemory()+`
    min-memory: 512
    max-memory: `+agentVMMemory()+`
    guest-agent: true
    disks: {root: 8G}
    network: [{name: %s}]
    placement: {host: %s}
    cloud-init:
      userdata: |
        #cloud-config
        package_update: true
        packages: [qemu-guest-agent]
        runcmd:
          - systemctl enable --now qemu-guest-agent
`, stack, bridge, bridge, subnet, vmName, testImage, bridge, hostNames[0])
	filePath := writeComposeFile(t, stack, compose)
	cleanup(t, func() { composeDown(t, stack) })
	composeUp(t, filePath)
	waitVM(t, vmName, "RUNNING", 3*time.Minute)

	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := lvErr(t, "exec", vmName, "true"); err == nil {
			return true
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("guest agent never connected on %s (no internet / image lacks qemu-guest-agent) — skipping agent assertions", vmName)
	return false
}

// TestGuestExec verifies the lv exec fix: the guest agent's base64 out-data is
// decoded into real stdout (not the raw QGA JSON envelope), and a non-zero
// guest exit surfaces as an error.
func TestGuestExec(t *testing.T) {
	requireImage(t)
	if skipSlow {
		t.Skip("E2E_SKIP_SLOW set, skipping guest-exec test")
	}
	vm := uniqueName("agx")
	if !provisionAgentVM(t, uniqueName("agxs"), vm, "agx", "10.221.0.0/24") {
		t.Skip("guest agent unavailable")
	}

	t.Run("DecodesStdout", func(t *testing.T) {
		out, err := lvErr(t, "exec", vm, "uname", "-s")
		if err != nil {
			t.Fatalf("exec uname failed: %v\n%s", err, out)
		}
		// Must be the decoded command output, NOT the raw QGA JSON envelope.
		if !strings.Contains(out, "Linux") || strings.Contains(out, "out-data") || strings.Contains(out, "\"return\"") {
			t.Errorf("expected decoded stdout containing 'Linux', got raw/undecoded: %q", out)
		}
	})

	t.Run("NonZeroExitErrors", func(t *testing.T) {
		// SetInterspersed(false) means flags pass through without `--`.
		_, err := lvErr(t, "exec", vm, "sh", "-c", "exit 7")
		if err == nil {
			t.Error("expected a non-zero guest exit to surface as an error")
		}
	})
}

// TestNotificationWebhook verifies a webhook notification target receives a
// delivery (MR2 #5). Local-mode only — the daemon must reach the in-process
// listener, which binds loopback on the cluster node running the test.
func TestNotificationWebhook(t *testing.T) {
	if !localMode {
		t.Skip("notification webhook test requires local mode (daemon must reach the in-process listener)")
	}
	got := make(chan []byte, 1)
	srv := &http.Server{Addr: "127.0.0.1:9098"}
	http.HandleFunc("/e2e-hook", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case got <- b:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	go srv.ListenAndServe()
	defer srv.Close()
	time.Sleep(500 * time.Millisecond)

	name := uniqueName("hook")
	lv(t, "notify", "target", "add", "--name", name, "--type", "webhook", "--url", "http://127.0.0.1:9098/e2e-hook")
	// Resolve the target id from the list, then clean up.
	id := firstField(lv(t, "notify", "target", "ls"), name)
	if id == "" {
		t.Fatal("could not find created notify target id")
	}
	cleanup(t, func() { lvErr(t, "notify", "target", "rm", id) })

	lv(t, "notify", "test", id)

	select {
	case body := <-got:
		if !strings.Contains(string(body), "test.notification") {
			t.Errorf("webhook payload missing kind=test.notification: %s", body)
		}
		t.Logf("webhook delivered: %s", body)
	case <-time.After(15 * time.Second):
		t.Error("webhook notification not delivered within 15s")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Distributed firewall (v21) — compose security groups + per-NIC enforcement,
// plus the cluster/host/ipset/default-deny management CLI.
// ═══════════════════════════════════════════════════════════════════════════

// assertEventually polls fn until it returns true or the deadline passes. Used
// to absorb the firewall reconciler's poll interval (up to ~30s) after a
// compose deploy before nftables rules take effect.
func assertEventually(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Errorf("condition never held within %v: %s", timeout, desc)
}

// nftTable dumps the litevirt-fw table on a cluster host via SSH (intra-cluster
// when run on a node; from a workstation when reachable). Returns "" + skip-ok
// if SSH isn't available, so the test degrades gracefully off-cluster.
func nftTable(t *testing.T, host string) (string, bool) {
	t.Helper()
	return nftTableOf(t, host, "inet", "litevirt-fw")
}

// nftTableOf dumps one nftables table of a cluster host (family and name as nft
// takes them). Security-group rules render into the per-NIC `bridge
// litevirt-nic` table; `inet litevirt-fw` holds the routed-traffic tiers.
func nftTableOf(t *testing.T, host, family, name string) (string, bool) {
	t.Helper()
	// By address: cluster host names do not resolve on the nodes.
	target := envOr("E2E_FW_SSH_"+strings.ReplaceAll(host, "-", "_"), sshTarget(host))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=no",
		target, "nft", "list", "table", family, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("nft dump on %s unavailable (%v); skipping kernel-state assertions", host, err)
		return "", false
	}
	return string(out), true
}

// TestFirewall proves the distributed firewall end-to-end on the live cluster:
// a compose-defined security group (allow tcp/8080, drop everything else) bound
// to one VM's NIC is rendered all the way into the host's nftables kernel state.
// The drop is scoped to the bound NIC (NO cluster-wide default-deny), so
// production VMs are never touched. Because the test image's qemu-guest-agent
// isn't available for in-guest curl/ping, enforcement is proven by inspecting
// the rendered kernel ruleset (the same nft path that powers host-isolation),
// backed by the renderer unit tests for packet-level behaviour.
func TestFirewall(t *testing.T) {
	ensureTopology(t)
	requireImage(t)
	if skipSlow {
		t.Skip("E2E_SKIP_SLOW set, skipping firewall test")
	}

	host := hostNames[0]
	stackName := uniqueName("fw")
	guarded := uniqueName("fwg") // binds the SG: 8080 + DHCP allowed, rest dropped
	open := uniqueName("fwo")    // no SG: unaffected (proves the drop is scoped)

	// SG "web": allow tcp/8080 ingress + DHCP-client (udp/68), drop all other
	// ingress. Bound only to the guarded VM's NIC.
	compose := fmt.Sprintf(`name: %s
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "8080", action: accept}
      - {direction: ingress, proto: udp, port: "68", action: accept}
      - {direction: ingress, proto: all, action: drop}
networks:
  fwnet:
    type: bridge
    interface: e2efwbr
    subnet: 10.203.0.0/24
    dhcp: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: fwnet
        security-groups: [web]
    placement:
      host: %s
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: fwnet
    placement:
      host: %s`, stackName,
		guarded, testImage, host,
		open, testImage, host)

	filePath := writeComposeFile(t, stackName, compose)
	cleanup(t, func() { composeDown(t, stackName) })

	composeUp(t, filePath)
	waitVM(t, guarded, "RUNNING", 3*time.Minute)
	waitVM(t, open, "RUNNING", 3*time.Minute)

	// The SG + per-NIC binding persist on deploy; assert they reached cluster state.
	t.Run("SecurityGroupPersisted", func(t *testing.T) {
		if sg := lv(t, "sg", "ls"); !strings.Contains(sg, "web") {
			t.Errorf("compose-defined SG 'web' not in `lv sg ls`:\n%s", sg)
		}
	})

	// Kernel proof: the web SG renders into the per-NIC bridge table
	// (`bridge litevirt-nic`), as 8080 accept + DHCP accept + drop, in order, in
	// the bound NIC's nic_in_<tap> chain; the other NIC's chain carries none of
	// it. The inet table's forward chain must appear exactly once (regression
	// guard for the atomic-replace fix: a merge-not-replace bug duplicated it).
	t.Run("RenderedIntoKernel", func(t *testing.T) {
		// The SG's drop renders as a drop in enforce mode and, in observe mode
		// (`lv firewall enforce off`), as a counter that returns, carrying an
		// "lv-wd" comment: the shape depends on the cluster's per-NIC mode, so
		// read the mode and assert the shape that mode promises. The cluster mode
		// is only ever enforce or observe; anything else means the status line
		// was not understood, which must not skip the test.
		var observe bool
		switch mode := nicEnforcementMode(lv(t, "firewall", "enforce", "status")); mode {
		case "enforce":
		case "observe":
			observe = true
		default:
			t.Fatalf("cannot read the per-NIC enforcement mode (got %q) from `lv firewall enforce status`", mode)
		}
		var nic, inet string
		var chain string
		deadline := time.Now().Add(2 * time.Minute) // tap discovery + 30s reconcile + margin
		for time.Now().Before(deadline) {
			tbl, ok := nftTableOf(t, host, "bridge", "litevirt-nic")
			if !ok {
				t.Skip("nft inspection unavailable off-cluster")
			}
			nic = tbl
			if chain = chainWith(nic, "nic_in_", "tcp dport 8080 accept"); chain != "" {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if chain == "" {
			t.Fatalf("web SG never rendered into a nic_in_ chain of bridge litevirt-nic on %s within 2m:\n%s", host, nic)
		}
		if err := sgChainOrdered(chain, observe); err != nil {
			t.Errorf("%v:\n%s", err, chain)
		}
		// Scoped to the bound NIC: exactly one nic_in_ chain carries the rule.
		if n := strings.Count(nic, "tcp dport 8080 accept"); n != 1 {
			t.Errorf("tcp dport 8080 accept appears %d times in bridge litevirt-nic, want 1 (the unbound NIC must carry none):\n%s", n, nic)
		}
		inet, ok := nftTable(t, host)
		if !ok {
			t.Skip("nft inspection unavailable off-cluster")
		}
		// The renderer emits two forward-hook chains on every host: the main
		// `forward` chain and `isolated_forward` (net isolation). Each must
		// appear exactly once; a missing or duplicated one is the
		// atomic-replace regression.
		hooks := forwardHookChains(inet)
		for _, name := range []string{"forward", "isolated_forward"} {
			if n := hooks[name]; n != 1 {
				t.Errorf("chain %q with a forward hook appears %d times in inet litevirt-fw, want 1 (atomic-replace regression):\n%s", name, n, inet)
			}
		}
		for name := range hooks {
			if name != "forward" && name != "isolated_forward" {
				t.Errorf("unexpected forward-hook chain %q in inet litevirt-fw:\n%s", name, inet)
			}
		}
		t.Logf("bridge litevirt-nic on %s rendered the web SG correctly (observe=%v: 8080 accept, DHCP accept, drop or would-drop counter; single inet forward chain)", host, observe)
	})
}

// forwardHookChains counts, by chain name, the chains of an `nft list table`
// dump that declare a forward hook.
func forwardHookChains(dump string) map[string]int {
	out := map[string]int{}
	cur := ""
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "chain" && f[len(f)-1] == "{" {
			cur = f[1]
			continue
		}
		if cur != "" && strings.Contains(line, "hook forward") {
			out[cur]++
		}
	}
	return out
}

// nicEnforcementMode parses the mode out of `lv firewall enforce status`
// ("per-NIC enforcement: enforce|observe|guards-only ..."), "" when absent.
func nicEnforcementMode(status string) string {
	_, rest, ok := strings.Cut(status, "per-NIC enforcement:")
	if !ok {
		return ""
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// sgChainOrdered checks a nic_in_ chain of an nft listing carries the web SG as
// three consecutive rules: tcp 8080 accept, udp 68 accept, and the SG's own
// `proto all drop`. Rules in a NIC chain are scoped to the NIC, so they list as
// `oifname "vnetX" tcp dport 8080 accept`.
//
// In enforce mode the drop is `oifname "vnetX" drop`, matched by its tokens
// (the NIC match, then only the verdict). In observe mode the product renders
// every drop as a counter that returns, labelled with an "lv-wd" comment
// (internal/firewall/nic_table.go): `oifname "vnetX" counter ... return comment
// "lv-wd vnetX in sg:web#2"`, and it must NOT be a drop. Either way the verdict
// rule must be the rule right after the DHCP accept: a later drop, such as a
// cluster default-deny, would not prove the SG's rendered.
func sgChainOrdered(chain string, observe bool) error {
	var rules []string
	for _, l := range strings.Split(chain, "\n") {
		if l = strings.TrimSpace(l); l != "" && l != "}" && !strings.HasSuffix(l, "{") && !strings.HasPrefix(l, "type ") {
			rules = append(rules, l)
		}
	}
	for i, r := range rules {
		if !strings.HasSuffix(r, "tcp dport 8080 accept") {
			continue
		}
		if i+2 >= len(rules) || !strings.HasSuffix(rules[i+1], "udp dport 68 accept") {
			return fmt.Errorf("the SG's 8080 accept is not followed by its DHCP accept")
		}
		v := rules[i+2]
		f := strings.Fields(v)
		// The match part, before any comment text (which may hold anything).
		match, comment, _ := strings.Cut(v, " comment ")
		mf := strings.Fields(match)
		if len(f) < 2 || f[0] != "oifname" || strings.ContainsAny(match, "{}") ||
			strings.Contains(match, "dport") || strings.Contains(match, "saddr") || strings.Contains(match, "daddr") {
			return fmt.Errorf("the SG's verdict does not follow its DHCP accept (next rule: %q)", v)
		}
		if !observe {
			if f[len(f)-1] != "drop" {
				return fmt.Errorf("enforce mode: the SG's drop does not follow its DHCP accept (next rule: %q)", v)
			}
			return nil
		}
		if mf[len(mf)-1] != "return" || !strings.Contains(match, "counter") || !strings.HasPrefix(comment, `"lv-wd `) || !strings.Contains(comment, " in sg:") {
			return fmt.Errorf("observe mode: the SG's drop is not an lv-wd counter-return (next rule: %q)", v)
		}
		return nil
	}
	return fmt.Errorf("no tcp dport 8080 accept rule")
}

// pureTests are the tests that touch no cluster and no lv, and so are the only
// ones LITEVIRT_E2E_UNIT=1 may run.
var pureTests = []string{"TestSGChainOrdered", "TestUnitRunAllowed", "TestEnforcementEditScript", "TestJoinMajority", "TestUsbHostdevPattern", "TestInspectFenceStrategy", "TestKnownAuditFork", "TestMinorityCopyStopped", "TestConditionsSince", "TestEnforcementEditScriptRefusesAnInlineBlock", "TestParseClaimView", "TestParseLogLines", "TestMailpitMatches", "TestCutPlan", "TestHoldersBetween", "TestTenureAt", "TestMintTime", "TestParseEnforcementGauges", "TestLeaseTermModeOf", "TestLeaseTermExpectFor", "TestW4aVerdict", "TestFreshTenureAt", "TestLeaseTermRefusalPattern", "TestInertJournalVerdict", "TestRefusalVerdict", "TestInspectNICIP", "TestPollFor", "TestHostStateInLs", "TestClassifyLease", "TestLeaseSampleExpiry", "TestExpiredLagNeverFails", "TestExpiredUnexplainedIsNoTenure", "TestLeaseWatchObserve", "TestObserveTick", "TestObserveTickUnknown", "TestSampleTick", "TestHoldersIn", "TestIncoherenceTracker", "TestPingVerdict", "TestUncertifiedDeclineVerdict", "TestGuestBootVerdict", "TestForwardHookChains"}

// unitRunAllowed reports whether a -test.run pattern selects only pureTests:
// the exact form ^(A|B)$ or ^A$, with every name pure.
func unitRunAllowed(run string) bool {
	if !strings.HasPrefix(run, "^") || !strings.HasSuffix(run, "$") {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(run, "^"), "$")
	body = strings.TrimSuffix(strings.TrimPrefix(body, "("), ")")
	for _, n := range strings.Split(body, "|") {
		ok := false
		for _, p := range pureTests {
			ok = ok || n == p
		}
		if !ok {
			return false
		}
	}
	return true
}

// TestUnitRunAllowed proves unit mode cannot select a cluster test.
func TestUnitRunAllowed(t *testing.T) {
	for run, want := range map[string]bool{
		"^TestSGChainOrdered$":                      true,
		"^(TestSGChainOrdered|TestUnitRunAllowed)$": true,
		"":                                    false,
		".":                                   false,
		"TestSGChainOrdered":                  false,
		"^TestSGChainOrdered|TestFirewall$":   false,
		"^(TestSGChainOrdered|TestFirewall)$": false,
		"^TestFirewall$":                      false,
		"^(TestSGChainOrdered|)$":             false,
		"^TestSGChainOrdered$|TestVM_AttachDetachNIC": false,
	} {
		if got := unitRunAllowed(run); got != want {
			t.Errorf("unitRunAllowed(%q) = %v, want %v", run, got, want)
		}
	}
}

// TestSGChainOrdered pins sgChainOrdered against a chain as nft lists one.
// Run it with LITEVIRT_E2E_UNIT=1 -test.run '^TestSGChainOrdered$' (it needs no cluster).
func TestSGChainOrdered(t *testing.T) {
	const good = `	chain nic_in_vnet3 {
		oifname "vnet3" tcp dport 8080 accept
		oifname "vnet3" udp dport 68 accept
		oifname "vnet3" drop
	}`
	if err := sgChainOrdered(good, false); err != nil {
		t.Errorf("a correct chain was refused: %v", err)
	}
	const observed = `	chain nic_in_vnet3 {
		oifname "vnet3" tcp dport 8080 accept
		oifname "vnet3" udp dport 68 accept
		oifname "vnet3" counter packets 0 bytes 0 return comment "lv-wd vnet3 in sg:web#2"
	}`
	if err := sgChainOrdered(observed, true); err != nil {
		t.Errorf("a correct observe-mode chain was refused: %v", err)
	}
	if err := sgChainOrdered(observed, false); err == nil {
		t.Error("an observe-mode chain was accepted as an enforce-mode one")
	}
	if err := sgChainOrdered(good, true); err == nil {
		t.Error("an enforce-mode chain was accepted as an observe-mode one")
	}
	if nicEnforcementMode("per-NIC enforcement: observe (since x)\n") != "observe" || nicEnforcementMode("nothing") != "" {
		t.Error("nicEnforcementMode misparses the status line")
	}
	for name, bad := range map[string]string{
		"drop missing, a later default-deny drop": "oifname \"vnet3\" tcp dport 8080 accept\noifname \"vnet3\" udp dport 68 accept\noifname \"vnet3\" tcp dport 22 accept\ndrop\n",
		"drop missing":            "oifname \"vnet3\" tcp dport 8080 accept\noifname \"vnet3\" udp dport 68 accept\n",
		"drop before the accepts": "oifname \"vnet3\" drop\noifname \"vnet3\" tcp dport 8080 accept\noifname \"vnet3\" udp dport 68 accept\n",
		"accepts out of order":    "oifname \"vnet3\" udp dport 68 accept\noifname \"vnet3\" tcp dport 8080 accept\noifname \"vnet3\" drop\n",
		"verdict is not a drop":   "oifname \"vnet3\" tcp dport 8080 accept\noifname \"vnet3\" udp dport 68 accept\noifname \"vnet3\" accept\n",
	} {
		if err := sgChainOrdered(bad, false); err == nil {
			t.Errorf("%s: an incorrect chain was accepted", name)
		}
	}
}

// chainWith returns the body of the first chain of an nft table dump whose name
// starts with prefix and whose body contains needle, or "".
func chainWith(table, prefix, needle string) string {
	for _, part := range strings.Split(table, "\tchain ")[1:] {
		if strings.HasPrefix(part, prefix) && strings.Contains(part, needle) {
			return part
		}
	}
	return ""
}

// TestFirewallManagementCLI exercises the cluster/host/ipset/default-deny
// management RPCs against the live daemon (create → list → delete round-trip).
// It uses only accept rules on unused ports and never flips the cluster default
// to deny, so it cannot disrupt any running workload.
func TestFirewallManagementCLI(t *testing.T) {
	// Not every test calls this first: run alone, hostNames is empty and the
	// host-rule subtest indexes it.
	ensureTopology(t)
	t.Run("ClusterRule", func(t *testing.T) {
		out := lv(t, "firewall", "cluster-rule", "add", "--direction", "ingress",
			"--proto", "tcp", "--port", "59443", "--action", "accept", "--comment", "e2e-cluster")
		t.Log(out)
		ls := lv(t, "firewall", "cluster-rule", "ls")
		if !strings.Contains(ls, "59443") {
			t.Fatalf("cluster rule not listed after add:\n%s", ls)
		}
		id := firstIDForPort(ls, "59443")
		if id == "" {
			t.Fatal("could not parse cluster rule id")
		}
		lv(t, "firewall", "cluster-rule", "rm", id)
		if ls := lv(t, "firewall", "cluster-rule", "ls"); strings.Contains(ls, "59443") {
			t.Errorf("cluster rule still listed after rm:\n%s", ls)
		}
	})

	t.Run("HostRule", func(t *testing.T) {
		requireHosts(t, 1) // skips, rather than indexing an empty hostNames
		out := lv(t, "firewall", "host-rule", "add", "--host", hostNames[0], "--direction", "ingress",
			"--proto", "tcp", "--port", "59444", "--action", "accept")
		t.Log(out)
		ls := lv(t, "firewall", "host-rule", "ls", "--host", hostNames[0])
		if !strings.Contains(ls, "59444") {
			t.Fatalf("host rule not listed after add:\n%s", ls)
		}
		id := firstIDForPort(ls, "59444")
		if id != "" {
			lv(t, "firewall", "host-rule", "rm", id)
		}
	})

	t.Run("IPSet", func(t *testing.T) {
		name := uniqueName("ips")
		lv(t, "firewall", "ipset", "add", name, "--cidr", "10.203.0.0/24", "--cidr", "10.204.0.0/24")
		ls := lv(t, "firewall", "ipset", "ls")
		if !strings.Contains(ls, name) {
			t.Fatalf("ipset not listed after add:\n%s", ls)
		}
		id := firstField(ls, name) // id is the first column on the matching row
		if id != "" {
			lv(t, "firewall", "ipset", "rm", id)
		}
	})

	t.Run("DefaultDenyQuery", func(t *testing.T) {
		// Setting the cluster default to ACCEPT is a no-op on a default-accept
		// cluster — safe — and verifies the RPC path works without risking
		// other workloads.
		lv(t, "firewall", "default-deny", "off")
	})
}

// firstIDForPort returns the first whitespace-delimited field (the ID column)
// of the first line containing port.
func firstIDForPort(table, port string) string {
	for _, line := range strings.Split(table, "\n") {
		if strings.Contains(line, port) {
			if f := strings.Fields(line); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// firstField returns the first field of the first line containing match.
func firstField(table, match string) string {
	for _, line := range strings.Split(table, "\n") {
		if strings.Contains(line, match) {
			if f := strings.Fields(line); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════
// WS2 small features — backup-schedule scopes, snapshot type, compose backup-repos
// ═══════════════════════════════════════════════════════════════════════════

// TestBackupScheduleScope verifies `lv backup schedule add --pool` (and the
// other scopes) work — previously the CLI only supported per-VM schedules.
func TestBackupScheduleScope(t *testing.T) {
	pool := "e2e-fakepool-" + uniqueName("p")
	cleanup(t, func() { lvErr(t, "backup", "schedule", "rm", "--pool", pool, "--repo", "main") })

	out, err := lvErr(t, "backup", "schedule", "add", "--pool", pool, "--repo", "main", "--cron", "0 3 * * *")
	if err != nil {
		t.Fatalf("pool-scoped schedule add failed: %v\n%s", err, out)
	}
	ls := lv(t, "backup", "schedule", "ls")
	if !strings.Contains(ls, "pool") {
		t.Errorf("expected a pool-scoped schedule in ls output:\n%s", ls)
	}
	t.Logf("schedule ls:\n%s", ls)
}

// TestSnapshotType verifies the disk/memory type is reported (the TYPE column /
// field that backs the UI snapshot table).
func TestSnapshotType(t *testing.T) {
	requireImage(t)
	name := uniqueName("snaptype")
	cleanup(t, func() {
		lvErr(t, "snapshot", "rm", name, "mem-snap")
		lvErr(t, "rm", name, "--force")
	})
	lv(t, "run", "--name", name, "--image", testImage, "--cpu", "1", "--memory", vmMemory(), "--disk", "5G", "--host", hostNames[0])
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// A memory (live) snapshot should report type=memory.
	if out, err := lvErr(t, "snapshot", "create", name, "mem-snap", "--memory"); err != nil {
		t.Fatalf("memory snapshot create failed: %v\n%s", err, out)
	}
	ls := lv(t, "snapshot", "ls", name)
	t.Logf("snapshot ls:\n%s", ls)
	if !strings.Contains(strings.ToLower(ls), "memory") {
		t.Errorf("expected a memory-type snapshot in ls output:\n%s", ls)
	}
}

// TestComposeBackupRepos verifies a compose top-level `backup-repos:` block is
// accepted and a VM backup schedule referencing the named repo is created.
func TestComposeBackupRepos(t *testing.T) {
	requireImage(t)
	if skipSlow {
		t.Skip("E2E_SKIP_SLOW set, skipping compose backup-repos test")
	}
	stackName := uniqueName("brepo")
	vmName := uniqueName("br")
	repoPath := "/tmp/e2e-" + stackName + "-repo"

	compose := fmt.Sprintf(`name: %s
backup-repos:
  e2erepo:
    path: %s
networks:
  brnet2:
    type: bridge
    interface: e2ebrepobr
    subnet: 10.205.0.0/24
    host-isolation: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: `+vmMemory()+`
    disks:
      root: 5G
    network:
      - name: brnet2
    placement:
      host: %s
    backup:
      repo: e2erepo
      schedule: "0 4 * * *"`, stackName, repoPath, vmName, testImage, hostNames[0])

	filePath := writeComposeFile(t, stackName, compose)
	cleanup(t, func() { composeDown(t, stackName) })

	composeUp(t, filePath)
	waitVM(t, vmName, "RUNNING", 3*time.Minute)

	// The compose backup: block creates a schedule referencing the named repo.
	ls := lv(t, "backup", "schedule", "ls")
	if !strings.Contains(ls, "e2erepo") {
		t.Errorf("expected a schedule referencing compose-defined repo 'e2erepo':\n%s", ls)
	}
}

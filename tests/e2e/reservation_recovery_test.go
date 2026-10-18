package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Host reservations on a live cluster: what `lv host inspect` reports, that a
// grown-then-deleted VM leaves no releasable reservation behind for long, and
// the manual release's refusals. The release of a live stale reservation is
// covered by tests/fleet (it cannot be staged here without a database write).

// inspectedReservations is the part of `lv host inspect` JSON this file reads.
type inspectedReservations struct {
	Reservations []struct {
		OperationID string `json:"operationId"`
		VM          string `json:"vm"`
		Vcpu        int    `json:"vcpu"`
		MemoryMib   int    `json:"memoryMib"`
		State       string `json:"state"`
		Detail      string `json:"detail"`
	} `json:"reservations"`
	ReservedCPU    int  `json:"reservedCpu"`
	ReservedMemMib int  `json:"reservedMemMib"`
	Partial        bool `json:"reservationsPartial"`
}

func inspectReservations(t *testing.T, host string) inspectedReservations {
	t.Helper()
	out := lv(t, "host", "inspect", host)
	var got inspectedReservations
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse lv host inspect %s: %v\n%s", host, err, out)
	}
	return got
}

// Every host's reserved figures are the sum of the reservations it lists.
func TestReservations_InspectSumsMatch(t *testing.T) {
	ensureTopology(t)
	for _, h := range hostNames {
		got := inspectReservations(t, h)
		if got.Partial {
			t.Logf("%s: reservations partial; reserved figures cover only the listed rows", h)
		}
		cpu, mem := 0, 0
		for _, r := range got.Reservations {
			cpu += r.Vcpu
			mem += r.MemoryMib
		}
		if cpu != got.ReservedCPU || mem != got.ReservedMemMib {
			t.Errorf("%s: reservedCpu/reservedMemMib = %d/%d, but its %d reservations sum to %d/%d",
				h, got.ReservedCPU, got.ReservedMemMib, len(got.Reservations), cpu, mem)
		}
	}
}

// A VM grown live and then deleted leaves no releasable reservation of its own
// on its host for longer than the sweep's interval plus replication.
func TestReservations_GrowThenDeleteLeavesNothingReleasable(t *testing.T) {
	requireImage(t)
	name := uniqueName("resrec")
	host := hostWithCapacity(t, 1, 2048)
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	out, err := lvErr(t, "run", "--name", name, "--image", testImage, "--cpu", "1",
		"--memory", "1024", "--memory-hotplug-max", "2048", "--disk", "5G", "--host", host)
	skipIfGated(t, out, err)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	waitVM(t, name, "RUNNING", 2*time.Minute)
	if out, err := lvErr(t, "set-memory", name, "1536"); err != nil {
		t.Skipf("memory hot-add unavailable on this cluster: %v\n%s", err, out)
	}
	lv(t, "rm", name, "--force")
	waitVMGone(t, name, 2*time.Minute)

	deadline := time.Now().Add(2*time.Minute + 30*time.Second)
	for {
		var releasable []string
		for _, r := range inspectReservations(t, host).Reservations {
			// Only this test's own VM: a releasable row another VM left on
			// the host is not this test's to judge.
			if r.State == "releasable" && r.VM == name {
				releasable = append(releasable, r.OperationID+" ("+r.Detail+")")
			}
		}
		if len(releasable) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still holds releasable reservations of %s after the sweep's budget: %s",
				host, name, strings.Join(releasable, "; "))
		}
		time.Sleep(10 * time.Second)
	}
}

// The manual release refuses without --force, before dialling, and answers an
// unknown operation with NotFound's text.
func TestReservations_ReleaseRefusals(t *testing.T) {
	ensureTopology(t)
	out, err := lvErr(t, "operation", "release-reservation", "deadbeef")
	if err == nil || !strings.Contains(out, "--force is required") {
		t.Fatalf("without --force: err=%v\n%s\nwant the client's --force refusal", err, out)
	}
	out, err = lvErr(t, "operation", "release-reservation", "deadbeef", "--force")
	if err == nil || !strings.Contains(out, "no operation deadbeef") {
		t.Fatalf("unknown operation: err=%v\n%s\nwant the NotFound refusal", err, out)
	}
}

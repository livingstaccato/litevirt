package firewall

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func armedSet(a *Arming) map[string]bool {
	m := map[string]bool{}
	for _, v := range a.Armed() {
		m[v] = true
	}
	return m
}

// settle is one loader pass: generations first, then the snapshots.
func settle(a *Arming, row string, runs bool) {
	a.Settle("A", a.Generations(), map[string]string{"x": row}, func(string) bool { return runs })
}

// arrivedAndLeft leaves x armed, arrived and with its row on B.
func arrivedAndLeft(t *testing.T, a *Arming) {
	t.Helper()
	a.Arm("x")
	settle(a, "A", true)
	if !a.arrived["x"] {
		t.Fatal("setup: x did not arrive")
	}
}

func TestArming_RowNamingHereWithoutRunningIsNotArrival(t *testing.T) {
	a := NewArming()
	a.Arm("x")
	settle(a, "A", false) // replica lag / not landed: the row alone proves nothing
	settle(a, "B", false)
	if !armedSet(a)["x"] {
		t.Fatal("disarmed an incoming VM that never ran here")
	}
}

func TestArming_StaleSnapshotAfterArmDoesNotDisarm(t *testing.T) {
	a := NewArming()
	arrivedAndLeft(t, a)
	gens := a.Generations() // the pass read these, and the row (A), before...
	a.Arm("x")              // ...a return migration armed it again
	a.Settle("A", gens, map[string]string{"x": "A"}, func(string) bool { return true })
	settle(a, "B", false) // next pass: row B, nothing runs yet
	if !armedSet(a)["x"] {
		t.Fatal("a snapshot older than an Arm marked the VM arrived; the incoming VM was disarmed")
	}
}

func TestArming_ArmClearsArrived(t *testing.T) {
	a := NewArming()
	arrivedAndLeft(t, a)
	a.Arm("x")
	settle(a, "B", false)
	if !armedSet(a)["x"] {
		t.Fatal("Arm did not clear arrived")
	}
}

func TestArming_SetPendingClearsArrived(t *testing.T) {
	a := NewArming()
	arrivedAndLeft(t, a)
	a.SetPending("x", []corrosion.HostVMNIC{{VMName: "x", MAC: "52:54:00:00:00:01"}})
	if a.arrived["x"] {
		t.Fatal("SetPending kept arrived")
	}
}

func TestArming_SettleDisarmClearsPending(t *testing.T) {
	a := NewArming()
	a.SetPending("x", []corrosion.HostVMNIC{{VMName: "x", MAC: "52:54:00:00:00:01"}})
	settle(a, "A", true)
	settle(a, "B", false)
	if armedSet(a)["x"] || len(a.Pending()) != 0 {
		t.Fatalf("armed=%v pending=%v", armedSet(a), a.Pending())
	}
}

package health

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A witness is never a worker, but it may move a stranded workload AWAY: the
// evacuation gate admits it (active or draining) while the worker gate, which
// start and create take, still refuses it.
//
// Mutation: drop the witness branch of localHostIsEvacuatingWorker - the
// witness rows go red.
func TestLocalHostIsEvacuatingWorker_AWitnessMayMoveWorkAway(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "w", State: "active", Role: "worker"},
		{Name: "dr", State: "draining", Role: "worker"},
		{Name: "mt", State: "maintenance", Role: "worker"},
		{Name: "wit", State: "active", Role: "witness"},
		{Name: "witd", State: "draining", Role: "witness"},
		{Name: "witm", State: "maintenance", Role: "witness"},
		{Name: "witf", State: "fenced", Role: "witness"},
	}
	for _, tc := range []struct {
		self   string
		evac   bool
		active bool
	}{
		{"w", true, true}, {"dr", true, false}, {"mt", false, false},
		{"wit", true, false}, {"witd", true, false}, {"witm", false, false}, {"witf", false, false},
		{"nobody", false, false},
	} {
		if got := localHostIsEvacuatingWorker(hosts, tc.self); got != tc.evac {
			t.Errorf("localHostIsEvacuatingWorker(%s) = %v, want %v", tc.self, got, tc.evac)
		}
		if got := localHostIsActiveWorker(hosts, tc.self); got != tc.active {
			t.Errorf("localHostIsActiveWorker(%s) = %v, want %v (a witness never starts work)", tc.self, got, tc.active)
		}
	}
}

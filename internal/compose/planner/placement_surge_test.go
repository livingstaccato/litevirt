package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// blue-green and snapshot-and-replace run the new VM BESIDE the old one until
// the cutover, so the host must hold both: a replacing update under them is
// charged in addition to the running VM, not in its place. db (1024 MiB) on
// node-2 (1947 allocatable) cannot have a 1024 MiB replacement beside it; the
// same image change under recreate, which deletes db first, fits.
func TestResolve_SurgeStrategiesChargeTheNewVMBesideTheOld(t *testing.T) {
	for _, c := range []struct {
		strategy string
		image    string
		fits     bool
	}{
		{"blue-green", "debian", false},
		{"snapshot-and-replace", "debian", false},
		{"recreate", "debian", true},
		{"stop-first", "debian", true},
		{"rolling", "debian", true},
		// Kept in place under every strategy (a live change): nothing surges.
		{"blue-green", "ubuntu", true},
		{"snapshot-and-replace", "ubuntu", true},
	} {
		f := makeFile("hc", map[string]compose.VMDef{
			"db": {Image: c.image, CPU: 1, Memory: 1024,
				Labels:    map[string]string{"tier": "data"},
				Placement: &compose.PlacementDef{Host: "node-2"},
				Update:    &compose.UpdateDef{Strategy: c.strategy}},
		})
		plan, err := Resolve(context.Background(), f, labUpdateState())
		name := c.strategy + "/" + c.image
		if c.fits {
			if err != nil {
				t.Errorf("%s: Resolve: %v", name, err)
				continue
			}
			if a := ctAction(plan, "db"); a == nil || a.Kind != OpUpdate {
				t.Errorf("%s: db = %+v, want an update", name, a)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "node-2: memory") {
			t.Errorf("%s: Resolve err = %v, want node-2 short of memory for the new VM beside db", name, err)
		}
	}
}

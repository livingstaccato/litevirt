package health

import (
	"errors"
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A container marker holds only its own host's row of that incarnation and
// owner epoch, and fails closed when it cannot be understood. A VM marker
// of the same name, in its own directory, is not read as one.
//
// Mutations: the hold ignores the epoch, the incarnation or the host: red;
// a corrupt marker holds nothing: red.
func TestContainerOperatorStopHold_IdentityAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ct := &corrosion.ContainerRecord{Name: "web", HostName: "node-a", CreatedAt: "2026-10-21T10:00:00Z", OwnerEpoch: 2}
	if why, _ := ContainerOperatorStopHold(dir, "node-a", ct); why != "" {
		t.Fatalf("no marker: held (%s)", why)
	}
	if err := WriteOperatorStopMarker(dir, OperatorStopMarker{VM: "web", Host: "node-a", Incarnation: ct.CreatedAt, OwnerEpoch: 2}); err != nil {
		t.Fatal(err)
	}
	if why, _ := ContainerOperatorStopHold(dir, "node-a", ct); why != "" {
		t.Fatalf("a VM's marker holds the container of the same name: %s", why)
	}
	if err := WriteContainerOperatorStopMarker(dir, ContainerOperatorStopMarker{Container: "web", Host: "node-a", Incarnation: ct.CreatedAt, OwnerEpoch: 2, StoppedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if why, corrupt := ContainerOperatorStopHold(dir, "node-a", ct); why == "" || corrupt {
		t.Errorf("own marker: held=%q corrupt=%v, want held", why, corrupt)
	}
	if why, _ := ContainerOperatorStopHold(dir, "node-b", &corrosion.ContainerRecord{Name: "web", HostName: "node-b", CreatedAt: ct.CreatedAt, OwnerEpoch: 2}); why != "" {
		t.Errorf("another host's marker holds: %s", why)
	}
	if why, _ := ContainerOperatorStopHold(dir, "node-a", &corrosion.ContainerRecord{Name: "web", HostName: "node-a", CreatedAt: "2026-10-22T00:00:00Z", OwnerEpoch: 2}); why != "" {
		t.Errorf("a marker holds a new incarnation of the name: %s", why)
	}
	if why, _ := ContainerOperatorStopHold(dir, "node-a", &corrosion.ContainerRecord{Name: "web", HostName: "node-a", CreatedAt: ct.CreatedAt, OwnerEpoch: 3}); why != "" {
		t.Errorf("a marker holds a later ownership of its incarnation: %s", why)
	}
	if names, err := ListContainerOperatorStopMarkers(dir); err != nil || len(names) != 1 || names[0] != "web" {
		t.Errorf("ListContainerOperatorStopMarkers = %v, %v, want [web]", names, err)
	}
	if vms, _ := ListOperatorStopMarkers(dir); len(vms) != 1 {
		t.Errorf("the container marker shows among the VM markers: %v", vms)
	}

	p, _ := ContainerOperatorStopMarkerPath(dir, "web")
	for name, body := range map[string]string{
		"truncated":      `{"version":1,"container":"web","ho`,
		"other version":  `{"version":2,"container":"web","host":"node-a","incarnation":"2026-10-21T10:00:00Z"}`,
		"other name":     `{"version":1,"container":"db","host":"node-a","incarnation":"2026-10-21T10:00:00Z"}`,
		"a VM's marker":  `{"version":1,"vm":"web","host":"node-a","incarnation":"2026-10-21T10:00:00Z"}`,
		"no incarnation": `{"version":1,"container":"web","host":"node-a"}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadContainerOperatorStopMarker(dir, "web"); !errors.Is(err, ErrOperatorStopMarkerCorrupt) {
			t.Errorf("%s: read err %v, want corrupt", name, err)
		}
		if why, corrupt := ContainerOperatorStopHold(dir, "node-b", &corrosion.ContainerRecord{Name: "web", HostName: "node-b"}); why == "" || !corrupt {
			t.Errorf("%s: held=%q corrupt=%v, want held, corrupt (whatever row asks)", name, why, corrupt)
		}
	}
	if err := RemoveContainerOperatorStopMarker(dir, "web"); err != nil {
		t.Fatal(err)
	}
	if why, _ := ContainerOperatorStopHold(dir, "node-a", ct); why != "" {
		t.Errorf("removed marker still holds: %s", why)
	}
}

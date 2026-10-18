package firewall

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_DepartedVMIsDisarmed: a VM armed here that arrived
// (its row named this host) and then left (its row names another host) stops
// being drawn here as soon as it no longer runs here. While it still runs
// here, or while it has not arrived yet (a migration in progress), it stays
// armed.
func TestCorrosionPlanLoader_DepartedVMIsDisarmed(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	insert := func(name, host, mac string) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: name, HostName: host, State: "running"},
			[]corrosion.InterfaceRecord{{VMName: name, NetworkName: "lan", MAC: mac, IP: "10.0.0.9"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	move := func(name, host string) {
		t.Helper()
		if err := db.Execute(ctx, `UPDATE vms SET host_name = ? WHERE name = ?`, host, name); err != nil {
			t.Fatal(err)
		}
	}
	insert("mover", "host-a", "52:54:00:00:00:11")
	insert("incoming", "host-b", "52:54:00:00:00:12")
	arm := NewArming()
	arm.Arm("mover")
	arm.Arm("incoming")
	running := map[string]map[string]string{}
	load := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return running, nil },
		TapBridge:   func(string) string { return "" },
		Arming:      arm,
	})
	armed := func() map[string]bool {
		m := map[string]bool{}
		for _, v := range arm.Armed() {
			m[v] = true
		}
		return m
	}
	if _, err := load(ctx); err != nil { // mover's row names here: it has arrived
		t.Fatal(err)
	}
	if a := armed(); !a["mover"] || !a["incoming"] {
		t.Fatalf("after arrival pass armed = %v", a)
	}
	move("mover", "host-b")
	running["mover"] = map[string]string{"52:54:00:00:00:11": "vnet9"}
	if _, err := load(ctx); err != nil {
		t.Fatal(err)
	}
	if !armed()["mover"] {
		t.Fatal("disarmed while the VM still runs here")
	}
	delete(running, "mover")
	if _, err := load(ctx); err != nil {
		t.Fatal(err)
	}
	a := armed()
	if a["mover"] {
		t.Fatal("departed VM still armed")
	}
	if !a["incoming"] {
		t.Fatal("a VM that has not arrived yet was disarmed")
	}
}

package firewall

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/nictap"
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
	fail := false
	load := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) {
			if fail {
				return nil, errors.New("libvirt down")
			}
			return running, nil
		},
		TapBridge: func(string) string { return "" },
		Arming:    arm,
	})
	armed := func() map[string]bool {
		m := map[string]bool{}
		for _, v := range arm.Armed() {
			m[v] = true
		}
		return m
	}
	running["mover"] = map[string]string{"52:54:00:00:00:11": "vnet9"}
	if _, err := load(ctx); err != nil { // mover's row names here and it runs here: arrived
		t.Fatal(err)
	}
	if a := armed(); !a["mover"] || !a["incoming"] {
		t.Fatalf("after arrival pass armed = %v", a)
	}
	move("mover", "host-b")
	if _, err := load(ctx); err != nil {
		t.Fatal(err)
	}
	if !armed()["mover"] {
		t.Fatal("disarmed while the VM still runs here")
	}
	// libvirt cannot be asked: nothing is disarmed.
	delete(running, "mover")
	fail = true
	if _, err := load(ctx); err == nil {
		t.Log("pass succeeded without taps")
	}
	if !armed()["mover"] {
		t.Fatal("disarmed while libvirt could not be asked")
	}
	fail = false
	plan, err := load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range plan.NICs {
		if n.NICDev == nictap.Name("52:54:00:00:00:11") {
			t.Fatal("departed VM still drawn in the plan")
		}
	}
	a := armed()
	if a["mover"] {
		t.Fatal("departed VM still armed")
	}
	if !a["incoming"] {
		t.Fatal("a VM that has not arrived yet was disarmed")
	}
}

// TestCorrosionPlanLoader_SettleIgnoresAJoinedOlderTapCall: a pass that joins a
// libvirt tap call started before it read the generations must not disarm on
// that answer, which may predate an Arm they reflect.
func TestCorrosionPlanLoader_SettleIgnoresAJoinedOlderTapCall(t *testing.T) {
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
	insert("other", "host-a", "52:54:00:00:00:21")
	insert("mover", "host-b", "52:54:00:00:00:22")
	arm := NewArming()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var calls int32
	load := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				entered <- struct{}{}
				<-release
			}
			return map[string]map[string]string{}, nil
		},
		TapBridge:  func(string) string { return "" },
		TapTimeout: 10 * time.Second,
		Arming:     arm,
	})
	// A pass with nothing armed yet starts the tap call and stalls in it.
	first := make(chan error, 1)
	go func() { _, err := load(ctx); first <- err }()
	<-entered
	// mover arrived here and has left; its arming is newer than the stalled call.
	arm.Arm("mover")
	arm.Settle("host-a", arm.Generations(), map[string]string{"mover": "host-a"}, func(string) bool { return true })
	// The pass under test joins that call, which started before its generations.
	second := make(chan error, 1)
	go func() { _, err := load(ctx); second <- err }()
	// Release only once both passes are parked in the join's select: a
	// goroutine scheduled after the release would start a fresh, valid lookup.
	waitParkedInFetch(t, 2)
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range arm.Armed() {
		found = found || v == "mover"
	}
	if !found {
		t.Fatal("a pass disarmed on a tap answer older than its generations")
	}
}

// waitParkedInFetch blocks until n goroutines are parked in the select of
// tapFetcher.fetchStamped, which a pass reaches only after it has started or
// joined a call. It reads goroutine stacks, so it needs no production hook.
func waitParkedInFetch(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		stacks := string(buf[:runtime.Stack(buf, true)])
		got := 0
		for _, g := range strings.Split(stacks, "\n\n") {
			if strings.Contains(g, "tapFetcher).fetchStamped") && strings.Contains(strings.SplitN(g, "\n", 2)[0], "[select") {
				got++
			}
		}
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fewer than %d passes parked in the tap fetch", n)
}

// Fleet scenarios for `lv host drain` with the split-brain gate ENFORCED, as
// it is on every real cluster: split_brain_gate_v1 is mandatory, so it latches
// with no operator opt-in.
//
// The other drain scenarios run with no gate at all (the harness sets none,
// and a nil gate is fail-open), so they never met the gate's host-state
// check. That check refused every move a drain makes: DrainHost marks the
// host `draining` before it moves anything, and ExecutionGate requires the
// local host to be `active`. On the lab every VM came back "drain refused:
// local_not_active_worker", and a second drain to retry was refused up front.
//
// Here every node runs a REAL health.Checker as its gate, with its probe
// results seeded as one completed probe cycle would leave them (the harness
// runs no probe loop) and split_brain_gate_v1 latched through the real Ping
// path. Each scenario's failure is therefore the gate's own answer.

package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// enforceGate wires a real health.Checker as every node's gate, seeds each
// with every other node probed healthy, and latches split_brain_gate_v1.
func enforceGate(t *testing.T, c *Cluster) map[string]*health.Checker {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.SplitBrainGateV1) {
			t.Fatalf("%s: split_brain_gate_v1 did not latch", n.Name)
		}
		if g := gates[n.Name].ExecutionGate(ctx); !g.OK {
			t.Fatalf("%s: ExecutionGate refused an active host with quorum: %s", n.Name, g.Reason)
		}
	}
	return gates
}

// addRunningSharedVM adds a running VM on the source whose only disk is on
// shared storage, so drain live-migrates it.
func (sc *coldStoppedScenario) addRunningSharedVM(t *testing.T, name string) {
	t.Helper()
	spec, err := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(sc.c.tmpRoot, "nfs", name+"-root.qcow2")
	if err := corrosion.InsertVM(context.Background(), sc.src.DB, corrosion.VMRecord{
		Name: name, HostName: sc.src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: name, DiskName: "root", HostName: sc.src.Name, Path: disk, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"},
	}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := sc.src.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>33333333-4444-4555-8666-777777777777</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain %s: %v", name, err)
	}
	if err := sc.src.Virt.StartDomain(name); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
}

func (sc *coldStoppedScenario) hostState(t *testing.T, n *Node) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), sc.src.DB, n.Name)
	if err != nil || h == nil {
		t.Fatalf("GetHost %s: %v %v", n.Name, h, err)
	}
	return h.State
}

func (sc *coldStoppedScenario) markDraining(t *testing.T) {
	t.Helper()
	if err := corrosion.UpdateHostState(context.Background(), sc.src.DB, sc.src.Name, "draining"); err != nil {
		t.Fatalf("mark %s draining: %v", sc.src.Name, err)
	}
}

// With the gate enforced, a drain moves every VM off the host, each the way
// it moves: a running VM with a host-local disk cold (shut down, moved with
// its disk, started on the target), a stopped one cold, and a running one on
// shared storage live. Nothing is refused for the host being `draining`,
// which the drain itself made it.
//
// On main-4ca641c2 every frame is "drain refused: local_not_active_worker".
//
// Mutations: the per-VM re-check back on ExecutionGate — every frame is that
// refusal again; migrateOwnedVM's source gate back on ExecutionGate for a
// drain — the two cold moves are refused "migration refused:
// local_not_active_worker".
func TestFleet_DrainUnderEnforcedGateMovesEveryVM(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	payload2 := []byte("os2's stopped local disk")
	disk2 := sc.addStoppedLocalVM(t, "os2", payload2)
	sc.addRunningSharedVM(t, "os3")
	enforceGate(t, sc.c)

	progress, err := sc.drain(t)
	for name, p := range progress {
		t.Logf("%s: %+v", name, p)
	}
	if err != nil {
		t.Fatalf("drain with the split-brain gate enforced: %v", err)
	}
	want := map[string]pb.MigrateStrategy{
		"os1": pb.MigrateStrategy_MIGRATE_COLD,
		"os2": pb.MigrateStrategy_MIGRATE_COLD,
		"os3": pb.MigrateStrategy_MIGRATE_LIVE,
	}
	for name, strat := range want {
		p := progress[name]
		if p == nil || p.Status != "done" || p.Error != "" || p.Strategy != strat {
			t.Errorf("drain progress for %s = %+v, want done, no error, strategy %s", name, p, strat)
		}
	}

	if vm := sc.vmNamed(t, "os1"); vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Errorf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.dst.Name)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1 is not running on %s after its cold move", sc.dst.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}
	if vm := sc.vmNamed(t, "os2"); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Errorf("os2 row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, disk2)); err != nil || string(got) != string(payload2) {
		t.Errorf("os2's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}
	if vm := sc.vmNamed(t, "os3"); vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Errorf("os3 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.dst.Name)
	}
	if st := sc.hostState(t, sc.src); st != "draining" {
		t.Errorf("drained host state = %s, want draining", st)
	}
}

// A drain that left VMs behind is retried by running it again on the host,
// which is `draining` by then. The retry is not refused up front, and moves
// what is left.
//
// On main-4ca641c2 it is refused before anything: "drain refused:
// local_not_active_worker".
//
// Mutation: DrainHost's up-front gate back on ExecutionGate — red with that
// refusal.
func TestFleet_DrainRetryOnADrainingHostMovesTheLeftovers(t *testing.T) {
	sc := newColdStoppedScenario(t)
	enforceGate(t, sc.c)
	sc.markDraining(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain re-run on a draining host: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Fatalf("os1 row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.dst.Name)
	}
}

// A cold move that fails after the VM was shut down starts the VM again on
// the drained host — which is `draining`. That start puts back what the drain
// itself took down; it is not new work on the host, and the gate lets it
// through.
//
// Mutation: restartAfterFailedColdMove back on ExecutionGate — os1 is left
// stopped ("start refused: local_not_active_worker") and goes red.
func TestFleet_DrainUnderEnforcedGateStartsAFailedMoveAgain(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	enforceGate(t, sc.c)
	sc.dst.Virt.FailDefineDomain = func(string) error { return io.ErrUnexpectedEOF }

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "started again on "+sc.src.Name) {
		t.Fatalf("drain progress for os1 = %+v, want failed: started again on %s", p, sc.src.Name)
	}
	sc.assertRunningOnSource(t)
}

// A draining host with the gate enforced still refuses to grow, while a VM
// may leave it by any route. An operator start of a stopped VM there is
// refused. An explicit `lv migrate` of a VM off it goes through — moving VMs
// away is what draining is for — and moving one back onto it is refused (the
// target must be active).
//
// Mutations: let ExecutionGate itself pass a draining host — the start goes
// through and the test goes red; migrateOwnedVM's source gate back on
// ExecutionGate — the migration off is refused and goes red.
func TestFleet_DrainingHostStillRefusesGrowth(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.addStoppedLocalVM(t, "os2", []byte("os2's disk"))
	enforceGate(t, sc.c)
	sc.markDraining(t)
	ctx := context.Background()

	_, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os2"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), health.ReasonLocalNotActiveWorker) {
		t.Errorf("start of a VM on a draining host = %v, want refused: %s", err, health.ReasonLocalNotActiveWorker)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os2"); active {
		t.Errorf("os2 was started on the draining host")
	}

	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("explicit migration of a VM off a draining host = %v, want it moved", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Fatalf("os1 row = host %s state %s after its migration off, want host %s stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}

	// Inbound: moving it back onto the draining host is refused, from the
	// host that now owns it.
	st, err := sc.c.SelfClient(sc.dst).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: sc.src.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "is not active") {
		t.Errorf("migration onto a draining host = %v, want refused: target is not active", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name {
		t.Errorf("os1 row names %s after a refused migration onto the draining host, want %s", vm.HostName, sc.dst.Name)
	}
}

// A live migration that fails during a drain under the enforced gate falls
// back to a cold move, which re-checks the gate on the (draining) source and
// goes ahead: the VM moves cold, with nothing left behind, and runs on the
// target.
//
// Mutation: the cold-fallback re-check in drainOneVM back on ExecutionGate —
// os3 is skipped with "drain refused: local_not_active_worker" and goes red.
func TestFleet_DrainUnderEnforcedGateFallsBackToColdWhenLiveFails(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.addRunningSharedVM(t, "os3")
	enforceGate(t, sc.c)
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name == "os3" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain with a failing live migration under the enforced gate: %v", err)
	}
	if p := progress["os3"]; p == nil || p.Status != "done" || p.Error != "" || p.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
		t.Fatalf("drain progress for os3 = %+v, want done cold", p)
	}
	if vm := sc.vmNamed(t, "os3"); vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Errorf("os3 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.dst.Name)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os3"); !active {
		t.Errorf("os3 is not running on %s after its cold fallback", sc.dst.Name)
	}
	if sc.src.Virt.DomainExists("os3") {
		t.Errorf("os3's domain is still defined on the drained host")
	}
}

// The startup recovery of a drain's interrupted cold move runs on a host the
// drain left `draining`, under the enforced gate. A move that died after the
// shutdown is started again here; one that died after the handoff is started
// on the target, which is active.
//
// Mutation: restartAfterFailedColdMove back on ExecutionGate — shut_off ends
// with os1 stopped and recovery reporting a move still pending.
func TestFleet_DrainRecoveryUnderEnforcedGateOnADrainingHost(t *testing.T) {
	for _, tc := range []struct {
		point  string
		onDest bool
	}{
		{"shut_off", false},
		{"handed_off", true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			sc := newColdStoppedScenario(t)
			sc.makeRunning(t)
			enforceGate(t, sc.c)
			sc.crashAt(t, tc.point)
			if st := sc.hostState(t, sc.src); st != "draining" {
				t.Fatalf("drained host state = %s, want draining", st)
			}

			left, err := sc.src.Server.ResumeDrainColdMoves(context.Background())
			if err != nil || left != 0 {
				t.Fatalf("ResumeDrainColdMoves = %d left, %v; want 0, nil", left, err)
			}
			want := sc.src
			if tc.onDest {
				want = sc.dst
			}
			sc.assertRunsOnExactlyOneHost(t, want)
		})
	}
}

// Every other condition of the gate still holds for a drain. A draining host
// that has lost quorum is refused the drain up front, and moves nothing.
//
// Mutation: skip the quorum check for a draining host — the drain goes ahead
// and the test goes red.
func TestFleet_DrainOnADrainingHostWithoutQuorumIsRefused(t *testing.T) {
	sc := newColdStoppedScenario(t)
	gates := enforceGate(t, sc.c)
	sc.markDraining(t)
	gates[sc.src.Name].SeedPeersForTests(map[string]bool{sc.dst.Name: false})

	_, err := sc.drain(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain refused: "+health.ReasonNoQuorum) {
		t.Fatalf("drain without quorum = %v, want drain refused: %s", err, health.ReasonNoQuorum)
	}
	if vm := sc.vm(t); vm.HostName != sc.src.Name {
		t.Errorf("os1 row names %s, want it left on %s", vm.HostName, sc.src.Name)
	}
}

// An operator start refused on a host that is draining, or in maintenance,
// says so and says what to do — and every route it names works. The gate's
// bare reason, "local_not_active_worker", named neither the host's state nor
// a way out, and was all the lab got back from `lv start` on a draining host.
//
// A draining host lets VMs leave, so its hints name two routes: undrain it,
// or move the VM off cold (a running VM's restart adds the stop) and start it
// there. A host in maintenance lets nothing leave (DrainExecutionGate admits
// active and draining hosts only), so its hints name undrain alone, and a
// migration off it is refused saying the same.
//
// Each subtest follows one route the refusals named and checks it ends with
// the VM running.
//
// Mutations: return the bare "start refused: <reason>" / "restart refused:
// <reason>" — the refusals subtests lose the state and the commands; name the
// migrate route in maintenance too — the maintenance refusals subtest finds
// it; return the bare "migration refused: <reason>" — the maintenance
// move-off subtest loses the undrain command.
func TestFleet_StartRefusedOnAnInactiveHostSaysWhyAndWhatToDo(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, state string) *coldStoppedScenario {
		t.Helper()
		sc := newColdStoppedScenario(t)
		sc.makeRunning(t)
		sc.addStoppedLocalVM(t, "os2", []byte("os2's disk"))
		enforceGate(t, sc.c)
		if err := corrosion.UpdateHostState(ctx, sc.src.DB, sc.src.Name, state); err != nil {
			t.Fatalf("mark %s %s: %v", sc.src.Name, state, err)
		}
		return sc
	}
	running := func(t *testing.T, sc *coldStoppedScenario, n *Node, name string) {
		t.Helper()
		if active, _ := n.Virt.DomainIsActive(name); !active {
			t.Errorf("%s is not running on %s after following the hint", name, n.Name)
		}
		if vm := sc.vmNamed(t, name); vm.HostName != n.Name || vm.State != "running" {
			t.Errorf("%s row = host %s state %s, want host %s running", name, vm.HostName, vm.State, n.Name)
		}
	}
	migrate := func(sc *coldStoppedScenario, name string) error {
		st, err := sc.c.SelfClient(sc.src).MigrateVM(ctx, &pb.MigrateVMRequest{
			VmName: name, TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
		})
		if err != nil {
			return err
		}
		for {
			if _, rerr := st.Recv(); rerr == io.EOF {
				return nil
			} else if rerr != nil {
				return rerr
			}
		}
	}

	for _, state := range []string{"draining", "maintenance"} {
		is := map[string]string{"draining": "is draining", "maintenance": "is in maintenance"}[state]
		moveOff := state == "draining"

		t.Run(state+"/refusals", func(t *testing.T) {
			sc := setup(t, state)
			h := sc.src.Name
			common := []string{health.ReasonLocalNotActiveWorker, "host " + h + " " + is, "`lv host undrain " + h + "`"}
			cases := []struct {
				what  string
				call  func() error
				want  []string
				route string // the move-off route, named only on a draining host
			}{
				{"start of stopped os2", func() error {
					_, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os2"})
					return err
				}, []string{"start refused", "`lv start os2`"}, "`lv migrate os2 <target-host> --cold`"},
				{"restart of stopped os2", func() error {
					_, err := sc.c.SelfClient(sc.src).RestartVM(ctx, &pb.RestartVMRequest{Name: "os2"})
					return err
				}, []string{"restart refused", "`lv start os2`"}, "`lv migrate os2 <target-host> --cold`"},
				{"restart of running os1", func() error {
					_, err := sc.c.SelfClient(sc.src).RestartVM(ctx, &pb.RestartVMRequest{Name: "os1"})
					return err
				}, []string{"restart refused", "`lv restart os1`"}, "`lv migrate os1 <target-host> --cold`"},
			}
			for _, c := range cases {
				err := c.call()
				want := append(append([]string{}, common...), c.want...)
				if moveOff {
					want = append(want, c.route)
					if c.what == "restart of running os1" {
						want = append(want, "`lv stop os1`")
					}
				}
				assertRefusedWith(t, c.what, err, want...)
				if !moveOff && err != nil && strings.Contains(err.Error(), "lv migrate") {
					t.Errorf("%s on a host in maintenance names a migration, which the gate refuses there: %q", c.what, status.Convert(err).Message())
				}
			}
			if active, _ := sc.src.Virt.DomainIsActive("os2"); active {
				t.Errorf("os2 was started on the %s host", state)
			}
		})

		t.Run(state+"/undrain", func(t *testing.T) {
			sc := setup(t, state)
			if _, err := sc.c.SelfClient(sc.dst).UndrainHost(ctx, &pb.UndrainHostRequest{Name: sc.src.Name}); err != nil {
				t.Fatalf("lv host undrain %s: %v", sc.src.Name, err)
			}
			if _, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os2"}); err != nil {
				t.Fatalf("lv start os2 after the undrain: %v", err)
			}
			running(t, sc, sc.src, "os2")
			if _, err := sc.c.SelfClient(sc.src).RestartVM(ctx, &pb.RestartVMRequest{Name: "os1"}); err != nil {
				t.Fatalf("lv restart os1 after the undrain: %v", err)
			}
			running(t, sc, sc.src, "os1")
		})

		if moveOff {
			t.Run(state+"/move-off", func(t *testing.T) {
				sc := setup(t, state)
				// Stopped os2: migrate it off cold, start it there.
				if err := migrate(sc, "os2"); err != nil {
					t.Fatalf("lv migrate os2 %s --cold: %v", sc.dst.Name, err)
				}
				if _, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os2"}); err != nil {
					t.Fatalf("lv start os2 on %s: %v", sc.dst.Name, err)
				}
				running(t, sc, sc.dst, "os2")
				// Running os1: stop it, migrate it off cold, start it there.
				if _, err := sc.c.SelfClient(sc.src).StopVM(ctx, &pb.StopVMRequest{Name: "os1"}); err != nil {
					t.Fatalf("lv stop os1: %v", err)
				}
				if err := migrate(sc, "os1"); err != nil {
					t.Fatalf("lv migrate os1 %s --cold: %v", sc.dst.Name, err)
				}
				if _, err := sc.c.SelfClient(sc.src).StartVM(ctx, &pb.StartVMRequest{Name: "os1"}); err != nil {
					t.Fatalf("lv start os1 on %s: %v", sc.dst.Name, err)
				}
				running(t, sc, sc.dst, "os1")
			})
		} else {
			t.Run(state+"/move-off-refused", func(t *testing.T) {
				sc := setup(t, state)
				err := migrate(sc, "os2")
				assertRefusedWith(t, "lv migrate os2 --cold off a host in maintenance", err,
					"migration refused", health.ReasonLocalNotActiveWorker, "host "+sc.src.Name+" "+is, "`lv host undrain "+sc.src.Name+"`")
				if vm := sc.vmNamed(t, "os2"); vm.HostName != sc.src.Name {
					t.Errorf("os2 row names %s after a refused migration, want %s", vm.HostName, sc.src.Name)
				}
			})
		}
	}
}

func assertRefusedWith(t *testing.T, what string, err error, want ...string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("%s = %v, want FailedPrecondition", what, err)
		return
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%s refusal %q does not contain %q", what, status.Convert(err).Message(), w)
		}
	}
}

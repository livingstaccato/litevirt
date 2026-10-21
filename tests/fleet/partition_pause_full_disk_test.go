package fleet

// A full data_dir on the minority: the partition pauser cannot
// write the record it writes before each pause. Before
// enforcement.partition_pause_record_failure, that failure was a failed pause:
// partition_pause_failed, and with a verified watchdog a self-fence that
// killed every VM on the host with no coordinator involved.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ppFullDisk is a full disk under one node's pauser, switched on at the split
// (the reserve is made while there is room) and off when space returns, plus
// a verified-watchdog self-fence stub that counts.
type ppFullDisk struct {
	on     atomic.Bool
	layers []string
	// noWatchdog leaves the self-fence unwired: no verified watchdog is armed.
	noWatchdog bool
	mu         sync.Mutex
	fenced     int
}

func (d *ppFullDisk) hook(owner, mode string) func(n *Node, p *health.PartitionPauser) {
	return func(n *Node, p *health.PartitionPauser) {
		if n.Name != owner {
			return
		}
		p.SetRecordFailure(mode)
		p.SetRecordFaultForTests(func(layer string, _ health.PauseRecord) error {
			if !d.on.Load() {
				return nil
			}
			for _, l := range d.layers {
				if l == layer {
					return &os.PathError{Op: "write", Path: "partition-pause", Err: syscall.ENOSPC}
				}
			}
			return nil
		})
		if !d.noWatchdog {
			p.SetSelfFence(func() bool { return true }, func() { d.mu.Lock(); d.fenced++; d.mu.Unlock() })
		}
	}
}

func (d *ppFullDisk) fences() int { d.mu.Lock(); defer d.mu.Unlock(); return d.fenced }

func pauseFailedOn(t *testing.T, n *Node) bool {
	t.Helper()
	failed, err := corrosion.HostPartitionPauseFailed(context.Background(), n.DB, n.Name)
	if err != nil {
		t.Fatalf("HostPartitionPauseFailed on %s: %v", n.Name, err)
	}
	return failed
}

// The default mode, end to end over a real 2|3 split, with neither the record
// directory nor the reserve writable: the owner pauses pp-vm anyway, its
// armed watchdog is never tripped, no partition_pause_failed is raised, the
// majority relies on the pause (self_paused) and starts the replacement only
// after the original stopped, so no instant has two running copies; once
// space returns the record reaches the record directory; after the heal the
// owner never runs pp-vm again.
//
// Mutation: make the default fail the pause on an unwritable record (treat
// "" as self_fence in record) — the owner self-fences and keeps pp-vm
// running, the fence-count check goes red; drop the flush — the record never
// reaches the directory, red.
func TestFleet_PartitionPause_FullDiskDefaultPausesWithoutSelfFencing(t *testing.T) {
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)

	disk := &ppFullDisk{layers: []string{health.PauseRecordLayerDisk, health.PauseRecordLayerReserve}}
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true},
		pauserHook: disk.hook(owner.Name, "")})
	rs := sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	minority, majority := c.Nodes[:2], c.Nodes[2:]
	disk.on.Store(true)
	c.SplitGossip(minority, majority)

	var dest *Node
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range majority {
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				dest = n
				return true
			}
		}
		return false
	})
	susp, ok := firstEvent(owner, "suspend", "pp-vm")
	if !ok {
		t.Fatalf("%s never suspended pp-vm with its record unwritable", owner.Name)
	}
	start, _ := firstEvent(dest, "start", "pp-vm")
	if !susp.When.Before(start.When) {
		t.Fatalf("the replacement started on %s at %s, before %s paused the original at %s",
			dest.Name, start.When.Format("15:04:05.000"), owner.Name, susp.When.Format("15:04:05.000"))
	}
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	if n := disk.fences(); n != 0 {
		t.Fatalf("%s self-fenced %d time(s) over a record it could not write", owner.Name, n)
	}
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StatePaused {
		t.Fatalf("pp-vm is %s on %s, want paused", st, owner.Name)
	}
	if pauseFailedOn(t, owner) {
		t.Fatalf("%s raised partition_pause_failed for a pause that happened", owner.Name)
	}
	rows, err := dest.DB.Query(context.Background(), `SELECT method, result, detail FROM fencing_log WHERE host_name = ?`, owner.Name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no fencing_log row for %s on %s: %v", owner.Name, dest.Name, err)
	}
	for _, r := range rows {
		if a := corrosion.FenceAssuranceDetail(r.String("method"), r.String("result"), r.String("detail")); a != corrosion.FenceSelfPaused {
			t.Errorf("fence of %s recorded with assurance %s, want %s", owner.Name, a, corrosion.FenceSelfPaused)
		}
	}
	recFile := filepath.Join(s.node(owner).dataDir, "partition-pause", "vm-pp-vm.json")
	if _, err := os.Stat(recFile); err == nil {
		t.Fatal("setup: the record file exists although every write failed")
	}

	// Space returns: the record reaches the record directory.
	disk.on.Store(false)
	eventually(t, 30*time.Second, "the record to reach the record directory", func() bool {
		_, err := os.Stat(recFile)
		return err == nil
	})

	// The heal: the owner never runs pp-vm again.
	rs.markNow()
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	time.Sleep(15 * time.Second)
	rs.mu.Lock()
	since, maxRun := rs.since, rs.max
	rs.mu.Unlock()
	if at, ran := since[owner.Name]; ran {
		t.Fatalf("%s ran pp-vm again at %s after the heal", owner.Name, at.Format("15:04:05.000"))
	}
	if maxRun > 1 {
		t.Fatal("pp-vm ran on more than one host at once after the heal")
	}
}

// self_fence: the behaviour before the setting. The owner's record write fails,
// so its pause fails: pp-vm keeps running, partition_pause_failed is raised,
// and the armed watchdog is tripped.
//
// Mutation: let self_fence fall back to the reserve — pp-vm is paused and
// nothing fences, red.
func TestFleet_PartitionPause_FullDiskSelfFenceModeFences(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, Relays: 3, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[1])

	disk := &ppFullDisk{layers: []string{health.PauseRecordLayerDisk}}
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{},
		pauserHook: disk.hook(owner.Name, health.PauseRecordFailureSelfFence)})
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	disk.on.Store(true)
	c.SplitGossip(c.Nodes[:1], c.Nodes[1:])
	eventually(t, time.Minute, "the owner to self-fence on its failed pause", func() bool { return disk.fences() > 0 })
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StateRunning {
		t.Fatalf("pp-vm is %s on %s; self_fence never pauses without a written record", st, owner.Name)
	}
	if !pauseFailedOn(t, owner) {
		t.Fatalf("%s has no open partition_pause_failed", owner.Name)
	}
}

// reserve: the record directory is full, the reserve made before the split is
// not. The owner writes the record into the reserve before it pauses, and
// does not self-fence.
//
// Mutation: skip the reserve in record — the pause fails, the watchdog is
// tripped, red.
func TestFleet_PartitionPause_FullDiskReserveModeWritesTheReserve(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, Relays: 3, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[1])

	disk := &ppFullDisk{layers: []string{health.PauseRecordLayerDisk}}
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{},
		pauserHook: disk.hook(owner.Name, health.PauseRecordFailureReserve)})
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	disk.on.Store(true)
	c.SplitGossip(c.Nodes[:1], c.Nodes[1:])
	eventually(t, time.Minute, "the owner to pause pp-vm", func() bool {
		st, _ := owner.Virt.RawState("pp-vm")
		return st == libvirtfake.StatePaused
	})
	if n := disk.fences(); n != 0 {
		t.Fatalf("%s self-fenced %d time(s) with the reserve writable", owner.Name, n)
	}
	dir := filepath.Join(s.node(owner).dataDir, "partition-pause")
	if _, err := os.Stat(filepath.Join(dir, "vm-pp-vm.json")); err == nil {
		t.Fatal("setup: the record file exists although the directory write failed")
	}
	b, err := os.ReadFile(filepath.Join(dir, "reserve"))
	if err != nil {
		t.Fatalf("no reserve: %v", err)
	}
	if !bytes.Contains(b, []byte(`"name":"pp-vm"`)) {
		t.Fatal("the reserve does not hold pp-vm's record")
	}
}

// ppOneCopyThroughSplit splits a 5-node cluster 2|3 with pp-vm on the
// minority's node-0, whose pauser hook makes its record writes fail or hang
// once on is set, and asserts that no instant had pp-vm running on two hosts
// and that the owner paused it. It returns the owner's stack node.
func ppOneCopyThroughSplit(t *testing.T, hook func(owner string) func(n *Node, p *health.PartitionPauser), on func()) (*Cluster, *ppStack) {
	t.Helper()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true},
		pauserHook: hook(owner.Name)})
	rs := sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	on()
	minority, majority := c.Nodes[:2], c.Nodes[2:]
	c.SplitGossip(minority, majority)
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range majority {
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				return true
			}
		}
		return false
	})
	time.Sleep(3 * time.Second)
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StatePaused {
		t.Fatalf("pp-vm is %s on %s, want paused", st, owner.Name)
	}
	if pauseFailedOn(t, owner) {
		t.Fatalf("%s raised partition_pause_failed for a pause that happened", owner.Name)
	}
	return c, s
}

// reserve and self_fence promise a self-fence on a record that cannot be
// written, and that needs a verified watchdog. With none armed, a failed pause
// keeps the copy running beside the majority's replacement (partition_pause_failed
// cannot reach the majority across the split), so both fall back to pause:
// the record is held in memory and the workload is paused.
//
// Mutation: fail the pause in reserve/self_fence mode whatever the watchdog
// says (the behaviour before the fallback) — pp-vm runs on two hosts, red.
func TestFleet_PartitionPause_FullDiskReserveModeWithoutAWatchdogPauses(t *testing.T) {
	disk := &ppFullDisk{layers: []string{health.PauseRecordLayerDisk, health.PauseRecordLayerReserve}, noWatchdog: true}
	ppOneCopyThroughSplit(t, func(owner string) func(*Node, *health.PartitionPauser) {
		return disk.hook(owner, health.PauseRecordFailureReserve)
	}, func() { disk.on.Store(true) })
}

func TestFleet_PartitionPause_FullDiskSelfFenceModeWithoutAWatchdogPauses(t *testing.T) {
	disk := &ppFullDisk{layers: []string{health.PauseRecordLayerDisk}, noWatchdog: true}
	ppOneCopyThroughSplit(t, func(owner string) func(*Node, *health.PartitionPauser) {
		return disk.hook(owner, health.PauseRecordFailureSelfFence)
	}, func() { disk.on.Store(true) })
}

// A dying disk: the record write never returns (I/O stuck in D state). The
// write is bounded, so the owner pauses with the record in memory before the
// majority starts the replacement, and once the disk answers again the
// record reaches the record directory.
//
// Mutation: wait for the record write without a bound — the suspend never
// comes, pp-vm runs on two hosts, red.
func TestFleet_PartitionPause_HungRecordWritePausesAnyway(t *testing.T) {
	var hang atomic.Bool
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	_, s := ppOneCopyThroughSplit(t, func(owner string) func(*Node, *health.PartitionPauser) {
		return func(n *Node, p *health.PartitionPauser) {
			if n.Name != owner {
				return
			}
			p.SetRecordFaultForTests(func(layer string, _ health.PauseRecord) error {
				if hang.Load() && layer == health.PauseRecordLayerDisk {
					<-release
				}
				return nil
			})
		}
	}, func() { hang.Store(true) })
	recFile := filepath.Join(s.nodes[0].dataDir, "partition-pause", "vm-pp-vm.json")
	if _, err := os.Stat(recFile); err == nil {
		t.Fatal("setup: the record file exists although every write hung")
	}
	hang.Store(false)
	once.Do(func() { close(release) })
	eventually(t, 30*time.Second, "the record to reach the record directory once the disk answers", func() bool {
		_, err := os.Stat(recFile)
		return err == nil
	})
}

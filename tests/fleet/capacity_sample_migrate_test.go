package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Lab 2 (ac2139ed), node mode: two creates on node-1 were refused for memory
// within 30 s of a VM live-migrating off it. node-1's capacity sampler, which
// ran every 60 s, had sampled while the VM was migrating. A migrating VM is
// charged by neither placement nor admission, so its qemu went into the
// observation as runtime-only load, and placement went on subtracting it until
// the next sample, after the VM had gone. The sampler now samples again as soon
// as the database's record of the host's workloads changes.

// startCapacitySampler runs n's capacity sampler as the daemon does, with an
// interval no scenario reaches: only a change to n's workloads samples again.
func startCapacitySampler(t *testing.T, n *Node) {
	t.Helper()
	n.Server.SetCapacityResampleCheckForTest(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.Server.RunCapacitySampler(ctx, time.Hour)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// migrateWithMidSample makes src's migrations of a VM take a capacity sample
// while the VM is migrating (as node-1's interval sample did), then land the
// guest on dst. keepSource leaves the source domain running, as a migration
// that left a copy behind would. It returns the mid-migration observation.
func migrateWithMidSample(t *testing.T, src, dst *Node, keepSource bool) *corrosion.HostCapacityObservation {
	t.Helper()
	mid := &corrosion.HostCapacityObservation{}
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		ctx := context.Background()
		if err := src.Server.SampleHostCapacity(ctx); err != nil {
			return err
		}
		obs, _, err := corrosion.GetHostCapacityObservation(ctx, src.DB, src.Name)
		if err != nil {
			return err
		}
		*mid = obs
		x, err := src.Virt.DumpXML(name)
		if err != nil {
			return err
		}
		if err := dst.Virt.DefineDomain(x); err != nil {
			return err
		}
		dst.Virt.SetState(name, libvirtfake.StateRunning)
		if keepSource {
			return nil
		}
		return src.Virt.UndefineDomain(name, false)
	}
	return mid
}

// waitForCapacitySample waits, up to a bound, for n's observation to charge no
// runtime-only memory, and returns what it last read.
func waitForCapacitySample(t *testing.T, n *Node, within time.Duration) corrosion.HostCapacityObservation {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		obs, _, err := corrosion.GetHostCapacityObservation(context.Background(), n.DB, n.Name)
		if err != nil {
			t.Fatalf("GetHostCapacityObservation: %v", err)
		}
		if obs.ExtraMemMiB == 0 || time.Now().After(deadline) {
			return obs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Mutation "the sampler never samples on a change" — red.
func TestFleet_MigrateVMAway_PlacementIsNotRefusedOnAStaleCapacitySample(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	// About 5 GiB allocatable: big fits, and big-again fits once big has
	// left, but not with big still charged.
	setHostCapacity(t, c, src.Name, 8, 6144)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	if _, err := runVM(t, c, src, "big", src.Name, 1, 3072); err != nil {
		t.Fatalf("create big: %v", err)
	}
	startCapacitySampler(t, src)
	mid := migrateWithMidSample(t, src, dst, false)
	if err := migrateAt(t, c, src, "big", dst.Name); err != nil {
		t.Fatalf("migrate big away: %v", err)
	}
	if mid.ExtraMemMiB < 3072 {
		t.Fatalf("premise: the mid-migration sample charged %d MiB of runtime-only memory, want big's 3072 (%s)",
			mid.ExtraMemMiB, mid.Detail)
	}
	// Well inside the 60 s interval the stale sample would otherwise hold.
	waitForCapacitySample(t, src, 10*time.Second)
	if _, err := runVM(t, c, src, "big-again", src.Name, 1, 3072); err != nil {
		t.Fatalf("a create on the source that fits once big has left: %v", err)
	}
}

// The fresh sample is still a sample: a migration that left the guest running
// on the source too leaves real load there, and placement keeps refusing it.
// No sampler loop runs here: the one sample asserted on is taken after big's
// row has moved, so no older sample can land on top of it.
//
// Mutation "a sample drops a VM the database records on another host" — red.
func TestFleet_MigrateVMAway_ACopyLeftOnTheSourceIsStillCharged(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, src.Name, 8, 6144)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	if _, err := runVM(t, c, src, "big", src.Name, 1, 3072); err != nil {
		t.Fatalf("create big: %v", err)
	}
	mid := migrateWithMidSample(t, src, dst, true)
	if err := migrateAt(t, c, src, "big", dst.Name); err != nil {
		t.Fatalf("migrate big away: %v", err)
	}
	if mid.ExtraMemMiB < 3072 {
		t.Fatalf("premise: the mid-migration sample charged %d MiB, want big's 3072", mid.ExtraMemMiB)
	}
	if vm, err := corrosion.GetVM(context.Background(), src.DB, "big"); err != nil || vm == nil || vm.HostName != dst.Name {
		t.Fatalf("premise: big's row is %+v (err %v), want it on %s", vm, err, dst.Name)
	}
	// The sample a change triggers once big's row has moved.
	if err := src.Server.SampleHostCapacity(context.Background()); err != nil {
		t.Fatalf("SampleHostCapacity: %v", err)
	}
	obs, _, err := corrosion.GetHostCapacityObservation(context.Background(), src.DB, src.Name)
	if err != nil {
		t.Fatalf("GetHostCapacityObservation: %v", err)
	}
	if obs.ExtraMemMiB < 3072 {
		t.Fatalf("the source still runs big, but its sample charges %d MiB runtime-only (%s)", obs.ExtraMemMiB, obs.Detail)
	}
	_, err = runVM(t, c, src, "big-again", src.Name, 1, 3072)
	if err == nil || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("create beside a copy of big still running on the source = %v; want refused for memory", err)
	}
}

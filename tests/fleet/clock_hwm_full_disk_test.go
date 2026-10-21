package fleet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestFleet_FullDiskClockHighWaterKeepsServing: a node whose data disk is full
// keeps serving writes, which replicate, and its clock high-water keeps
// persisting. On lab 2 (2026-10-20) a full disk exited the daemon 214 ms after
// the first failed nowts.hwm save, and its peers fenced the host: each save
// wrote a temp file and renamed it, so it needed a new block every ~2 s.
func TestFleet_FullDiskClockHighWaterKeepsServing(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, ClockSeam: true})
	a := c.Nodes[0]
	ctx := context.Background()

	var mu sync.Mutex
	var fatal []error
	fillDisk := a.DB.ClockPersistenceForTests(t, t.TempDir(), func(err error) {
		mu.Lock()
		defer mu.Unlock()
		fatal = append(fatal, err) // the daemon calls os.Exit here
	})
	fillDisk()
	start := a.DB.ClockDurableCeilingForTests()

	var names []string
	for i := 0; i < 15; i++ { // 15 s of clock: seven times the persist-ahead headroom
		a.StepClock(time.Second)
		name := fmt.Sprintf("/full-disk-%d", i)
		if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: name}); err != nil {
			t.Fatalf("step %d: %s refused a write with its disk full: %v", i, a.Name, err)
		}
		names = append(names, name)
		mu.Lock()
		var first error
		if len(fatal) != 0 {
			first = fatal[0]
		}
		mu.Unlock()
		if first != nil {
			t.Fatalf("step %d: %s's clock high-water could not persist on a full disk; the daemon exits here: %v", i, a.Name, first)
		}
	}
	if got := a.DB.ClockDurableCeilingForTests(); !got.After(start.Add(10 * time.Second)) {
		t.Fatalf("%s's durable clock ceiling did not advance on a full disk: %s, was %s", a.Name, got, start)
	}
	for _, peer := range c.Nodes[1:] {
		eventually(t, 30*time.Second, "every project written on the full-disk node to reach "+peer.Name, func() bool {
			for _, name := range names {
				if _, err := c.SelfClient(peer).GetProject(ctx, &pb.GetProjectRequest{Name: name}); err != nil {
					return false
				}
			}
			return true
		})
	}
}

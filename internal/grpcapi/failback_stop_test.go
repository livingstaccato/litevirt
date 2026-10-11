package grpcapi

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A daemon that stops while drain records are still queued (`lv host drain a
// && systemctl stop litevirt`, with a first use waiting on a slow voter) waits
// a bounded time for them, then abandons the rest and names every VM whose
// record it abandoned, on the VM's events (which replicate when the host
// returns). The attempt in flight is cancelled and nothing queued behind it is
// tried, so a record is never written after the daemon reported it lost; and
// an abandoned attempt is not a refusal, so it starts no backoff.
//
// Mutations: drop the wait in FinishDrainRecords - the records are abandoned
// while they could still land (the fast case returns names); return no names /
// write no event - the abandoned VMs are unmarked; do not cancel the attempt
// in flight - the recorder outlives the stop; keep trying queued records after
// the stop - the gate is asked again.
func TestDrainRecords_AStopNamesTheRecordsItAbandons(t *testing.T) {
	t.Cleanup(SetDrainRecordTimingForTest(30*time.Second, time.Minute))
	s, g := recordServer(t, map[string]string{"v1": "b", "v2": "b", "v3": "b"})
	entered := make(chan struct{}, 1)
	g.fn = func(ctx context.Context, call int) error {
		if call == 1 {
			entered <- struct{}{}
			<-ctx.Done() // a first use whose acknowledgements never come
			return ctx.Err()
		}
		return nil
	}
	add, done := s.startDrainRecords(context.Background(), 3)
	for _, vm := range []string{"v1", "v2", "v3"} {
		add(drainRecordJob{vm: vm, from: "a", to: "b"})
	}
	done()
	<-entered

	start := time.Now()
	got := s.FinishDrainRecords(100 * time.Millisecond)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the stop waited %s; it is bounded by the wait it was given", el)
	}
	slices.Sort(got)
	if want := []string{"v1", "v2", "v3"}; !slices.Equal(got, want) {
		t.Fatalf("abandoned = %v, want %v", got, want)
	}
	waited := make(chan struct{})
	go func() { s.WaitDrainRecordsForTest(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("the record in flight outlived the stop")
	}
	if n := g.called(); n != 1 {
		t.Fatalf("the gate was asked %d times; a record queued behind the stop must not be tried", n)
	}
	if vms := recordedVMs(t, s, "a"); len(vms) != 0 {
		t.Fatalf("records written after the stop abandoned them: %v", vms)
	}
	for _, vm := range got {
		if !failbackEvent(t, s, vm, "the daemon stopped") {
			t.Errorf("the abandoned record of %s is not on its events", vm)
		}
	}
	s.drainRecords.mu.Lock()
	until := s.drainRecords.until
	s.drainRecords.mu.Unlock()
	if !until.IsZero() {
		t.Fatalf("an abandoned attempt started a backoff (until %s)", until)
	}
}

// Records that land within the wait are not abandoned: the stop waits for them.
func TestDrainRecords_AStopWaitsForRecordsThatLand(t *testing.T) {
	s, g := recordServer(t, map[string]string{"v1": "b", "v2": "b"})
	release := make(chan struct{})
	g.fn = func(ctx context.Context, call int) error {
		<-release
		return nil
	}
	add, done := s.startDrainRecords(context.Background(), 2)
	add(drainRecordJob{vm: "v1", from: "a", to: "b"})
	add(drainRecordJob{vm: "v2", from: "a", to: "b"})
	done()
	time.AfterFunc(200*time.Millisecond, func() { close(release) })
	if got := s.FinishDrainRecords(5 * time.Second); len(got) != 0 {
		t.Fatalf("abandoned %v although every record landed within the wait", got)
	}
	if vms := recordedVMs(t, s, "a"); len(vms) != 2 {
		t.Fatalf("records = %v, want v1 and v2", vms)
	}
}

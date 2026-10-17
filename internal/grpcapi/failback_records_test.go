package grpcapi

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// scriptedFeatureGate is a release-feature gate whose answer a test scripts
// per call (fn, given the call's 1-based number); a nil fn or a nil answer
// grants.
type scriptedFeatureGate struct {
	t     testing.TB
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, call int) error
}

func (g *scriptedFeatureGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.mu.Lock()
	g.calls++
	n, fn := g.calls, g.fn
	g.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, n); err != nil {
			return err
		}
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *scriptedFeatureGate) FeatureAvailable(capabilities.Feature) bool { return true }

func (g *scriptedFeatureGate) called() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// recordServer is a server whose release token has latched (the scripted gate
// says so) and whose cluster-policy writes are open, with the VMs given on
// their hosts.
func recordServer(t *testing.T, vmHosts map[string]string) (*Server, *scriptedFeatureGate) {
	t.Helper()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	g := &scriptedFeatureGate{t: t}
	s.SetReleaseFeatureGate(g)
	for vm, host := range vmHosts {
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: vm, HostName: host, State: "running", Spec: `{"name":"` + vm + `"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm, err)
		}
	}
	return s, g
}

func recordedVMs(t *testing.T, s *Server, from string) []string {
	t.Helper()
	o, err := corrosion.ListDrainOrigins(context.Background(), s.db, from)
	if err != nil {
		t.Fatal(err)
	}
	var vms []string
	for _, r := range o {
		vms = append(vms, r.VM)
	}
	return vms
}

func failbackEvent(t *testing.T, s *Server, vm, substr string) bool {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 20, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Type == "vm.failback" && strings.Contains(e.Detail, substr) {
			return true
		}
	}
	return false
}

// The backoff after a refused first use stands in for asking the gate again,
// whose answer is the same until a recipient returns. Once this replica holds
// an acknowledged record (another node completed the first use), the gate
// passes on its local path, so a record is not skipped for the backoff - the
// shape the login policy's backoff takes.
//
// Mutation: drop the acknowledged-record check - w is skipped for the backoff.
func TestDrainRecords_AnAcknowledgedUseLiftsTheBackoff(t *testing.T) {
	ctx := context.Background()
	s, g := recordServer(t, map[string]string{"w": "b"})
	s.drainRecords.until = time.Now().Add(time.Hour)
	s.drainRecords.delay = 10 * time.Minute

	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "w", from: "a", to: "b"})
	if n := g.called(); n != 0 {
		t.Fatalf("the gate was asked %d times inside a backoff, with no acknowledged use here", n)
	}
	if !failbackEvent(t, s, "w", "not recorded for failback") {
		t.Fatal("the skip is not on w's events")
	}

	info, _ := capabilities.LookupFeature(capabilities.FeatureDrainFailback)
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, info.Token, string(capabilities.FeatureDrainFailback), "e2", true); err != nil {
		t.Fatal(err)
	}
	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "w", from: "a", to: "b"})
	if n := g.called(); n != 1 {
		t.Fatalf("the gate was asked %d times; an acknowledged use here lifts the backoff", n)
	}
	if vms := recordedVMs(t, s, "a"); !slices.Equal(vms, []string{"w"}) {
		t.Fatalf("records = %v, want w's", vms)
	}
}

// Inside a backoff, a VM the record would not be written for anyway (no longer
// where the drain put it) gets no "not recorded ... move it back by hand"
// event: the skip is only for a record that would have been written.
//
// Mutation: check the backoff before the VM's placement - gone gets the event.
func TestDrainRecords_ABackoffSkipsOnlyARecordItWouldWrite(t *testing.T) {
	ctx := context.Background()
	s, g := recordServer(t, map[string]string{"gone": "c", "here": "b"})
	s.drainRecords.until = time.Now().Add(time.Hour)
	s.drainRecords.delay = 10 * time.Minute

	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "gone", from: "a", to: "b"})
	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "here", from: "a", to: "b"})
	if failbackEvent(t, s, "gone", "") {
		t.Fatal("gone, which is no longer on b, got a vm.failback event; it would not have been recorded")
	}
	if !failbackEvent(t, s, "here", "not recorded for failback") {
		t.Fatal("here's skip is not on its events")
	}
	if n := g.called(); n != 0 {
		t.Fatalf("the gate was asked %d times inside a backoff", n)
	}
}

// Two drains whose attempts are both in flight when the gate refuses start one
// backoff, not two: the second refusal finds the first one's window running and
// keeps it, so the delay doubles once.
//
// Mutation: double the delay on every refusal - the second doubles it again.
func TestDrainRecords_ConcurrentRefusalsDoubleTheBackoffOnce(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(SetDrainRecordTimingForTest(time.Second, 5*time.Second))
	s, g := recordServer(t, map[string]string{"v1": "b", "v2": "b"})
	var both sync.WaitGroup
	both.Add(2)
	g.fn = func(context.Context, int) error {
		both.Done()
		both.Wait() // both attempts are past the backoff check
		return refusedForTest
	}
	var wg sync.WaitGroup
	for _, vm := range []string{"v1", "v2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.recordDrainOriginBounded(ctx, drainRecordJob{vm: vm, from: "a", to: "b"})
		}()
	}
	wg.Wait()
	s.drainRecords.mu.Lock()
	delay, until := s.drainRecords.delay, s.drainRecords.until
	s.drainRecords.mu.Unlock()
	if delay != 10*time.Second {
		t.Fatalf("next delay = %s, want 10s: two refusals at once double it once", delay)
	}
	if left := time.Until(until); left > 5*time.Second {
		t.Fatalf("backoff runs %s more, want at most the minimum 5s", left)
	}
}

var refusedForTest = errRefusedForTest{}

type errRefusedForTest struct{}

func (errRefusedForTest) Error() string { return "the cluster upgrade must finish first (test)" }

// The worker's read of the VM's placement as its move ends tells "found it on
// the target" (the record describes that placement), "found it elsewhere" (it
// moved again before the read: no record) and "could not read" (the record is
// built from the row when it is written) apart.
//
// Mutation: report a VM found elsewhere as unread - its job falls back to the
// write-time row.
func TestDrainRecordJobFor_TellsElsewhereFromUnread(t *testing.T) {
	ctx := context.Background()
	s, _ := recordServer(t, map[string]string{"here": "b", "away": "c"})
	if j := s.drainRecordJobFor(ctx, "here", "a", "b"); j.at == nil || j.movedAgain {
		t.Fatalf("job for a VM on its target = %+v, want its placement", j)
	}
	if j := s.drainRecordJobFor(ctx, "away", "a", "b"); j.at != nil || !j.movedAgain {
		t.Fatalf("job for a VM found elsewhere = %+v, want it marked as moved again", j)
	}
	if j := s.drainRecordJobFor(ctx, "missing", "a", "b"); j.at != nil || j.movedAgain {
		t.Fatalf("job for a VM whose row could not be read = %+v, want neither", j)
	}
}

// A VM the drain's worker found elsewhere, or whose placement has changed
// since the drain's move, gets no record even though it is back on the
// target when the record would be written; and its events say why, so an
// operator reading them after `undrain --failback` sees why it stayed.
//
// Mutations: ignore movedAgain - the record is written from the write-time
// row; drop the event - nothing on the VM's events.
func TestDrainRecords_AVMMovedAgainGetsNoRecordAndAnEvent(t *testing.T) {
	ctx := context.Background()
	s, g := recordServer(t, map[string]string{"v1": "b", "v2": "b"})
	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "v1", from: "a", to: "b", movedAgain: true})
	stale := &drainPlacement{epoch: 41, gen: 7}
	s.recordDrainOriginBounded(ctx, drainRecordJob{vm: "v2", from: "a", to: "b", at: stale})
	if vms := recordedVMs(t, s, "a"); len(vms) != 0 {
		t.Fatalf("records = %v, want none for VMs moved again", vms)
	}
	if n := g.called(); n != 0 {
		t.Fatalf("the gate was asked %d times for VMs that get no record", n)
	}
	for _, vm := range []string{"v1", "v2"} {
		if !failbackEvent(t, s, vm, "moved again since the drain moved it") {
			t.Errorf("%s's events do not say why it got no record", vm)
		}
	}
}

// An undrain counts only the drain records that still describe a VM: a record
// whose VM was deleted (or moved for another reason) is not "a VM a drain moved
// that has not opted in", and it is collected rather than reported again on
// every later undrain.
//
// The record is written AFTER the delete in the "older node" case: a node that
// predates the delete writers spending the record leaves it behind, and only
// the validity filter keeps the count right then.
//
// Mutations: drop the filter in autoFailback - the deleted VMs are counted
// ("1 VM(s)" / "2 VM(s)") and their records stay; drop the delete writers'
// spend - the "this build" case leaves its record.
func TestAutoFailback_CountsOnlyRecordsThatStillApply(t *testing.T) {
	ctx := context.Background()
	put := func(t *testing.T, s *Server, vm string) {
		t.Helper()
		v, err := corrosion.GetVM(ctx, s.db, vm)
		if err != nil || v == nil {
			t.Fatalf("GetVM %s: %v", vm, err)
		}
		gen, _ := corrosion.GetPlacementGen(ctx, s.db, vm)
		if err := corrosion.PutDrainOrigin(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureDrainFailback),
			corrosion.DrainOrigin{VM: vm, From: "h1", To: "h2", Epoch: v.OwnerEpoch, CreatedAt: v.CreatedAt, Gen: gen}, "drain"); err != nil {
			t.Fatal(err)
		}
	}
	undrain := func(s *Server) *pb.Host {
		h := &pb.Host{Name: "h1"}
		s.autoFailback(ctx, "h1", h)
		return h
	}

	t.Run("deleted by this build", func(t *testing.T) {
		s, _ := recordServer(t, map[string]string{"v": "h2"})
		put(t, s, "v")
		if err := corrosion.DeleteVM(ctx, s.db, "v"); err != nil {
			t.Fatal(err)
		}
		if h := undrain(s); h.FailbackNote != "" || h.FailbackStarted {
			t.Fatalf("note = %q started = %v, want neither for a deleted VM", h.FailbackNote, h.FailbackStarted)
		}
		if vms := recordedVMs(t, s, "h1"); len(vms) != 0 {
			t.Fatalf("records left = %v", vms)
		}
	})

	t.Run("deleted by an older node that left the record", func(t *testing.T) {
		s, _ := recordServer(t, map[string]string{"v": "h2", "w": "h2"})
		put(t, s, "v")
		put(t, s, "w")
		v, _ := corrosion.GetVM(ctx, s.db, "v")
		w, _ := corrosion.GetVM(ctx, s.db, "w")
		for _, name := range []string{"v", "w"} {
			if err := corrosion.DeleteVM(ctx, s.db, name); err != nil {
				t.Fatal(err)
			}
		}
		// What an older node's delete leaves behind.
		for _, vm := range []*corrosion.VMRecord{v, w} {
			if err := corrosion.PutDrainOrigin(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureDrainFailback),
				corrosion.DrainOrigin{VM: vm.Name, From: "h1", To: "h2", Epoch: vm.OwnerEpoch, CreatedAt: vm.CreatedAt}, "drain"); err != nil {
				t.Fatal(err)
			}
		}
		if vms := recordedVMs(t, s, "h1"); len(vms) != 2 {
			t.Fatalf("setup: records = %v, want 2", vms)
		}
		if h := undrain(s); h.FailbackNote != "" || h.FailbackStarted {
			t.Fatalf("note = %q started = %v, want neither for deleted VMs", h.FailbackNote, h.FailbackStarted)
		}
		if vms := recordedVMs(t, s, "h1"); len(vms) != 0 {
			t.Fatalf("records left = %v, want them collected", vms)
		}
	})

	t.Run("a live record still counts, a moved one does not", func(t *testing.T) {
		s, _ := recordServer(t, map[string]string{"live": "h2", "moved": "h2"})
		put(t, s, "live")
		// moved's record is from an earlier placement generation: failback
		// would discard it as moved for another reason.
		mv, _ := corrosion.GetVM(ctx, s.db, "moved")
		if err := corrosion.PutDrainOrigin(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureDrainFailback),
			corrosion.DrainOrigin{VM: "moved", From: "h1", To: "h2", Epoch: mv.OwnerEpoch, CreatedAt: mv.CreatedAt, Gen: 99}, "drain"); err != nil {
			t.Fatal(err)
		}
		h := undrain(s)
		if !strings.HasPrefix(h.FailbackNote, "1 VM(s) a drain moved from h1 have not opted in") {
			t.Fatalf("note = %q, want exactly the live VM counted", h.FailbackNote)
		}
		if vms := recordedVMs(t, s, "h1"); !slices.Equal(vms, []string{"live"}) {
			t.Fatalf("records = %v, want only live's", vms)
		}
	})
}

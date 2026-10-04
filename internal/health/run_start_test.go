package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A failing verdict carries when its run of unanswered probes began, in
// last_seen. Failover reads it as the start of the outage the observer is
// watching. It used to derive the start from the count, one probe per
// ProbeInterval, and a probe of a powered-off host takes ~2.85 s on the kvm003
// lab: the derived start drifted later through the outage, until a fence or an
// operator confirmation made minutes into it read as older than the outage
// (drills 3 and 6 on main-e004c250).
//
// Each probe here runs ~2.85 s on the observer's clock, beating as the
// heartbeat would, so no probe straddles a stall.
//
// Mutation: drop the last_seen argument from the failing verdict (bind nil) —
// every failing verdict publishes no start.
func TestCheckHost_FailingVerdictCarriesItsRunStart(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "obs", Address: "10.9.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01"},
		{Name: "dead", Address: "10.9.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "02"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := NewChecker("obs", t.TempDir(), db)
	c.clock = clock
	answer := "down" // "up", "unready" or "down"
	c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		// The probe of a dead host runs out its timeout; the heartbeat keeps
		// beating meanwhile.
		switch answer {
		case "up":
			return true, "", nil
		case "unready":
			return false, "store wedged", nil
		}
		for i := 0; i < 3; i++ {
			advance(950 * time.Millisecond)
			c.beat(c.now())
		}
		return false, "", errors.New("i/o timeout")
	})
	type verdict struct {
		failures int
		lastSeen interface{}
	}
	var published []verdict
	c.writeFn = func(_ context.Context, sqlStr string, args ...interface{}) error {
		if args[1] != "dead" {
			return nil
		}
		if sqlStr == healthyVerdictSQL {
			published = append(published, verdict{0, args[3]})
		} else {
			published = append(published, verdict{args[3].(int), args[4]})
		}
		return nil
	}
	host := corrosion.HostRecord{Name: "dead", Address: "10.9.0.2", GRPCPort: 7443, State: "active"}
	probe := func() {
		advance(100 * time.Millisecond)
		c.beat(c.now())
		c.checkHost(ctx, host)
	}

	// The host answers once, then goes dark: the run starts at the first
	// unanswered probe's observation, and every verdict of the run says so.
	answer = "up"
	probe()
	answer = "down"
	published = nil
	probe()
	start := clock()
	for i := 0; i < 40; i++ {
		probe()
	}
	if len(published) != 41 || published[40].failures != 41 {
		t.Fatalf("want 41 failing verdicts counting to 41, have %d (last %+v)", len(published), published[len(published)-1])
	}
	want := start.UTC().Format(time.RFC3339Nano)
	for i, v := range published {
		if v.lastSeen != want {
			t.Fatalf("failing verdict %d (count %d) carries last_seen %v, want the run's start %s", i, v.failures, v.lastSeen, want)
		}
	}
	// What the count alone used to say: 40 × ProbeInterval back from the
	// last verdict is well after the run began.
	if derived := clock().Add(-40 * ProbeInterval); !derived.After(start.Add(30 * time.Second)) {
		t.Fatalf("fixture: the cadence must outrun ProbeInterval (derived %v, start %v)", derived, start)
	}

	// An unready answer ends the run; the next silence starts a new one.
	answer = "unready"
	published = nil
	probe()
	if len(published) != 1 || published[0].lastSeen != nil {
		t.Fatalf("an unready answer must publish no run start, have %+v", published)
	}
	answer = "down"
	published = nil
	probe()
	restart := clock()
	probe()
	probe()
	for _, v := range published {
		if v.lastSeen != restart.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("after an unready answer the run must restart at its first silent probe %s, verdict %+v", restart.UTC().Format(time.RFC3339Nano), v)
		}
	}

	// So does a healthy one.
	answer = "up"
	published = nil
	probe()
	if len(published) != 1 || published[0].failures != 0 {
		t.Fatalf("want one healthy verdict, have %+v", published)
	}
	answer = "down"
	published = nil
	probe()
	again := clock()
	probe()
	if len(published) != 2 || published[1].lastSeen != again.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("after a healthy answer the run must restart at its first failed probe %s, have %+v",
			again.UTC().Format(time.RFC3339Nano), published)
	}
}

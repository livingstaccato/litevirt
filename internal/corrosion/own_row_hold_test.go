package corrosion

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Test 15 (I5, R-I1): the own-row hold.

// ownRow gives c's own host (c.hostName) a live row naming serial.
func ownRow(t *testing.T, c *Client, serial string) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{Name: c.hostName, Address: "10.0.0.15",
		SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: serial}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnRowHold_Arms(t *testing.T) {
	ctx := context.Background()
	t.Run("a: live under another serial", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "01old")
		st, err := c.ConfigureOwnRowHold(ctx, "02new")
		if err != nil || !st.Held || st.Arm != "a" || st.Reason != OwnRowHeldAtStart {
			t.Fatalf("hold = %+v, %v; want held on arm a at start", st, err)
		}
		if st.InstalledSerial != "02new" || st.RecordedSerial != "01old" {
			t.Errorf("serials = %+v", st)
		}
		err = RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"})
		if !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("RegisterHost while held = %v, want ErrOwnRowHeld", err)
		}
		if err := UpdateHostStartup(ctx, c, c.hostName, "active", "v", 1, 2, 3, true); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("UpdateHostStartup while held = %v", err)
		}
		if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "02new"); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("RecordOwnCertSerial while held = %v", err)
		}
		if err := c.OwnRowWritable(c.hostName); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("OwnRowWritable while held = %v", err)
		}
		if err := c.OwnRowWritable("someone-else"); err != nil {
			t.Errorf("another host's row is not held: %v", err)
		}
	})
	t.Run("b: tombstone", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "01old")
		if err := DeleteHost(ctx, c, c.hostName); err != nil {
			t.Fatal(err)
		}
		st, _ := c.ConfigureOwnRowHold(ctx, "02new")
		if !st.Held || st.Arm != "b" {
			t.Fatalf("hold = %+v, want arm b", st)
		}
	})
	t.Run("a missing row does not hold", func(t *testing.T) {
		c := newTestDB(t)
		if st, _ := c.ConfigureOwnRowHold(ctx, "02new"); st.Held {
			t.Fatalf("hold = %+v over a missing row", st)
		}
		if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); err != nil {
			t.Fatalf("an empty database's registration: %v", err)
		}
	})
	t.Run("a restart after adoption starts open", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "02new")
		if st, _ := c.ConfigureOwnRowHold(ctx, "02new"); st.Held {
			t.Fatalf("hold = %+v on the admitted row", st)
		}
	})
}

// It opens only on a row that names the installed serial: the number alone,
// under another serial, keeps it held (M9).
func TestOwnRowHold_OpensOnlyOnTheInstalledSerial(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	ownRow(t, c, "01old")
	if st, _ := c.ConfigureOwnRowHold(ctx, "02new"); !st.Held {
		t.Fatal("not held")
	}
	// Another admission's row at incarnation 1 (a superseding serial).
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, cert_serial = '03other' WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded); !st.Held {
		t.Fatal("the hold opened on a row at the next incarnation under another serial")
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET cert_serial = '02new' WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded); st.Held {
		t.Fatalf("the hold did not open on the installed serial: %+v", st)
	}
}

// It re-engages at runtime when an apply moves the own row away from the
// installed serial (R-I1), with reason superseded; and on a tombstone, removed.
func TestOwnRowHold_ReengagesWhenSuperseded(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	ownRow(t, c, "02new")
	if st, _ := c.ConfigureOwnRowHold(ctx, "02new"); st.Held {
		t.Fatal("held at start")
	}
	var fired atomic.Int32
	done := make(chan struct{}, 4)
	c.SetOwnRowChangeHook(func() {
		fired.Add(1)
		c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded)
		done <- struct{}{}
	})
	// A replicated write to this host's row naming another serial.
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: recordOwnCertSerialSQL,
		Params: []interface{}{"03other", "2999-01-01T00:00:00.000000000Z", c.hostName}})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the own-row hook did not fire")
	}
	st := c.OwnRowHold()
	if !st.Held || st.Reason != OwnRowHeldSuperseded || st.Arm != "a" {
		t.Fatalf("hold = %+v, want re-held as superseded", st)
	}
	if err := UpdateHostStartup(ctx, c, c.hostName, "active", "v", 1, 2, 3, true); !errors.Is(err, ErrOwnRowHeld) {
		t.Errorf("an own-row write after supersession = %v", err)
	}
	// Removed while up.
	applyRemote(t, c, "2999000000001-0000-peer", Statement{SQL: deleteHostSQL, Params: []interface{}{
		"2999-01-01T00:00:00.000000001Z", "2999-01-01T00:00:00.000000001Z", c.hostName}})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the own-row hook did not fire on the removal")
	}
	if st := c.OwnRowHold(); !st.Held || st.Reason != OwnRowHeldRemoved || st.Arm != "b" {
		t.Errorf("hold = %+v, want re-held as removed", st)
	}
}

// Bounded: past OwnRowHoldTimeout the hold reports timed out and lets the
// writers fall back (M10).
func TestOwnRowHold_TimesOut(t *testing.T) {
	ctx := context.Background()
	old := OwnRowHoldTimeout
	OwnRowHoldTimeout = 50 * time.Millisecond
	t.Cleanup(func() { OwnRowHoldTimeout = old })
	c := newTestDB(t)
	ownRow(t, c, "01old")
	if st, _ := c.ConfigureOwnRowHold(ctx, "02new"); !st.Held {
		t.Fatal("not held")
	}
	time.Sleep(100 * time.Millisecond)
	st := c.OwnRowHold()
	if !st.Held || !st.TimedOut {
		t.Fatalf("hold = %+v, want timed out", st)
	}
	// Arm (a) falls back to today's re-record.
	if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); err != nil {
		t.Fatalf("RegisterHost after the timeout: %v", err)
	}
	if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "02new" {
		t.Errorf("the fallback did not re-record: %s", got)
	}
}

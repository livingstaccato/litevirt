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
		st, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", ""))
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
		st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", ""))
		if !st.Held || st.Arm != "b" {
			t.Fatalf("hold = %+v, want arm b", st)
		}
	})
	t.Run("a missing row does not hold", func(t *testing.T) {
		c := newTestDB(t)
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); st.Held {
			t.Fatalf("hold = %+v over a missing row", st)
		}
		if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); err != nil {
			t.Fatalf("an empty database's registration: %v", err)
		}
	})
	t.Run("a restart after adoption starts open", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "02new")
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); st.Held {
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
	if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); !st.Held {
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
	if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); st.Held {
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
	if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); !st.Held {
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

// I-1: a renewal — live, or while the host was down — never raises a hold.
func TestOwnRowHold_ARenewalIsNotAnArm(t *testing.T) {
	ctx := context.Background()
	t.Run("live", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "01old")
		installed := "01old"
		renewedFrom := ""
		if st, _ := c.ConfigureOwnRowHold(ctx, func() (string, string) { return installed, renewedFrom }); st.Held {
			t.Fatalf("held at start: %+v", st)
		}
		// `lv host renew-cert` installs a successor in place.
		installed, renewedFrom = "02new", "01old"
		if st, _ := c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded); st.Held {
			t.Fatalf("a live renewal raised the hold: %+v", st)
		}
		if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "02new"); err != nil {
			t.Fatalf("the re-record of a renewal: %v", err)
		}
		if st, _ := c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded); st.Held {
			t.Fatalf("held after the re-record: %+v", st)
		}
		if err := UpdateHostState(ctx, c, c.hostName, "draining"); err != nil {
			t.Errorf("an own-row write after a live renewal: %v", err)
		}
	})
	t.Run("while down", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "01old")
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "01old")); st.Held {
			t.Fatalf("a boot after an offline renewal held: %+v", st)
		}
		if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); err != nil {
			t.Fatalf("RegisterHost after an offline renewal: %v", err)
		}
		if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "02new" {
			t.Errorf("the renewal was not re-recorded at once: %s", got)
		}
	})
}

// I-2: a hold raised at runtime (superseded) never times out, and nor does one
// over a counted row: the local row may be another machine's admission.
func TestOwnRowHold_ASupersededHoldNeverTimesOut(t *testing.T) {
	ctx := context.Background()
	old := OwnRowHoldTimeout
	OwnRowHoldTimeout = 20 * time.Millisecond
	t.Cleanup(func() { OwnRowHoldTimeout = old })
	for _, tc := range []struct {
		name   string
		reason string
		n      int
	}{
		{"superseded at runtime", OwnRowHeldSuperseded, 1},
		{"at start over a counted row", OwnRowHeldAtStart, 1},
	} {
		c := newTestDB(t)
		ownRow(t, c, "02new")
		if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); err != nil {
			t.Fatal(err)
		}
		// The winner's admission, under another serial.
		if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = ?, cert_serial = 'yy09' WHERE name = ?`, tc.n, c.hostName); err != nil {
			t.Fatal(err)
		}
		if tc.reason == OwnRowHeldAtStart {
			if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); err != nil {
				t.Fatal(err)
			}
		} else {
			c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded)
		}
		time.Sleep(60 * time.Millisecond)
		st := c.OwnRowHold()
		if !st.Held || st.TimedOut {
			t.Errorf("%s: hold = %+v, want held and never timed out", tc.name, st)
		}
		before := mutationLogText(t, c)
		if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("%s: RegisterHost past the timeout = %v, want ErrOwnRowHeld", tc.name, err)
		}
		if after := mutationLogText(t, c); after != before {
			t.Errorf("%s: a superseded host re-recorded its serial at the winner's key", tc.name)
		}
	}
}

// I-3: the hold is enforced centrally, on every locally originated write to
// the own row, whichever writer makes it.
func TestOwnRowHold_EveryOwnRowWriterIsHeld(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	ownRow(t, c, "01old")
	if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); !st.Held {
		t.Fatal("not held")
	}
	if err := SetHostLabel(ctx, c, c.hostName, "litevirt.lxc", "true"); !errors.Is(err, ErrOwnRowHeld) {
		t.Errorf("a label write on a held host = %v", err)
	}
	if _, err := UpdateHostStateFrom(ctx, c, c.hostName, "active", "upgrading"); !errors.Is(err, ErrOwnRowHeld) {
		t.Errorf("an activation on a held host = %v", err)
	}
	if err := UpdateHostVersion(ctx, c, c.hostName, "v9"); !errors.Is(err, ErrOwnRowHeld) {
		t.Errorf("a version write on a held host = %v", err)
	}
	// Another host's row is not held.
	if err := InsertHost(ctx, c, HostRecord{Name: "other", Address: "10.0.0.16", State: "active", CertSerial: "o1"}); err != nil {
		t.Fatal(err)
	}
	if err := SetHostLabel(ctx, c, "other", "k", "v"); err != nil {
		t.Errorf("another host's label write: %v", err)
	}
}

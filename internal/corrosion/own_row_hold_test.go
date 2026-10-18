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

// Re-review I-1 (a): a hold raised at start over a row at incarnation 0 that
// then moves to a counted incarnation under the same arm never times out.
func TestOwnRowHold_AStartHoldWhoseRowIsReadmittedNeverTimesOut(t *testing.T) {
	ctx := context.Background()
	old := OwnRowHoldTimeout
	OwnRowHoldTimeout = 20 * time.Millisecond
	t.Cleanup(func() { OwnRowHoldTimeout = old })
	c := newTestDB(t)
	ownRow(t, c, "01old") // the stale row at 0, under another serial
	if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); !st.Held || st.Incarnation != 0 {
		t.Fatalf("hold = %+v, want held at start over incarnation 0", st)
	}
	// Another machine's admission at 1, under a third serial: the arm stays a.
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, cert_serial = 'yy09' WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded)
	time.Sleep(60 * time.Millisecond)
	if st, _ := c.EvaluateOwnRowHold(ctx, OwnRowHeldSuperseded); !st.Held || st.TimedOut {
		t.Fatalf("hold = %+v, want held and never timed out", st)
	}
	// Re-review 2, m-1: the reason follows the row.
	if st := c.OwnRowHold(); st.Reason != OwnRowHeldSuperseded {
		t.Errorf("reason = %q, want superseded once the row is another admission", st.Reason)
	}
	before := mutationLogText(t, c)
	if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); err == nil {
		t.Error("RegisterHost re-recorded over another admission's row")
	}
	if after := mutationLogText(t, c); after != before {
		t.Error("the mutation log changed")
	}
}

// Re-review I-1 (b): the writers themselves never re-record over a counted row
// that names neither the installed certificate nor the one it renewed,
// whatever the hold says; a renewal of the recorded certificate is re-recorded.
func TestReRecord_RefusedOverAnotherAdmissionsCountedRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	ownRow(t, c, "yy09")
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1 WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	// No hold configured: nothing proves a renewal.
	if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "02new"}); !errors.Is(err, ErrReRecordAtCountedRow) {
		t.Errorf("RegisterHost = %v, want ErrReRecordAtCountedRow", err)
	}
	if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "02new"); !errors.Is(err, ErrReRecordAtCountedRow) {
		t.Errorf("RecordOwnCertSerial = %v, want ErrReRecordAtCountedRow", err)
	}
	if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "yy09" {
		t.Fatalf("serial = %s", got)
	}
	// A renewal of the recorded certificate is re-recorded.
	if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "yy09")); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "02new"); err != nil {
		t.Errorf("the renewal's re-record: %v", err)
	}
	if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "02new" {
		t.Errorf("serial = %s, want the renewal", got)
	}
}

// memAdmission is an in-memory AdmissionMemory.
type memAdmission struct {
	n  int64
	at string
	ok bool
}

func (m *memAdmission) Load() (int64, string, bool) { return m.n, m.at, m.ok }
func (m *memAdmission) Store(n int64, at string) error {
	m.n, m.at, m.ok = n, at, true
	return nil
}

// Re-review 2, I-1: a certificate reissued outside the renewal flow, over the
// admission this host remembers, is re-recorded (the trust_rotated_peer_certs
// recovery converges); over another admission's key, or with no memory, it is
// not.
func TestOwnAdmission_AReissuedCertificateOverItsOwnAdmission(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, mem *memAdmission) *Client {
		c := newTestDB(t)
		ownRow(t, c, "s1")
		if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, created_at = '2026-01-01T00:00:00.000000000Z' WHERE name = ?`, c.hostName); err != nil {
			t.Fatal(err)
		}
		if mem != nil {
			c.SetOwnAdmissionMemory(mem)
		}
		// While the row named its certificate, the hold remembered it.
		if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s1", "")); err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("its own admission: re-recorded", func(t *testing.T) {
		mem := &memAdmission{}
		c := setup(t, mem)
		if !mem.ok || mem.n != 1 {
			t.Fatalf("the admission was not remembered: %+v", mem)
		}
		// The PKI directory is regenerated: s2, not a renewal of s1.
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s2", "")); st.Held {
			t.Fatalf("held over its own admission: %+v", st)
		}
		if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "s2"}); err != nil {
			t.Fatalf("RegisterHost: %v", err)
		}
		if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "s2" {
			t.Errorf("serial = %s, want the reissued s2", got)
		}
	})
	t.Run("another admission's key: refused", func(t *testing.T) {
		mem := &memAdmission{}
		c := setup(t, mem)
		if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 2, cert_serial = 'y9' WHERE name = ?`, c.hostName); err != nil {
			t.Fatal(err)
		}
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s2", "")); !st.Held {
			t.Fatalf("not held over another admission: %+v", st)
		}
		if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "s2"); err == nil {
			t.Error("re-recorded over another admission")
		}
		if err := c.reRecordRefused(c.hostName, "y9", "s2", 2, "2026-01-01T00:00:00.000000000Z"); !errors.Is(err, ErrReRecordAtCountedRow) {
			t.Errorf("the writer check = %v", err)
		}
	})
	t.Run("same incarnation, another stamp: refused", func(t *testing.T) {
		mem := &memAdmission{}
		c := setup(t, mem)
		if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s2", "")); err != nil {
			t.Fatal(err)
		}
		if err := c.reRecordRefused(c.hostName, "s1", "s2", 1, "2026-01-01T00:00:00.000000000Z"); err != nil {
			t.Fatalf("precondition: its own admission is refused: %v", err)
		}
		if err := c.reRecordRefused(c.hostName, "y9", "s2", 1, "2026-02-01T00:00:00.000000000Z"); !errors.Is(err, ErrReRecordAtCountedRow) {
			t.Errorf("the writer check = %v", err)
		}
	})
	t.Run("no memory: refused", func(t *testing.T) {
		c := setup(t, nil)
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s2", "")); !st.Held {
			t.Fatalf("not held without a memory: %+v", st)
		}
		if err := c.reRecordRefused(c.hostName, "s1", "s2", 1, "2026-01-01T00:00:00.000000000Z"); !errors.Is(err, ErrReRecordAtCountedRow) {
			t.Errorf("the writer check = %v", err)
		}
	})
}

// Re-review 2, m-2: no own-row write lands on another admission's row, even
// before the hold's next evaluation — after a timed-out hold, and with no hold
// raised at all.
func TestOwnRowHold_EveryWriteReadsTheRowItWrites(t *testing.T) {
	ctx := context.Background()
	old := OwnRowHoldTimeout
	OwnRowHoldTimeout = 20 * time.Millisecond
	t.Cleanup(func() { OwnRowHoldTimeout = old })
	t.Run("a timed-out hold", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "01old")
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); !st.Held {
			t.Fatal("not held")
		}
		time.Sleep(40 * time.Millisecond)
		if st := c.OwnRowHold(); !st.TimedOut {
			t.Fatalf("hold = %+v, want timed out", st)
		}
		// Another admission lands; nothing evaluates the hold.
		if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, cert_serial = 'yy09' WHERE name = ?`, c.hostName); err != nil {
			t.Fatal(err)
		}
		before := mutationLogText(t, c)
		if err := UpdateHostStartup(ctx, c, c.hostName, "active", "v", 1, 2, 3, true); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("a boot report over another admission's row = %v, want ErrOwnRowHeld", err)
		}
		if err := SetHostLabel(ctx, c, c.hostName, "k", "v"); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("a label write over another admission's row = %v, want ErrOwnRowHeld", err)
		}
		if after := mutationLogText(t, c); after != before {
			t.Error("the mutation log changed")
		}
	})
	t.Run("no hold yet", func(t *testing.T) {
		c := newTestDB(t)
		ownRow(t, c, "02new")
		if st, _ := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("02new", "")); st.Held {
			t.Fatal("held")
		}
		if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, cert_serial = 'yy09' WHERE name = ?`, c.hostName); err != nil {
			t.Fatal(err)
		}
		if err := UpdateHostVersion(ctx, c, c.hostName, "v9"); !errors.Is(err, ErrOwnRowHeld) {
			t.Errorf("a version write over another admission's row = %v, want ErrOwnRowHeld", err)
		}
	})
}

// Lab test 26, F7: a certificate swapped while the daemon runs, not by a
// renewal, is held until the daemon restarts even over the admission this host
// remembers (docs/auth.md); the restart's registration then re-records it. A
// renewal is re-recorded at runtime.
func TestOwnAdmission_ARuntimeSwapIsHeldUntilRestart(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	ownRow(t, c, "s1")
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, created_at = '2026-01-01T00:00:00.000000000Z' WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	c.SetOwnAdmissionMemory(&memAdmission{})
	if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s1", "")); err != nil {
		t.Fatal(err)
	}
	// An unrelated certificate is loaded at runtime.
	if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s2", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "s2"); !errors.Is(err, ErrCertSwappedAtRuntime) {
		t.Errorf("runtime re-record of a swapped certificate = %v, want ErrCertSwappedAtRuntime", err)
	}
	if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "s1" {
		t.Fatalf("serial = %s, want s1 held until restart", got)
	}
	// The restart's registration re-records it over its own admission.
	if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "s2"}); err != nil {
		t.Fatalf("RegisterHost at restart: %v", err)
	}
	if got := oneString(t, c, `SELECT cert_serial FROM hosts WHERE name = ?`, "cert_serial", c.hostName); got != "s2" {
		t.Fatalf("serial = %s, want s2 after the restart", got)
	}
	// A renewal at runtime is re-recorded.
	if _, err := c.ConfigureOwnRowHold(ctx, StaticInstalledCert("s3", "s2")); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOwnCertSerial(ctx, c, c.hostName, "s3"); err != nil {
		t.Errorf("runtime re-record of a renewal: %v", err)
	}
}

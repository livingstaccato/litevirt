package corrosion

import (
	"context"
	"testing"
)

// The re-admission's incarnation stamp (host_readmit.go, THE INCARNATION).

func hostCreatedAt(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT created_at FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host-x: %d %v", len(rows), err)
	}
	return rows[0].String("created_at")
}

// Every node that applies the re-admission stamps the same instant: the
// admission's own updated_at, as wall time, in NowTS's fixed-width form.
func TestReplicatedReadmission_StampsItsIncarnation(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	const ts = "2999-01-01T00:00:07.000001Z"
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	if got := hostCreatedAt(t, c); got != "2999-01-01T00:00:07.000001000Z" {
		t.Errorf("created_at = %q after the re-admission, want its own instant 2999-01-01T00:00:07.000001000Z", got)
	}
}

// An HLC updated_at is read by its physical time.
func TestReplicatedReadmission_StampsAnHLCAdmissionAsWallTime(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	// 4102444807000 ms = 2100-01-01T00:00:07Z.
	const ts = "4102444807000-0000-peer"
	if at, ok := tsInstant(ts); !ok || at.UTC().Format("2006-01-02T15:04:05Z07:00") != "2100-01-01T00:00:07Z" {
		t.Fatalf("fixture: %q does not parse as the expected HLC instant (%v %v)", ts, at, ok)
	}
	applyRemote(t, c, ts, Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	if got := hostCreatedAt(t, c); got != "2100-01-01T00:00:07.000000000Z" {
		t.Errorf("created_at = %q, want the HLC's physical instant 2100-01-01T00:00:07.000000000Z", got)
	}
}

// The node `lv host add` runs on stamps it too.
func TestAdmitHost_StampsItsIncarnation(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	if _, err := c.DB().Exec(`UPDATE hosts SET created_at = '2026-01-01T00:00:00Z' WHERE name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	before := hostCreatedAt(t, c)
	if err := AdmitHost(context.Background(), c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: HostStateJoining, CertSerial: readmitSerial,
	}); err != nil {
		t.Fatalf("AdmitHost: %v", err)
	}
	rows, err := c.Query(context.Background(), `SELECT created_at, updated_at FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host-x: %d %v", len(rows), err)
	}
	at, ok := tsInstant(rows[0].String("updated_at"))
	if !ok {
		t.Fatalf("updated_at %q does not parse", rows[0].String("updated_at"))
	}
	want := at.UTC().Format(nowTSLayout)
	if got := rows[0].String("created_at"); got != want || got == before {
		t.Errorf("created_at = %q (was %q), want the admission's instant %q", got, before, want)
	}
}

// The machine's own stale database: its row is live, its serial re-recorded
// at a clock newer than the admission. The admission does not apply there,
// and nothing is stamped: the row stays the previous incarnation, which is
// what lets the tie chain hand it the re-admitted row.
func TestReplicatedReadmission_OverALiveNewerRowStampsNothing(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	before := hostCreatedAt(t, c)
	if _, err := c.DB().Exec(recordOwnCertSerialSQL, readmitSerial, "2999-06-01T00:00:00.000001Z", "host-x"); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if got := hostCreatedAt(t, c); got != before {
		t.Errorf("created_at = %q, want %q: a re-admission that did not apply must not stamp", got, before)
	}
}

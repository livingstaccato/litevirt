package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The host incarnation counter (host_incarnation.go). Each test names the
// design's test number (eqts-report.md, section 7).

const (
	incSerialA = "0a01"
	incSerialB = "0b02"
)

func incGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)
}

// incKey reads host-x's ordering key.
func incKey(t *testing.T, c *Client) hostKey {
	t.Helper()
	tx, err := c.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	k, found, err := localHostKey(context.Background(), tx, "host-x")
	if err != nil || !found {
		t.Fatalf("read host-x's key: found=%v err=%v", found, err)
	}
	return k
}

// lastEntry is the statements of c's newest mutation_log entry.
func incLastEntry(t *testing.T, c *Client) []Statement {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the last mutation_log entry: %d rows, %v", len(rows), err)
	}
	var stmts []Statement
	if err := json.Unmarshal([]byte(rows[0].String("stmts")), &stmts); err != nil {
		t.Fatal(err)
	}
	return stmts
}

func incLastEntryJSON(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the last mutation_log entry: %d rows, %v", len(rows), err)
	}
	return rows[0].String("stmts")
}

// admittedV2 is a node that held host-x's tombstone at 0 and re-admitted it
// at incarnation 1 with incSerialA. It returns the node and the admission's
// entry.
func admittedV2(t *testing.T) (*Client, []Statement) {
	t.Helper()
	a := newTestDB(t)
	oldIncarnation(t, a)
	n, at, err := AdmitHostV2(context.Background(), a, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: HostStateJoining, CertSerial: incSerialA,
	}, incGrant(t))
	if err != nil {
		t.Fatalf("AdmitHostV2: %v", err)
	}
	if n != 1 || at == "" {
		t.Fatalf("AdmitHostV2 issued (%d, %q), want (1, a stamp)", n, at)
	}
	return a, incLastEntry(t, a)
}

func region(t *testing.T, c *Client) string {
	return oneString(t, c, `SELECT region FROM hosts WHERE name = 'host-x'`, "region")
}

// Test 4 (and R-M3): a statement written against a lower key is refused,
// whatever its clock; the admitter and a receiver hold the same key.
func TestHostIncarnation_WALRefusesALowerKey(t *testing.T) {
	a, entry := admittedV2(t)
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	if got, want := incKey(t, c), incKey(t, a); got != want {
		t.Fatalf("receiver key %+v, admitter key %+v; every node must hold the admission's key", got, want)
	}
	if k := incKey(t, c); k.n != 1 || k.deleted {
		t.Fatalf("receiver row = %+v, want live at incarnation 1", k)
	}
	// The admitter applied its own statement through the same reset form.
	assertNoOldIncarnation(t, a)

	// A stale partial update (no envelope: incarnation 0), far newer in time.
	applyRemote(t, c, "2999000000001-0000-stale", Statement{
		SQL: `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"rack-a", "2999-01-01T00:00:00.000000001Z", "host-x"},
	})
	if got := region(t, c); got != "default" {
		t.Errorf("a write against incarnation 0 applied over incarnation 1: region %q", got)
	}
	// A stale removal, far newer in time.
	applyRemote(t, c, "2999000000002-0000-stale", Statement{SQL: deleteHostSQL, Params: []interface{}{
		"2999-01-01T00:00:00.000000002Z", "2999-01-01T00:00:00.000000002Z", "host-x"}})
	if incKey(t, c).deleted {
		t.Error("a removal of incarnation 0 removed incarnation 1")
	}
	// A duplicate admission at the same number with an EARLIER stamp loses.
	k := incKey(t, c)
	early := "2000-01-01T00:00:00.000000000Z"
	dup := HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: HostStateJoining, CertSerial: incSerialB}
	applyRemote(t, c, "2999000000003-0000-dup", Statement{SQL: readmitHostV2SQL,
		Params:          readmitV2Params(dup, 1, early, "2999-01-01T00:00:00.000000003Z"),
		HostIncarnation: &HostIncarnation{N: 1, At: early}})
	if got := incKey(t, c); got.serial != k.serial {
		t.Errorf("a duplicate admission with an earlier stamp replaced the row: %+v", got)
	}
	// One with a LATER stamp wins, whole.
	late := "2998-01-01T00:00:00.000000000Z"
	applyRemote(t, c, "2999000000004-0000-dup", Statement{SQL: readmitHostV2SQL,
		Params:          readmitV2Params(dup, 1, late, "2998-01-01T00:00:00.000000000Z"),
		HostIncarnation: &HostIncarnation{N: 1, At: late}})
	if got := incKey(t, c); got.serial != incSerialB || got.at != late {
		t.Errorf("a duplicate admission with a later stamp did not win: %+v", got)
	}
}

// Test 5 (and M2): a V2 re-admission resets a STALE LIVE row of a lower
// incarnation, even one newer in time and already naming the new serial.
func TestHostIncarnation_V2OverAStaleLiveNewerRow(t *testing.T) {
	for _, reRecorded := range []bool{false, true} {
		_, entry := admittedV2(t)
		c := newTestDB(t)
		c.SetCredentialsSplitGate(func() bool { return true })
		if err := InsertHost(context.Background(), c, HostRecord{Name: "host-x", Address: "10.0.0.15",
			SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		serial := "01old"
		if reRecorded {
			serial = incSerialA
		}
		if _, err := c.DB().Exec(`UPDATE hosts SET fence_strategy = 'ipmi', ipmi_address = '10.0.1.15',
			ipmi_user = 'probe', ipmi_pass = 'p', region = 'rack-a', cert_serial = ?, updated_at = '2999-06-01T00:00:00.000000000Z'
			WHERE name = 'host-x'`, serial); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", "p", "2025-01-01T00:00:00.000000000Z"); err != nil {
			t.Fatal(err)
		}
		applyRemote(t, c, "2999000000000-0000-admitter", entry...)
		got := readHostSettings(t, c)
		if got.deleted || got.region != "'default'" || got.fence != "'best-effort'" || got.ipmiAddr != "NULL" {
			t.Errorf("re-recorded=%v: the stale row was not reset: %+v", reRecorded, got)
		}
		if k := incKey(t, c); k.n != 1 || k.serial != incSerialA {
			t.Errorf("re-recorded=%v: key %+v, want incarnation 1 with the admitted serial", reRecorded, k)
		}
		if pass, ok := liveCredential(t, c); ok {
			t.Errorf("re-recorded=%v: the old credential is still live (%q)", reRecorded, pass)
		}
	}
}

// Test 6 (and M4): a write against a key this node does not hold yet is
// refused, and anti-entropy brings the row whole; a removal that arrives ahead
// of its incarnation's re-admission is held off until anti-entropy too.
func TestHostIncarnation_WALRefusesAheadThenAERepairs(t *testing.T) {
	ctx := context.Background()
	a, entry := admittedV2(t)
	if err := UpdateHostRegion(ctx, a, "host-x", "rack-b"); err != nil {
		t.Fatal(err)
	}
	update := incLastEntry(t, a)
	if update[0].HostIncarnation == nil || update[0].HostIncarnation.N != 1 {
		t.Fatalf("the update is not stamped with incarnation 1: %+v", update[0].HostIncarnation)
	}
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", update...)
	if k := incKey(t, c); !k.deleted || k.n != 0 {
		t.Fatalf("an update of incarnation 1 applied over the tombstone at 0: %+v", k)
	}
	mergeHostsFrom(t, a, c)
	if got := region(t, c); got != "rack-b" || incKey(t, c).n != 1 {
		t.Errorf("anti-entropy did not bring the re-admitted row whole: region %q, key %+v", got, incKey(t, c))
	}

	// Two origins: the removal of incarnation 1 reaches a node before the
	// re-admission that made it.
	if err := DeleteHost(ctx, a, "host-x"); err != nil {
		t.Fatal(err)
	}
	removal := incLastEntry(t, a)
	d := newTestDB(t)
	oldIncarnation(t, d)
	applyRemote(t, d, "2999000000001-0000-admitter", removal...)
	applyRemote(t, d, "2999000000000-0000-admitter", entry...)
	if k := incKey(t, d); k.deleted {
		t.Fatalf("the removal should have waited; key %+v", k)
	}
	mergeHostsFrom(t, a, d)
	if k := incKey(t, d); !k.deleted || k.n != 1 {
		t.Errorf("anti-entropy did not bring the removal of incarnation 1: %+v", k)
	}
}

// mergeHostsFrom runs one anti-entropy merge of from's hosts table into to.
func mergeHostsFrom(t *testing.T, from, to *Client) {
	t.Helper()
	st, ok := from.dumpTable("hosts")
	if !ok {
		t.Fatal("dump hosts")
	}
	mergeHostsTable(t, to, st)
}

func mergeHostsTable(t *testing.T, to *Client, st syncTable) {
	t.Helper()
	// Through JSON, as a peer's dump arrives.
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var wire syncTable
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := to.mergeTable(wire, map[string]bool{"hosts": true}); err != nil {
		t.Fatalf("merge hosts: %v", err)
	}
}

// Test 7: anti-entropy orders hosts rows by the key ahead of the clock.
func TestHostIncarnation_AE(t *testing.T) {
	ctx := context.Background()
	t.Run("a higher key wins over a newer timestamp", func(t *testing.T) {
		a, _ := admittedV2(t)
		c := newTestDB(t)
		if err := InsertHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DB().Exec(`UPDATE hosts SET region = 'rack-a', updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		mergeHostsFrom(t, a, c)
		if k := incKey(t, c); k.n != 1 || region(t, c) != "default" {
			t.Errorf("the stale newer row kept: key %+v region %q", k, region(t, c))
		}
	})
	t.Run("a higher live row beats a lower newer tombstone", func(t *testing.T) {
		a, _ := admittedV2(t)
		c := newTestDB(t)
		oldIncarnation(t, c)
		if _, err := c.DB().Exec(`UPDATE hosts SET updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		mergeHostsFrom(t, a, c)
		if k := incKey(t, c); k.deleted || k.n != 1 {
			t.Errorf("the newer tombstone at 0 kept: %+v", k)
		}
	})
	t.Run("a higher tombstone beats a lower newer live row", func(t *testing.T) {
		a, _ := admittedV2(t)
		if err := DeleteHost(ctx, a, "host-x"); err != nil {
			t.Fatal(err)
		}
		c := newTestDB(t)
		if err := InsertHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DB().Exec(`UPDATE hosts SET updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		mergeHostsFrom(t, a, c)
		if k := incKey(t, c); !k.deleted || k.n != 1 {
			t.Errorf("the newer live row at 0 kept: %+v", k)
		}
	})
	t.Run("a lower key is refused", func(t *testing.T) {
		a, entry := admittedV2(t)
		_ = a
		c := newTestDB(t)
		oldIncarnation(t, c)
		applyRemote(t, c, "2999000000000-0000-admitter", entry...)
		stale := newTestDB(t)
		if err := InsertHost(ctx, stale, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		if _, err := stale.DB().Exec(`UPDATE hosts SET region = 'rack-a', updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		mergeHostsFrom(t, stale, c)
		if k := incKey(t, c); k.n != 1 || region(t, c) != "default" {
			t.Errorf("a row of incarnation 0 replaced incarnation 1: %+v region %q", k, region(t, c))
		}
	})
	t.Run("a dump without the column reads as incarnation 0", func(t *testing.T) {
		_, entry := admittedV2(t)
		c := newTestDB(t)
		oldIncarnation(t, c)
		applyRemote(t, c, "2999000000000-0000-admitter", entry...)
		stale := newTestDB(t)
		if err := InsertHost(ctx, stale, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		if _, err := stale.DB().Exec(`UPDATE hosts SET region = 'rack-a', updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		st, _ := stale.dumpTable("hosts")
		mergeHostsTable(t, c, withoutColumn(st, "incarnation"))
		if k := incKey(t, c); k.n != 1 || region(t, c) != "default" {
			t.Errorf("a previous-build row replaced incarnation 1: %+v region %q", k, region(t, c))
		}
	})
}

// withoutColumn is st as a previous build, which has no col, dumps it.
func withoutColumn(st syncTable, col string) syncTable {
	i := indexOf(st.Columns, col)
	if i < 0 {
		return st
	}
	out := syncTable{Name: st.Name}
	out.Columns = append(append([]string{}, st.Columns[:i]...), st.Columns[i+1:]...)
	for _, r := range st.Rows {
		out.Rows = append(out.Rows, append(append([]interface{}{}, r[:i]...), r[i+1:]...))
	}
	return out
}

// Test 8: the tie chain decides by the key first.
func TestHostsTieChain_KeyDecidesFirst(t *testing.T) {
	cols := []string{"name", "incarnation", "created_at", "cert_serial", "deleted_at", "updated_at"}
	idx := columnIndexMap(cols)
	view := func(local, incoming []interface{}) rowView {
		return rowView{cols: cols, colIdx: idx, local: local, incoming: incoming}
	}
	ts := "2026-01-01T00:00:00.000000000Z"
	for _, tc := range []struct {
		name            string
		local, incoming []interface{}
		want            string // "local", "incoming", "pass"
	}{
		{"higher incarnation incoming", []interface{}{"h", int64(0), ts, "a", nil, ts}, []interface{}{"h", int64(1), ts, "b", nil, ts}, "incoming"},
		{"higher incarnation local", []interface{}{"h", int64(2), ts, "a", nil, ts}, []interface{}{"h", int64(1), ts, "b", nil, ts}, "local"},
		{"lower tombstone loses", []interface{}{"h", int64(1), ts, "a", nil, ts}, []interface{}{"h", int64(0), ts, "a", ts, ts}, "local"},
		{"equal incarnation later stamp", []interface{}{"h", int64(1), "2026-01-01T00:00:00.000000000Z", "a", nil, ts}, []interface{}{"h", int64(1), "2026-01-02T00:00:00.000000000Z", "b", nil, ts}, "incoming"},
		{"equal incarnation, a tombstone of the earlier admission loses", []interface{}{"h", int64(1), "2026-01-01T00:00:00.000000000Z", "a", ts, ts}, []interface{}{"h", int64(1), "2026-01-02T00:00:00.000000000Z", "b", nil, ts}, "incoming"},
		{"same admission, the tombstone stands", []interface{}{"h", int64(1), ts, "a", ts, ts}, []interface{}{"h", int64(1), ts, "a", nil, ts}, "local"},
		{"same admission, another serial (a renewal): the clock decides", []interface{}{"h", int64(1), ts, "ff", nil, ts}, []interface{}{"h", int64(1), ts, "00", nil, ts}, "pass"},
		{"same admission", []interface{}{"h", int64(1), ts, "a", nil, ts}, []interface{}{"h", int64(1), ts, "a", nil, ts}, "pass"},
		{"both legacy", []interface{}{"h", int64(0), ts, "a", nil, ts}, []interface{}{"h", int64(0), ts, "b", nil, ts}, "pass"},
	} {
		d := ruleIncarnationCounter()(view(tc.local, tc.incoming))
		got := "pass"
		switch {
		case !d.decided:
		case d.keepLocal:
			got = "local"
		default:
			got = "incoming"
		}
		if got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	// The counter is the chain's first rule.
	local := []interface{}{"h", int64(1), ts, "a", ts, ts}
	incoming := []interface{}{"h", int64(2), ts, "b", nil, ts}
	if d := capabilityMap["hosts"].chain[0](view(local, incoming)); !d.decided || d.keepLocal {
		t.Error("the hosts chain's first rule does not take a higher incarnation over a lower tombstone")
	}
}

// Test 3 (C1): a legacy re-admission never applies over a counted row, and
// AdmitHost refuses to emit one.
func TestHostIncarnation_LegacyReadmitOverCounterRefused(t *testing.T) {
	ctx := context.Background()
	a, entry := admittedV2(t)
	if err := DeleteHost(ctx, a, "host-x"); err != nil {
		t.Fatal(err)
	}
	removal := incLastEntry(t, a)
	c := newTestDB(t)
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	applyRemote(t, c, "2999000000001-0000-admitter", removal...)
	applyRemote(t, c, "2999000000002-0000-legacy", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, incSerialB, "2999-01-01T00:00:00.000000000Z", "host-x", incSerialB,
	}})
	if k := incKey(t, c); !k.deleted || k.n != 1 {
		t.Errorf("a legacy re-admission applied over a tombstone at incarnation 1: %+v", k)
	}
	sm.mu.Lock()
	refusals := strings.Join(sm.mergeRejected, ",")
	sm.mu.Unlock()
	if !strings.Contains(refusals, "hosts/wal/"+reasonLegacyOver) {
		t.Errorf("the refusal was not reported as %s: %s", reasonLegacyOver, refusals)
	}
	err := AdmitHost(ctx, a, HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialB})
	if !errors.Is(err, ErrReadmitNeedsCounter) {
		t.Errorf("AdmitHost over a counted tombstone = %v, want ErrReadmitNeedsCounter", err)
	}
}

// Test 2 (C1): the daemon's registration never issues an incarnation.
func TestRegisterHost_NeverIssues(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1, deleted_at = updated_at WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	before := mutationLogText(t, c)
	if err := RegisterHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", State: "active", CertSerial: incSerialA}); err != nil {
		t.Fatalf("RegisterHost: %v", err)
	}
	if after := mutationLogText(t, c); after != before {
		t.Errorf("RegisterHost over its own counted tombstone wrote: %s", strings.TrimPrefix(after, before))
	}
}

// Test 10 (I2): every hosts write is stamped with the row's key just before it
// runs, on both log sites; at incarnation 0 the wire is byte-identical.
func TestHostIncarnation_EveryHostsWriterIsStamped(t *testing.T) {
	ctx := context.Background()
	a, _ := admittedV2(t)
	k := incKey(t, a)
	want := &HostIncarnation{N: k.n, At: k.at}
	writes := []struct {
		name  string
		write func() error
	}{
		// First, while the row is still 'joining': the guarded write
		// (ExecuteEntriesGuarded) must find its state and log an entry.
		{"guarded startup (ExecuteEntriesGuarded)", func() error {
			ok, err := UpdateHostStartupFrom(ctx, a, "host-x", HostStateJoining, "upgrading", "v4", 1, 2, 3, true)
			if err == nil && !ok {
				t.Fatal("the guarded startup wrote nothing")
			}
			return err
		}},
		{"label", func() error { return SetHostLabel(ctx, a, "host-x", "k", "v") }},
		{"region", func() error { return UpdateHostRegion(ctx, a, "host-x", "r") }},
		{"role", func() error { return UpdateHostRole(ctx, a, "host-x", "witness") }},
		{"state", func() error { return UpdateHostState(ctx, a, "host-x", "maintenance") }},
		{"version", func() error { return UpdateHostVersion(ctx, a, "host-x", "v2") }},
		{"resources", func() error { return UpdateHostResources(ctx, a, "host-x", 1, 2, 3) }},
		{"startup", func() error { return UpdateHostStartup(ctx, a, "host-x", "active", "v3", 1, 2, 3, true) }},
	}
	for _, w := range writes {
		before := incLastEntryJSON(t, a)
		if err := w.write(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if incLastEntryJSON(t, a) == before {
			t.Fatalf("%s logged no entry", w.name)
		}
		for _, s := range incLastEntry(t, a) {
			if !strings.Contains(s.SQL, "UPDATE hosts") {
				continue
			}
			if s.HostIncarnation == nil || *s.HostIncarnation != *want {
				t.Errorf("%s: %q stamped %+v, want %+v", w.name, s.SQL, s.HostIncarnation, want)
			}
		}
	}
	// A batch writing the host twice: the re-admission, then a write on top.
	b := newTestDB(t)
	oldIncarnation(t, b)
	h := HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialA}
	uts := b.NowTS()
	at, _ := ReadmitStamp(uts)
	if err := b.ExecuteBatch(ctx, []Statement{
		{SQL: readmitHostV2SQL, Params: readmitV2Params(h, 1, at, uts)},
		{SQL: `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"r", b.NowTS(), "host-x"}},
	}); err != nil {
		t.Fatal(err)
	}
	for i, s := range incLastEntry(t, b) {
		if s.HostIncarnation == nil || s.HostIncarnation.N != 1 || s.HostIncarnation.At != at {
			t.Errorf("statement %d of the batch stamped %+v, want (1, %s)", i, s.HostIncarnation, at)
		}
	}
	// Incarnation 0: no key on the wire at all.
	z := newTestDB(t)
	if err := InsertHost(ctx, z, HostRecord{Name: "host-z", Address: "10.0.0.16", State: "active", CertSerial: "01"}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostRegion(ctx, z, "host-z", "r"); err != nil {
		t.Fatal(err)
	}
	if j := incLastEntryJSON(t, z); strings.Contains(j, "HostIncarnation") {
		t.Errorf("a write at incarnation 0 carries the key: %s", j)
	}
}

// Test 12 (I2): a V2 whose envelope disagrees with its parameters is refused.
func TestHostIncarnation_V2EnvelopeMismatchRefused(t *testing.T) {
	_, entry := admittedV2(t)
	bad := append([]Statement(nil), entry...)
	bad[0].HostIncarnation = &HostIncarnation{N: 2, At: bad[0].HostIncarnation.At}
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", bad...)
	if k := incKey(t, c); !k.deleted || k.n != 0 {
		t.Errorf("a V2 with a mismatched envelope applied: %+v", k)
	}
}

// Test 13 (and M1): a refused hosts statement is not absorbed into its split
// row; a co-batched split statement still lands.
func TestHostIncarnation_RefusedStatementIsNotAbsorbed(t *testing.T) {
	_, entry := admittedV2(t)
	c := newTestDB(t)
	c.SetHostMembershipGate(func() bool { return true })
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	before := oneString(t, c, `SELECT COALESCE((SELECT state FROM host_membership WHERE host_name = 'host-x'), '') AS s`, "s")
	// A lagging node's state write to hosts alone, against incarnation 0.
	applyRemote(t, c, "2999000000001-0000-lagging", Statement{SQL: updateHostStateSQL,
		Params: []interface{}{"maintenance", "2999-01-01T00:00:00.000000000Z", "host-x"}})
	if got := oneString(t, c, `SELECT COALESCE((SELECT state FROM host_membership WHERE host_name = 'host-x'), '') AS s`, "s"); got != before {
		t.Errorf("a refused hosts state write was absorbed into host_membership: %q -> %q", before, got)
	}
	// The same write dual-written: hosts refused, membership lands (M1).
	applyRemote(t, c, "2999000000002-0000-lagging",
		Statement{SQL: updateHostStateSQL, Params: []interface{}{"maintenance", "2999-01-01T00:00:00.000000001Z", "host-x"}},
		Statement{SQL: hostMembershipStateSQL, Params: []interface{}{"host-x", "maintenance", int64(0), "", "2999-01-01T00:00:00.000000001Z"}})
	if got := oneString(t, c, `SELECT state FROM hosts WHERE name = 'host-x'`, "state"); got == "maintenance" {
		t.Error("the hosts half of a lagging write applied")
	}
	if got := oneString(t, c, `SELECT state FROM host_membership WHERE host_name = 'host-x'`, "state"); got != "maintenance" {
		t.Errorf("the membership half did not land: %q", got)
	}
}

// Test 14 (M3): a parked update meets the rule when it is replayed.
func TestParkedUpdate_RefusedWhenTheRowArrivesAtAnotherKey(t *testing.T) {
	c := newTestDB(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	// An update written against incarnation 1 reaches a node with no row.
	if _, err := r.ApplyRemoteMutationsFrom(ctx, replayEntry(t, "peer", "2999000000001-0000-peer", Statement{
		SQL: `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"rack-z", "2999-01-01T00:00:00.000000000Z", "host-x"},
		HostIncarnation: &HostIncarnation{N: 1, At: "2026-01-01T00:00:00.000000000Z"},
	}), false); err != nil {
		t.Fatal(err)
	}
	// The row arrives by an insert at incarnation 0.
	ins := Statement{SQL: insertHostSQL, Params: []interface{}{"host-x", "10.0.0.15", "root", 22, 7443, "active", "01",
		0, 0, 0, "best-effort", "", "worker", 0.0, 0.0, -1, -1, "", "2026-01-01T00:00:00.000000000Z", "2026-01-01T00:00:00.000000000Z"}}
	if _, err := r.ApplyRemoteMutationsFrom(ctx, replayEntry(t, "peer", "2999000000002-0000-peer", ins), false); err != nil {
		t.Fatal(err)
	}
	if got := region(t, c); got == "rack-z" {
		t.Error("a parked update of incarnation 1 applied over a row at 0 on replay")
	}
}

// Test 17 (part): the endpoint writer takes a counted own row only.
func TestWriteOwnEndpoint_OnlyOnACountedOwnRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertHost(ctx, c, HostRecord{Name: c.hostName, Address: "10.0.0.15", GRPCPort: 7443, State: "active", CertSerial: "01"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnEndpoint(ctx, c, c.hostName, "10.0.0.16", 37000, incGrant(t)); err == nil {
		t.Error("WriteOwnEndpoint wrote an own row at incarnation 0")
	}
	if _, err := c.DB().Exec(`UPDATE hosts SET incarnation = 1 WHERE name = ?`, c.hostName); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnEndpoint(ctx, c, c.hostName, "10.0.0.16", 37000, incGrant(t)); err != nil {
		t.Fatalf("WriteOwnEndpoint: %v", err)
	}
	if got := oneString(t, c, `SELECT grpc_port FROM hosts WHERE name = ?`, "grpc_port", c.hostName); got != "37000" {
		t.Errorf("grpc_port = %s", got)
	}
	if err := WriteOwnEndpoint(ctx, c, "other", "10.0.0.16", 37000, incGrant(t)); err == nil {
		t.Error("WriteOwnEndpoint wrote another host's row")
	}
}

// C-1: a certificate renewal of a re-added host is an ordinary later write.
// Two copies of one admission that differ only by the renewal are ordered by
// their clock, never by serial: anti-entropy never reverts the renewal, in
// either direction, whichever serial is larger.
func TestHostIncarnation_ARenewalIsNeverRevertedByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	for _, renewed := range []string{"00aa", "ffaa"} { // below and above incSerialA
		_, entry := admittedV2(t)
		before, after := newTestDB(t), newTestDB(t)
		for _, c := range []*Client{before, after} {
			oldIncarnation(t, c)
			applyRemote(t, c, "2999000000000-0000-admitter", entry...)
		}
		// The host renews its certificate; one replica has the re-record.
		if err := after.Execute(ctx, recordOwnCertSerialSQL, renewed, after.NowTS(), "host-x"); err != nil {
			t.Fatal(err)
		}
		if k := incKey(t, after); k.serial != renewed || k.n != 1 {
			t.Fatalf("renewed=%s: the re-record did not apply: %+v", renewed, k)
		}
		// The renewed replica pulls the pre-renewal copy: keeps the renewal.
		mergeHostsFrom(t, before, after)
		if k := incKey(t, after); k.serial != renewed {
			t.Errorf("renewed=%s: anti-entropy reverted the renewal to %s", renewed, k.serial)
		}
		// The other replica pulls the renewal: takes it.
		mergeHostsFrom(t, after, before)
		if k := incKey(t, before); k.serial != renewed {
			t.Errorf("renewed=%s: anti-entropy did not carry the renewal (%s)", renewed, k.serial)
		}
	}
}

// Merge with credential retirement (credentials_revive_guard.go): a fence
// credential that rides with a hosts write this node refused as another
// incarnation's is that admission's credential, and is skipped with it —
// whatever its clock, and whether or not this node holds a tombstone for it.
func TestHostIncarnation_ARefusedEntrysCredentialIsSkipped(t *testing.T) {
	_, entry := admittedV2(t)
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	if _, err := c.DB().Exec(`DELETE FROM host_fence_credentials WHERE host_name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	const ts = "2999-01-01T00:00:00.000000000Z"
	// A lagging node's `lv host configure --ipmi-pass`, against incarnation 0.
	applyRemote(t, c, "2999000000001-0000-lagging",
		Statement{SQL: `UPDATE hosts SET ipmi_pass = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"old-pass", ts, "host-x"}},
		Statement{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "old-pass", ts}})
	if got := oneString(t, c, `SELECT COALESCE((SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = 'host-x'), '') AS p`, "p"); got != "" {
		t.Errorf("the credential of a refused incarnation-0 write landed over incarnation 1: %q", got)
	}
	// Precondition: the same credential, alone in its entry, is not refused.
	applyRemote(t, c, "2999000000002-0000-lagging",
		Statement{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "new-pass", ts}})
	if got := oneString(t, c, `SELECT COALESCE((SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = 'host-x'), '') AS p`, "p"); got != "new-pass" {
		t.Errorf("a credential alone in its entry did not land: %q", got)
	}
}

// incCredentialRow reads host-x's credential row: its password, whether it is
// live, and its retirement evidence.
func incCredentialRow(t *testing.T, c *Client) (pass string, live bool, after string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT ipmi_pass, deleted_at, after_retirement FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host-x's credential row: %d rows, %v", len(rows), err)
	}
	return rows[0].String("ipmi_pass"), rows[0].String("deleted_at") == "", rows[0].String("after_retirement")
}

// laggingConfigure is a `lv host config --ipmi-pass` entry from a node still
// on host-x's old admission (no envelope: incarnation 0), at ts.
func laggingConfigure(pass, ts string) []Statement {
	return []Statement{
		{SQL: `UPDATE hosts SET ipmi_pass = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{pass, ts, "host-x"}},
		{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", pass, ts}},
	}
}

func retirementOf(t *testing.T, c *Client) string {
	t.Helper()
	return oneString(t, c, `SELECT deleted_at FROM host_fence_credentials WHERE host_name = 'host-x'`, "deleted_at")
}

// Re-review 4, m-4: an up-to-date node that holds the re-admission's
// tombstone skips a lagging configure's credential, whatever its clock, and
// no row carries the re-admission's retirement as evidence.
func TestHostIncarnation_ARefusedEntrysCredentialLeavesTheTombstone(t *testing.T) {
	_, entry := admittedV2(t)
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	retired := retirementOf(t, c)
	if _, live, _ := incCredentialRow(t, c); live || retired == "" {
		t.Fatal("fixture: the re-admission did not retire host-x's credential")
	}
	applyRemote(t, c, "2999000000001-0000-lagging", laggingConfigure("old-pass", "2999-01-01T00:00:00.000000000Z")...)
	if pass, live, after := incCredentialRow(t, c); live || pass != "" || after == retired {
		t.Errorf("credential row = (%q, live %v, after %q); want the tombstone, carrying no evidence", pass, live, after)
	}
}

// Re-review 4, m-2: the skip does not depend on the order of the entry. The
// clear pass writes the upsert ahead of its hosts clear; over no credential
// row the upsert would otherwise land before the clear is refused.
func TestHostIncarnation_ARefusedClearPassSkipsTheUpsertAheadOfIt(t *testing.T) {
	_, entry := admittedV2(t)
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	if _, err := c.DB().Exec(`DELETE FROM host_fence_credentials WHERE host_name = 'host-x'`); err != nil {
		t.Fatal(err)
	}
	const ts = "2999-01-01T00:00:00.000000000Z"
	applyRemote(t, c, "2999000000001-0000-lagging",
		Statement{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{"host-x", "old-pass", ts}},
		Statement{SQL: hostsClearIPMIPassSQL, Params: []interface{}{"", "2999-01-01T00:00:00.000000001Z", "host-x"}})
	if pass, ok := liveCredential(t, c); ok {
		t.Errorf("a refused clear pass's upsert landed: %q", pass)
	}
}

// Re-review 4, m-1: a node whose hosts row lags the re-admission, while its
// credential row already holds the re-admission's tombstone (its sensitive
// pull ran, its public one did not), gives a lagging operator write no
// evidence, on the WAL apply path and on its own write path. The same write
// on the re-admission's row does carry it.
func TestCredential_ALaggingHostsRowGivesAnOperatorWriteNoEvidence(t *testing.T) {
	ctx := context.Background()
	a, _ := admittedV2(t)
	retired := retirementOf(t, a)
	const ts = "2999-01-01T00:00:00.000000000Z"
	// lagging is a node at host-x's old admission, live and older than the
	// retirement, holding the re-admission's tombstone.
	lagging := func(t *testing.T, n int64) *Client {
		c := newTestDB(t)
		oldIncarnation(t, c)
		if _, err := c.DB().Exec(`UPDATE hosts SET deleted_at = NULL, incarnation = ?,
			created_at = '2026-01-01T00:00:00.000000000Z', updated_at = '2026-01-02T00:00:00.000000000Z'
			WHERE name = 'host-x'`, n); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = '', deleted_at = ?, updated_at = ?,
			after_retirement = '' WHERE host_name = 'host-x'`, retired, retired); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, n := range []int64{0, 1} {
		t.Run(fmt.Sprintf("apply, hosts row at %d", n), func(t *testing.T) {
			c := lagging(t, n)
			stmts := laggingConfigure("old-pass", ts)
			if n > 0 {
				// Written against the row this node holds, so only the
				// evidence rule decides.
				stmts[0].HostIncarnation = &HostIncarnation{N: n, At: "2026-01-01T00:00:00.000000000Z"}
			}
			applyRemote(t, c, "2999000000001-0000-lagging", stmts...)
			if pass, live, after := incCredentialRow(t, c); live || after == retired {
				t.Errorf("credential row = (%q, live %v, after %q); want the tombstone", pass, live, after)
			}
		})
		t.Run(fmt.Sprintf("local write, hosts row at %d", n), func(t *testing.T) {
			c := lagging(t, n)
			if err := c.ExecuteBatch(ctx, laggingConfigure("old-pass", ts)); err != nil {
				t.Fatal(err)
			}
			if pass, live, after := incCredentialRow(t, c); live || after == retired {
				t.Errorf("credential row = (%q, live %v, after %q); want the tombstone", pass, live, after)
			}
		})
	}
	t.Run("the re-admission's own row", func(t *testing.T) {
		if err := a.ExecuteBatch(ctx, laggingConfigure("new-pass", ts)); err != nil {
			t.Fatal(err)
		}
		if pass, live, after := incCredentialRow(t, a); !live || pass != "new-pass" || after != retired {
			t.Errorf("credential row = (%q, live %v, after %q); want new-pass carrying %s", pass, live, after, retired)
		}
	})
}

// Re-review 4, m-4: the skip never loses a legitimate write for good. A node
// that has not applied the re-admission skips the new admission's password
// (its hosts write is a newer incarnation's); once the re-admission and one
// sensitive merge reach it, it holds the password.
func TestHostIncarnation_ASkippedNewerPasswordArrivesByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	a, entry := admittedV2(t)
	const ts = "2999-01-01T00:00:00.000000000Z"
	if err := a.ExecuteBatch(ctx, laggingConfigure("new-pass", ts)); err != nil {
		t.Fatal(err)
	}
	set := incLastEntry(t, a)
	c := newTestDB(t)
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000001-0000-admitter", set...)
	if pass, ok := liveCredential(t, c); ok && pass == "new-pass" {
		t.Fatal("fixture: a node at the old admission applied the new one's password")
	}
	applyRemote(t, c, "2999000000000-0000-admitter", entry...)
	if err := c.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	if pass, ok := liveCredential(t, c); !ok || pass != "new-pass" {
		t.Errorf("after the re-admission and a sensitive merge the password is %q (live %v), want new-pass", pass, ok)
	}
}

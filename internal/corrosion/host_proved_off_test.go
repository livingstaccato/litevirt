package corrosion

import (
	"context"
	"testing"
	"time"
)

// HostProvedOff is 'fenced' AND a proof-grade newest fence: the state alone
// is not proof (colonelpanik/litevirt#253). A leader before fence_state_v1
// latched records 'fenced' for an SSH poweroff nothing verified.
//
// Mutation: make HostProvedOff read the state alone — every 'fenced' case
// without a proof-grade newest fence goes red.
// Mutation: let any proof-grade row prove it, not the newest — the
// newer-unverified and failed-after-verified cases go red. Mutation: let a
// tie resolve to the stronger row — the same-second case goes red.
func TestHostProvedOff(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	type row struct {
		method, result string
		at             time.Time
	}
	for _, tc := range []struct {
		name  string
		state string
		rows  []row
		want  bool
	}{
		{"verified ipmi", "fenced", []row{{"ipmi", "fenced", now}}, true},
		{"operator confirmation", "fenced", []row{{"manual", "partial", now.Add(-time.Minute)}, {"manual", "manual-confirmed", now}}, true},
		{"ssh, recorded fenced by an older leader", "fenced", []row{{"ssh", "fenced", now}}, false},
		{"watchdog", "fenced", []row{{"watchdog", "fenced", now}}, false},
		{"best-effort", "fenced", []row{{"best-effort-ssh", "fenced", now}}, false},
		{"an unverified fence after a verified one", "fenced", []row{{"ipmi", "fenced", now.Add(-time.Hour)}, {"ssh", "fenced", now}}, false},
		{"a failed fence after a verified one", "fenced", []row{{"ipmi", "fenced", now.Add(-time.Hour)}, {"ipmi", "partial", now}}, false},
		{"a confirmation after an unverified fence", "fenced", []row{{"ssh", "fenced", now.Add(-time.Minute)}, {"manual", "manual-confirmed", now}}, true},
		{"a verified and an unverified fence in one second", "fenced", []row{{"ipmi", "fenced", now}, {"ssh", "fenced", now}}, false},
		{"no fence on record", "fenced", nil, false},
		{"a verified fence, but the host is offline", "offline", []row{{"ipmi", "fenced", now}}, false},
		{"a verified fence, but the host is back", "active", []row{{"ipmi", "fenced", now}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			seedHost(t, c, "h1")
			if err := UpdateHostState(ctx, c, "h1", tc.state); err != nil {
				t.Fatal(err)
			}
			for i, r := range tc.rows {
				if err := c.Execute(ctx,
					`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'h1', ?, ?, ?, '')`,
					string(rune('a'+i)), r.method, r.result, r.at.Format(time.RFC3339)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := HostProvedOff(ctx, c, "h1")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("HostProvedOff = %v, want %v", got, tc.want)
			}
		})
	}
}

// A 'fenced' state over an UNVERIFIED fence dates the host's life like any
// other state's: an earlier life's operator confirmation — the old machine's,
// still in fencing_log when the name was given to a new one — does not count
// as a proof-grade fence of the host that an older leader has since recorded
// 'fenced' on an SSH poweroff. `lv host rm --dead` must not remove it as
// proven off.
//
// Mutation: exempt every 'fenced' state from HostFenceLife again — the old
// confirmation counts and the test goes red.
func TestHostProofGradeFence_UnverifiedFencedStateDatesTheLife(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	c := testClient(t)
	seedHost(t, c, "h1")
	c.SetHostMembershipGate(func() bool { return true })
	if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
		t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES ('old', 'h1', 'manual', 'manual-confirmed', ?, '')`,
		now.Add(-time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := RecordFenceWithState(ctx, c, FenceLogRecord{ID: "ssh", HostName: "h1", Method: "ssh", Result: "fenced"}, "fenced"); err != nil {
		t.Fatal(err)
	}
	if rec, ok, err := HostProofGradeFence(ctx, c, "h1"); err != nil || ok {
		t.Errorf("HostProofGradeFence = %+v, %v, %v; an earlier life's confirmation must not prove a host "+
			"recorded 'fenced' on an SSH fence off", rec, ok, err)
	}

	// The operator confirms THIS host off: that counts.
	if err := UpdateHostState(ctx, c, "h1", "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := InsertFenceLog(ctx, c, FenceLogRecord{ID: "now", HostName: "h1", Method: "manual", Result: "manual-confirmed"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := HostProofGradeFence(ctx, c, "h1"); err != nil || !ok {
		t.Errorf("ok=%v err=%v; a confirmation of the host as it is now must count", ok, err)
	}
}

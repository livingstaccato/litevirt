package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// gateRefusal adds the host's state and the remedy only for a refusal whose
// reason is that this host is not an active worker, and only while its record
// says it is draining or in maintenance. Every other refusal — another reason,
// another state, an unreadable record — keeps the bare "<what> refused:
// <reason>" that callers and tests match on. promote, container restore and
// lb apply take the generic remedy; start and restart are pinned end to end in
// tests/fleet (TestFleet_StartRefusedOnAnInactiveHostSaysWhyAndWhatToDo).
//
// Mutations: drop the reason check — the no_quorum case gains the hint and
// goes red; drop the state switch's default — the active and fenced cases gain
// it and go red.
func TestGateRefusal_HintOnlyForAHostOutOfService(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		state, reason string
		want          string // "" = the bare message
	}{
		{"draining", health.ReasonLocalNotActiveWorker, "promote refused: local_not_active_worker — host test-host is draining, and takes on no new work until it is active again: return it to active with `lv host undrain test-host` first"},
		{"maintenance", health.ReasonLocalNotActiveWorker, "promote refused: local_not_active_worker — host test-host is in maintenance, and takes on no new work until it is active again: return it to active with `lv host undrain test-host` first"},
		{"draining", health.ReasonNoQuorum, ""},
		{"active", health.ReasonLocalNotActiveWorker, ""},
		{"fenced", health.ReasonLocalNotActiveWorker, ""},
		{"", health.ReasonLocalNotActiveWorker, ""}, // no host record
	} {
		s := testServer(t)
		if tc.state != "" {
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: tc.state}); err != nil {
				t.Fatal(err)
			}
		}
		got := s.gateRefusal(ctx, "promote", tc.reason, returnToServiceHint)
		want := tc.want
		if want == "" {
			want = "promote refused: " + tc.reason
		}
		if got != want {
			t.Errorf("state %q reason %q:\n got %q\nwant %q", tc.state, tc.reason, got, want)
		}
	}
	// The drain's own hint is the start hint for a draining host, word for word.
	if got, want := startOnDrainedHostHint("os1", "h1"), startOnInactiveHostHint("os1", "h1", "is draining"); got != want ||
		!strings.Contains(got, "once h1 is no longer draining (`lv host undrain h1`)") {
		t.Errorf("startOnDrainedHostHint = %q", got)
	}
	if got := startOnInactiveHostHint("os1", "h1", "is in maintenance"); !strings.Contains(got, "once h1 is no longer in maintenance") {
		t.Errorf("maintenance start hint = %q", got)
	}
}

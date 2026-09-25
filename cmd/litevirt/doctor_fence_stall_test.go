package main

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv doctor fence` is where an operator asks "why has this host not been
// fenced yet?". A node whose fence votes are withheld after a stall is the
// answer, so the doctor names it, with how long it was paused and until when.
func TestDoctorFence_NamesStalledObservers(t *testing.T) {
	conds := []*pb.HealthCondition{
		{Code: "observer_stalled", SubjectKind: "host", SubjectId: "node-3", Lifecycle: "confirmed",
			Evidence: `{"detail":"x","gap_seconds":34.2,"grace_until":"2026-09-24T14:02:11Z"}`},
		{Code: "observer_stalled", SubjectKind: "host", SubjectId: "node-2", Lifecycle: "resolved",
			Evidence: `{"gap_seconds":5,"grace_until":"2026-09-24T13:00:00Z"}`},
		{Code: "gossip_isolated", SubjectKind: "host", SubjectId: "node-4", Lifecycle: "confirmed"},
	}
	var out bytes.Buffer
	printStalledObservers(&out, conds)
	got := out.String()
	for _, want := range []string{"node-3", "34s", "2026-09-24T14:02:11Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"node-2", "node-4"} {
		if strings.Contains(got, not) {
			t.Errorf("output names %s, which has no open stall:\n%s", not, got)
		}
	}
}

func TestDoctorFence_NoStalledObserversPrintsNothing(t *testing.T) {
	var out bytes.Buffer
	printStalledObservers(&out, []*pb.HealthCondition{
		{Code: "gossip_isolated", SubjectKind: "host", SubjectId: "node-4", Lifecycle: "confirmed"},
	})
	if out.Len() != 0 {
		t.Fatalf("printed a stall section with no stalled observer:\n%s", out.String())
	}
}

// The command itself, not just the printer, reports a stalled observer.
func TestDoctorFence_CommandReportsAStalledObserver(t *testing.T) {
	out, _ := runDoctorFenceWithHealth(t, &pb.FenceReadiness{}, &pb.ClusterHealth{
		Conditions: []*pb.HealthCondition{{
			Code: "observer_stalled", SubjectKind: "host", SubjectId: "node-3", Lifecycle: "confirmed",
			Evidence: `{"gap_seconds":34,"grace_until":"2026-09-24T14:02:11Z"}`,
		}},
	})
	if !strings.Contains(out, "stalled observers") || !strings.Contains(out, "node-3") {
		t.Fatalf("lv doctor fence did not report the stalled observer:\n%s", out)
	}
}

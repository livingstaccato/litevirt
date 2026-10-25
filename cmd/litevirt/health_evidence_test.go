package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The rc10 lab's N1: `lv health` printed a condition's evidence only for
// vm.move_unresolved, so the operator never saw what to do about
// vm_start_stranded_paused or ha.recovery.unproven_fence there. Every open
// condition whose evidence carries a detail or a remedy prints them under it,
// indented and wrapped, never as raw JSON; a resolved one, or evidence with
// neither, prints nothing.
//
// Mutation: print the evidence only for vm.move_unresolved, as before — red.
func TestPrintClusterHealth_ShowsEachConditionsDetailAndRemedy(t *testing.T) {
	long := "once node-5 is powered off, `lv host fence-confirm node-5`, and the recovery resumes from it. " +
		"To recover at once next time, give it a fence that proves a power-off: " +
		"`lv host config node-5 --fence-strategy ipmi|redfish`"
	out := captureStdout(t, func() {
		printClusterHealth(&pb.ClusterHealth{Overall: "CRITICAL", Conditions: []*pb.HealthCondition{
			{Code: "ha.recovery.unproven_fence", SubjectKind: "host", SubjectId: "node-5", Lifecycle: "confirmed",
				Severity: "critical", Hosts: []string{"node-5"},
				Evidence: `{"detail":"the recovery of node-5 is held: the SSH fence failed","workloads":["vm/a"],"remedy":"` + long + `"}`},
			{Code: "vm_start_stranded_paused", SubjectKind: "vm", SubjectId: "rc10v1@node-1", Lifecycle: "confirmed",
				Severity: "warning", Hosts: []string{"node-1"},
				Evidence: `{"vm":"rc10v1","host":"node-1","never_ran":true,"detail":"QEMU reports the guest never ran (prelaunch), so ` +
					"`lv stop --force rc10v1`" + ` loses nothing"}`},
			{Code: "some.resolved", SubjectKind: "host", SubjectId: "node-2", Lifecycle: "resolved",
				Evidence: `{"detail":"RESOLVED-DETAIL"}`},
			{Code: "no.detail", SubjectKind: "host", SubjectId: "node-3", Lifecycle: "confirmed",
				Evidence: `{"count":3}`},
			{Code: "not.json", SubjectKind: "host", SubjectId: "node-4", Lifecycle: "confirmed", Evidence: `NOT-JSON`},
		}})
	})
	for _, want := range []string{
		"\nha.recovery.unproven_fence on host/node-5:\n    detail: the recovery of node-5 is held: the SSH fence failed\n",
		"\n    remedy: once node-5 is powered off,",
		"\nvm_start_stranded_paused on vm/rc10v1@node-1:\n    detail: QEMU reports the guest never ran (prelaunch),",
		"loses nothing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, notWant := range []string{"RESOLVED-DETAIL", "no.detail on", "not.json on", "NOT-JSON", `{"`, "workloads"} {
		if strings.Contains(out, notWant) {
			t.Errorf("output has %q:\n%s", notWant, out)
		}
	}
	// Wrapped and indented: the remedy's words all appear, on lines no wider
	// than the wrap width, each continuation indented under its label.
	if !strings.Contains(strings.Join(strings.Fields(out), " "), long) {
		t.Errorf("the remedy's words are not all there:\n%s", out)
	}
	inRemedy := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "    remedy: "):
			inRemedy = true
		case inRemedy && strings.HasPrefix(line, "            "):
		default:
			inRemedy = false
		}
		if inRemedy && len(line) > evidenceWrapWidth {
			t.Errorf("line wider than %d: %q", evidenceWrapWidth, line)
		}
	}
	if strings.Count(out, "\n            ") == 0 {
		t.Errorf("the long remedy is not wrapped onto indented lines:\n%s", out)
	}
}

// wrapIndented never splits a word, even one longer than the width, nor a
// `code span`, and indents each continuation line.
func TestWrapIndented(t *testing.T) {
	got := wrapIndented("aa bb cc "+strings.Repeat("x", 30)+" dd", "  k: ", "     ", 14)
	want := "  k: aa bb cc\n     " + strings.Repeat("x", 30) + "\n     dd\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	got = wrapIndented("run `lv host config node-5 --x` now", "k: ", "   ", 16)
	want = "k: run\n   `lv host config node-5 --x`\n   now\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
